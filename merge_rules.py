#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import logging
import requests
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Set, List, Optional, Dict, Any
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from zoneinfo import ZoneInfo

# 带颜色的日志格式
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AdGuardRuleMerger:
    REQUEST_TIMEOUT = (10, 30)
    MAX_RETRIES = 1
    MAX_WORKERS = 8
    MAX_RULE_LENGTH = 1024
    
    def __init__(self):
        self.network_rules: Set[str] = set()
        self.stats: Dict[str, Any] = {
            'total_sources': 0, 'total_network_rules': 0, 'duplicate_rules': 0,
            'invalid_rules': 0, 'sources_processed': 0, 'pruned_subdomain_rules': 0,
            # 'failed_sources' 已删除
        }
        self.lock = threading.Lock()

    def _normalize_domain(self, domain: str) -> str:
        return domain.strip().lower()

    def normalize_network_rule(self, rule: str) -> str:
        rule = rule.strip().lower()
        if not (rule.startswith('||') and rule.endswith('^') and '$' not in rule):
            return ""
        domain_part = rule.lstrip('|').split('^')[0]
        return f'||{self._normalize_domain(domain_part)}^' if domain_part else ""

    def download_rules(self, url: str) -> Optional[str]:
        session = requests.Session()
        retry = Retry(total=self.MAX_RETRIES, backoff_factor=2, status_forcelist=(429, 502, 503, 504))
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.mount("http://", HTTPAdapter(max_retries=retry))
        try:
            resp = session.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=self.REQUEST_TIMEOUT)
            resp.raise_for_status()
            resp.encoding = resp.apparent_encoding
            return resp.text
        except Exception as e:
            logging.error(f"\033[91m[下载失败] {url}: {e}\033[0m")  # 红色
            return None  # 不再记录到 stats

    def process_rules(self, content: str):
        if not content:
            return
        local_stats = {'duplicate': 0, 'invalid': 0, 'network_rules': 0}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(('!', '#', '[')):
                continue
            if len(line) > self.MAX_RULE_LENGTH:
                local_stats['invalid'] += 1
                continue
            if not (line.startswith('||') and line.endswith('^')):
                local_stats['invalid'] += 1
                continue
            rule = self.normalize_network_rule(line)
            if not rule:
                continue
            with self.lock:
                if rule in self.network_rules:
                    local_stats['duplicate'] += 1
                else:
                    self.network_rules.add(rule)
                    local_stats['network_rules'] += 1
        with self.lock:
            self.stats['duplicate_rules'] += local_stats['duplicate']
            self.stats['invalid_rules'] += local_stats['invalid']
            self.stats['total_network_rules'] += local_stats['network_rules']
            self.stats['sources_processed'] += 1

    def load_sources(self, file: str = 'sources.txt') -> List[str]:
        for encoding in ('utf-8-sig', 'gbk', 'latin-1'):
            try:
                with open(file, encoding=encoding) as f:
                    sources = [line.split('#')[0].strip() for line in f if line.strip() and not line.startswith('#')]
                    valid_sources = [url for url in sources if urlparse(url).scheme in ('http', 'https')]
                    self.stats['total_sources'] = len(valid_sources)
                    logging.info(f"\033[92m已加载 {len(valid_sources)} 个有效来源\033[0m")  # 绿色
                    return valid_sources
            except (UnicodeDecodeError, FileNotFoundError):
                continue
        logging.error(f"\033[91m无法读取 {file}\033[0m")
        return []

    def prune_subdomain_rules(self):
        if not self.network_rules:
            return
        def extract_domain(rule: str) -> str:
            return rule.lstrip('|').split('^')[0]
        all_domains = {extract_domain(r) for r in self.network_rules}
        parent_domains = set()
        for domain in all_domains:
            parts = domain.split('.')
            for i in range(1, len(parts)):
                parent = '.'.join(parts[i:])
                if parent in all_domains:
                    parent_domains.add(parent)
        kept_domains = all_domains - parent_domains
        final_rules = {r for r in self.network_rules if extract_domain(r) in kept_domains}
        self.stats['pruned_subdomain_rules'] = len(self.network_rules) - len(final_rules)
        logging.info(f"子域剪枝完成: 移除 {self.stats['pruned_subdomain_rules']} 条父域规则")
        self.network_rules = final_rules

    def save_merged_rules(self, filename: str):
        with self.lock:
            all_rules = list(self.network_rules)
            self.stats['total_rules'] = len(all_rules)
        
        temp_dir = os.environ.get('TMPDIR') or os.environ.get('TEMP') or '/tmp'
        filepath = os.path.join(temp_dir, filename)
        
        # ✅ 细节调整1：清理旧文件
        if os.path.exists(filepath):
            os.remove(filepath)
        
        try:
            tz = ZoneInfo('Asia/Shanghai')
        except:
            tz = ZoneInfo('UTC')
        now = datetime.now(tz)
        
        content = [
            f'! AdGuardHome 合并规则 - {now:%Y-%m-%d %H:%M:%S %Z}\n',
            f'! 规则总数: {len(all_rules)} | 剪枝: {self.stats["pruned_subdomain_rules"]} | 重复: {self.stats["duplicate_rules"]} | 无效: {self.stats["invalid_rules"]}\n!\n'
        ]
        content.extend(f'{r}\n' for r in sorted(all_rules))
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(content)
        
        logging.info(f"\033[92m已保存到临时目录: {filepath}\033[0m")  # 绿色
        print(''.join(content))

    def run(self, sources_file: str = 'sources.txt', output_file: str = 'adguard_rules.txt', no_prune: bool = False):
        logging.info("=" * 50)
        logging.info("AdGuardHome 规则合并")
        logging.info("=" * 50)
        
        sources = self.load_sources(sources_file)
        if not sources:
            logging.error("\033[91m未找到网络源，退出\033[0m")
            sys.exit(1)
        
        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            future_to_url = {executor.submit(self.download_and_process, url): url for url in sources}
            for future in as_completed(future_to_url):
                future.result()
        
        if not no_prune:  # ✅ 细节调整4：默认开启剪枝
            if self.network_rules:
                logging.info("正在执行子域剪枝...")
                self.prune_subdomain_rules()
        
        self.save_merged_rules(output_file)
        logging.info("=" * 50)
        logging.info("\033[92m全部任务完成\033[0m")  # 绿色
        logging.info("=" * 50)

    def download_and_process(self, url: str):
        logging.info(f"正在获取: {url}")
        content = self.download_rules(url)
        if content:
            self.process_rules(content)

def main():
    parser = argparse.ArgumentParser(description='AdGuardHome 规则合并（个人终极版）')
    parser.add_argument('-s', '--sources', default='sources.txt', help='来源列表文件')
    parser.add_argument('-o', '--output', default='adguard_rules.txt', help='输出文件名')
    parser.add_argument('--no-prune', action='store_true', help='禁用子域剪枝（默认启用）')
    parser.add_argument('-v', '--verbose', action='store_true', help='启用详细日志')
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        merger = AdGuardRuleMerger()
        merger.run(sources_file=args.sources, output_file=args.output, no_prune=args.no_prune)
    except KeyboardInterrupt:
        logging.info("\n用户中断")
        sys.exit(130)
    except Exception as e:
        logging.error(f"\033[91m致命错误: {e}\033[0m")
        sys.exit(1)

if __name__ == '__main__':
    main()
