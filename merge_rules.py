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

# 只保留控制台输出
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AdGuardRuleMerger:
    # 常量配置
    REQUEST_TIMEOUT = (10, 30)
    MAX_RETRIES = 1  # ✅ 优化：失败当场重试1次
    MAX_WORKERS = 8  # GitHub Actions安全并发
    MAX_RULE_LENGTH = 1024
    
    def __init__(self):
        self.network_rules: Set[str] = set()
        # ✅ 优化：个人用户无需本地黑白名单
        self.stats: Dict[str, Any] = {
            'total_sources': 0, 'total_network_rules': 0, 'duplicate_rules': 0,
            'invalid_rules': 0, 'sources_processed': 0, 'failed_sources': [],
            'pruned_subdomain_rules': 0,
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
        retry = Retry(total=self.MAX_RETRIES, backoff_factor=2, status_forcelist=(429, 500, 502, 503, 504))
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.mount("http://", HTTPAdapter(max_retries=retry))
        try:
            resp = session.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=self.REQUEST_TIMEOUT)
            resp.raise_for_status()
            resp.encoding = resp.apparent_encoding
            return resp.text
        except Exception as e:
            logging.error(f"[下载失败] {url}: {e}")
            with self.lock:
                self.stats['failed_sources'].append(url)
            return None

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
                    logging.info(f"已加载 {len(valid_sources)} 个有效来源")
                    return valid_sources
            except (UnicodeDecodeError, FileNotFoundError):
                continue
        logging.error(f"无法读取 {file}")
        return []

    # ✅ 优化：子域剪枝改为可选功能
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
        
        # ✅ 优化：输出到系统临时目录，减少磁盘写入
        temp_dir = os.environ.get('TMPDIR') or os.environ.get('TEMP') or '/tmp'
        filepath = os.path.join(temp_dir, filename)
        
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
        
        logging.info(f"已保存到临时目录: {filepath}")
        # 控制台直接输出规则内容，方便管道操作
        print(''.join(content))

    # ✅ 优化：核心并发流程
    def run(self, sources_file: str = 'sources.txt', output_file: str = 'adguard_rules.txt', do_prune: bool = False):
        logging.info("=" * 50)
        logging.info("AdGuardHome 规则合并")
        logging.info("=" * 50)
        
        sources = self.load_sources(sources_file)
        if not sources:
            logging.warning("未找到网络源，退出")
            sys.exit(1)
        
        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            future_to_url = {executor.submit(self.download_and_process, url): url for url in sources}
            for future in as_completed(future_to_url):
                future.result()  # 异常会自然抛出
        
        # ✅ 优化：移除失败率检查，个人网络稳定无需统计
        if self.stats['failed_sources']:
            logging.warning(f"失败源数量: {len(self.stats['failed_sources'])}")
        
        # ✅ 优化：剪枝功能默认关闭，需手动启用
        if do_prune and self.network_rules:
            logging.info("正在执行子域剪枝...")
            self.prune_subdomain_rules()
        
        self.save_merged_rules(output_file)
        logging.info("=" * 50)
        logging.info("全部任务完成")
        logging.info("=" * 50)

    def download_and_process(self, url: str):
        logging.info(f"正在获取: {url}")
        content = self.download_rules(url)
        if content:
            self.process_rules(content)

def main():
    parser = argparse.ArgumentParser(description='AdGuardHome 规则合并（个人优化版）')
    parser.add_argument('-s', '--sources', default='sources.txt', help='来源列表文件')
    parser.add_argument('-o', '--output', default='adguard_rules.txt', help='输出文件名')
    parser.add_argument('--prune', action='store_true', help='启用子域剪枝（默认关闭）')
    parser.add_argument('-v', '--verbose', action='store_true', help='启用详细日志')
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        merger = AdGuardRuleMerger()
        merger.run(sources_file=args.sources, output_file=args.output, do_prune=args.prune)
    except KeyboardInterrupt:
        logging.info("\n用户中断")
        sys.exit(130)
    except Exception as e:
        logging.error(f"致命错误: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
