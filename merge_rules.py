#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import argparse
import logging
import requests
import json
from datetime import datetime
from typing import Set, List, Optional, Dict, Any
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from zoneinfo import ZoneInfo

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('merge.log', encoding='utf-8')
    ]
)

class AdGuardRuleMerger:
    MIN_DOMAIN_LENGTH = 2
    MAX_DOMAIN_LABEL_LENGTH = 63
    MAX_TOTAL_LENGTH = 253
    MAX_RULE_LENGTH = 1024
    REQUEST_TIMEOUT = (10, 30)
    MAX_RETRIES = 3
    MAX_FAILURE_RATE = 0.5

    def __init__(self, blacklist_file: str = 'blacklist.txt', whitelist_file: str = 'whitelist.txt'):
        self.network_rules: Set[str] = set()
        self.custom_rules: Set[str] = set()
        self.custom_exceptions: Set[str] = set()
        
        self.stats: Dict[str, Any] = {
            'total_sources': 0,
            'total_network_rules': 0,
            'total_custom_rules': 0,
            'total_custom_exceptions': 0,
            'duplicate_rules': 0,
            'invalid_rules': 0,
            'invalid_domains': 0,
            'invalid_length': 0,
            'invalid_type': 0,
            'sources_processed': 0,
            'pruned_subdomain_rules': 0,
            'failed_sources': [],
            'conflict_resolved': 0,
            'network_whitelist_discarded': 0,
            'unicode_domains_discarded': 0,
        }
        self.black_file = blacklist_file
        self.white_file = whitelist_file

        self.domain_pattern = re.compile(
            r'^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)*'
            r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)$'
        )

    def _normalize_domain(self, domain: str) -> str:
        domain = domain.strip().lower()
        if any(ord(c) > 127 for c in domain):
            logging.debug(f"[Unicode域名已丢弃] {domain}")
            self.stats['unicode_domains_discarded'] += 1
            return ""
        if not self.domain_pattern.match(domain):
            self.stats['invalid_domains'] += 1
            return ""
        labels = domain.split('.')
        for label in labels:
            if len(label) > self.MAX_DOMAIN_LABEL_LENGTH or \
               label.startswith('-') or label.endswith('-') or \
               '_' in label:
                self.stats['invalid_domains'] += 1
                return ""
        return domain

    def _extract_domain_from_rule(self, rule: str) -> Optional[str]:
        rule = rule.strip().lower()
        if '$' in rule:
            rule = rule.split('$')[0]
        if rule.startswith('||') and '^' in rule:
            domain_part = rule.lstrip('|').split('^')[0]
            return self._normalize_domain(domain_part)
        if self.domain_pattern.match(rule):
            return self._normalize_domain(rule)
        return None

    def normalize_network_rule(self, rule: str) -> str:
        rule = rule.strip().lower()
        if not (rule.startswith('||') and rule.endswith('^')):
            return ""
        domain_part = rule.lstrip('|').split('^')[0].split('$')[0]
        normalized_domain = self._normalize_domain(domain_part)
        return f'||{normalized_domain}^' if normalized_domain else ""

    def download_rules(self, url: str) -> Optional[str]:
        session = requests.Session()
        retry = Retry(
            total=self.MAX_RETRIES,
            backoff_factor=2,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "HEAD")
        )
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.mount("http://", HTTPAdapter(max_retries=retry))
        try:
            resp = session.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=self.REQUEST_TIMEOUT)
            resp.raise_for_status()
            resp.encoding = resp.apparent_encoding
            return resp.text
        except Exception as e:
            logging.error(f"[下载失败] {url}: {e}")
            self.stats['failed_sources'].append(url)
            return None

    def process_rules(self, content: str, source: str):
        if not content:
            return
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(('!', '#', '[')):
                continue
            if len(line) > self.MAX_RULE_LENGTH:
                self.stats['invalid_length'] += 1
                continue
            if not (line.startswith('||') and line.endswith('^') and '$' not in line):
                self.stats['invalid_rules'] += 1
                continue
            if line.startswith('@@'):
                logging.debug(f"[网络源白名单已丢弃] {line}")
                self.stats['network_whitelist_discarded'] += 1
                continue
            rule = self.normalize_network_rule(line)
            if not rule:
                continue
            conflict_detected = False
            domain_only = self._extract_domain_from_rule(rule)
            for custom_rule in self.custom_rules:
                custom_domain = self._extract_domain_from_rule(custom_rule)
                if custom_domain and custom_domain == domain_only:
                    conflict_detected = True
                    logging.debug(f"[冲突已解决] 网络源规则 {rule} 被自定义规则覆盖")
                    break
            if conflict_detected:
                self.stats['conflict_resolved'] += 1
                continue
            if rule in self.network_rules:
                self.stats['duplicate_rules'] += 1
                continue
            self.network_rules.add(rule)
            self.stats['total_network_rules'] += 1
        self.stats['sources_processed'] += 1

    def load_sources(self, file: str = 'sources.txt') -> List[str]:
        for encoding in ('utf-8-sig', 'gbk', 'latin-1'):
            try:
                with open(file, encoding=encoding) as f:
                    sources = [line.split('#')[0].strip() for line in f if line.strip() and not line.startswith('#')]
                    valid_sources = []
                    for url in sources:
                        try:
                            result = urlparse(url)
                            if result.scheme in ('http', 'https') and result.netloc:
                                valid_sources.append(url)
                        except:
                            continue
                    self.stats['total_sources'] = len(valid_sources)
                    logging.info(f"已加载 {len(valid_sources)} 个有效来源（编码: {encoding}）")
                    return valid_sources
            except (UnicodeDecodeError, FileNotFoundError):
                continue
        logging.error(f"无法读取 {file}")
        return []

    def apply_custom_lists(self):
        if os.path.isfile(self.black_file):
            count = 0
            with open(self.black_file, encoding='utf-8-sig') as f:
                for line in f:
                    raw_rule = line.strip().strip('\u200b\u200c\u200d')
                    if not raw_rule or raw_rule.startswith(('#', '!')):
                        continue
                    if '||^' in raw_rule:
                        logging.warning(f"  无效规则被忽略: {line.strip()}")
                        continue
                    self.custom_rules.add(raw_rule)
                    count += 1
            self.stats['total_custom_rules'] = count
            logging.info(f"已应用自定义黑名单: {self.black_file}（共 {count} 条）")
        else:
            logging.info(f"自定义黑名单不存在，跳过: {self.black_file}")

        if os.path.isfile(self.white_file):
            count = 0
            with open(self.white_file, encoding='utf-8-sig') as f:
                for line in f:
                    raw_rule = line.strip().strip('\u200b\u200c\u200d')
                    if not raw_rule or raw_rule.startswith(('#', '!')):
                        continue
                    self.custom_exceptions.add(raw_rule)
                    count += 1
            self.stats['total_custom_exceptions'] = count
            logging.info(f"已应用自定义白名单: {self.white_file}（共 {count} 条）")
        else:
            logging.info(f"自定义白名单不存在，跳过: {self.white_file}")

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
                    logging.debug(f"标记父域待删除: {parent}（子域 {domain} 存在）")
        kept_domains = all_domains - parent_domains
        final_rules = {r for r in self.network_rules if extract_domain(r) in kept_domains}
        self.stats['pruned_subdomain_rules'] = len(self.network_rules) - len(final_rules)
        logging.info(f"子域剪枝完成: 移除 {self.stats['pruned_subdomain_rules']} 条父域规则")
        self.network_rules = final_rules

    def save_merged_rules(self, filename: str = 'adguard_rules.txt'):
        os.makedirs(os.path.dirname(filename) or '.', exist_ok=True)
        all_rules = list(self.network_rules) + list(self.custom_rules)
        all_exceptions = list(self.custom_exceptions)
        self.stats['total_rules'] = len(all_rules) + len(all_exceptions)
        try:
            tz = ZoneInfo('Asia/Shanghai')
        except:
            tz = ZoneInfo('UTC')
        now = datetime.now(tz)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f'! {"="*70}\n')
            f.write(f'! AdGuardHome 合并规则\n')
            f.write(f'! 生成时间: {now:%Y-%m-%d %H:%M:%S %Z}\n')
            f.write(f'! 规则总数: {self.stats["total_rules"]} | 网络源: {len(self.network_rules)} | 黑名单: {len(self.custom_rules)} | 白名单: {len(self.custom_exceptions)}\n')
            f.write(f'! 剪枝: {self.stats["pruned_subdomain_rules"]} | 重复: {self.stats["duplicate_rules"]} | 冲突: {self.stats["conflict_resolved"]} | 无效: {self.stats["invalid_rules"]}\n')
            f.write(f'! {"="*70}\n!\n')
            for title, rules in {'网络源阻止规则': sorted(self.network_rules), '自定义黑名单': sorted(self.custom_rules), '自定义白名单': sorted(self.custom_exceptions)}.items():
                if rules:
                    f.write(f'! ---- {title} ----\n')
                    f.writelines(f'{r}\n' for r in rules)
                    f.write('!\n')
        logging.info(f"已保存: {filename}（共 {self.stats['total_rules']} 条规则）")
        
        # 强制创建统计文件
        with open('merge_stats.json', 'w', encoding='utf-8') as f:
            json.dump(self.stats, f, ensure_ascii=False, indent=2)

    def run(self, sources_file: str = 'sources.txt', output_file: str = 'adguard_rules.txt'):
        logging.info("=" * 60)
        logging.info("AdGuardHome 规则合并")
        logging.info("=" * 60)
        self.apply_custom_lists()
        sources = self.load_sources(sources_file)
        if not sources:
            logging.warning("未找到网络源，仅使用自定义规则")
        else:
            for idx, url in enumerate(sources, 1):
                logging.info(f"[{idx}/{len(sources)}] 正在获取: {url}")
                content = self.download_rules(url)
                if content:
                    self.process_rules(content, url)
            failure_rate = len(self.stats['failed_sources']) / len(sources) if sources else 0
            if failure_rate > self.MAX_FAILURE_RATE:
                logging.error(f"❌ 失败源超过阈值 ({failure_rate:.1%} > {self.MAX_FAILURE_RATE:.0%})，中止执行")
                sys.exit(1)
        if self.stats['failed_sources']:
            logging.warning("\n[!] 失败的来源:")
            for url in self.stats['failed_sources']:
                logging.warning(f"   - {url}")
        if self.network_rules:
            logging.info("正在执行子域剪枝...")
            self.prune_subdomain_rules()
        if self.stats['network_whitelist_discarded'] > 0:
            logging.info(f"[!] 网络源白名单已丢弃: {self.stats['network_whitelist_discarded']} 条")
        if self.stats['unicode_domains_discarded'] > 0:
            logging.info(f"[!] Unicode域名已丢弃: {self.stats['unicode_domains_discarded']} 条")
        self.save_merged_rules(output_file)
        logging.info("=" * 60)
        logging.info("全部任务完成")
        logging.info("=" * 60)

def main():
    parser = argparse.ArgumentParser(description='AdGuardHome 规则合并')
    parser.add_argument('-s', '--sources', default='sources.txt', help='来源列表文件')
    parser.add_argument('-o', '--output', default='adguard_rules.txt', help='输出文件')
    parser.add_argument('-b', '--blacklist', default='blacklist.txt', help='自定义黑名单')
    parser.add_argument('-w', '--whitelist', default='whitelist.txt', help='自定义白名单')
    parser.add_argument('-v', '--verbose', action='store_true', help='启用详细日志')
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    try:
        merger = AdGuardRuleMerger(blacklist_file=args.blacklist, whitelist_file=args.whitelist)
        merger.run(sources_file=args.sources, output_file=args.output)
    except KeyboardInterrupt:
        logging.info("\n用户中断")
        sys.exit(130)
    except Exception as e:
        logging.error(f"致命错误: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()