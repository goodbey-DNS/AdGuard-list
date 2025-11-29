#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import logging
import requests
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Set, List, Dict, Any, Optional
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from zoneinfo import ZoneInfo

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class AdGuardRuleMerger:
    REQUEST_TIMEOUT = (10, 30)
    MAX_RETRIES = 1
    MAX_WORKERS = 8
    MAX_RULE_LENGTH = 1024
    
    def __init__(self):
        self.network_rules: Set[str] = set()
        self.custom_rules: Set[str] = set()  # 自定义黑名单
        self.custom_exceptions: Set[str] = set()  # 自定义白名单（只存域名）
        self.stats: Dict[str, Any] = {
            'total_sources': 0, 'total_network_rules': 0, 'duplicate_rules': 0,
            'invalid_rules': 0, 'sources_processed': 0, 'failed_sources': [],
            'pruned_subdomain_rules': 0, 'total_custom_rules': 0, 'total_custom_exceptions': 0,
        }
        self.lock = threading.Lock()

    def normalize_network_rule(self, rule: str) -> str:
        rule = rule.strip().lower()
        if not (rule.startswith('||') and rule.endswith('^') and '$' not in rule):
            return ""
        domain_part = rule.lstrip('|').split('^')[0]
        return f'||{domain_part}^' if domain_part else ""

    # ✅ 精简：提取域名用于白名单匹配
    def _extract_domain(self, rule: str) -> Optional[str]:
        if rule.startswith('||') and rule.endswith('^'):
            return rule.lstrip('|').split('^')[0]
        return None

    def download_rules(self, url: str) -> Optional[str]:
        with requests.Session() as session:
            retry = Retry(total=self.MAX_RETRIES, backoff_factor=2, status_forcelist=(429, 502, 503, 504))
            session.mount("https://", HTTPAdapter(max_retries=retry))
            session.mount("http://", HTTPAdapter(max_retries=retry))
            try:
                resp = session.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=self.REQUEST_TIMEOUT)
                resp.raise_for_status()
                resp.encoding = resp.apparent_encoding
                return resp.text
            except Exception as e:
                logging.error(f"[Download Failed] {url}: {e}")
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
            
            # ✅ 精简：白名单精确匹配域名
            rule_domain = self._extract_domain(rule)
            if rule_domain and rule_domain in self.custom_exceptions:
                continue  # 跳过白名单中的域名
            
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
                    return valid_sources
            except (UnicodeDecodeError, FileNotFoundError):
                continue
        return []

    # ✅ 精简：加载本地黑白名单（无文件时静默跳过）
    def apply_custom_lists(self):
        # 白名单：只存域名，不带 ||^
        if os.path.exists('whitelist.txt'):
            try:
                with open('whitelist.txt', 'r', encoding='utf-8-sig') as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain and not domain.startswith(('#', '!')):
                            self.custom_exceptions.add(domain)
                self.stats['total_custom_exceptions'] = len(self.custom_exceptions)
                logging.info(f"Loaded {self.stats['total_custom_exceptions']} whitelist domains")
            except Exception as e:
                logging.warning(f"Failed to load whitelist.txt: {e}")
        
        # 黑名单：存完整规则
        if os.path.exists('blacklist.txt'):
            try:
                with open('blacklist.txt', 'r', encoding='utf-8-sig') as f:
                    for line in f:
                        rule = line.strip()
                        if rule and not rule.startswith(('#', '!')):
                            self.custom_rules.add(rule)
                self.stats['total_custom_rules'] = len(self.custom_rules)
                logging.info(f"Loaded {self.stats['total_custom_rules']} custom blacklist rules")
            except Exception as e:
                logging.warning(f"Failed to load blacklist.txt: {e}")

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
        logging.info(f"Subdomain pruning complete: removed {self.stats['pruned_subdomain_rules']} parent rules")
        self.network_rules = final_rules

    def save_merged_rules(self, filename: str = 'adguard_rules.txt'):
        with self.lock:
            all_rules = list(self.network_rules)
        
        filepath = filename
        
        try:
            tz = ZoneInfo('Asia/Shanghai')
        except Exception:
            tz = ZoneInfo('UTC')
        now = datetime.now(tz)
        
        # ✅ 三段式写入：网络规则 + 黑名单（白名单不输出，只作例外）
        with open(filepath, 'w', encoding='utf-8') as f:
            # Header
            f.write(f'! AdGuardHome Merged Rules - {now:%Y-%m-%d %H:%M:%S %Z}\n')
            f.write(f'! Total: {len(all_rules) + len(self.custom_rules)} | Network: {len(all_rules)} | Blacklist: {len(self.custom_rules)}\n')
            f.write(f'! Pruned: {self.stats["pruned_subdomain_rules"]} | Duplicate: {self.stats["duplicate_rules"]} | Invalid: {self.stats["invalid_rules"]}\n!\n')
            
            # Network rules
            if all_rules:
                f.write('! ---- Network Rules ----\n')
                for rule in sorted(all_rules):
                    f.write(f'{rule}\n')
                f.write('!\n')
            
            # Custom blacklist
            if self.custom_rules:
                f.write('! ---- Custom Blacklist ----\n')
                for rule in sorted(self.custom_rules):
                    f.write(f'{rule}\n')
                f.write('!\n')
        
        logging.info(f"Saved: {filepath} ({len(all_rules) + len(self.custom_rules)} total rules)")

    def run(self, sources_file: str = 'sources.txt', output_file: str = 'adguard_rules.txt'):
        logging.info("=" * 50)
        logging.info("AdGuardHome Rules Merge")
        logging.info("=" * 50)
        
        # ✅ 关键修复：先加载黑白名单，再加载网络源（避免源为空时跳过加载）
        self.apply_custom_lists()
        
        sources = self.load_sources(sources_file)
        
        if sources:
            with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
                future_to_url = {executor.submit(self.download_and_process, url): url for url in sources}
                for future in as_completed(future_to_url):
                    future.result()
        else:
            logging.warning("No network sources, using only custom rules")
        
        if self.network_rules:
            logging.info("Running subdomain pruning...")
            self.prune_subdomain_rules()
        
        self.save_merged_rules(output_file)
        logging.info("=" * 50)
        logging.info("All tasks completed")
        logging.info("=" * 50)

    def download_and_process(self, url: str):
        logging.info(f"Fetching: {url}")
        content = self.download_rules(url)
        if content:
            self.process_rules(content)

if __name__ == '__main__':
    try:
        merger = AdGuardRuleMerger()
        merger.run()
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)
