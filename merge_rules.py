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

# Logging config for GitHub Actions
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class AdGuardRuleMerger:
    REQUEST_TIMEOUT = (10, 30)
    MAX_RETRIES = 1
    MAX_WORKERS = 8
    MAX_RULE_LENGTH = 1024
    
    def __init__(self):
        self.network_rules: Set[str] = set()
        self.custom_rules: Set[str] = set()  # ✅ 恢复：自定义黑名单
        self.custom_exceptions: Set[str] = set()  # ✅ 恢复：自定义白名单
        self.stats: Dict[str, Any] = {
            'total_sources': 0, 'total_network_rules': 0, 'duplicate_rules': 0,
            'invalid_rules': 0, 'sources_processed': 0, 'failed_sources': [],
            'pruned_subdomain_rules': 0,
            # ✅ 新增统计
            'total_custom_rules': 0,
            'total_custom_exceptions': 0,
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
