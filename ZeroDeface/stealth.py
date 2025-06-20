#!/usr/bin/env python3
import random
import time
import requests
import base64
import hashlib
from datetime import datetime
import os
import re

class StealthEngine:
    def __init__(self, stealth_level='medium', proxy=None):
        self.levels = {
            'low': {
                'delay': (1, 3),
                'headers': self._gen_headers(['chrome', 'firefox']),
                'jitter': 0.3,
                'obfuscation': ['none']
            },
            'medium': {
                'delay': (3, 7),
                'headers': self._gen_headers(['edge', 'safari', 'mobile']),
                'jitter': 0.5,
                'obfuscation': ['base64', 'rot13']
            },
            'high': {
                'delay': (5, 15),
                'headers': self._gen_headers(['legacy', 'embedded', 'bot']),
                'jitter': 0.8,
                'obfuscation': ['base64', 'hex', 'reverse', 'rot13']
            }
        }
        self.level = self.levels[stealth_level]
        self.last_request_time = 0
        self.proxy = proxy
        self.request_counter = 0
        self.cookie_jar = {}
        
        # For log cleaning simulation
        self.log_patterns = [
            r'access\.log',
            r'error\.log',
            r'audit\.log',
            r'httpd\.log'
        ]

    def _gen_headers(self, types):
        """Generate realistic headers for different browser types with more variety"""
        headers_db = {
            'chrome': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br'
            },
            'firefox': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br'
            },
            'mobile': {
                'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
                'X-Requested-With': 'com.apple.mobilesafari',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            },
            'bot': {
                'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'From': 'googlebot(at)google.com'
            },
            'legacy': {
                'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)',
                'Accept': 'text/html, application/xhtml+xml, */*',
                'Accept-Encoding': 'gzip, deflate'
            }
        }
        return [headers_db[t] for t in types]

    def get_headers(self):
        """Return randomized headers with session persistence"""
        base = {
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        }
        
        # Rotate headers every 5-10 requests
        if self.request_counter % random.randint(5, 10) == 0:
            base.update(random.choice(self.level['headers']))
        else:
            base.update(self.current_headers)
            
        self.current_headers = base
        self.request_counter += 1
        return base

    def apply_delay(self):
        """Randomized wait between requests with jitter"""
        min_d, max_d = self.level['delay']
        delay = random.uniform(min_d, max_d) * (1 + random.uniform(-self.level['jitter'], self.level['jitter']))
        elapsed = time.time() - self.last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self.last_request_time = time.time()

    def obfuscate_url(self, url):
        """Add random parameters and path variations to disguise scans"""
        # Random URL variations
        variations = [
            lambda u: f"{u}?{random.choice(['_','rand','cacheid','sessionid'])}_{random.randint(1000,9999)}",
            lambda u: f"{u}?{random.choice(['utm_source=google','ref=organic','from=newsletter'])}",
            lambda u: re.sub(r'(.+?\.\w{2,4})', r'\1?', u) + f"cache={random.randint(100,999)}"
        ]
        
        if '?' in url:
            return random.choice(variations)(url.split('?')[0]) + '&' + url.split('?')[1]
        return random.choice(variations)(url)

    def obfuscate_payload(self, payload):
        """Obfuscate payload using multiple methods"""
        method = random.choice(self.level['obfuscation'])
        
        if method == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif method == 'hex':
            return ''.join([f'\\x{ord(c):02x}' for c in payload])
        elif method == 'reverse':
            return payload[::-1]
        elif method == 'rot13':
            return payload.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
        return payload

    def make_request(self, session, url, method='GET', **kwargs):
        """Execute a stealthy request with proxy support and cookie handling"""
        self.apply_delay()
        url = self.obfuscate_url(url)
        headers = self.get_headers()
        
        # Rotate cookies
        if self.cookie_jar:
            headers['Cookie'] = '; '.join([f"{k}={v}" for k,v in self.cookie_jar.items()])
        
        try:
            proxies = {'http': self.proxy, 'https': self.proxy} if self.proxy else None
            response = session.request(
                method,
                url,
                headers=headers,
                proxies=proxies,
                allow_redirects=False,  # Handle redirects manually for stealth
                timeout=random.uniform(8, 15),
                **kwargs
            )
            
            # Update cookies from response
            if 'set-cookie' in response.headers:
                for cookie in response.headers.getlist('set-cookie'):
                    key_val = cookie.split(';')[0].split('=')
                    if len(key_val) == 2:
                        self.cookie_jar[key_val[0]] = key_val[1]
            
            return response
        
        except Exception as e:
            # Return a mock response to avoid breaking scan flow
            mock = requests.Response()
            mock.status_code = 408
            mock._content = b'Request Timeout'
            return mock

    def clean_logs(self, target):
        """Simulate log cleaning operations (returns commands for actual execution)"""
        commands = []
        domain = target.split('//')[-1].split('/')[0]
        
        # Common log locations
        log_locations = [
            f"/var/log/apache2/{domain}",
            f"/var/log/nginx/{domain}",
            "/var/log/httpd/access_log",
            "/var/log/audit/audit.log"
        ]
        
        for log_path in log_locations:
            commands.extend([
                f"echo '[log sanitized]' > {log_path}",
                f"chmod 600 {log_path}",
                f"touch -t 202001010000 {log_path}"
            ])
        
        return commands

    def clear_traces(self):
        """Generate commands to clear system traces"""
        return [
            "history -c",
            "killall -9 bash",
            "rm -f ~/.bash_history",
            "find /tmp -type f -mtime -1 -exec rm -f {} \\;"
        ]

    def generate_junk_data(self, size_kb=10):
        """Generate random junk data for log flooding"""
        chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        return ''.join(random.choice(chars) for _ in range(size_kb * 1024))