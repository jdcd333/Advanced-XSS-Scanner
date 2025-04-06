#!/usr/bin/env python3

"""
Description: A Python tool to detect Cross-Site Scripting (XSS) vulnerabilities in web applications with detailed reporting.
Author: jdcd333
Version: 1.0
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from tqdm import tqdm
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin
import json
from datetime import datetime

class EnhancedXSSTester:
    def __init__(self):
        # Initialize payloads and configurations
        self.payloads = self.load_xss_payloads()
        self.session = requests.Session()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.timeout = 10
        self.max_redirects = 3
        
        # Statistics
        self.stats = {
            'total': 0,
            'vuln': 0,
            'no_vuln': 0,
            'errors': 0,
            'start_time': datetime.now()
        }

    def load_xss_payloads(self):
        """Load XSS payloads from external file"""
        return [
            # Basic payloads
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            # ... (other payloads)
        ]

    def test_url(self, url):
        """Test a URL for XSS vulnerabilities"""
        try:
            # Basic reflection test
            for payload in self.payloads[:5]:  # Limit payloads for demo
                test_url = f"{url}?test={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                if payload in response.text:
                    return {
                        'url': url,
                        'status': 'vuln',
                        'payload': payload,
                        'type': 'reflected'
                    }
            
            return {
                'url': url,
                'status': 'no-vuln'
            }
            
        except Exception as e:
            return {
                'url': url,
                'status': 'error',
                'message': str(e)
            }

    def generate_report(self, results, filename="xss_report.txt"):
        """Generate a clear and organized report"""
        with open(filename, 'w') as f:
            # Header
            f.write("=== XSS SCAN REPORT ===\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Targets scanned: {self.stats['total']}\n\n")
            
            # Vulnerabilities section
            vuln_list = [r for r in results if r['status'] == 'vuln']
            if vuln_list:
                f.write("=== VULNERABLE SUBDOMAINS (vuln) ===\n")
                for item in vuln_list:
                    f.write(f"[vuln] {item['url']}\n")
                    f.write(f"  - Type: {item['type']}\n")
                    f.write(f"  - Payload: {item['payload']}\n\n")
            else:
                f.write("=== NO VULNERABLE SUBDOMAINS FOUND ===\n\n")
            
            # Secure subdomains section
            no_vuln_list = [r for r in results if r['status'] == 'no-vuln']
            if no_vuln_list:
                f.write("\n=== SECURE SUBDOMAINS (no-vuln) ===\n")
                for item in no_vuln_list[:100]:  # Show only first 100
                    f.write(f"[no-vuln] {item['url']}\n")
                if len(no_vuln_list) > 100:
                    f.write(f"... plus {len(no_vuln_list)-100} more secure subdomains\n")
            
            # Errors section
            error_list = [r for r in results if r['status'] == 'error']
            if error_list:
                f.write("\n=== ERRORS ===\n")
                for item in error_list[:20]:  # Show only first 20 errors
                    f.write(f"[error] {item['url']} - {item['message']}\n")
                if len(error_list) > 20:
                    f.write(f"... plus {len(error_list)-20} more errors\n")
            
            # Summary
            duration = datetime.now() - self.stats['start_time']
            f.write("\n=== SCAN SUMMARY ===\n")
            f.write(f"Total subdomains: {self.stats['total']}\n")
            f.write(f"Vulnerable (vuln): {self.stats['vuln']}\n")
            f.write(f"Secure (no-vuln): {self.stats['no_vuln']}\n")
            f.write(f"Errors: {self.stats['errors']}\n")
            f.write(f"Duration: {duration}\n")
            f.write(f"Vulnerability rate: {(self.stats['vuln']/self.stats['total'])*100:.2f}%\n")

    def scan_subdomains(self, input_file, output_file="xss_report.txt", max_workers=5):
        """Scan multiple subdomains"""
        with open(input_file, 'r') as f:
            subdomains = [f"http://{line.strip()}" for line in f if line.strip()]
        
        self.stats['total'] = len(subdomains)
        results = []
        
        print(f"[*] Starting scan of {self.stats['total']} subdomains")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor, \
             tqdm(total=len(subdomains), desc="Scanning") as pbar:
            
            futures = {executor.submit(self.test_url, url): url for url in subdomains}
            
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                
                # Update statistics
                if result['status'] == 'vuln':
                    self.stats['vuln'] += 1
                elif result['status'] == 'no-vuln':
                    self.stats['no_vuln'] += 1
                else:
                    self.stats['errors'] += 1
                
                pbar.update(1)
        
        # Generate report
        self.generate_report(results, output_file)
        print(f"\n[+] Report generated at {output_file}")

if __name__ == "__main__":
    scanner = EnhancedXSSTester()
    
    # Input file with subdomains
    input_file = "subdomains.txt"
    
    # Output file for the report
    output_file = "xss_clear_report.txt"
    
    # Execute scan
    scanner.scan_subdomains(input_file, output_file, max_workers=5)
