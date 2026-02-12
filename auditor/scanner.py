"""
Security Auditor - Automated Vulnerability Scanner
Based on OWASP Top 10 and current market security conditions (2026)
"""
import requests
import re
import json
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from datetime import datetime


class SecurityAuditor:
    """Main security auditor class for vulnerability scanning"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.vulnerabilities = []
        self.session = requests.Session()
        
    def scan(self) -> Dict[str, Any]:
        """Run all security scans"""
        print(f"Starting security audit of {self.base_url}")
        
        # Run all scanners
        self.scan_sql_injection()
        self.scan_xss()
        self.scan_command_injection()
        self.scan_path_traversal()
        
        # Generate report
        return self.generate_report()
    
    def scan_sql_injection(self):
        """Scan for SQL Injection vulnerabilities"""
        print("Scanning for SQL Injection vulnerabilities...")
        
        test_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
        ]
        
        # Test endpoints that might be vulnerable
        test_urls = [
            '/search?q=',
            '/login?username=',
            '/user?id=',
        ]
        
        for endpoint in test_urls:
            url = urljoin(self.base_url, endpoint)
            
            # First get baseline response
            try:
                baseline_response = self.session.get(url + 'normalquery', timeout=5)
                baseline_length = len(baseline_response.text)
            except:
                baseline_length = 0
            
            for payload in test_payloads:
                try:
                    test_url = url + payload
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for SQL error messages
                    sql_errors = [
                        'sql syntax',
                        'sqlite_error',
                        'mysql',
                        'postgresql',
                        'ora-',
                        'syntax error',
                        'unclosed quotation',
                        'sqlite3.operationalerror',
                    ]
                    
                    content_lower = response.text.lower()
                    
                    # Check for SQL errors
                    for error in sql_errors:
                        if error in content_lower:
                            self.vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': 'Critical',
                                'url': test_url,
                                'payload': payload,
                                'evidence': f'SQL error pattern detected: {error}',
                                'description': 'Application appears vulnerable to SQL injection attacks',
                                'recommendation': 'Use parameterized queries or prepared statements'
                            })
                            break
                    else:
                        # Check for successful SQL injection (different response)
                        # If payload contains SQL and response is significantly different
                        if response.status_code == 200 and "OR '1'='1" in payload:
                            # Check if we got results in JSON
                            try:
                                data = response.json()
                                if 'results' in data and 'query' in data:
                                    # Query is shown, indicating SQL injection vulnerability
                                    if payload in data['query']:
                                        self.vulnerabilities.append({
                                            'type': 'SQL Injection',
                                            'severity': 'Critical',
                                            'url': test_url,
                                            'payload': payload,
                                            'evidence': f'SQL query exposed in response: {data["query"][:100]}',
                                            'description': 'Application executes unsanitized SQL queries and exposes query structure',
                                            'recommendation': 'Use parameterized queries or prepared statements'
                                        })
                                        break
                            except Exception:
                                pass
                            
                except Exception:
                    pass
    
    def scan_xss(self):
        """Scan for Cross-Site Scripting (XSS) vulnerabilities"""
        print("Scanning for XSS vulnerabilities...")
        
        test_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg/onload=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            "javascript:alert('XSS')",
        ]
        
        test_urls = [
            '/greet?name=',
            '/search?q=',
            '/comment?text=',
        ]
        
        for endpoint in test_urls:
            url = urljoin(self.base_url, endpoint)
            for payload in test_payloads:
                try:
                    test_url = url + payload
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check if payload is reflected without encoding
                    if payload in response.text:
                        self.vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'High',
                            'url': test_url,
                            'payload': payload,
                            'evidence': 'Unencoded user input reflected in response',
                            'description': 'Application reflects user input without proper encoding',
                            'recommendation': 'Implement proper output encoding and Content Security Policy'
                        })
                        break
                        
                except Exception:
                    pass
    
    def scan_command_injection(self):
        """Scan for Command Injection vulnerabilities"""
        print("Scanning for Command Injection vulnerabilities...")
        
        test_payloads = [
            '; ls',
            '| cat /etc/passwd',
            '& whoami',
            '`id`',
            '$(whoami)',
        ]
        
        test_urls = [
            '/ping?host=',
            '/exec?cmd=',
            '/run?command=',
        ]
        
        for endpoint in test_urls:
            url = urljoin(self.base_url, endpoint)
            for payload in test_payloads:
                try:
                    test_url = url + '127.0.0.1' + payload
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for command execution indicators
                    indicators = [
                        'uid=',
                        'gid=',
                        'root:',
                        'total ',
                        'drwx',
                    ]
                    
                    for indicator in indicators:
                        if indicator in response.text:
                            self.vulnerabilities.append({
                                'type': 'Command Injection',
                                'severity': 'Critical',
                                'url': test_url,
                                'payload': payload,
                                'evidence': f'Command execution indicator detected: {indicator}',
                                'description': 'Application executes system commands with user input',
                                'recommendation': 'Never pass user input to system commands. Use safe APIs instead'
                            })
                            break
                            
                except Exception:
                    pass
    
    def scan_path_traversal(self):
        """Scan for Path Traversal vulnerabilities"""
        print("Scanning for Path Traversal vulnerabilities...")
        
        test_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
        ]
        
        test_urls = [
            '/file?name=',
            '/download?file=',
            '/read?path=',
        ]
        
        for endpoint in test_urls:
            url = urljoin(self.base_url, endpoint)
            for payload in test_payloads:
                try:
                    test_url = url + payload
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for sensitive file content
                    indicators = [
                        'root:x:0:0',
                        '/bin/bash',
                        '/bin/sh',
                        'daemon:',
                        '127.0.0.1',
                    ]
                    
                    content = response.text
                    
                    for indicator in indicators:
                        if indicator in content:
                            self.vulnerabilities.append({
                                'type': 'Path Traversal',
                                'severity': 'High',
                                'url': test_url,
                                'payload': payload,
                                'evidence': f'Sensitive file content detected: {indicator}',
                                'description': 'Application allows access to files outside intended directory',
                                'recommendation': 'Validate and sanitize file paths. Use allowlists for permitted files'
                            })
                            break
                    else:
                        # Also check if error message reveals path traversal attempt
                        path_indicators = [
                            '[Errno 2]',
                            'No such file or directory',
                            '../',
                            'FileNotFoundError',
                        ]
                        
                        for indicator in path_indicators:
                            if indicator in content and '../' in payload:
                                # The app is trying to access the traversed path
                                self.vulnerabilities.append({
                                    'type': 'Path Traversal',
                                    'severity': 'High',
                                    'url': test_url,
                                    'payload': payload,
                                    'evidence': f'Path traversal attempt processed: {indicator}',
                                    'description': 'Application processes path traversal sequences without validation',
                                    'recommendation': 'Validate and sanitize file paths. Use allowlists for permitted files'
                                })
                                break
                            
                except Exception:
                    pass
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate a comprehensive security audit report"""
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for vuln in self.vulnerabilities:
            severity_counts[vuln['severity']] += 1
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': self.base_url,
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_summary': severity_counts,
            'vulnerabilities': self.vulnerabilities,
            'scan_status': 'completed'
        }
        
        return report
    
    def print_report(self):
        """Print a human-readable report"""
        report = self.generate_report()
        
        print("\n" + "="*80)
        print("SECURITY AUDIT REPORT")
        print("="*80)
        print(f"Target: {report['target']}")
        print(f"Scan Time: {report['timestamp']}")
        print(f"Total Vulnerabilities Found: {report['total_vulnerabilities']}")
        print("\nSeverity Summary:")
        for severity, count in report['severity_summary'].items():
            print(f"  {severity}: {count}")
        
        if report['vulnerabilities']:
            print("\n" + "-"*80)
            print("VULNERABILITIES DETECTED")
            print("-"*80)
            
            for i, vuln in enumerate(report['vulnerabilities'], 1):
                print(f"\n{i}. {vuln['type']} [{vuln['severity']}]")
                print(f"   URL: {vuln['url']}")
                print(f"   Payload: {vuln['payload']}")
                print(f"   Evidence: {vuln['evidence']}")
                print(f"   Description: {vuln['description']}")
                print(f"   Recommendation: {vuln['recommendation']}")
        else:
            print("\nNo vulnerabilities detected.")
        
        print("\n" + "="*80)
        
        return report


def main():
    """Main entry point for the security auditor"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m auditor.scanner <target_url>")
        print("Example: python -m auditor.scanner http://localhost:5000")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    # Run the security audit
    auditor = SecurityAuditor(target_url)
    report = auditor.scan()
    auditor.print_report()
    
    # Save report to file
    report_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nReport saved to: {report_file}")


if __name__ == '__main__':
    main()
