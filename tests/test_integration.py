"""
Integration tests for the vulnerable app and security auditor
These tests verify that the auditor can detect vulnerabilities in the vulnerable app
"""
import pytest
import threading
import time
import requests
from vulnerable_app.app import app, init_db
from auditor.scanner import SecurityAuditor


@pytest.fixture(scope="module")
def test_server():
    """Start the vulnerable app in a separate thread for testing"""
    init_db()
    
    # Start Flask app in a thread
    def run_app():
        app.run(host='127.0.0.1', port=5555, debug=False, use_reloader=False)
    
    thread = threading.Thread(target=run_app, daemon=True)
    thread.start()
    
    # Wait for server to start
    time.sleep(2)
    
    # Verify server is running
    max_retries = 5
    for _ in range(max_retries):
        try:
            response = requests.get('http://127.0.0.1:5555/', timeout=2)
            if response.status_code == 200:
                break
        except:
            time.sleep(1)
    
    yield 'http://127.0.0.1:5555'
    
    # Server will be stopped when test process ends


class TestIntegration:
    """Integration tests for auditor against vulnerable app"""
    
    def test_app_is_running(self, test_server):
        """Test that the vulnerable app is running"""
        response = requests.get(test_server, timeout=5)
        assert response.status_code == 200
        assert 'Vulnerable Web Application' in response.text
    
    def test_sql_injection_detection(self, test_server):
        """Test that SQL injection vulnerabilities are detected"""
        auditor = SecurityAuditor(test_server)
        auditor.scan_sql_injection()
        
        # Should find at least one SQL injection vulnerability
        sql_vulns = [v for v in auditor.vulnerabilities if v['type'] == 'SQL Injection']
        assert len(sql_vulns) > 0, "SQL Injection vulnerability not detected"
        
        # Check vulnerability properties
        vuln = sql_vulns[0]
        assert vuln['severity'] == 'Critical'
        assert 'sql' in vuln['evidence'].lower() or 'syntax' in vuln['evidence'].lower()
    
    def test_xss_detection(self, test_server):
        """Test that XSS vulnerabilities are detected"""
        auditor = SecurityAuditor(test_server)
        auditor.scan_xss()
        
        # Should find at least one XSS vulnerability
        xss_vulns = [v for v in auditor.vulnerabilities if 'XSS' in v['type']]
        assert len(xss_vulns) > 0, "XSS vulnerability not detected"
        
        # Check vulnerability properties
        vuln = xss_vulns[0]
        assert vuln['severity'] in ['High', 'Critical']
        assert 'script' in vuln['payload'].lower() or 'alert' in vuln['payload'].lower()
    
    def test_command_injection_detection(self, test_server):
        """Test that command injection vulnerabilities are detected"""
        auditor = SecurityAuditor(test_server)
        auditor.scan_command_injection()
        
        # Should find at least one command injection vulnerability
        cmd_vulns = [v for v in auditor.vulnerabilities if 'Command Injection' in v['type']]
        assert len(cmd_vulns) > 0, "Command Injection vulnerability not detected"
        
        # Check vulnerability properties
        vuln = cmd_vulns[0]
        assert vuln['severity'] == 'Critical'
    
    def test_path_traversal_detection(self, test_server):
        """Test that path traversal vulnerabilities are detected"""
        auditor = SecurityAuditor(test_server)
        auditor.scan_path_traversal()
        
        # Should find at least one path traversal vulnerability
        path_vulns = [v for v in auditor.vulnerabilities if 'Path Traversal' in v['type']]
        assert len(path_vulns) > 0, "Path Traversal vulnerability not detected"
        
        # Check vulnerability properties
        vuln = path_vulns[0]
        assert vuln['severity'] in ['High', 'Critical']
    
    def test_full_scan(self, test_server):
        """Test a full security scan"""
        auditor = SecurityAuditor(test_server)
        report = auditor.scan()
        
        # Should find multiple vulnerabilities
        assert report['total_vulnerabilities'] > 0, "No vulnerabilities detected in full scan"
        assert report['scan_status'] == 'completed'
        
        # Should have detected critical vulnerabilities
        assert report['severity_summary']['Critical'] > 0, "No critical vulnerabilities detected"
        
        # Report should be complete
        assert 'timestamp' in report
        assert 'target' in report
        assert report['target'] == test_server


class TestVulnerableAppEndpoints:
    """Test individual vulnerable app endpoints"""
    
    def test_search_endpoint(self, test_server):
        """Test search endpoint is accessible"""
        response = requests.get(f'{test_server}/search', timeout=5)
        assert response.status_code == 200
    
    def test_greet_endpoint(self, test_server):
        """Test greet endpoint is accessible"""
        response = requests.get(f'{test_server}/greet', timeout=5)
        assert response.status_code == 200
    
    def test_ping_endpoint(self, test_server):
        """Test ping endpoint is accessible"""
        response = requests.get(f'{test_server}/ping', timeout=5)
        assert response.status_code == 200
    
    def test_file_endpoint(self, test_server):
        """Test file endpoint is accessible"""
        response = requests.get(f'{test_server}/file', timeout=5)
        assert response.status_code == 200
