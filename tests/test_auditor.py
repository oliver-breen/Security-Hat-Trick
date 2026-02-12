"""
Tests for the Security Auditor
"""
import pytest
import json
from auditor.scanner import SecurityAuditor


class TestSecurityAuditor:
    """Test suite for the Security Auditor"""
    
    def test_auditor_initialization(self):
        """Test that the auditor initializes correctly"""
        auditor = SecurityAuditor("http://example.com")
        assert auditor.base_url == "http://example.com"
        assert auditor.vulnerabilities == []
        assert auditor.session is not None
    
    def test_generate_empty_report(self):
        """Test report generation with no vulnerabilities"""
        auditor = SecurityAuditor("http://example.com")
        report = auditor.generate_report()
        
        assert report['target'] == "http://example.com"
        assert report['total_vulnerabilities'] == 0
        assert report['severity_summary']['Critical'] == 0
        assert report['severity_summary']['High'] == 0
        assert report['scan_status'] == 'completed'
    
    def test_generate_report_with_vulnerabilities(self):
        """Test report generation with vulnerabilities"""
        auditor = SecurityAuditor("http://example.com")
        
        # Add test vulnerabilities
        auditor.vulnerabilities.append({
            'type': 'SQL Injection',
            'severity': 'Critical',
            'url': 'http://example.com/test',
            'payload': "' OR '1'='1",
            'evidence': 'Test evidence',
            'description': 'Test description',
            'recommendation': 'Test recommendation'
        })
        
        auditor.vulnerabilities.append({
            'type': 'XSS',
            'severity': 'High',
            'url': 'http://example.com/xss',
            'payload': '<script>alert(1)</script>',
            'evidence': 'Test evidence',
            'description': 'Test description',
            'recommendation': 'Test recommendation'
        })
        
        report = auditor.generate_report()
        
        assert report['total_vulnerabilities'] == 2
        assert report['severity_summary']['Critical'] == 1
        assert report['severity_summary']['High'] == 1
        assert len(report['vulnerabilities']) == 2
    
    def test_vulnerability_structure(self):
        """Test that vulnerabilities have the correct structure"""
        auditor = SecurityAuditor("http://example.com")
        
        auditor.vulnerabilities.append({
            'type': 'Test Vulnerability',
            'severity': 'Critical',
            'url': 'http://example.com/test',
            'payload': 'test payload',
            'evidence': 'test evidence',
            'description': 'test description',
            'recommendation': 'test recommendation'
        })
        
        vuln = auditor.vulnerabilities[0]
        assert 'type' in vuln
        assert 'severity' in vuln
        assert 'url' in vuln
        assert 'payload' in vuln
        assert 'evidence' in vuln
        assert 'description' in vuln
        assert 'recommendation' in vuln
    
    def test_severity_levels(self):
        """Test different severity levels"""
        auditor = SecurityAuditor("http://example.com")
        
        severities = ['Critical', 'High', 'Medium', 'Low']
        
        for severity in severities:
            auditor.vulnerabilities.append({
                'type': f'{severity} Test',
                'severity': severity,
                'url': 'http://example.com/test',
                'payload': 'test',
                'evidence': 'test',
                'description': 'test',
                'recommendation': 'test'
            })
        
        report = auditor.generate_report()
        
        for severity in severities:
            assert report['severity_summary'][severity] == 1


class TestSQLInjectionScanner:
    """Tests for SQL Injection detection"""
    
    def test_sql_injection_scanner_method_exists(self):
        """Test that SQL injection scanner method exists"""
        auditor = SecurityAuditor("http://example.com")
        assert hasattr(auditor, 'scan_sql_injection')
        assert callable(auditor.scan_sql_injection)


class TestXSSScanner:
    """Tests for XSS detection"""
    
    def test_xss_scanner_method_exists(self):
        """Test that XSS scanner method exists"""
        auditor = SecurityAuditor("http://example.com")
        assert hasattr(auditor, 'scan_xss')
        assert callable(auditor.scan_xss)


class TestCommandInjectionScanner:
    """Tests for Command Injection detection"""
    
    def test_command_injection_scanner_method_exists(self):
        """Test that command injection scanner method exists"""
        auditor = SecurityAuditor("http://example.com")
        assert hasattr(auditor, 'scan_command_injection')
        assert callable(auditor.scan_command_injection)


class TestPathTraversalScanner:
    """Tests for Path Traversal detection"""
    
    def test_path_traversal_scanner_method_exists(self):
        """Test that path traversal scanner method exists"""
        auditor = SecurityAuditor("http://example.com")
        assert hasattr(auditor, 'scan_path_traversal')
        assert callable(auditor.scan_path_traversal)


class TestReportGeneration:
    """Tests for report generation functionality"""
    
    def test_report_contains_timestamp(self):
        """Test that report includes a timestamp"""
        auditor = SecurityAuditor("http://example.com")
        report = auditor.generate_report()
        assert 'timestamp' in report
        assert report['timestamp'] is not None
    
    def test_report_json_serializable(self):
        """Test that report can be serialized to JSON"""
        auditor = SecurityAuditor("http://example.com")
        report = auditor.generate_report()
        
        # Should not raise an exception
        json_str = json.dumps(report)
        assert json_str is not None
        
        # Should be deserializable
        parsed = json.loads(json_str)
        assert parsed['target'] == "http://example.com"
    
    def test_print_report_method_exists(self):
        """Test that print_report method exists"""
        auditor = SecurityAuditor("http://example.com")
        assert hasattr(auditor, 'print_report')
        assert callable(auditor.print_report)
