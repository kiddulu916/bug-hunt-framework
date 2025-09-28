"""
Comprehensive tests for Nuclei Scanner Engine
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from django.test import TestCase
from pathlib import Path
import tempfile
import os

from services.scanner_engines.nuclei_engine import NucleiEngine
from apps.scanning.models import ScanSession, ToolExecution
from tests.factories import TargetFactory, ScanSessionFactory


@pytest.mark.unit
@pytest.mark.scanner
class TestNucleiEngineComprehensive(TestCase):
    """Comprehensive tests for Nuclei scanner engine"""

    def setUp(self):
        self.nuclei_engine = NucleiEngine()
        self.target = TargetFactory()
        self.scan_session = ScanSessionFactory(target=self.target)

    def test_nuclei_engine_initialization(self):
        """Test Nuclei engine initialization"""
        self.assertIsInstance(self.nuclei_engine, NucleiEngine)
        self.assertEqual(self.nuclei_engine.tool_name, 'nuclei')
        self.assertEqual(self.nuclei_engine.tool_category, 'vulnerability_scanning')
        self.assertIsNotNone(self.nuclei_engine.default_config)

    def test_build_nuclei_command_basic(self):
        """Test building basic Nuclei command"""
        target_url = 'https://example.com'
        template_paths = ['/templates/sql-injection.yaml']
        output_file = '/tmp/nuclei_output.json'

        command = self.nuclei_engine.build_nuclei_command(
            target_url=target_url,
            template_paths=template_paths,
            output_file=output_file
        )

        self.assertIn('nuclei', command)
        self.assertIn('-u', command)
        self.assertIn('https://example.com', command)
        self.assertIn('-t', command)
        self.assertIn('/templates/sql-injection.yaml', command)
        self.assertIn('-o', command)
        self.assertIn('/tmp/nuclei_output.json', command)

    def test_build_nuclei_command_with_options(self):
        """Test building Nuclei command with various options"""
        target_url = 'https://example.com'
        template_paths = ['/templates/']
        output_file = '/tmp/nuclei_output.json'

        config = {
            'concurrency': 50,
            'rate_limit': 100,
            'timeout': 30,
            'retries': 2,
            'severity': ['high', 'critical'],
            'tags': ['sqli', 'xss'],
            'exclude_tags': ['dos', 'intrusive'],
            'headers': {'User-Agent': 'NucleiBugBounty/1.0'},
            'follow_redirects': True,
            'max_redirects': 5
        }

        command = self.nuclei_engine.build_nuclei_command(
            target_url=target_url,
            template_paths=template_paths,
            output_file=output_file,
            config=config
        )

        # Check for concurrency and rate limiting
        self.assertIn('-c', command)
        self.assertIn('50', command)
        self.assertIn('-rl', command)
        self.assertIn('100', command)

        # Check for timeout and retries
        self.assertIn('-timeout', command)
        self.assertIn('30', command)
        self.assertIn('-retries', command)
        self.assertIn('2', command)

        # Check for severity filtering
        self.assertIn('-severity', command)
        severity_index = command.index('-severity')
        self.assertIn('high,critical', command[severity_index + 1])

        # Check for tag filtering
        self.assertIn('-tags', command)
        self.assertIn('-exclude-tags', command)

    def test_build_nuclei_command_multiple_targets(self):
        """Test building Nuclei command with multiple targets"""
        targets = ['https://example.com', 'https://test.com', 'https://demo.com']
        template_paths = ['/templates/']
        output_file = '/tmp/nuclei_output.json'

        command = self.nuclei_engine.build_nuclei_command(
            target_urls=targets,
            template_paths=template_paths,
            output_file=output_file
        )

        # Should use target list file instead of individual URLs
        self.assertIn('-l', command)

    def test_parse_nuclei_output_json(self):
        """Test parsing Nuclei JSON output"""
        sample_nuclei_output = [
            {
                "template": "sql-injection",
                "template-url": "https://nuclei-templates.com/sql-injection",
                "template-id": "sql-injection-login",
                "info": {
                    "name": "SQL Injection - Login Form",
                    "author": ["test"],
                    "tags": ["sqli", "injection"],
                    "severity": "high",
                    "description": "SQL injection vulnerability in login form"
                },
                "type": "http",
                "host": "https://example.com",
                "matched-at": "https://example.com/login",
                "request": "POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin%27+OR+%271%27%3D%271&password=test",
                "response": "HTTP/1.1 200 OK\r\n\r\nWelcome admin!",
                "ip": "93.184.216.34",
                "timestamp": "2024-01-15T10:30:00.000Z",
                "curl-command": "curl -X 'POST' -d 'username=admin%27+OR+%271%27%3D%271&password=test' 'https://example.com/login'"
            },
            {
                "template": "xss-reflected",
                "template-url": "https://nuclei-templates.com/xss-reflected",
                "template-id": "xss-reflected-search",
                "info": {
                    "name": "Reflected XSS - Search Parameter",
                    "author": ["test"],
                    "tags": ["xss", "reflection"],
                    "severity": "medium",
                    "description": "Reflected XSS in search parameter"
                },
                "type": "http",
                "host": "https://example.com",
                "matched-at": "https://example.com/search?q=<script>alert(1)</script>",
                "request": "GET /search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1\r\nHost: example.com",
                "response": "HTTP/1.1 200 OK\r\n\r\n<html>Results for: <script>alert(1)</script></html>",
                "ip": "93.184.216.34",
                "timestamp": "2024-01-15T10:31:00.000Z",
                "curl-command": "curl 'https://example.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E'"
            }
        ]

        parsed_results = self.nuclei_engine.parse_nuclei_output(sample_nuclei_output)

        self.assertEqual(len(parsed_results), 2)

        # Check first vulnerability (SQL Injection)
        sql_vuln = parsed_results[0]
        self.assertEqual(sql_vuln['vulnerability_name'], 'SQL Injection - Login Form')
        self.assertEqual(sql_vuln['vulnerability_type'], 'sql_injection')
        self.assertEqual(sql_vuln['severity'], 'high')
        self.assertEqual(sql_vuln['affected_url'], 'https://example.com/login')
        self.assertIn('SQL injection vulnerability', sql_vuln['impact_description'])

        # Check second vulnerability (XSS)
        xss_vuln = parsed_results[1]
        self.assertEqual(xss_vuln['vulnerability_name'], 'Reflected XSS - Search Parameter')
        self.assertEqual(xss_vuln['vulnerability_type'], 'xss_reflected')
        self.assertEqual(xss_vuln['severity'], 'medium')
        self.assertEqual(xss_vuln['affected_url'], 'https://example.com/search?q=<script>alert(1)</script>')

    def test_parse_nuclei_output_info_severity(self):
        """Test parsing Nuclei output with info severity findings"""
        info_nuclei_output = [
            {
                "template": "ssl-cipher-check",
                "template-id": "ssl-cipher-weak",
                "info": {
                    "name": "Weak SSL Cipher Detected",
                    "author": ["test"],
                    "tags": ["ssl", "tls"],
                    "severity": "info",
                    "description": "Weak SSL/TLS cipher suite detected"
                },
                "type": "ssl",
                "host": "https://example.com",
                "matched-at": "example.com:443",
                "timestamp": "2024-01-15T10:32:00.000Z"
            }
        ]

        parsed_results = self.nuclei_engine.parse_nuclei_output(info_nuclei_output)

        self.assertEqual(len(parsed_results), 1)
        ssl_finding = parsed_results[0]
        self.assertEqual(ssl_finding['severity'], 'info')
        self.assertEqual(ssl_finding['vulnerability_type'], 'ssl_tls_misconfiguration')

    @patch('subprocess.run')
    def test_execute_scan_success(self, mock_subprocess):
        """Test successful Nuclei scan execution"""
        # Mock successful subprocess execution
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ''
        mock_result.stderr = ''
        mock_subprocess.return_value = mock_result

        # Mock file operations
        sample_output = [
            {
                "template": "test-template",
                "template-id": "test-id",
                "info": {
                    "name": "Test Vulnerability",
                    "severity": "medium",
                    "description": "Test description"
                },
                "host": "https://example.com",
                "matched-at": "https://example.com/test"
            }
        ]

        with patch('builtins.open', create=True) as mock_open:
            with patch('json.load', return_value=sample_output):
                with patch('os.path.exists', return_value=True):
                    result = self.nuclei_engine.execute_scan(
                        target_url='https://example.com',
                        scan_session_id=self.scan_session.id
                    )

        self.assertEqual(result['status'], 'completed')
        self.assertEqual(len(result['vulnerabilities']), 1)
        self.assertIn('execution_time', result)

    @patch('subprocess.run')
    def test_execute_scan_failure(self, mock_subprocess):
        """Test Nuclei scan execution failure"""
        # Mock failed subprocess execution
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ''
        mock_result.stderr = 'Nuclei execution failed'
        mock_subprocess.return_value = mock_result

        result = self.nuclei_engine.execute_scan(
            target_url='https://example.com',
            scan_session_id=self.scan_session.id
        )

        self.assertEqual(result['status'], 'failed')
        self.assertIn('error', result)
        self.assertIn('Nuclei execution failed', result['error'])

    @patch('subprocess.run')
    def test_execute_scan_timeout(self, mock_subprocess):
        """Test Nuclei scan execution timeout"""
        from subprocess import TimeoutExpired

        # Mock timeout
        mock_subprocess.side_effect = TimeoutExpired('nuclei', 300)

        result = self.nuclei_engine.execute_scan(
            target_url='https://example.com',
            scan_session_id=self.scan_session.id,
            timeout=300
        )

        self.assertEqual(result['status'], 'timeout')
        self.assertIn('error', result)
        self.assertIn('timeout', result['error'].lower())

    def test_filter_templates_by_severity(self):
        """Test filtering Nuclei templates by severity"""
        config = {
            'severity_filter': ['high', 'critical'],
            'template_directory': '/nuclei-templates'
        }

        filtered_templates = self.nuclei_engine.filter_templates_by_criteria(config)

        # Should return templates filtered by severity
        self.assertIsInstance(filtered_templates, list)

    def test_filter_templates_by_tags(self):
        """Test filtering Nuclei templates by tags"""
        config = {
            'include_tags': ['sqli', 'xss'],
            'exclude_tags': ['dos', 'intrusive'],
            'template_directory': '/nuclei-templates'
        }

        filtered_templates = self.nuclei_engine.filter_templates_by_criteria(config)

        # Should return templates filtered by tags
        self.assertIsInstance(filtered_templates, list)

    def test_custom_template_validation(self):
        """Test custom Nuclei template validation"""
        valid_template = """
id: custom-sql-injection

info:
  name: Custom SQL Injection Test
  author: security-team
  severity: high
  description: Custom SQL injection detection template
  tags: sqli,injection

http:
  - method: GET
    path:
      - "{{BaseURL}}/login?id=1'"

    matchers:
      - type: word
        words:
          - "SQL syntax error"
          - "mysql_fetch_array()"
        condition: or
"""

        invalid_template = """
id: invalid-template
# Missing required fields
"""

        # Test valid template
        self.assertTrue(self.nuclei_engine.validate_template(valid_template))

        # Test invalid template
        self.assertFalse(self.nuclei_engine.validate_template(invalid_template))

    def test_nuclei_update_check(self):
        """Test Nuclei version and template update checking"""
        with patch('subprocess.run') as mock_subprocess:
            # Mock version check
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = 'v2.9.4'
            mock_subprocess.return_value = mock_result

            version = self.nuclei_engine.check_version()
            self.assertIn('2.9.4', version)

    @patch('subprocess.run')
    def test_nuclei_template_update(self, mock_subprocess):
        """Test Nuclei template update process"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = 'Templates updated successfully'
        mock_subprocess.return_value = mock_result

        result = self.nuclei_engine.update_templates()

        self.assertTrue(result['success'])
        self.assertIn('updated', result['message'].lower())

    def test_scan_config_validation(self):
        """Test Nuclei scan configuration validation"""
        valid_configs = [
            {
                'concurrency': 25,
                'rate_limit': 150,
                'timeout': 30,
                'severity': ['high', 'critical']
            },
            {
                'tags': ['sqli', 'xss'],
                'exclude_tags': ['dos'],
                'follow_redirects': True
            }
        ]

        invalid_configs = [
            {
                'concurrency': -1,  # Invalid negative value
                'rate_limit': 'invalid'  # Invalid type
            },
            {
                'severity': ['invalid_severity'],  # Invalid severity
                'timeout': 0  # Invalid timeout
            }
        ]

        for config in valid_configs:
            self.assertTrue(self.nuclei_engine.validate_config(config))

        for config in invalid_configs:
            self.assertFalse(self.nuclei_engine.validate_config(config))

    def test_output_format_handling(self):
        """Test handling different Nuclei output formats"""
        # Test JSON output (default)
        json_output = [{"template": "test", "info": {"name": "Test", "severity": "medium"}}]
        json_results = self.nuclei_engine.parse_nuclei_output(json_output)
        self.assertIsInstance(json_results, list)

        # Test handling malformed JSON
        malformed_json = '{"template": "test", "incomplete": }'
        with self.assertRaises(json.JSONDecodeError):
            self.nuclei_engine.parse_nuclei_output(malformed_json)

    def test_target_scope_validation(self):
        """Test target scope validation for Nuclei scans"""
        in_scope_targets = [
            'https://example.com',
            'https://api.example.com',
            'https://admin.example.com'
        ]

        out_of_scope_targets = [
            'https://blog.example.com',
            'https://external-service.com'
        ]

        # Update target with scope information
        self.target.in_scope_urls = in_scope_targets
        self.target.out_of_scope_urls = out_of_scope_targets
        self.target.save()

        # Test in-scope validation
        for target_url in in_scope_targets:
            self.assertTrue(
                self.nuclei_engine.validate_target_scope(target_url, self.target)
            )

        # Test out-of-scope validation
        for target_url in out_of_scope_targets:
            self.assertFalse(
                self.nuclei_engine.validate_target_scope(target_url, self.target)
            )

    def test_rate_limiting_enforcement(self):
        """Test rate limiting enforcement in Nuclei scans"""
        target_rate_limit = 5.0  # 5 requests per second
        self.target.requests_per_second = target_rate_limit
        self.target.save()

        config = self.nuclei_engine.apply_target_constraints(self.target)

        self.assertIn('rate_limit', config)
        self.assertEqual(config['rate_limit'], int(target_rate_limit))

    def test_concurrent_scan_handling(self):
        """Test handling of concurrent Nuclei scans"""
        concurrent_config = {
            'max_concurrent_scans': 3,
            'concurrency_per_scan': 25
        }

        # Test concurrency calculation
        adjusted_config = self.nuclei_engine.calculate_concurrency(concurrent_config)

        self.assertIn('concurrency', adjusted_config)
        self.assertLessEqual(
            adjusted_config['concurrency'],
            concurrent_config['concurrency_per_scan']
        )

    def test_vulnerability_deduplication(self):
        """Test vulnerability deduplication in Nuclei results"""
        duplicate_output = [
            {
                "template": "sql-injection",
                "template-id": "sql-injection-login",
                "info": {"name": "SQL Injection", "severity": "high"},
                "host": "https://example.com",
                "matched-at": "https://example.com/login"
            },
            {
                "template": "sql-injection",
                "template-id": "sql-injection-login",
                "info": {"name": "SQL Injection", "severity": "high"},
                "host": "https://example.com",
                "matched-at": "https://example.com/login"  # Duplicate
            },
            {
                "template": "xss-reflected",
                "template-id": "xss-reflected-search",
                "info": {"name": "XSS Reflected", "severity": "medium"},
                "host": "https://example.com",
                "matched-at": "https://example.com/search"
            }
        ]

        deduplicated_results = self.nuclei_engine.deduplicate_vulnerabilities(
            self.nuclei_engine.parse_nuclei_output(duplicate_output)
        )

        # Should remove duplicates
        self.assertEqual(len(deduplicated_results), 2)

    def test_evidence_collection(self):
        """Test evidence collection from Nuclei scans"""
        nuclei_output_with_evidence = [
            {
                "template": "sql-injection",
                "template-id": "sql-injection-login",
                "info": {"name": "SQL Injection", "severity": "high"},
                "host": "https://example.com",
                "matched-at": "https://example.com/login",
                "request": "POST /login HTTP/1.1\nusername=admin'+OR+'1'='1",
                "response": "HTTP/1.1 200 OK\nWelcome admin!",
                "curl-command": "curl -X POST -d \"username=admin'+OR+'1'='1\" https://example.com/login"
            }
        ]

        parsed_results = self.nuclei_engine.parse_nuclei_output(nuclei_output_with_evidence)
        vulnerability = parsed_results[0]

        # Should include evidence data
        self.assertIn('request_data', vulnerability)
        self.assertIn('response_data', vulnerability)
        self.assertIn('payload_used', vulnerability)

    def test_template_management(self):
        """Test Nuclei template management functionality"""
        # Test listing available templates
        with patch('os.walk') as mock_walk:
            mock_walk.return_value = [
                ('/templates', ['cves', 'exposures'], ['info.yaml']),
                ('/templates/cves', [], ['CVE-2021-44228.yaml', 'CVE-2022-0847.yaml']),
                ('/templates/exposures', [], ['db-exposure.yaml'])
            ]

            templates = self.nuclei_engine.list_available_templates('/templates')
            self.assertGreater(len(templates), 0)

    def test_performance_metrics_collection(self):
        """Test collection of performance metrics during Nuclei scans"""
        with patch('time.time', side_effect=[0, 100]):  # 100 second execution
            with patch('subprocess.run') as mock_subprocess:
                mock_result = Mock()
                mock_result.returncode = 0
                mock_result.stdout = ''
                mock_subprocess.return_value = mock_result

                with patch('builtins.open', create=True):
                    with patch('json.load', return_value=[]):
                        with patch('os.path.exists', return_value=True):
                            result = self.nuclei_engine.execute_scan(
                                target_url='https://example.com',
                                scan_session_id=self.scan_session.id
                            )

        self.assertIn('execution_time', result)
        self.assertEqual(result['execution_time'], 100)
        self.assertIn('performance_metrics', result)