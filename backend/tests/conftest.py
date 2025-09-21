"""
Pytest configuration and fixtures for Bug Bounty Automation Platform tests
"""

import os
import pytest
import tempfile
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import transaction
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

# Configure Django settings for testing
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.testing')

import django
django.setup()

from apps.targets.models import Target, BugBountyPlatform
from apps.vulnerabilities.models import Vulnerability, VulnSeverity
from apps.scanning.models import ScanSession, ScanStatus, ToolExecution
from apps.exploitation.models import ExploitationSession, ExploitResult
from apps.reconnaissance.models import ReconSession
from apps.reporting.models import Report

User = get_user_model()


@pytest.fixture(scope='session')
def django_db_setup():
    """
    Configure the test database setup
    """
    from django.conf import settings
    settings.DATABASES['default'] = {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
        'OPTIONS': {
            'timeout': 20,
        }
    }


@pytest.fixture(scope='session')
def temp_media_root():
    """
    Create temporary media directory for tests
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


@pytest.fixture
def api_client():
    """
    DRF API client for testing
    """
    return APIClient()


@pytest.fixture
def authenticated_client(api_client, test_user):
    """
    API client authenticated with test user
    """
    refresh = RefreshToken.for_user(test_user)
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
    return api_client


@pytest.fixture
def admin_client(api_client, admin_user):
    """
    API client authenticated with admin user
    """
    refresh = RefreshToken.for_user(admin_user)
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
    return api_client


@pytest.fixture
def test_user(db):
    """
    Create a test user
    """
    return User.objects.create_user(
        username='testuser',
        email='test@example.com',
        password='testpass123'
    )


@pytest.fixture
def admin_user(db):
    """
    Create an admin user
    """
    return User.objects.create_superuser(
        username='admin',
        email='admin@example.com',
        password='adminpass123'
    )


@pytest.fixture
def sample_target(db):
    """
    Create a sample target for testing
    """
    return Target.objects.create(
        target_name='Example Corp',
        platform=BugBountyPlatform.HACKERONE,
        researcher_username='test_researcher',
        main_url='https://example.com',
        in_scope_urls=['https://example.com', 'https://api.example.com'],
        out_of_scope_urls=['https://blog.example.com'],
        requests_per_second=5.0,
        concurrent_requests=10,
        required_headers={'User-Agent': 'BugBountyBot'},
        program_notes='Test target for automated testing'
    )


@pytest.fixture
def sample_scan_session(db, sample_target):
    """
    Create a sample scan session
    """
    return ScanSession.objects.create(
        target=sample_target,
        session_name='Test Scan Session',
        status=ScanStatus.QUEUED,
        scan_config={
            'tools': ['nuclei', 'nmap', 'amass'],
            'intensity': 'medium'
        },
        methodology_phases=['reconnaissance', 'scanning', 'exploitation']
    )


@pytest.fixture
def sample_vulnerability(db, sample_scan_session):
    """
    Create a sample vulnerability
    """
    return Vulnerability.objects.create(
        scan_session=sample_scan_session,
        vulnerability_name='SQL Injection in Login Form',
        vulnerability_type='sql_injection',
        owasp_category='A03',
        cwe_id='CWE-89',
        severity=VulnSeverity.HIGH,
        cvss_score=8.1,
        impact_description='Potential data breach and unauthorized access',
        affected_url='https://example.com/login',
        affected_parameter='username',
        http_method='POST',
        payload_used="admin' OR '1'='1' --",
        discovered_by_tool='sqlmap',
        discovery_method='automated_parameter_fuzzing',
        confidence_level=0.9,
        remediation_suggestion='Use parameterized queries'
    )


@pytest.fixture
def sample_exploitation_session(db, sample_vulnerability, sample_target):
    """
    Create a sample exploitation session
    """
    return ExploitationSession.objects.create(
        vulnerability=sample_vulnerability,
        target=sample_target,
        exploitation_type='sql_injection',
        status='pending',
        payloads_used=["' OR 1=1 --", "' UNION SELECT 1,2,3 --"],
        notes='Automated exploitation attempt'
    )


@pytest.fixture
def sample_tool_execution(db, sample_scan_session):
    """
    Create a sample tool execution
    """
    return ToolExecution.objects.create(
        scan_session=sample_scan_session,
        tool_name='nuclei',
        tool_category='vulnerability_scanning',
        command_executed='nuclei -u https://example.com -t /nuclei-templates/',
        status='completed',
        execution_time_seconds=45.2,
        parsed_results_count=3,
        tool_parameters={
            'templates': '/nuclei-templates/',
            'concurrency': 25,
            'rate_limit': 150
        }
    )


@pytest.fixture
def mock_celery_task():
    """
    Mock Celery task for testing
    """
    with patch('celery.current_app.send_task') as mock_task:
        mock_task.return_value.id = 'test-task-id'
        mock_task.return_value.state = 'PENDING'
        yield mock_task


@pytest.fixture
def mock_tool_execution():
    """
    Mock external tool execution
    """
    with patch('subprocess.run') as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'Mock tool output'
        mock_run.return_value.stderr = ''
        yield mock_run


@pytest.fixture
def mock_requests():
    """
    Mock HTTP requests
    """
    with patch('requests.get') as mock_get, \
         patch('requests.post') as mock_post:

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '<html><body>Test response</body></html>'
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.json.return_value = {'status': 'success'}

        mock_get.return_value = mock_response
        mock_post.return_value = mock_response

        yield {'get': mock_get, 'post': mock_post, 'response': mock_response}


@pytest.fixture
def sample_scan_results():
    """
    Sample scan results data
    """
    return {
        'nuclei_results': [
            {
                'template': 'ssl-issuer',
                'url': 'https://example.com',
                'severity': 'info',
                'description': 'SSL certificate issuer information'
            },
            {
                'template': 'xss-reflected',
                'url': 'https://example.com/search?q=test',
                'severity': 'medium',
                'description': 'Reflected XSS vulnerability'
            }
        ],
        'nmap_results': {
            'hosts': [
                {
                    'ip': '93.184.216.34',
                    'hostname': 'example.com',
                    'ports': [
                        {'port': 80, 'protocol': 'tcp', 'state': 'open', 'service': 'http'},
                        {'port': 443, 'protocol': 'tcp', 'state': 'open', 'service': 'https'}
                    ]
                }
            ]
        },
        'subdomain_results': [
            'www.example.com',
            'api.example.com',
            'mail.example.com'
        ]
    }


@pytest.fixture
def sample_exploitation_results():
    """
    Sample exploitation results data
    """
    return {
        'sql_injection': {
            'success': True,
            'payload': "admin' OR '1'='1' --",
            'response_time': 0.234,
            'evidence': 'Database error revealing schema information',
            'impact': 'Authentication bypass achieved'
        },
        'xss': {
            'success': True,
            'payload': '<script>alert("XSS")</script>',
            'response_time': 0.156,
            'evidence': 'Script executed in browser context',
            'impact': 'Cookie theft possible'
        }
    }


@pytest.fixture
def temp_scan_directory(tmp_path):
    """
    Create temporary directory for scan results
    """
    scan_dir = tmp_path / 'scan_results'
    scan_dir.mkdir()

    raw_dir = scan_dir / 'raw'
    raw_dir.mkdir()

    parsed_dir = scan_dir / 'parsed'
    parsed_dir.mkdir()

    return scan_dir


@pytest.fixture
def mock_file_operations():
    """
    Mock file system operations
    """
    with patch('builtins.open', create=True) as mock_open, \
         patch('os.makedirs') as mock_makedirs, \
         patch('os.path.exists') as mock_exists:

        mock_exists.return_value = True
        mock_makedirs.return_value = None

        yield {
            'open': mock_open,
            'makedirs': mock_makedirs,
            'exists': mock_exists
        }


@pytest.fixture
def clean_database(db):
    """
    Ensure clean database state for tests
    """
    # Clear all test data before each test
    with transaction.atomic():
        Target.objects.all().delete()
        ScanSession.objects.all().delete()
        Vulnerability.objects.all().delete()
        ExploitationSession.objects.all().delete()
        ToolExecution.objects.all().delete()
    yield
    # Clean up after test
    with transaction.atomic():
        Target.objects.all().delete()
        ScanSession.objects.all().delete()
        Vulnerability.objects.all().delete()
        ExploitationSession.objects.all().delete()
        ToolExecution.objects.all().delete()


# Pytest markers
pytestmark = [
    pytest.mark.django_db,
]


# Custom test utilities
class BugBountyTestCase(TestCase):
    """
    Base test case with common functionality
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def authenticate(self, user=None):
        """Authenticate the test client"""
        user = user or self.user
        refresh = RefreshToken.for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    def assert_status_code(self, response, expected_status):
        """Assert response status code with helpful error message"""
        if response.status_code != expected_status:
            print(f"Response content: {response.content}")
        self.assertEqual(response.status_code, expected_status)

    def assert_contains_fields(self, data, required_fields):
        """Assert that response data contains required fields"""
        for field in required_fields:
            self.assertIn(field, data, f"Missing required field: {field}")

    def create_test_target(self, **kwargs):
        """Create a test target with default values"""
        defaults = {
            'target_name': 'Test Target',
            'platform': BugBountyPlatform.HACKERONE,
            'researcher_username': 'testuser',
            'main_url': 'https://test.example.com'
        }
        defaults.update(kwargs)
        return Target.objects.create(**defaults)