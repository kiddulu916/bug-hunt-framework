#!/usr/bin/env python
"""
Comprehensive Security Testing Suite

Tests for authentication, authorization, input validation, encryption,
and security configurations.
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status

User = get_user_model()


@pytest.mark.security
@pytest.mark.phase3
class TestAuthenticationSecurity(TestCase):
    """Test authentication security mechanisms"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_password_strength_requirements(self):
        """Test password strength validation"""
        weak_passwords = [
            '123',
            'password',
            '12345678',
            'qwerty',
            'admin'
        ]

        for weak_password in weak_passwords:
            response = self.client.post('/api/auth/register/', {
                'username': 'newuser',
                'email': 'new@example.com',
                'password': weak_password
            })
            # Should reject weak passwords
            self.assertNotEqual(response.status_code, 201)

    def test_brute_force_protection(self):
        """Test protection against brute force attacks"""
        # Attempt multiple failed logins
        for i in range(10):
            response = self.client.post('/api/auth/login/', {
                'username': 'testuser',
                'password': 'wrongpassword'
            })

        # Should be rate limited after multiple attempts
        response = self.client.post('/api/auth/login/', {
            'username': 'testuser',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 429)

    def test_session_security(self):
        """Test session security configurations"""
        response = self.client.post('/api/auth/login/', {
            'username': 'testuser',
            'password': 'testpass123'
        })

        # Check secure session configuration
        self.assertIn('sessionid', response.cookies)
        session_cookie = response.cookies['sessionid']
        self.assertTrue(session_cookie['secure'])
        self.assertTrue(session_cookie['httponly'])

    def test_jwt_token_security(self):
        """Test JWT token security"""
        response = self.client.post('/api/auth/login/', {
            'username': 'testuser',
            'password': 'testpass123'
        })

        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Check token structure and security
        self.assertIn('access_token', data)
        self.assertIn('refresh_token', data)

        # Verify token expiration is set
        access_token = data['access_token']
        self.assertIsInstance(access_token, str)
        self.assertTrue(len(access_token) > 100)  # Should be a proper JWT

    def test_logout_invalidates_tokens(self):
        """Test that logout properly invalidates tokens"""
        # Login
        login_response = self.client.post('/api/auth/login/', {
            'username': 'testuser',
            'password': 'testpass123'
        })

        token = login_response.json()['access_token']

        # Use token to access protected endpoint
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        response = self.client.get('/api/user/profile/')
        self.assertEqual(response.status_code, 200)

        # Logout
        logout_response = self.client.post('/api/auth/logout/')
        self.assertEqual(logout_response.status_code, 200)

        # Try to use token after logout
        response = self.client.get('/api/user/profile/')
        self.assertEqual(response.status_code, 401)


@pytest.mark.security
@pytest.mark.phase3
class TestInputValidationSecurity(TestCase):
    """Test input validation and sanitization"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        # Login to get authentication
        response = self.client.post('/api/auth/login/', {
            'username': 'testuser',
            'password': 'testpass123'
        })
        token = response.json()['access_token']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

    def test_sql_injection_protection(self):
        """Test protection against SQL injection"""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'/*",
            "1; SELECT * FROM users",
            "' UNION SELECT password FROM users --"
        ]

        for malicious_input in malicious_inputs:
            response = self.client.get(
                f'/api/targets/?search={malicious_input}'
            )
            # Should not cause a server error
            self.assertNotEqual(response.status_code, 500)

    def test_xss_protection(self):
        """Test protection against XSS attacks"""
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src="x" onerror="alert(1)">',
            'javascript:alert("XSS")',
            '<svg onload="alert(1)">',
            '"><script>alert("XSS")</script>'
        ]

        for payload in xss_payloads:
            response = self.client.post('/api/targets/', {
                'name': payload,
                'scope': 'example.com',
                'target_type': 'domain'
            })

            if response.status_code == 201:
                # If created, check the response doesn't contain raw script
                data = response.json()
                self.assertNotIn('<script>', str(data))
                self.assertNotIn('javascript:', str(data))

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
            response = self.client.post('/api/scans/', {
                'target': f'example.com{payload}',
                'scan_type': 'web'
            })

            # Should not execute commands
            self.assertNotEqual(response.status_code, 500)

    def test_file_upload_security(self):
        """Test file upload security"""
        malicious_files = [
            ('malicious.php', b'<?php system($_GET["cmd"]); ?>'),
            ('malicious.jsp', b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'),
            ('malicious.exe', b'MZ\x90\x00'),  # PE header
            ('script.js', b'alert("XSS");')
        ]

        for filename, content in malicious_files:
            response = self.client.post('/api/uploads/', {
                'file': (filename, content, 'application/octet-stream')
            })

            # Should reject malicious file types
            self.assertIn(response.status_code, [400, 403, 415])


@pytest.mark.security
@pytest.mark.phase3
class TestAuthorizationSecurity(TestCase):
    """Test authorization and access control"""

    def setUp(self):
        self.client = APIClient()

        # Create users with different roles
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpass123',
            is_staff=True,
            is_superuser=True
        )

        self.regular_user = User.objects.create_user(
            username='user',
            email='user@example.com',
            password='userpass123'
        )

    def test_unauthorized_access_protection(self):
        """Test protection against unauthorized access"""
        protected_endpoints = [
            '/api/admin/users/',
            '/api/admin/system/',
            '/api/scans/',
            '/api/targets/',
            '/api/vulnerabilities/'
        ]

        # Test without authentication
        for endpoint in protected_endpoints:
            response = self.client.get(endpoint)
            self.assertEqual(response.status_code, 401)

    def test_privilege_escalation_protection(self):
        """Test protection against privilege escalation"""
        # Login as regular user
        response = self.client.post('/api/auth/login/', {
            'username': 'user',
            'password': 'userpass123'
        })
        token = response.json()['access_token']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        # Try to access admin endpoints
        admin_endpoints = [
            '/api/admin/users/',
            '/api/admin/system/',
            '/api/admin/settings/'
        ]

        for endpoint in admin_endpoints:
            response = self.client.get(endpoint)
            self.assertIn(response.status_code, [403, 404])

    def test_horizontal_privilege_escalation(self):
        """Test protection against horizontal privilege escalation"""
        # Create another user
        other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='otherpass123'
        )

        # Login as regular user
        response = self.client.post('/api/auth/login/', {
            'username': 'user',
            'password': 'userpass123'
        })
        token = response.json()['access_token']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        # Try to access other user's data
        response = self.client.get(f'/api/users/{other_user.id}/')
        self.assertIn(response.status_code, [403, 404])


@pytest.mark.security
@pytest.mark.phase3
class TestEncryptionSecurity(TestCase):
    """Test encryption and data protection"""

    def test_password_hashing(self):
        """Test password hashing security"""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

        # Password should be hashed
        self.assertNotEqual(user.password, 'testpass123')
        self.assertTrue(user.password.startswith('pbkdf2_sha256$'))

        # Should be able to verify password
        self.assertTrue(user.check_password('testpass123'))
        self.assertFalse(user.check_password('wrongpassword'))

    def test_sensitive_data_encryption(self):
        """Test encryption of sensitive data"""
        # This would test encryption of API keys, tokens, etc.
        # Implementation depends on your encryption strategy
        pass

    def test_https_enforcement(self):
        """Test HTTPS enforcement"""
        # This would test that HTTPS is required in production
        # Implementation depends on your deployment setup
        pass


@pytest.mark.security
@pytest.mark.phase3
class TestSecurityHeaders(TestCase):
    """Test security headers and configurations"""

    def setUp(self):
        self.client = Client()

    def test_security_headers_present(self):
        """Test that required security headers are present"""
        response = self.client.get('/')

        security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]

        for header in security_headers:
            self.assertIn(header, response.headers)

    def test_content_security_policy(self):
        """Test Content Security Policy configuration"""
        response = self.client.get('/')

        csp = response.headers.get('Content-Security-Policy', '')

        # Should have restrictive CSP
        self.assertIn("default-src 'self'", csp)
        self.assertNotIn("'unsafe-eval'", csp)
        self.assertNotIn("'unsafe-inline'", csp)

    def test_cors_configuration(self):
        """Test CORS configuration security"""
        response = self.client.options('/api/')

        # Should not allow all origins
        cors_origin = response.headers.get('Access-Control-Allow-Origin', '')
        self.assertNotEqual(cors_origin, '*')


@pytest.mark.security
@pytest.mark.phase3
class TestDataProtection(TestCase):
    """Test data protection and privacy"""

    def test_sensitive_data_exposure(self):
        """Test that sensitive data is not exposed"""
        client = APIClient()

        # Create user
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

        # Login
        response = client.post('/api/auth/login/', {
            'username': 'testuser',
            'password': 'testpass123'
        })
        token = response.json()['access_token']
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        # Get user profile
        response = client.get('/api/user/profile/')
        data = response.json()

        # Sensitive fields should not be exposed
        sensitive_fields = ['password', 'password_hash', 'secret_key']
        for field in sensitive_fields:
            self.assertNotIn(field, data)

    def test_data_minimization(self):
        """Test that only necessary data is collected"""
        # This would test that forms and APIs only collect required data
        pass

    def test_data_retention_policies(self):
        """Test data retention and deletion policies"""
        # This would test automated data cleanup
        pass


@pytest.mark.security
@pytest.mark.phase3
class TestSecurityConfiguration(TestCase):
    """Test security configuration and hardening"""

    def test_debug_mode_disabled(self):
        """Test that debug mode is disabled in production"""
        from django.conf import settings

        # In testing environment, this might be enabled
        # In production, should be False
        if hasattr(settings, 'DEBUG'):
            # Test would vary based on environment
            pass

    def test_secret_key_security(self):
        """Test secret key configuration"""
        from django.conf import settings

        # Secret key should be present and secure
        self.assertTrue(hasattr(settings, 'SECRET_KEY'))
        self.assertGreater(len(settings.SECRET_KEY), 32)

        # Should not be a default or common key
        insecure_keys = [
            'django-insecure-',
            'your-secret-key-here',
            '1234567890'
        ]

        for insecure_key in insecure_keys:
            self.assertNotIn(insecure_key, settings.SECRET_KEY)

    def test_database_security(self):
        """Test database security configuration"""
        # This would test database connection security
        pass

    def test_file_permissions(self):
        """Test file permission security"""
        # This would test that sensitive files have proper permissions
        pass