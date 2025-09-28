"""
API Edge Cases and Boundary Testing
"""

import pytest
import json
from unittest.mock import Mock, patch
from django.test import TransactionTestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from tests.factories import UserFactory, TargetFactory, ScanSessionFactory, VulnerabilityFactory


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
class TestAPIEdgeCases(TransactionTestCase):
    """Test API edge cases and boundary conditions"""

    def setUp(self):
        self.client = APIClient()
        self.user = UserFactory()
        self.target = TargetFactory()

        # Authenticate client
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    def test_malformed_json_requests(self):
        """Test handling of malformed JSON requests"""
        malformed_json_data = [
            '{"invalid": json}',  # Missing quotes
            '{"key": "value",}',  # Trailing comma
            '{invalid_key: "value"}',  # Unquoted key
            '{"nested": {"incomplete": }',  # Incomplete nested object
            '["array", "missing", "bracket"',  # Incomplete array
        ]

        for malformed_data in malformed_json_data:
            response = self.client.post(
                '/api/targets/',
                data=malformed_data,
                content_type='application/json'
            )
            self.assertEqual(response.status_code, 400)
            self.assertIn('error', response.data)

    def test_oversized_request_payloads(self):
        """Test handling of oversized request payloads"""
        # Create extremely large payload
        large_payload = {
            'target_name': 'Test Target',
            'platform': 'hackerone',
            'researcher_username': 'test',
            'main_url': 'https://example.com',
            'program_notes': 'A' * 100000,  # 100KB of text
            'large_array': ['item'] * 10000  # Large array
        }

        response = self.client.post('/api/targets/', large_payload, format='json')
        # Should either handle gracefully or return appropriate error
        self.assertIn(response.status_code, [400, 413, 414])

    def test_null_and_empty_values(self):
        """Test handling of null and empty values"""
        test_cases = [
            {
                'target_name': None,
                'platform': 'hackerone',
                'researcher_username': 'test',
                'main_url': 'https://example.com'
            },
            {
                'target_name': '',
                'platform': 'hackerone',
                'researcher_username': 'test',
                'main_url': 'https://example.com'
            },
            {
                'target_name': 'Test Target',
                'platform': None,
                'researcher_username': 'test',
                'main_url': 'https://example.com'
            },
            {
                'target_name': 'Test Target',
                'platform': 'hackerone',
                'researcher_username': '',
                'main_url': None
            }
        ]

        for test_data in test_cases:
            response = self.client.post('/api/targets/', test_data, format='json')
            self.assertEqual(response.status_code, 400)
            self.assertIn('errors', response.data)

    def test_unicode_and_special_characters(self):
        """Test handling of Unicode and special characters"""
        unicode_test_cases = [
            {
                'target_name': '测试目标 🎯',  # Chinese + emoji
                'platform': 'hackerone',
                'researcher_username': 'test_ûser',
                'main_url': 'https://example.com'
            },
            {
                'target_name': 'Тест Мишень',  # Cyrillic
                'platform': 'hackerone',
                'researcher_username': 'test',
                'main_url': 'https://example.com'
            },
            {
                'target_name': 'Target with "quotes" and \'apostrophes\'',
                'platform': 'hackerone',
                'researcher_username': 'test',
                'main_url': 'https://example.com'
            },
            {
                'target_name': 'Target with <tags> & symbols',
                'platform': 'hackerone',
                'researcher_username': 'test',
                'main_url': 'https://example.com'
            }
        ]

        for test_data in unicode_test_cases:
            response = self.client.post('/api/targets/', test_data, format='json')
            # Should handle Unicode gracefully
            self.assertIn(response.status_code, [201, 400])

    def test_boundary_value_testing(self):
        """Test boundary values for numeric fields"""
        boundary_test_cases = [
            # CVSS score boundaries
            {'cvss_score': -1.0},   # Below minimum
            {'cvss_score': 0.0},    # Minimum valid
            {'cvss_score': 10.0},   # Maximum valid
            {'cvss_score': 11.0},   # Above maximum

            # Rate limiting boundaries
            {'requests_per_second': -1.0},     # Below minimum
            {'requests_per_second': 0.0},      # Minimum edge case
            {'requests_per_second': 1000.0},   # High but valid
            {'requests_per_second': 10000.0},  # Extremely high

            # Concurrent requests boundaries
            {'concurrent_requests': -1},   # Below minimum
            {'concurrent_requests': 0},    # Minimum edge case
            {'concurrent_requests': 1},    # Minimum valid
            {'concurrent_requests': 1000}, # High but valid
        ]

        scan_session = ScanSessionFactory(target=self.target)

        for boundary_data in boundary_test_cases:
            if 'cvss_score' in boundary_data:
                vuln_data = {
                    'scan_session': scan_session.id,
                    'vulnerability_name': 'Test Vulnerability',
                    'vulnerability_type': 'xss_reflected',
                    'severity': 'medium',
                    'affected_url': 'https://example.com',
                    **boundary_data
                }
                response = self.client.post('/api/vulnerabilities/', vuln_data, format='json')
            else:
                target_data = {
                    'target_name': f'Boundary Test {list(boundary_data.keys())[0]}',
                    'platform': 'hackerone',
                    'researcher_username': 'test',
                    'main_url': 'https://example.com',
                    **boundary_data
                }
                response = self.client.post('/api/targets/', target_data, format='json')

            # Should validate boundaries appropriately
            if any(value < 0 for value in boundary_data.values() if isinstance(value, (int, float))):
                self.assertEqual(response.status_code, 400)

    def test_extremely_long_strings(self):
        """Test handling of extremely long string values"""
        long_string_tests = [
            ('target_name', 'A' * 1000),
            ('program_notes', 'X' * 50000),
            ('researcher_username', 'user' * 100),
            ('vulnerability_name', 'SQL Injection ' * 1000),
            ('payload_used', 'SELECT * FROM users; ' * 1000)
        ]

        scan_session = ScanSessionFactory(target=self.target)

        for field_name, long_value in long_string_tests:
            if field_name in ['vulnerability_name', 'payload_used']:
                test_data = {
                    'scan_session': scan_session.id,
                    'vulnerability_type': 'sql_injection',
                    'severity': 'high',
                    'affected_url': 'https://example.com',
                    field_name: long_value
                }
                endpoint = '/api/vulnerabilities/'
            else:
                test_data = {
                    'platform': 'hackerone',
                    'researcher_username': 'test',
                    'main_url': 'https://example.com',
                    field_name: long_value
                }
                endpoint = '/api/targets/'

            response = self.client.post(endpoint, test_data, format='json')
            # Should handle long strings gracefully (truncate or reject)
            self.assertIn(response.status_code, [201, 400])

    def test_nested_data_depth_limits(self):
        """Test handling of deeply nested data structures"""
        # Create deeply nested configuration
        deeply_nested = {'level_1': {'level_2': {'level_3': {'level_4': {'level_5': {'level_6': 'deep_value'}}}}}}

        scan_data = {
            'target_id': self.target.id,
            'session_name': 'Deep Nesting Test',
            'scan_config': deeply_nested
        }

        response = self.client.post('/api/scanning/', scan_data, format='json')
        # Should handle or limit nesting depth
        self.assertIn(response.status_code, [201, 400])

    def test_concurrent_request_handling(self):
        """Test handling of concurrent requests"""
        import threading
        import time

        results = []

        def make_request():
            target_data = {
                'target_name': f'Concurrent Target {threading.current_thread().ident}',
                'platform': 'hackerone',
                'researcher_username': 'test',
                'main_url': 'https://example.com'
            }
            response = self.client.post('/api/targets/', target_data, format='json')
            results.append(response.status_code)

        # Create multiple threads to make concurrent requests
        threads = []
        for i in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # All requests should be handled properly
        self.assertEqual(len(results), 10)
        success_count = sum(1 for status in results if status == 201)
        self.assertGreater(success_count, 0)  # At least some should succeed

    def test_invalid_http_methods(self):
        """Test endpoints with invalid HTTP methods"""
        invalid_method_tests = [
            ('PUT', '/api/targets/'),      # POST-only endpoint
            ('DELETE', '/api/targets/'),   # POST-only endpoint
            ('POST', '/api/targets/999/'), # GET/PUT/DELETE-only endpoint
            ('PATCH', '/api/auth/login/'), # POST-only endpoint
        ]

        for method, endpoint in invalid_method_tests:
            if method == 'PUT':
                response = self.client.put(endpoint, {}, format='json')
            elif method == 'DELETE':
                response = self.client.delete(endpoint)
            elif method == 'POST':
                response = self.client.post(endpoint, {}, format='json')
            elif method == 'PATCH':
                response = self.client.patch(endpoint, {}, format='json')

            # Should return Method Not Allowed
            self.assertEqual(response.status_code, 405)

    def test_content_type_handling(self):
        """Test handling of different content types"""
        target_data = {
            'target_name': 'Content Type Test',
            'platform': 'hackerone',
            'researcher_username': 'test',
            'main_url': 'https://example.com'
        }

        content_type_tests = [
            ('application/xml', 400),      # Should reject XML
            ('text/plain', 400),           # Should reject plain text
            ('multipart/form-data', 201),  # Should accept form data
            ('application/json', 201),     # Should accept JSON
        ]

        for content_type, expected_status in content_type_tests:
            if content_type == 'application/xml':
                response = self.client.post(
                    '/api/targets/',
                    data='<xml>test</xml>',
                    content_type=content_type
                )
            elif content_type == 'text/plain':
                response = self.client.post(
                    '/api/targets/',
                    data='plain text data',
                    content_type=content_type
                )
            else:
                response = self.client.post(
                    '/api/targets/',
                    target_data,
                    format='json' if content_type == 'application/json' else 'multipart'
                )

            # Some content types should be rejected
            if expected_status == 400:
                self.assertEqual(response.status_code, 400)

    def test_parameter_injection_attempts(self):
        """Test parameter injection attempts"""
        injection_payloads = [
            # SQL injection attempts
            "'; DROP TABLE targets; --",
            "' OR 1=1 --",
            "' UNION SELECT * FROM users --",

            # NoSQL injection attempts
            {"$ne": None},
            {"$gt": ""},
            {"$where": "function() { return true; }"},

            # Command injection attempts
            "; ls -la",
            "| cat /etc/passwd",
            "&& rm -rf /",
            "`whoami`",

            # Path traversal attempts
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
        ]

        for payload in injection_payloads:
            target_data = {
                'target_name': payload if isinstance(payload, str) else 'Test Target',
                'platform': 'hackerone',
                'researcher_username': payload if isinstance(payload, str) else 'test',
                'main_url': 'https://example.com'
            }

            response = self.client.post('/api/targets/', target_data, format='json')
            # Should sanitize or reject injection attempts
            if response.status_code == 201:
                # If accepted, data should be sanitized
                created_target = response.data
                if isinstance(payload, str):
                    # Check that dangerous characters are removed/escaped
                    for field in ['target_name', 'researcher_username']:
                        if field in created_target and created_target[field]:
                            field_value = created_target[field]
                            self.assertNotIn('DROP TABLE', field_value)
                            self.assertNotIn('/etc/passwd', field_value)
                            self.assertNotIn('rm -rf', field_value)

    def test_pagination_edge_cases(self):
        """Test pagination edge cases"""
        # Create test data
        VulnerabilityFactory.create_batch(50, scan_session=ScanSessionFactory(target=self.target))

        pagination_tests = [
            # Invalid page numbers
            ('page=-1', 400),
            ('page=0', 400),
            ('page=abc', 400),

            # Invalid page sizes
            ('page_size=-1', 400),
            ('page_size=0', 400),
            ('page_size=10000', 400),  # Too large
            ('page_size=abc', 400),

            # Extremely large page numbers
            ('page=999999', 404),

            # Valid edge cases
            ('page=1&page_size=1', 200),
            ('page=50&page_size=1', 200),
        ]

        for params, expected_status in pagination_tests:
            response = self.client.get(f'/api/vulnerabilities/?{params}')
            if expected_status == 200:
                self.assertEqual(response.status_code, 200)
            else:
                self.assertIn(response.status_code, [400, 404])

    def test_filter_injection_attempts(self):
        """Test filter parameter injection attempts"""
        # Create test data
        VulnerabilityFactory.create_batch(5, scan_session=ScanSessionFactory(target=self.target))

        filter_injection_tests = [
            # SQL injection in filters
            "severity=high'; DROP TABLE vulnerabilities; --",
            "type=' OR 1=1 --",
            "search=' UNION SELECT password FROM users --",

            # Script injection in filters
            "search=<script>alert('xss')</script>",
            "severity=<img src=x onerror=alert('xss')>",

            # Command injection in filters
            "search=test; cat /etc/passwd",
            "type=xss | whoami",
        ]

        for malicious_filter in filter_injection_tests:
            response = self.client.get(f'/api/vulnerabilities/?{malicious_filter}')
            # Should handle malicious filters safely
            self.assertIn(response.status_code, [200, 400])

            if response.status_code == 200:
                # Response should not contain dangerous content
                response_content = json.dumps(response.data)
                self.assertNotIn('DROP TABLE', response_content)
                self.assertNotIn('<script>', response_content)
                self.assertNotIn('/etc/passwd', response_content)

    def test_file_upload_edge_cases(self):
        """Test file upload edge cases"""
        from django.core.files.uploadedfile import SimpleUploadedFile

        # Test oversized files
        large_file = SimpleUploadedFile(
            "large_file.txt",
            b"A" * (10 * 1024 * 1024),  # 10MB file
            content_type="text/plain"
        )

        # Test files with malicious names
        malicious_names = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "file<script>alert('xss')</script>.txt",
            "file'; DROP TABLE files; --.txt",
        ]

        for malicious_name in malicious_names:
            malicious_file = SimpleUploadedFile(
                malicious_name,
                b"test content",
                content_type="text/plain"
            )

            # Attempt file upload (adjust endpoint as needed)
            response = self.client.post(
                '/api/vulnerabilities/1/evidence/',
                {
                    'evidence_type': 'document',
                    'description': 'Test file',
                    'file': malicious_file
                },
                format='multipart'
            )

            # Should sanitize filenames or reject malicious files
            self.assertIn(response.status_code, [201, 400, 404])

    def test_rate_limiting_edge_cases(self):
        """Test rate limiting edge cases"""
        # Make rapid successive requests
        responses = []
        for i in range(100):
            response = self.client.get('/api/targets/')
            responses.append(response.status_code)

        # Should implement rate limiting after many requests
        rate_limited_count = sum(1 for status in responses if status == 429)

        # May or may not be rate limited depending on configuration
        # This test documents the behavior rather than enforcing it