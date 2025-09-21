"""
Unit tests for Target models
"""

import pytest
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.db import IntegrityError

from apps.targets.models import Target, BugBountyPlatform
from tests.factories import TargetFactory
from tests.test_utils import DatabaseTestMixin


@pytest.mark.unit
class TargetModelTest(TestCase, DatabaseTestMixin):
    """Test Target model functionality"""

    def setUp(self):
        self.target_data = {
            'target_name': 'Example Corp',
            'platform': BugBountyPlatform.HACKERONE,
            'researcher_username': 'test_researcher',
            'main_url': 'https://example.com',
            'requests_per_second': 5.0,
            'concurrent_requests': 10,
            'request_delay_ms': 200
        }

    def test_target_creation(self):
        """Test basic target creation"""
        target = Target.objects.create(**self.target_data)

        self.assertEqual(target.target_name, 'Example Corp')
        self.assertEqual(target.platform, BugBountyPlatform.HACKERONE)
        self.assertEqual(target.researcher_username, 'test_researcher')
        self.assertEqual(target.main_url, 'https://example.com')
        self.assertTrue(target.is_active)
        self.assertIsNotNone(target.id)
        self.assertIsNotNone(target.created_at)
        self.assertIsNotNone(target.updated_at)

    def test_target_string_representation(self):
        """Test target string representation"""
        target = Target.objects.create(**self.target_data)
        expected_str = "Example Corp (HackerOne)"
        self.assertEqual(str(target), expected_str)

    def test_target_name_uniqueness(self):
        """Test that target names must be unique"""
        Target.objects.create(**self.target_data)

        # Try to create another target with the same name
        duplicate_data = self.target_data.copy()
        duplicate_data['platform'] = BugBountyPlatform.BUGCROWD

        with self.assertRaises(IntegrityError):
            Target.objects.create(**duplicate_data)

    def test_target_required_fields(self):
        """Test that required fields are enforced"""
        # Missing target_name
        incomplete_data = self.target_data.copy()
        del incomplete_data['target_name']

        with self.assertRaises(IntegrityError):
            Target.objects.create(**incomplete_data)

        # Missing platform
        incomplete_data = self.target_data.copy()
        del incomplete_data['platform']

        with self.assertRaises(IntegrityError):
            Target.objects.create(**incomplete_data)

    def test_target_default_values(self):
        """Test model default values"""
        minimal_data = {
            'target_name': 'Minimal Target',
            'platform': BugBountyPlatform.HACKERONE,
            'researcher_username': 'test_user',
            'main_url': 'https://minimal.com'
        }

        target = Target.objects.create(**minimal_data)

        # Check default values
        self.assertEqual(target.requests_per_second, 5.0)
        self.assertEqual(target.concurrent_requests, 10)
        self.assertEqual(target.request_delay_ms, 200)
        self.assertEqual(target.in_scope_urls, [])
        self.assertEqual(target.out_of_scope_urls, [])
        self.assertEqual(target.in_scope_assets, [])
        self.assertEqual(target.out_of_scope_assets, [])
        self.assertEqual(target.required_headers, {})
        self.assertEqual(target.authentication_headers, {})
        self.assertEqual(target.user_agents, [])
        self.assertEqual(target.pii_redaction_rules, {})
        self.assertTrue(target.is_active)

    def test_target_array_fields(self):
        """Test array field functionality"""
        target_data = self.target_data.copy()
        target_data.update({
            'in_scope_urls': ['https://example.com', 'https://api.example.com'],
            'out_of_scope_urls': ['https://blog.example.com'],
            'in_scope_assets': ['192.168.1.0/24', '10.0.0.0/16'],
            'out_of_scope_assets': ['192.168.1.100'],
            'user_agents': ['BugBountyBot/1.0', 'Mozilla/5.0 Custom']
        })

        target = Target.objects.create(**target_data)

        self.assertEqual(len(target.in_scope_urls), 2)
        self.assertIn('https://example.com', target.in_scope_urls)
        self.assertIn('https://api.example.com', target.in_scope_urls)

        self.assertEqual(len(target.out_of_scope_urls), 1)
        self.assertIn('https://blog.example.com', target.out_of_scope_urls)

        self.assertEqual(len(target.in_scope_assets), 2)
        self.assertEqual(len(target.out_of_scope_assets), 1)
        self.assertEqual(len(target.user_agents), 2)

    def test_target_json_fields(self):
        """Test JSON field functionality"""
        target_data = self.target_data.copy()
        target_data.update({
            'required_headers': {
                'User-Agent': 'BugBountyBot/1.0',
                'Accept': 'application/json'
            },
            'authentication_headers': {
                'Authorization': 'Bearer token123',
                'X-API-Key': 'key456'
            },
            'pii_redaction_rules': {
                'email_pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'ssn_pattern': r'\d{3}-\d{2}-\d{4}'
            }
        })

        target = Target.objects.create(**target_data)

        # Test required_headers
        self.assertEqual(target.required_headers['User-Agent'], 'BugBountyBot/1.0')
        self.assertEqual(target.required_headers['Accept'], 'application/json')

        # Test authentication_headers
        self.assertEqual(target.authentication_headers['Authorization'], 'Bearer token123')
        self.assertEqual(target.authentication_headers['X-API-Key'], 'key456')

        # Test pii_redaction_rules
        self.assertIn('email_pattern', target.pii_redaction_rules)
        self.assertIn('ssn_pattern', target.pii_redaction_rules)

    def test_target_platform_choices(self):
        """Test platform choice validation"""
        valid_platforms = [
            BugBountyPlatform.HACKERONE,
            BugBountyPlatform.BUGCROWD,
            BugBountyPlatform.INTIGRITI,
            BugBountyPlatform.SYNACK,
            BugBountyPlatform.YESWEHACK,
            BugBountyPlatform.PRIVATE
        ]

        for platform in valid_platforms:
            target_data = self.target_data.copy()
            target_data['target_name'] = f'Target for {platform}'
            target_data['platform'] = platform

            target = Target.objects.create(**target_data)
            self.assertEqual(target.platform, platform)

    def test_get_scope_summary_method(self):
        """Test get_scope_summary property method"""
        target_data = self.target_data.copy()
        target_data.update({
            'in_scope_urls': ['https://example.com', 'https://api.example.com'],
            'out_of_scope_urls': ['https://blog.example.com'],
            'in_scope_assets': ['192.168.1.0/24', '10.0.0.0/16'],
            'out_of_scope_assets': ['192.168.1.100']
        })

        target = Target.objects.create(**target_data)
        scope_summary = target.get_scope_summary()

        expected_summary = {
            'in_scope_urls_count': 2,
            'out_of_scope_urls_count': 1,
            'in_scope_assets_count': 2,
            'out_of_scope_assets_count': 1
        }

        self.assertEqual(scope_summary, expected_summary)

    def test_target_rate_limiting_validation(self):
        """Test rate limiting parameter validation"""
        target_data = self.target_data.copy()

        # Test valid rate limiting values
        target_data['requests_per_second'] = 1.5
        target_data['concurrent_requests'] = 5
        target_data['request_delay_ms'] = 500

        target = Target.objects.create(**target_data)
        self.assertEqual(target.requests_per_second, 1.5)
        self.assertEqual(target.concurrent_requests, 5)
        self.assertEqual(target.request_delay_ms, 500)

    def test_target_ordering(self):
        """Test model ordering (should be by -created_at)"""
        # Create multiple targets
        target1 = TargetFactory.create(target_name='Target 1')
        target2 = TargetFactory.create(target_name='Target 2')
        target3 = TargetFactory.create(target_name='Target 3')

        # Get all targets (should be ordered by -created_at)
        targets = list(Target.objects.all())

        # The most recently created should be first
        self.assertEqual(targets[0], target3)
        self.assertEqual(targets[1], target2)
        self.assertEqual(targets[2], target1)

    def test_target_relationships(self):
        """Test target relationships with other models"""
        target = TargetFactory.create()

        # Test scan_sessions relationship exists
        self.assertTrue(hasattr(target, 'scan_sessions'))

        # Test exploitation_sessions relationship exists
        self.assertTrue(hasattr(target, 'exploitation_sessions'))

        # Initially should have no related objects
        self.assertEqual(target.scan_sessions.count(), 0)
        self.assertEqual(target.exploitation_sessions.count(), 0)

    def test_target_properties_with_no_scans(self):
        """Test target properties when no scan sessions exist"""
        target = TargetFactory.create()

        # Properties should handle empty relationships gracefully
        self.assertEqual(target.total_scan_sessions, 0)
        self.assertIsNone(target.latest_scan_session)

    def test_target_properties_with_scans(self):
        """Test target properties when scan sessions exist"""
        from tests.factories import ScanSessionFactory

        target = TargetFactory.create()

        # Create scan sessions
        scan1 = ScanSessionFactory.create(target=target)
        scan2 = ScanSessionFactory.create(target=target)
        scan3 = ScanSessionFactory.create(target=target)

        # Test properties
        self.assertEqual(target.total_scan_sessions, 3)
        self.assertIsNotNone(target.latest_scan_session)
        # Latest scan should be the most recently created
        self.assertEqual(target.latest_scan_session, scan3)

    def test_target_indexing(self):
        """Test that database indexes are created correctly"""
        # This test ensures the Meta.indexes are properly configured
        # We can't directly test index creation in Django unit tests,
        # but we can test that the indexed fields perform efficiently

        # Create multiple targets with different platforms and active states
        TargetFactory.create_batch(5, platform=BugBountyPlatform.HACKERONE, is_active=True)
        TargetFactory.create_batch(3, platform=BugBountyPlatform.BUGCROWD, is_active=False)

        # These queries should be efficient due to indexes
        active_targets = Target.objects.filter(is_active=True)
        hackerone_targets = Target.objects.filter(platform=BugBountyPlatform.HACKERONE)

        self.assertEqual(active_targets.count(), 5)
        self.assertEqual(hackerone_targets.count(), 5)

    def test_target_db_table_name(self):
        """Test that the database table name is correct"""
        target = TargetFactory.create()
        self.assertEqual(target._meta.db_table, 'targets')

    def test_wildcard_url_field(self):
        """Test wildcard URL field functionality"""
        target_data = self.target_data.copy()
        target_data['wildcard_url'] = '*.example.com'

        target = Target.objects.create(**target_data)
        self.assertEqual(target.wildcard_url, '*.example.com')

        # Test that wildcard_url can be None
        target_data_no_wildcard = self.target_data.copy()
        target_data_no_wildcard['target_name'] = 'No Wildcard Target'
        target_no_wildcard = Target.objects.create(**target_data_no_wildcard)
        self.assertIsNone(target_no_wildcard.wildcard_url)

    def test_target_notes_fields(self):
        """Test program notes and special requirements fields"""
        target_data = self.target_data.copy()
        target_data.update({
            'program_notes': 'This is a test program for educational purposes only.',
            'special_requirements': 'Do not test admin panels. Rate limit: 10 req/sec max.'
        })

        target = Target.objects.create(**target_data)
        self.assertEqual(
            target.program_notes,
            'This is a test program for educational purposes only.'
        )
        self.assertEqual(
            target.special_requirements,
            'Do not test admin panels. Rate limit: 10 req/sec max.'
        )

        # Test blank values are allowed
        target_data_blank = self.target_data.copy()
        target_data_blank['target_name'] = 'Blank Notes Target'
        target_blank = Target.objects.create(**target_data_blank)
        self.assertEqual(target_blank.program_notes, '')
        self.assertEqual(target_blank.special_requirements, '')


@pytest.mark.unit
class BugBountyPlatformTest(TestCase):
    """Test BugBountyPlatform choices"""

    def test_platform_choices_values(self):
        """Test that all platform choices have correct values"""
        expected_choices = {
            'hackerone': 'HackerOne',
            'bugcrowd': 'Bugcrowd',
            'intigriti': 'Intigriti',
            'synack': 'Synack',
            'yeswehack': 'YesWeHack',
            'private': 'Private Program'
        }

        for choice_value, choice_label in BugBountyPlatform.choices:
            self.assertIn(choice_value, expected_choices)
            self.assertEqual(expected_choices[choice_value], choice_label)

    def test_platform_enum_values(self):
        """Test enum-style access to platform values"""
        self.assertEqual(BugBountyPlatform.HACKERONE, 'hackerone')
        self.assertEqual(BugBountyPlatform.BUGCROWD, 'bugcrowd')
        self.assertEqual(BugBountyPlatform.INTIGRITI, 'intigriti')
        self.assertEqual(BugBountyPlatform.SYNACK, 'synack')
        self.assertEqual(BugBountyPlatform.YESWEHACK, 'yeswehack')
        self.assertEqual(BugBountyPlatform.PRIVATE, 'private')


@pytest.mark.unit
class TargetFactoryTest(TestCase):
    """Test Target factory functionality"""

    def test_target_factory_creation(self):
        """Test that TargetFactory creates valid targets"""
        target = TargetFactory.create()

        self.assertIsInstance(target, Target)
        self.assertIsNotNone(target.target_name)
        self.assertIsNotNone(target.platform)
        self.assertIsNotNone(target.researcher_username)
        self.assertIsNotNone(target.main_url)
        self.assertTrue(target.is_active)

    def test_target_factory_batch_creation(self):
        """Test creating multiple targets with factory"""
        targets = TargetFactory.create_batch(5)

        self.assertEqual(len(targets), 5)
        for target in targets:
            self.assertIsInstance(target, Target)

        # All targets should have unique names (due to factory randomization)
        target_names = [target.target_name for target in targets]
        self.assertEqual(len(target_names), len(set(target_names)))

    def test_target_factory_with_custom_data(self):
        """Test creating target with custom factory data"""
        custom_target = TargetFactory.create(
            target_name='Custom Target',
            platform=BugBountyPlatform.PRIVATE,
            requests_per_second=2.5
        )

        self.assertEqual(custom_target.target_name, 'Custom Target')
        self.assertEqual(custom_target.platform, BugBountyPlatform.PRIVATE)
        self.assertEqual(custom_target.requests_per_second, 2.5)

    def test_target_factory_realistic_data(self):
        """Test that factory generates realistic data"""
        target = TargetFactory.create()

        # URL should be valid format
        self.assertTrue(target.main_url.startswith(('http://', 'https://')))

        # Wildcard URL should be related to main URL if present
        if target.wildcard_url:
            main_domain = target.main_url.split('://')[1]
            self.assertTrue(target.wildcard_url.endswith(main_domain))

        # Rate limiting values should be reasonable
        self.assertGreater(target.requests_per_second, 0)
        self.assertGreater(target.concurrent_requests, 0)
        self.assertGreater(target.request_delay_ms, 0)

        # Arrays should be lists
        self.assertIsInstance(target.in_scope_urls, list)
        self.assertIsInstance(target.out_of_scope_urls, list)
        self.assertIsInstance(target.in_scope_assets, list)
        self.assertIsInstance(target.out_of_scope_assets, list)
        self.assertIsInstance(target.user_agents, list)

        # JSON fields should be dictionaries
        self.assertIsInstance(target.required_headers, dict)
        self.assertIsInstance(target.authentication_headers, dict)
        self.assertIsInstance(target.pii_redaction_rules, dict)