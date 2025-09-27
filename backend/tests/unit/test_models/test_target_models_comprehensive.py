"""
Comprehensive tests for target models with edge cases.
Tests all model methods, properties, validations, and edge cases.
"""

import pytest
import re
from datetime import datetime, timedelta
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from apps.targets.models import Target, BugBountyPlatform
from tests.factories import TargetFactory, UserFactory


@pytest.mark.unit
class TestBugBountyPlatformModel(TestCase):
    """Comprehensive tests for BugBountyPlatform model."""

    def test_platform_creation_valid_data(self):
        """Test creating platform with valid data."""
        # BugBountyPlatform is a TextChoices enum, not a model
        # Test target creation with platform choice instead
        target = Target.objects.create(
            target_name="Test Target",
            platform=BugBountyPlatform.HACKERONE,
            researcher_username="test_user",
            main_url="https://example.com"
        )

        self.assertIsNotNone(target.id)
        self.assertEqual(target.platform, BugBountyPlatform.HACKERONE)
        self.assertEqual(target.researcher_username, "test_user")
        self.assertEqual(target.main_url, "https://example.com")

    def test_platform_string_representation(self):
        """Test string representation of platform."""
        target = Target.objects.create(
            target_name="Bugcrowd Target",
            platform=BugBountyPlatform.BUGCROWD,
            researcher_username="test_user",
            main_url="https://bugcrowd-target.com"
        )
        self.assertEqual(str(target), "Bugcrowd Target (Bugcrowd)")

    def test_platform_unique_name_constraint(self):
        """Test unique name constraint."""
        Target.objects.create(
            target_name="TestTarget",
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user",
            main_url="https://test1.com"
        )

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Target.objects.create(
                    target_name="TestTarget",  # Duplicate name
                    platform=BugBountyPlatform.PRIVATE,
                    researcher_username="test_user",
                    main_url="https://test2.com"
                )

    def test_platform_url_validation(self):
        """Test URL field validation."""
        # Valid URLs
        valid_urls = [
            "https://example.com",
            "http://test.com",
            "https://subdomain.example.com:8080",
            "https://api.example.com/v1"
        ]

        for i, url in enumerate(valid_urls):
            target = Target.objects.create(
                target_name=f"TestTarget{i}",
                platform=BugBountyPlatform.PRIVATE,
                researcher_username="test_user",
                main_url=url
            )
            self.assertEqual(target.main_url, url)

    def test_platform_optional_fields(self):
        """Test optional fields."""
        target = Target.objects.create(
            target_name="MinimalTarget",
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user",
            main_url="https://minimal.com"
            # Optional fields not provided
        )

        self.assertIsNone(target.wildcard_url)
        self.assertEqual(target.program_notes, "")
        self.assertTrue(target.is_active)  # Default value

    def test_platform_deactivation(self):
        """Test platform deactivation."""
        target = Target.objects.create(
            target_name="TestTarget",
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user",
            main_url="https://test.com",
            is_active=True
        )

        target.is_active = False
        target.save()

        self.assertFalse(target.is_active)

    def test_platform_with_api_configuration(self):
        """Test platform with API configuration."""
        api_config = {
            "authentication": "api_key",
            "rate_limit": 100,
            "endpoints": {
                "reports": "/reports",
                "programs": "/programs"
            }
        }

        target = Target.objects.create(
            target_name="ConfiguredTarget",
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user",
            main_url="https://configured.com",
            required_headers=api_config
        )

        self.assertEqual(target.required_headers, api_config)
        self.assertEqual(target.required_headers["rate_limit"], 100)

    def test_platform_ordering(self):
        """Test default ordering by name."""
        target_z = Target.objects.create(
            target_name="ZTarget",
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user",
            main_url="https://z.com"
        )
        target_a = Target.objects.create(
            target_name="ATarget",
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user",
            main_url="https://a.com"
        )

        targets = Target.objects.all()
        # Default ordering is by created_at descending, so newer first
        self.assertEqual(targets.first(), target_a)
        self.assertEqual(targets.last(), target_z)


@pytest.mark.unit
class TestTargetModel(TestCase):
    """Comprehensive tests for Target model."""

    def setUp(self):
        """Set up test data."""
        self.user = UserFactory()
        # BugBountyPlatform is a TextChoices enum, not a model

    def test_target_creation_valid_data(self):
        """Test creating target with valid data."""
        target = Target.objects.create(
            target_name="Example Corp",
            main_url="https://example.com",
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user"
        )

        self.assertIsNotNone(target.id)
        self.assertEqual(target.target_name, "Example Corp")
        self.assertEqual(target.target_url, "https://example.com")
        self.assertEqual(target.platform, BugBountyPlatform.PRIVATE)
        self.assertEqual(target.created_by, self.user)
        self.assertTrue(target.is_active)

    def test_target_string_representation(self):
        """Test string representation of target."""
        target = TargetFactory(
            target_name="Test Target",
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user"
        )
        self.assertEqual(str(target), "Test Target")

    def test_target_url_validation(self):
        """Test URL validation."""
        valid_urls = [
            "https://example.com",
            "https://sub.example.com",
            "https://example.com:8080",
            "https://example.com/path",
            "http://localhost:3000"  # For development
        ]

        for i, url in enumerate(valid_urls):
            target = Target.objects.create(
                target_name=f"Test Target {i}",
                main_url=url,
                platform=BugBountyPlatform.PRIVATE,
                researcher_username="test_user"
            )
            self.assertEqual(target.target_url, url)

    def test_target_scope_arrays(self):
        """Test in-scope and out-of-scope URL arrays."""
        in_scope_urls = [
            "https://example.com/*",
            "https://api.example.com/*",
            "https://admin.example.com/*"
        ]
        out_of_scope_urls = [
            "https://blog.example.com/*",
            "https://docs.example.com/*"
        ]

        target = Target.objects.create(
            target_name="Scoped Target",
            main_url="https://example.com",
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user",
            in_scope_urls=in_scope_urls,
            out_of_scope_urls=out_of_scope_urls
        )

        self.assertEqual(target.in_scope_urls, in_scope_urls)
        self.assertEqual(target.out_of_scope_urls, out_of_scope_urls)
        self.assertEqual(len(target.in_scope_urls), 3)
        self.assertEqual(len(target.out_of_scope_urls), 2)

    def test_target_program_metadata(self):
        """Test program metadata JSON field."""
        program_metadata = {
            "program_id": "12345",
            "program_type": "public",
            "submission_guidelines": "Please follow responsible disclosure",
            "reward_range": "$100-$5000",
            "last_updated": "2024-01-01"
        }

        target = Target.objects.create(
            target_name="Metadata Target",
            main_url="https://metadata.com",
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user",
            program_metadata=program_metadata
        )

        self.assertEqual(target.program_metadata, program_metadata)
        self.assertEqual(target.program_metadata["program_type"], "public")
        self.assertEqual(target.program_metadata["reward_range"], "$100-$5000")

    def test_target_user_agents_array(self):
        """Test user agents array field."""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "BugBountyScanner/1.0"
        ]

        target = Target.objects.create(
            target_name="User Agent Target",
            main_url="https://useragent.com",
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user",
            user_agents=user_agents
        )

        self.assertEqual(target.user_agents, user_agents)
        self.assertEqual(len(target.user_agents), 3)

    def test_target_scanning_configuration(self):
        """Test scanning configuration JSON field."""
        scanning_config = {
            "max_scan_depth": 5,
            "requests_per_second": 10,
            "exclude_extensions": [".jpg", ".png", ".gif"],
            "custom_headers": {
                "X-Bug-Bounty": "true",
                "User-Agent": "BugBountyScanner"
            },
            "authentication": {
                "type": "cookie",
                "value": "session_id=abc123"
            }
        }

        target = Target.objects.create(
            target_name="Configured Target",
            main_url="https://configured.com",
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user",
            scanning_configuration=scanning_config
        )

        self.assertEqual(target.scanning_configuration, scanning_config)
        self.assertEqual(target.scanning_configuration["max_scan_depth"], 5)
        self.assertEqual(
            target.scanning_configuration["authentication"]["type"],
            "cookie"
        )

    def test_target_timestamps(self):
        """Test automatic timestamp fields."""
        target = TargetFactory(
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user"
        )

        self.assertIsInstance(target.created_at, datetime)
        self.assertIsInstance(target.updated_at, datetime)

        # Test updated_at changes on save
        original_updated = target.updated_at
        target.target_name = "Updated Name"
        target.save()

        self.assertNotEqual(target.updated_at, original_updated)

    def test_target_platform_relationship(self):
        """Test platform foreign key relationship."""
        target = TargetFactory(
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user"
        )

        self.assertEqual(target.platform, BugBountyPlatform.PRIVATE)
        self.assertIn(target, BugBountyPlatform.PRIVATE.targets.all())

    def test_target_user_relationship(self):
        """Test user foreign key relationship."""
        target = TargetFactory(
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user"
        )

        self.assertEqual(target.created_by, self.user)

    def test_target_deactivation(self):
        """Test target deactivation."""
        target = TargetFactory(
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user",
            is_active=True
        )

        target.is_active = False
        target.save()

        self.assertFalse(target.is_active)

    def test_target_ordering(self):
        """Test default ordering by creation date."""
        older_target = TargetFactory(
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user"
        )
        older_target.created_at = datetime.now() - timedelta(hours=1)
        older_target.save()

        newer_target = TargetFactory(
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user"
        )

        targets = Target.objects.all()
        self.assertEqual(targets.first(), newer_target)
        self.assertEqual(targets.last(), older_target)

    def test_target_cascade_deletion(self):
        """Test cascade deletion behavior."""
        target = TargetFactory(
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user"
        )
        target_id = target.id

        # Deleting platform should cascade delete target
        BugBountyPlatform.PRIVATE.delete()

        with self.assertRaises(Target.DoesNotExist):
            Target.objects.get(id=target_id)

    def test_target_edge_cases(self):
        """Test edge cases and boundary conditions."""
        # Test with maximum length strings
        long_name = "A" * 255  # Assuming max_length=255
        long_description = "B" * 1000

        target = Target.objects.create(
            target_name=long_name,
            main_url="https://example.com",
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user",
            description=long_description
        )

        self.assertEqual(len(target.target_name), 255)
        self.assertEqual(len(target.description), 1000)

    def test_target_empty_arrays(self):
        """Test targets with empty arrays."""
        target = Target.objects.create(
            target_name="Empty Arrays Target",
            main_url="https://empty.com",
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user",
            in_scope_urls=[],
            out_of_scope_urls=[],
            user_agents=[]
        )

        self.assertEqual(target.in_scope_urls, [])
        self.assertEqual(target.out_of_scope_urls, [])
        self.assertEqual(target.user_agents, [])

    def test_target_null_json_fields(self):
        """Test targets with null JSON fields."""
        target = Target.objects.create(
            target_name="Null JSON Target",
            main_url="https://null.com",
            platform=BugBountyPlatform.PRIVATE,
            researcher_username="test_user"
            # JSON fields not provided (should default to empty dict)
        )

        self.assertEqual(target.program_metadata, {})
        self.assertEqual(target.scanning_configuration, {})


# TargetScope model doesn't exist in current implementation
# Removed this test class as the model is not implemented


@pytest.mark.unit
class TestTargetQuerysets(TestCase):
    """Test custom querysets and managers for Target model."""

    def setUp(self):
        """Set up test data."""
        self.user = UserFactory()
        # Using platform enum choices instead of creating objects

    def test_active_targets_filtering(self):
        """Test filtering active targets."""
        active_target = TargetFactory(
            platform=BugBountyPlatform.HACKERONE,
            researcher_username="test_user",
            is_active=True
        )
        inactive_target = TargetFactory(
            platform=BugBountyPlatform.HACKERONE,
            researcher_username="test_user",
            is_active=False
        )

        active_targets = Target.objects.filter(is_active=True)
        self.assertIn(active_target, active_targets)
        self.assertNotIn(inactive_target, active_targets)

    def test_platform_filtering(self):
        """Test filtering by platform."""
        target1 = TargetFactory(
            platform=BugBountyPlatform.HACKERONE,
            researcher_username="test_user"
        )
        target2 = TargetFactory(
            platform=BugBountyPlatform.BUGCROWD,
            researcher_username="test_user"
        )

        BugBountyPlatform.HACKERONE_targets = Target.objects.filter(platform=BugBountyPlatform.HACKERONE)
        self.assertIn(target1, BugBountyPlatform.HACKERONE_targets)
        self.assertNotIn(target2, BugBountyPlatform.HACKERONE_targets)

    def test_user_filtering(self):
        """Test filtering by user."""
        user2 = UserFactory()

        user1_target = TargetFactory(
            platform=BugBountyPlatform.HACKERONE,
            researcher_username="test_user"
        )
        user2_target = TargetFactory(
            platform=BugBountyPlatform.HACKERONE,
            created_by=user2
        )

        user1_targets = Target.objects.filter(researcher_username="test_user")
        self.assertIn(user1_target, user1_targets)
        self.assertNotIn(user2_target, user1_targets)

    def test_complex_queries(self):
        """Test complex queries with multiple filters."""
        # Create test data
        active_BugBountyPlatform.HACKERONE_target = TargetFactory(
            platform=BugBountyPlatform.HACKERONE,
            researcher_username="test_user",
            is_active=True
        )
        inactive_BugBountyPlatform.HACKERONE_target = TargetFactory(
            platform=BugBountyPlatform.HACKERONE,
            researcher_username="test_user",
            is_active=False
        )
        active_BugBountyPlatform.BUGCROWD_target = TargetFactory(
            platform=BugBountyPlatform.BUGCROWD,
            researcher_username="test_user",
            is_active=True
        )

        # Complex query: active targets on BugBountyPlatform.HACKERONE by user
        complex_targets = Target.objects.filter(
            platform=BugBountyPlatform.HACKERONE,
            researcher_username="test_user",
            is_active=True
        )

        self.assertIn(active_BugBountyPlatform.HACKERONE_target, complex_targets)
        self.assertNotIn(inactive_BugBountyPlatform.HACKERONE_target, complex_targets)
        self.assertNotIn(active_BugBountyPlatform.BUGCROWD_target, complex_targets)

    def test_url_pattern_filtering(self):
        """Test filtering by URL patterns."""
        https_target = TargetFactory(
            platform=BugBountyPlatform.HACKERONE,
            researcher_username="test_user",
            main_url="https://example.com"
        )
        http_target = TargetFactory(
            platform=BugBountyPlatform.HACKERONE,
            researcher_username="test_user",
            main_url="http://example.com"
        )

        https_targets = Target.objects.filter(target_url__startswith="https://")
        self.assertIn(https_target, https_targets)
        self.assertNotIn(http_target, https_targets)

    def test_date_range_filtering(self):
        """Test filtering by date ranges."""
        old_target = TargetFactory(
            platform=BugBountyPlatform.HACKERONE,
            researcher_username="test_user"
        )
        old_target.created_at = datetime.now() - timedelta(days=30)
        old_target.save()

        recent_target = TargetFactory(
            platform=BugBountyPlatform.HACKERONE,
            researcher_username="test_user"
        )

        # Filter recent targets (last 7 days)
        recent_date = datetime.now() - timedelta(days=7)
        recent_targets = Target.objects.filter(created_at__gte=recent_date)

        self.assertIn(recent_target, recent_targets)
        self.assertNotIn(old_target, recent_targets)

    def test_search_functionality(self):
        """Test search functionality."""
        target1 = TargetFactory(
            platform=BugBountyPlatform.HACKERONE,
            researcher_username="test_user",
            target_name="Example Corporation"
        )
        target2 = TargetFactory(
            platform=BugBountyPlatform.HACKERONE,
            researcher_username="test_user",
            target_name="Test Company"
        )

        # Search by name
        search_targets = Target.objects.filter(
            target_name__icontains="example"
        )
        self.assertIn(target1, search_targets)
        self.assertNotIn(target2, search_targets)

    def test_performance_queries(self):
        """Test performance-optimized queries."""
        # Create multiple targets
        targets = []
        for i in range(10):
            target = TargetFactory(
                platform=BugBountyPlatform.HACKERONE,
                researcher_username="test_user"
            )
            targets.append(target)

        # Test select_related for foreign keys
        targets_with_related = Target.objects.select_related(
            'platform', 'created_by'
        ).filter(platform=BugBountyPlatform.HACKERONE)

        # These should not trigger additional queries
        for target in targets_with_related:
            self.assertEqual(target.platform.name, "Platform1")
            self.assertIsNotNone(target.created_by.username)