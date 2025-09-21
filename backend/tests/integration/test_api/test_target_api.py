"""
Integration tests for Target API endpoints
"""

import pytest
import json
from datetime import timedelta
from django.test import TestCase
from django.utils import timezone
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.targets.models import Target, BugBountyPlatform
from tests.factories import (
    TargetFactory, UserFactory, AdminUserFactory, ScanSessionFactory,
    VulnerabilityFactory
)
from tests.test_utils import APITestMixin, DatabaseTestMixin


@pytest.mark.integration
class TargetAPITest(TestCase, APITestMixin, DatabaseTestMixin):
    """Test Target API endpoints"""

    def setUp(self):
        self.client = APIClient()
        self.user = UserFactory.create()
        self.admin_user = AdminUserFactory.create()

        # Authenticate user
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        self.target_data = {
            'target_name': 'Test Corp API',
            'platform': BugBountyPlatform.HACKERONE,
            'researcher_username': 'test_researcher',
            'main_url': 'https://testcorp.com',
            'wildcard_url': '*.testcorp.com',
            'in_scope_urls': ['https://testcorp.com', 'https://api.testcorp.com'],
            'out_of_scope_urls': ['https://blog.testcorp.com'],
            'requests_per_second': 5.0,
            'concurrent_requests': 10,
            'program_notes': 'Test program for API testing'
        }

    def test_create_target_success(self):
        """Test successful target creation"""
        url = reverse('target-list')
        response = self.client.post(url, self.target_data, format='json')

        self.assert_api_response(response, status.HTTP_201_CREATED, [
            'id', 'target_name', 'platform', 'main_url', 'created_at'
        ])

        # Verify target was created in database
        self.assert_model_count(Target, 1)

        target = Target.objects.first()
        self.assertEqual(target.target_name, 'Test Corp API')
        self.assertEqual(target.platform, BugBountyPlatform.HACKERONE)
        self.assertEqual(target.main_url, 'https://testcorp.com')

    def test_create_target_duplicate_name(self):
        """Test creating target with duplicate name fails"""
        # Create existing target
        TargetFactory.create(target_name='Test Corp API')

        url = reverse('target-list')
        response = self.client.post(url, self.target_data, format='json')

        self.assert_api_error(response, status.HTTP_400_BAD_REQUEST, 'already exists')

    def test_create_target_invalid_data(self):
        """Test creating target with invalid data"""
        invalid_data = self.target_data.copy()
        del invalid_data['target_name']  # Required field

        url = reverse('target-list')
        response = self.client.post(url, invalid_data, format='json')

        self.assert_api_error(response, status.HTTP_400_BAD_REQUEST)

    def test_create_target_unauthenticated(self):
        """Test creating target without authentication fails"""
        self.client.credentials()  # Remove authentication

        url = reverse('target-list')
        response = self.client.post(url, self.target_data, format='json')

        self.assert_api_error(response, status.HTTP_401_UNAUTHORIZED)

    def test_list_targets(self):
        """Test listing targets"""
        # Create test targets
        target1 = TargetFactory.create(target_name='Target 1')
        target2 = TargetFactory.create(target_name='Target 2')
        target3 = TargetFactory.create(target_name='Target 3', is_active=False)

        url = reverse('target-list')
        response = self.client.get(url)

        self.assert_api_response(response, status.HTTP_200_OK, ['results'])

        data = response.json()
        self.assertEqual(len(data['results']), 3)

        # Check ordering (should be by -created_at)
        target_names = [item['target_name'] for item in data['results']]
        self.assertEqual(target_names[0], 'Target 3')  # Most recent
        self.assertEqual(target_names[1], 'Target 2')
        self.assertEqual(target_names[2], 'Target 1')

    def test_list_targets_filtering(self):
        """Test listing targets with filters"""
        # Create targets with different attributes
        active_target = TargetFactory.create(is_active=True, platform=BugBountyPlatform.HACKERONE)
        inactive_target = TargetFactory.create(is_active=False, platform=BugBountyPlatform.BUGCROWD)

        # Test active_only filter
        url = reverse('target-list')
        response = self.client.get(url, {'active_only': 'true'})

        self.assert_api_response(response, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(len(data['results']), 1)
        self.assertEqual(data['results'][0]['id'], str(active_target.id))

        # Test platform filter
        response = self.client.get(url, {'platform': BugBountyPlatform.BUGCROWD})

        data = response.json()
        self.assertEqual(len(data['results']), 1)
        self.assertEqual(data['results'][0]['id'], str(inactive_target.id))

    def test_list_targets_search(self):
        """Test listing targets with search"""
        target1 = TargetFactory.create(target_name='Example Corp')
        target2 = TargetFactory.create(target_name='Test Company')
        target3 = TargetFactory.create(target_name='Another Corp')

        url = reverse('target-list')

        # Search by target name
        response = self.client.get(url, {'search': 'Corp'})
        data = response.json()
        self.assertEqual(len(data['results']), 2)

        # Search by specific name
        response = self.client.get(url, {'search': 'Example'})
        data = response.json()
        self.assertEqual(len(data['results']), 1)
        self.assertEqual(data['results'][0]['target_name'], 'Example Corp')

    def test_retrieve_target(self):
        """Test retrieving a specific target"""
        target = TargetFactory.create()

        url = reverse('target-detail', kwargs={'pk': target.id})
        response = self.client.get(url)

        self.assert_api_response(response, status.HTTP_200_OK, [
            'id', 'target_name', 'platform', 'main_url', 'in_scope_urls',
            'out_of_scope_urls', 'created_at', 'updated_at'
        ])

        data = response.json()
        self.assertEqual(data['id'], str(target.id))
        self.assertEqual(data['target_name'], target.target_name)

    def test_retrieve_target_not_found(self):
        """Test retrieving non-existent target"""
        url = reverse('target-detail', kwargs={'pk': '00000000-0000-0000-0000-000000000000'})
        response = self.client.get(url)

        self.assert_api_error(response, status.HTTP_404_NOT_FOUND)

    def test_update_target(self):
        """Test updating a target"""
        target = TargetFactory.create()

        update_data = {
            'target_name': 'Updated Target Name',
            'program_notes': 'Updated notes for the target'
        }

        url = reverse('target-detail', kwargs={'pk': target.id})
        response = self.client.patch(url, update_data, format='json')

        self.assert_api_response(response, status.HTTP_200_OK)

        # Verify target was updated
        target.refresh_from_db()
        self.assertEqual(target.target_name, 'Updated Target Name')
        self.assertEqual(target.program_notes, 'Updated notes for the target')

    def test_delete_target(self):
        """Test deleting a target"""
        target = TargetFactory.create()

        url = reverse('target-detail', kwargs={'pk': target.id})
        response = self.client.delete(url)

        self.assert_api_response(response, status.HTTP_204_NO_CONTENT)

        # Verify target was deleted
        self.assert_model_count(Target, 0)

    def test_target_scope_action_get(self):
        """Test getting target scope information"""
        target = TargetFactory.create(
            in_scope_urls=['https://example.com', 'https://api.example.com'],
            out_of_scope_urls=['https://blog.example.com'],
            in_scope_assets=['192.168.1.0/24'],
            out_of_scope_assets=['192.168.1.100']
        )

        url = reverse('target-scope', kwargs={'pk': target.id})
        response = self.client.get(url)

        self.assert_api_response(response, status.HTTP_200_OK, [
            'in_scope_urls', 'out_of_scope_urls', 'in_scope_assets', 'out_of_scope_assets'
        ])

        data = response.json()
        self.assertEqual(len(data['in_scope_urls']), 2)
        self.assertEqual(len(data['out_of_scope_urls']), 1)
        self.assertIn('https://example.com', data['in_scope_urls'])

    def test_target_scope_action_update(self):
        """Test updating target scope"""
        target = TargetFactory.create()

        scope_data = {
            'in_scope_urls': ['https://newdomain.com', 'https://api.newdomain.com'],
            'out_of_scope_urls': ['https://blog.newdomain.com'],
            'in_scope_assets': ['10.0.0.0/16'],
            'out_of_scope_assets': ['10.0.0.1']
        }

        url = reverse('target-scope', kwargs={'pk': target.id})
        response = self.client.patch(url, scope_data, format='json')

        self.assert_api_response(response, status.HTTP_200_OK, ['message', 'scope'])

        # Verify scope was updated
        target.refresh_from_db()
        self.assertEqual(target.in_scope_urls, scope_data['in_scope_urls'])
        self.assertEqual(target.out_of_scope_urls, scope_data['out_of_scope_urls'])

    def test_target_config_action_get(self):
        """Test getting target configuration"""
        target = TargetFactory.create(
            requests_per_second=10.0,
            concurrent_requests=20,
            required_headers={'User-Agent': 'TestBot'},
            authentication_headers={'Authorization': 'Bearer token123'}
        )

        url = reverse('target-config', kwargs={'pk': target.id})
        response = self.client.get(url)

        self.assert_api_response(response, status.HTTP_200_OK, [
            'requests_per_second', 'concurrent_requests', 'required_headers'
        ])

        data = response.json()
        self.assertEqual(data['requests_per_second'], 10.0)
        self.assertEqual(data['concurrent_requests'], 20)

    def test_target_config_action_update(self):
        """Test updating target configuration"""
        target = TargetFactory.create()

        config_data = {
            'requests_per_second': 2.5,
            'concurrent_requests': 5,
            'request_delay_ms': 500,
            'required_headers': {
                'User-Agent': 'UpdatedBot/1.0',
                'Accept': 'application/json'
            }
        }

        url = reverse('target-config', kwargs={'pk': target.id})
        response = self.client.patch(url, config_data, format='json')

        self.assert_api_response(response, status.HTTP_200_OK, ['message', 'config'])

        # Verify config was updated
        target.refresh_from_db()
        self.assertEqual(target.requests_per_second, 2.5)
        self.assertEqual(target.concurrent_requests, 5)
        self.assertEqual(target.required_headers['User-Agent'], 'UpdatedBot/1.0')

    def test_validate_scope_action(self):
        """Test scope validation action"""
        target = TargetFactory.create(
            main_url='https://example.com',
            wildcard_url='*.example.com',
            in_scope_urls=['https://app.example.com'],
            out_of_scope_urls=['https://blog.example.com']
        )

        validation_data = {
            'urls': [
                'https://example.com',  # Should be in scope (main URL)
                'https://api.example.com',  # Should be in scope (wildcard)
                'https://app.example.com',  # Should be in scope (explicitly listed)
                'https://blog.example.com',  # Should be out of scope (explicitly listed)
                'https://external.com'  # Should be out of scope (different domain)
            ]
        }

        url = reverse('target-validate-scope', kwargs={'pk': target.id})
        response = self.client.post(url, validation_data, format='json')

        self.assert_api_response(response, status.HTTP_200_OK, [
            'target', 'validation_results', 'total_checked', 'in_scope_count'
        ])

        data = response.json()
        self.assertEqual(data['total_checked'], 5)
        self.assertEqual(data['in_scope_count'], 3)
        self.assertEqual(data['out_of_scope_count'], 2)

        # Check specific results
        results_by_url = {r['url']: r for r in data['validation_results']}
        self.assertTrue(results_by_url['https://example.com']['in_scope'])
        self.assertTrue(results_by_url['https://api.example.com']['in_scope'])
        self.assertFalse(results_by_url['https://blog.example.com']['in_scope'])
        self.assertFalse(results_by_url['https://external.com']['in_scope'])

    def test_validate_scope_action_no_urls(self):
        """Test scope validation with no URLs provided"""
        target = TargetFactory.create()

        url = reverse('target-validate-scope', kwargs={'pk': target.id})
        response = self.client.post(url, {}, format='json')

        self.assert_api_error(response, status.HTTP_400_BAD_REQUEST, 'No URLs provided')

    def test_target_statistics_action(self):
        """Test target statistics action"""
        target = TargetFactory.create()

        # Create related data
        scan_session = ScanSessionFactory.create(target=target, status='completed')
        ScanSessionFactory.create(target=target, status='running')
        ScanSessionFactory.create(target=target, status='failed')

        # Create vulnerabilities
        VulnerabilityFactory.create(scan_session=scan_session, severity='critical')
        VulnerabilityFactory.create(scan_session=scan_session, severity='high')

        url = reverse('target-statistics', kwargs={'pk': target.id})
        response = self.client.get(url)

        self.assert_api_response(response, status.HTTP_200_OK, [
            'target_info', 'scope_statistics', 'scan_statistics', 'recent_activity'
        ])

        data = response.json()

        # Check target info
        self.assertEqual(data['target_info']['name'], target.target_name)
        self.assertEqual(data['target_info']['platform'], target.get_platform_display())

        # Check scan statistics
        self.assertEqual(data['scan_statistics']['total_sessions'], 3)
        self.assertEqual(data['scan_statistics']['completed_sessions'], 1)
        self.assertEqual(data['scan_statistics']['running_sessions'], 1)
        self.assertEqual(data['scan_statistics']['failed_sessions'], 1)

        # Check vulnerability statistics
        self.assertEqual(data['recent_activity']['total_vulnerabilities'], 2)
        self.assertEqual(data['recent_activity']['critical_vulnerabilities'], 1)

    def test_targets_summary_action(self):
        """Test targets summary action"""
        # Create targets with different platforms
        TargetFactory.create(platform=BugBountyPlatform.HACKERONE, is_active=True)
        TargetFactory.create(platform=BugBountyPlatform.HACKERONE, is_active=True)
        TargetFactory.create(platform=BugBountyPlatform.BUGCROWD, is_active=False)

        url = reverse('target-summary')
        response = self.client.get(url)

        self.assert_api_response(response, status.HTTP_200_OK, [
            'total_targets', 'active_targets', 'by_platform', 'recent_targets'
        ])

        data = response.json()
        self.assertEqual(data['total_targets'], 3)
        self.assertEqual(data['active_targets'], 2)
        self.assertEqual(data['by_platform']['HackerOne'], 2)
        self.assertEqual(data['by_platform']['Bugcrowd'], 1)

    def test_toggle_active_action(self):
        """Test toggle active status action"""
        target = TargetFactory.create(is_active=True)

        url = reverse('target-toggle-active', kwargs={'pk': target.id})
        response = self.client.post(url)

        self.assert_api_response(response, status.HTTP_200_OK, ['message', 'is_active'])

        data = response.json()
        self.assertFalse(data['is_active'])
        self.assertIn('deactivated', data['message'])

        # Verify in database
        target.refresh_from_db()
        self.assertFalse(target.is_active)

        # Toggle again
        response = self.client.post(url)
        data = response.json()
        self.assertTrue(data['is_active'])
        self.assertIn('activated', data['message'])

    def test_target_ordering(self):
        """Test target list ordering"""
        # Create targets with known creation times
        target1 = TargetFactory.create(target_name='First Target')
        target2 = TargetFactory.create(target_name='Second Target')

        url = reverse('target-list')

        # Test default ordering (-created_at)
        response = self.client.get(url)
        data = response.json()
        self.assertEqual(data['results'][0]['target_name'], 'Second Target')
        self.assertEqual(data['results'][1]['target_name'], 'First Target')

        # Test explicit ordering by name
        response = self.client.get(url, {'ordering': 'target_name'})
        data = response.json()
        self.assertEqual(data['results'][0]['target_name'], 'First Target')
        self.assertEqual(data['results'][1]['target_name'], 'Second Target')

    def test_target_pagination(self):
        """Test target list pagination"""
        # Create many targets
        TargetFactory.create_batch(25)

        url = reverse('target-list')
        response = self.client.get(url)

        self.assert_api_response(response, status.HTTP_200_OK, [
            'count', 'next', 'previous', 'results'
        ])

        data = response.json()
        self.assertEqual(data['count'], 25)
        self.assertEqual(len(data['results']), 20)  # Default page size
        self.assertIsNotNone(data['next'])
        self.assertIsNone(data['previous'])

        # Test second page
        response = self.client.get(data['next'])
        data = response.json()
        self.assertEqual(len(data['results']), 5)  # Remaining items
        self.assertIsNone(data['next'])
        self.assertIsNotNone(data['previous'])

    def test_target_permissions(self):
        """Test target access permissions"""
        target = TargetFactory.create()

        # Test authenticated access works
        url = reverse('target-detail', kwargs={'pk': target.id})
        response = self.client.get(url)
        self.assert_api_response(response, status.HTTP_200_OK)

        # Test unauthenticated access fails
        self.client.credentials()  # Remove authentication
        response = self.client.get(url)
        self.assert_api_error(response, status.HTTP_401_UNAUTHORIZED)


@pytest.mark.integration
class TargetAPISerializerTest(TestCase):
    """Test Target API serializers"""

    def setUp(self):
        self.client = APIClient()
        self.user = UserFactory.create()

        # Authenticate user
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    def test_target_serializer_validation(self):
        """Test target serializer field validation"""
        # Test invalid URL
        invalid_data = {
            'target_name': 'Test Target',
            'platform': BugBountyPlatform.HACKERONE,
            'researcher_username': 'test_user',
            'main_url': 'not-a-valid-url'
        }

        url = reverse('target-list')
        response = self.client.post(url, invalid_data, format='json')
        self.assert_api_error(response, status.HTTP_400_BAD_REQUEST)

        # Test invalid platform
        invalid_data['main_url'] = 'https://example.com'
        invalid_data['platform'] = 'invalid_platform'

        response = self.client.post(url, invalid_data, format='json')
        self.assert_api_error(response, status.HTTP_400_BAD_REQUEST)

    def test_target_serializer_required_fields(self):
        """Test required field validation"""
        required_fields = ['target_name', 'platform', 'researcher_username', 'main_url']

        for field in required_fields:
            incomplete_data = {
                'target_name': 'Test Target',
                'platform': BugBountyPlatform.HACKERONE,
                'researcher_username': 'test_user',
                'main_url': 'https://example.com'
            }
            del incomplete_data[field]

            url = reverse('target-list')
            response = self.client.post(url, incomplete_data, format='json')
            self.assert_api_error(response, status.HTTP_400_BAD_REQUEST)

    def test_target_serializer_optional_fields(self):
        """Test optional field handling"""
        minimal_data = {
            'target_name': 'Minimal Target',
            'platform': BugBountyPlatform.HACKERONE,
            'researcher_username': 'test_user',
            'main_url': 'https://example.com'
        }

        url = reverse('target-list')
        response = self.client.post(url, minimal_data, format='json')
        self.assert_api_response(response, status.HTTP_201_CREATED)

        # Verify defaults were applied
        data = response.json()
        self.assertEqual(data['requests_per_second'], 5.0)
        self.assertEqual(data['concurrent_requests'], 10)
        self.assertEqual(data['in_scope_urls'], [])

    def test_target_serializer_array_fields(self):
        """Test array field serialization"""
        target_data = {
            'target_name': 'Array Test Target',
            'platform': BugBountyPlatform.HACKERONE,
            'researcher_username': 'test_user',
            'main_url': 'https://example.com',
            'in_scope_urls': ['https://example.com', 'https://api.example.com'],
            'out_of_scope_urls': ['https://blog.example.com'],
            'user_agents': ['Bot/1.0', 'Bot/2.0']
        }

        url = reverse('target-list')
        response = self.client.post(url, target_data, format='json')
        self.assert_api_response(response, status.HTTP_201_CREATED)

        data = response.json()
        self.assertEqual(data['in_scope_urls'], target_data['in_scope_urls'])
        self.assertEqual(data['out_of_scope_urls'], target_data['out_of_scope_urls'])
        self.assertEqual(data['user_agents'], target_data['user_agents'])

    def test_target_serializer_json_fields(self):
        """Test JSON field serialization"""
        target_data = {
            'target_name': 'JSON Test Target',
            'platform': BugBountyPlatform.HACKERONE,
            'researcher_username': 'test_user',
            'main_url': 'https://example.com',
            'required_headers': {
                'User-Agent': 'TestBot/1.0',
                'Accept': 'application/json'
            },
            'authentication_headers': {
                'Authorization': 'Bearer token123'
            }
        }

        url = reverse('target-list')
        response = self.client.post(url, target_data, format='json')
        self.assert_api_response(response, status.HTTP_201_CREATED)

        data = response.json()
        self.assertEqual(data['required_headers'], target_data['required_headers'])
        self.assertEqual(data['authentication_headers'], target_data['authentication_headers'])


@pytest.mark.integration
class TargetAPIErrorHandlingTest(TestCase):
    """Test Target API error handling"""

    def setUp(self):
        self.client = APIClient()
        self.user = UserFactory.create()

        # Authenticate user
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    def test_target_not_found_errors(self):
        """Test 404 errors for non-existent targets"""
        non_existent_id = '00000000-0000-0000-0000-000000000000'

        # Test retrieve
        url = reverse('target-detail', kwargs={'pk': non_existent_id})
        response = self.client.get(url)
        self.assert_api_error(response, status.HTTP_404_NOT_FOUND)

        # Test update
        response = self.client.patch(url, {'target_name': 'Updated'}, format='json')
        self.assert_api_error(response, status.HTTP_404_NOT_FOUND)

        # Test delete
        response = self.client.delete(url)
        self.assert_api_error(response, status.HTTP_404_NOT_FOUND)

        # Test custom actions
        scope_url = reverse('target-scope', kwargs={'pk': non_existent_id})
        response = self.client.get(scope_url)
        self.assert_api_error(response, status.HTTP_404_NOT_FOUND)

    def test_invalid_request_data(self):
        """Test handling of invalid request data"""
        url = reverse('target-list')

        # Test malformed JSON
        response = self.client.post(
            url,
            '{"invalid": json}',
            content_type='application/json'
        )
        self.assert_api_error(response, status.HTTP_400_BAD_REQUEST)

        # Test invalid field types
        invalid_data = {
            'target_name': 'Test Target',
            'platform': BugBountyPlatform.HACKERONE,
            'researcher_username': 'test_user',
            'main_url': 'https://example.com',
            'requests_per_second': 'not_a_number'  # Should be float
        }

        response = self.client.post(url, invalid_data, format='json')
        self.assert_api_error(response, status.HTTP_400_BAD_REQUEST)

    def test_method_not_allowed(self):
        """Test method not allowed errors"""
        target = TargetFactory.create()

        # Test unsupported methods on detail endpoint
        url = reverse('target-detail', kwargs={'pk': target.id})

        # OPTIONS should be allowed
        response = self.client.options(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test unsupported method on custom action
        scope_url = reverse('target-scope', kwargs={'pk': target.id})
        response = self.client.delete(scope_url)  # DELETE not supported
        self.assert_api_error(response, status.HTTP_405_METHOD_NOT_ALLOWED)