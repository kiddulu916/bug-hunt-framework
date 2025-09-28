"""
Integration tests for Authentication API endpoints
"""

import pytest
import json
from unittest.mock import Mock, patch
from django.test import TransactionTestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from tests.factories import UserFactory

User = get_user_model()


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
class TestAuthenticationAPIEndpoints(TransactionTestCase):
    """Test authentication API endpoints"""

    def setUp(self):
        self.client = APIClient()
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'securepassword123',
            'first_name': 'Test',
            'last_name': 'User'
        }

    def test_user_registration(self):
        """Test user registration endpoint"""
        response = self.client.post('/api/auth/register/', self.user_data, format='json')
        self.assertEqual(response.status_code, 201)

        # Verify user was created
        user = User.objects.get(username='testuser')
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.first_name, 'Test')
        self.assertFalse(user.is_staff)  # Should not be staff by default

        # Verify response contains expected fields
        self.assertIn('user', response.data)
        self.assertIn('tokens', response.data)
        self.assertIn('access', response.data['tokens'])
        self.assertIn('refresh', response.data['tokens'])

    def test_user_login(self):
        """Test user login endpoint"""
        # Create user first
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='securepassword123'
        )

        login_data = {
            'username': 'testuser',
            'password': 'securepassword123'
        }

        response = self.client.post('/api/auth/login/', login_data, format='json')
        self.assertEqual(response.status_code, 200)

        # Verify response contains tokens
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['username'], 'testuser')

    def test_user_login_with_email(self):
        """Test user login with email instead of username"""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='securepassword123'
        )

        login_data = {
            'email': 'test@example.com',
            'password': 'securepassword123'
        }

        response = self.client.post('/api/auth/login/', login_data, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['user']['email'], 'test@example.com')

    def test_invalid_login_credentials(self):
        """Test login with invalid credentials"""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='securepassword123'
        )

        # Wrong password
        login_data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }

        response = self.client.post('/api/auth/login/', login_data, format='json')
        self.assertEqual(response.status_code, 401)
        self.assertIn('error', response.data)

        # Non-existent user
        login_data = {
            'username': 'nonexistent',
            'password': 'anypassword'
        }

        response = self.client.post('/api/auth/login/', login_data, format='json')
        self.assertEqual(response.status_code, 401)

    def test_token_refresh(self):
        """Test JWT token refresh endpoint"""
        user = UserFactory()
        refresh = RefreshToken.for_user(user)

        refresh_data = {
            'refresh': str(refresh)
        }

        response = self.client.post('/api/auth/token/refresh/', refresh_data, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertIn('access', response.data)

    def test_invalid_token_refresh(self):
        """Test token refresh with invalid refresh token"""
        refresh_data = {
            'refresh': 'invalid_refresh_token'
        }

        response = self.client.post('/api/auth/token/refresh/', refresh_data, format='json')
        self.assertEqual(response.status_code, 401)

    def test_token_verify(self):
        """Test JWT token verification endpoint"""
        user = UserFactory()
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        verify_data = {
            'token': access_token
        }

        response = self.client.post('/api/auth/token/verify/', verify_data, format='json')
        self.assertEqual(response.status_code, 200)

    def test_invalid_token_verify(self):
        """Test token verification with invalid token"""
        verify_data = {
            'token': 'invalid_access_token'
        }

        response = self.client.post('/api/auth/token/verify/', verify_data, format='json')
        self.assertEqual(response.status_code, 401)

    def test_user_logout(self):
        """Test user logout endpoint"""
        user = UserFactory()
        refresh = RefreshToken.for_user(user)

        # Authenticate client
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        logout_data = {
            'refresh': str(refresh)
        }

        response = self.client.post('/api/auth/logout/', logout_data, format='json')
        self.assertEqual(response.status_code, 200)

        # Verify refresh token is blacklisted
        response = self.client.post('/api/auth/token/refresh/', logout_data, format='json')
        self.assertEqual(response.status_code, 401)

    def test_get_current_user(self):
        """Test getting current authenticated user"""
        user = UserFactory()
        refresh = RefreshToken.for_user(user)

        # Authenticate client
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        response = self.client.get('/api/auth/user/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['id'], user.id)
        self.assertEqual(response.data['username'], user.username)
        self.assertEqual(response.data['email'], user.email)

    def test_update_current_user(self):
        """Test updating current authenticated user"""
        user = UserFactory()
        refresh = RefreshToken.for_user(user)

        # Authenticate client
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        update_data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'email': 'updated@example.com'
        }

        response = self.client.patch('/api/auth/user/', update_data, format='json')
        self.assertEqual(response.status_code, 200)

        # Verify updates
        user.refresh_from_db()
        self.assertEqual(user.first_name, 'Updated')
        self.assertEqual(user.last_name, 'Name')
        self.assertEqual(user.email, 'updated@example.com')

    def test_change_password(self):
        """Test changing user password"""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='oldpassword123'
        )
        refresh = RefreshToken.for_user(user)

        # Authenticate client
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        password_data = {
            'old_password': 'oldpassword123',
            'new_password': 'newpassword123',
            'confirm_password': 'newpassword123'
        }

        response = self.client.post('/api/auth/change-password/', password_data, format='json')
        self.assertEqual(response.status_code, 200)

        # Verify password was changed
        user.refresh_from_db()
        self.assertTrue(user.check_password('newpassword123'))
        self.assertFalse(user.check_password('oldpassword123'))

    def test_change_password_invalid_old_password(self):
        """Test changing password with invalid old password"""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='oldpassword123'
        )
        refresh = RefreshToken.for_user(user)

        # Authenticate client
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        password_data = {
            'old_password': 'wrongoldpassword',
            'new_password': 'newpassword123',
            'confirm_password': 'newpassword123'
        }

        response = self.client.post('/api/auth/change-password/', password_data, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('old_password', response.data)

    def test_change_password_mismatch(self):
        """Test changing password with mismatched confirmation"""
        user = UserFactory()
        refresh = RefreshToken.for_user(user)

        # Authenticate client
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        password_data = {
            'old_password': 'testpass123',  # Default factory password
            'new_password': 'newpassword123',
            'confirm_password': 'differentpassword123'
        }

        response = self.client.post('/api/auth/change-password/', password_data, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('passwords do not match', str(response.data).lower())

    def test_password_reset_request(self):
        """Test requesting password reset"""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='oldpassword123'
        )

        reset_data = {
            'email': 'test@example.com'
        }

        with patch('django.core.mail.send_mail') as mock_send_mail:
            response = self.client.post('/api/auth/password-reset/', reset_data, format='json')
            self.assertEqual(response.status_code, 200)
            self.assertIn('message', response.data)

            # Verify email was sent
            mock_send_mail.assert_called_once()

    def test_password_reset_invalid_email(self):
        """Test password reset with non-existent email"""
        reset_data = {
            'email': 'nonexistent@example.com'
        }

        response = self.client.post('/api/auth/password-reset/', reset_data, format='json')
        # Should still return 200 for security (don't reveal if email exists)
        self.assertEqual(response.status_code, 200)

    @patch('django.contrib.auth.tokens.default_token_generator.check_token')
    def test_password_reset_confirm(self, mock_check_token):
        """Test confirming password reset with token"""
        mock_check_token.return_value = True

        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='oldpassword123'
        )

        # Simulate password reset confirmation
        reset_confirm_data = {
            'token': 'reset-token-123',
            'uid': user.pk,
            'new_password': 'newresetpassword123',
            'confirm_password': 'newresetpassword123'
        }

        response = self.client.post('/api/auth/password-reset-confirm/', reset_confirm_data, format='json')
        self.assertEqual(response.status_code, 200)

    def test_registration_validation(self):
        """Test user registration validation"""
        # Test missing required fields
        incomplete_data = {
            'username': 'testuser'
            # Missing email and password
        }

        response = self.client.post('/api/auth/register/', incomplete_data, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('email', response.data)
        self.assertIn('password', response.data)

        # Test duplicate username
        User.objects.create_user(username='testuser', email='test@example.com', password='pass123')

        duplicate_data = {
            'username': 'testuser',
            'email': 'different@example.com',
            'password': 'password123'
        }

        response = self.client.post('/api/auth/register/', duplicate_data, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('username', response.data)

    def test_weak_password_validation(self):
        """Test password strength validation during registration"""
        weak_passwords = [
            'password',
            '123456',
            'qwerty',
            'abc123'
        ]

        for weak_password in weak_passwords:
            registration_data = {
                'username': f'user_{weak_password}',
                'email': f'{weak_password}@example.com',
                'password': weak_password
            }

            response = self.client.post('/api/auth/register/', registration_data, format='json')
            self.assertEqual(response.status_code, 400)
            self.assertIn('password', response.data)

    def test_email_verification_required(self):
        """Test email verification requirement"""
        response = self.client.post('/api/auth/register/', self.user_data, format='json')
        self.assertEqual(response.status_code, 201)

        # User should be created but not active
        user = User.objects.get(username='testuser')
        self.assertFalse(user.is_active)

        # Login should fail for inactive user
        login_data = {
            'username': 'testuser',
            'password': 'securepassword123'
        }

        response = self.client.post('/api/auth/login/', login_data, format='json')
        self.assertEqual(response.status_code, 401)
        self.assertIn('account not activated', str(response.data).lower())

    @patch('django.contrib.auth.tokens.default_token_generator.check_token')
    def test_email_verification_confirm(self, mock_check_token):
        """Test email verification confirmation"""
        mock_check_token.return_value = True

        # Create inactive user
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='password123',
            is_active=False
        )

        verification_data = {
            'token': 'verification-token-123',
            'uid': user.pk
        }

        response = self.client.post('/api/auth/verify-email/', verification_data, format='json')
        self.assertEqual(response.status_code, 200)

        # User should now be active
        user.refresh_from_db()
        self.assertTrue(user.is_active)

    def test_user_profile_endpoints(self):
        """Test user profile related endpoints"""
        user = UserFactory()
        refresh = RefreshToken.for_user(user)

        # Authenticate client
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Test getting user profile
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('user_preferences', response.data)
        self.assertIn('api_usage_stats', response.data)

        # Test updating user preferences
        preferences_data = {
            'email_notifications': True,
            'scan_completion_alerts': False,
            'timezone': 'UTC',
            'language': 'en'
        }

        response = self.client.patch('/api/auth/profile/', preferences_data, format='json')
        self.assertEqual(response.status_code, 200)

    def test_api_key_management(self):
        """Test API key generation and management"""
        user = UserFactory()
        refresh = RefreshToken.for_user(user)

        # Authenticate client
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Generate new API key
        response = self.client.post('/api/auth/api-keys/')
        self.assertEqual(response.status_code, 201)
        self.assertIn('api_key', response.data)
        self.assertIn('key_id', response.data)

        # List API keys
        response = self.client.get('/api/auth/api-keys/')
        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.data['keys']), 0)

        # Revoke API key
        key_id = response.data['keys'][0]['id']
        response = self.client.delete(f'/api/auth/api-keys/{key_id}/')
        self.assertEqual(response.status_code, 204)

    def test_session_management(self):
        """Test active session management"""
        user = UserFactory()
        refresh = RefreshToken.for_user(user)

        # Authenticate client
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Get active sessions
        response = self.client.get('/api/auth/sessions/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('active_sessions', response.data)

        # Revoke all other sessions
        response = self.client.post('/api/auth/sessions/revoke-all/')
        self.assertEqual(response.status_code, 200)

    def test_two_factor_authentication(self):
        """Test 2FA setup and verification"""
        user = UserFactory()
        refresh = RefreshToken.for_user(user)

        # Authenticate client
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Enable 2FA
        response = self.client.post('/api/auth/2fa/enable/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('qr_code', response.data)
        self.assertIn('backup_codes', response.data)

        # Verify 2FA setup
        verification_data = {
            'token': '123456'  # TOTP token
        }

        with patch('pyotp.TOTP.verify', return_value=True):
            response = self.client.post('/api/auth/2fa/verify/', verification_data, format='json')
            self.assertEqual(response.status_code, 200)

        # Disable 2FA
        response = self.client.post('/api/auth/2fa/disable/')
        self.assertEqual(response.status_code, 200)

    def test_unauthorized_endpoints(self):
        """Test that protected endpoints require authentication"""
        protected_endpoints = [
            '/api/auth/user/',
            '/api/auth/profile/',
            '/api/auth/change-password/',
            '/api/auth/logout/',
            '/api/auth/api-keys/',
            '/api/auth/sessions/'
        ]

        for endpoint in protected_endpoints:
            response = self.client.get(endpoint)
            self.assertEqual(response.status_code, 401)

    def test_rate_limiting_login_attempts(self):
        """Test rate limiting on login attempts"""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='password123'
        )

        login_data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }

        # Make multiple failed login attempts
        for i in range(10):
            response = self.client.post('/api/auth/login/', login_data, format='json')

        # Should eventually be rate limited
        final_response = self.client.post('/api/auth/login/', login_data, format='json')
        self.assertIn(final_response.status_code, [429, 403])  # Too Many Requests or Forbidden