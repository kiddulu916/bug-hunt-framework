"""
Unit tests for authentication functionality
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from fastapi import HTTPException
from fastapi.testclient import TestClient

from core.security import SecurityManager, security_manager
from api.routers.auth import authenticate_user, create_user_tokens
from models import User


class TestSecurityManager:
    """Test the SecurityManager class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.security_mgr = SecurityManager()

    def test_password_hashing(self):
        """Test password hashing and verification"""
        password = "test_password_123!"
        hashed = self.security_mgr.get_password_hash(password)

        # Should be different from original
        assert hashed != password

        # Should verify correctly
        assert self.security_mgr.verify_password(password, hashed)

        # Should not verify wrong password
        assert not self.security_mgr.verify_password("wrong_password", hashed)

    def test_password_strength_validation(self):
        """Test password strength validation"""
        # Weak password
        weak_result = self.security_mgr.validate_password_strength("123")
        assert not weak_result["is_valid"]
        assert len(weak_result["feedback"]) > 0

        # Strong password
        strong_result = self.security_mgr.validate_password_strength("SecurePass123!")
        assert strong_result["is_valid"]
        assert strong_result["score"] >= 4

        # Common password
        common_result = self.security_mgr.validate_password_strength("password")
        assert not common_result["is_valid"]
        assert "too common" in " ".join(common_result["feedback"]).lower()

    def test_token_generation_and_verification(self):
        """Test JWT token generation and verification"""
        user_data = {
            "id": 1,
            "username": "testuser",
            "email": "test@example.com",
            "permissions": ["scan_access"],
            "roles": ["user"],
            "is_active": True,
            "is_staff": False,
            "is_superuser": False
        }

        # Generate access token
        access_token = self.security_mgr.generate_access_token(user_data)
        assert access_token

        # Verify token
        payload = self.security_mgr.verify_token(access_token)
        assert payload["sub"] == "1"
        assert payload["username"] == "testuser"
        assert payload["type"] == "access"

        # Generate refresh token
        refresh_token = self.security_mgr.generate_refresh_token(user_data)
        assert refresh_token

        # Verify refresh token
        refresh_payload = self.security_mgr.verify_token(refresh_token)
        assert refresh_payload["sub"] == "1"
        assert refresh_payload["type"] == "refresh"

    def test_invalid_token_verification(self):
        """Test verification of invalid tokens"""
        with pytest.raises(HTTPException) as exc_info:
            self.security_mgr.verify_token("invalid_token")

        assert exc_info.value.status_code == 401

    def test_expired_token_verification(self):
        """Test verification of expired tokens"""
        user_data = {"id": 1, "username": "testuser"}

        # Create token with very short expiry
        short_expire = timedelta(milliseconds=1)
        token = self.security_mgr.create_access_token(user_data, short_expire)

        # Wait for expiration
        import time
        time.sleep(0.002)

        with pytest.raises(HTTPException) as exc_info:
            self.security_mgr.verify_token(token)

        assert exc_info.value.status_code == 401

    def test_input_validation(self):
        """Test input validation and sanitization"""
        # Test URL validation
        assert self.security_mgr.validate_url("https://example.com")
        assert self.security_mgr.validate_url("http://test.local:8080/path")
        assert not self.security_mgr.validate_url("not-a-url")
        assert not self.security_mgr.validate_url("ftp://example.com")

        # Test input sanitization
        malicious_input = "<script>alert('xss')</script>"
        sanitized = self.security_mgr.sanitize_input(malicious_input)
        assert "<script>" not in sanitized
        assert "&lt;script&gt;" in sanitized

    def test_command_injection_validation(self):
        """Test command injection validation"""
        # Safe inputs
        assert self.security_mgr.validate_command_injection("normal text")
        assert self.security_mgr.validate_command_injection("file.txt")

        # Dangerous inputs
        assert not self.security_mgr.validate_command_injection("rm -rf /")
        assert not self.security_mgr.validate_command_injection("cat /etc/passwd")
        assert not self.security_mgr.validate_command_injection("cmd1; cmd2")
        assert not self.security_mgr.validate_command_injection("cmd1 | cmd2")

    def test_api_key_generation_and_verification(self):
        """Test API key functionality"""
        api_key = self.security_mgr.generate_api_key()
        assert len(api_key) > 20  # Should be a reasonable length

        # Hash and verify
        hashed_key = self.security_mgr.hash_api_key(api_key)
        assert self.security_mgr.verify_api_key(api_key, hashed_key)
        assert not self.security_mgr.verify_api_key("wrong_key", hashed_key)


class TestAuthenticationEndpoints:
    """Test authentication API endpoints"""

    @pytest.fixture
    def mock_db_session(self):
        """Mock database session"""
        return Mock()

    @pytest.fixture
    def sample_user(self):
        """Sample user for testing"""
        user = Mock(spec=User)
        user.id = 1
        user.username = "testuser"
        user.email = "test@example.com"
        user.password_hash = security_manager.get_password_hash("password123")
        user.is_active = True
        user.is_staff = False
        user.is_superuser = False
        user.permissions = ["scan_access", "report_access"]
        user.roles = ["user"]
        user.failed_login_attempts = 0
        user.account_locked_until = None
        user.last_login = None
        return user

    def test_authenticate_user_success(self, mock_db_session, sample_user):
        """Test successful user authentication"""
        mock_db_session.query.return_value.filter.return_value.first.return_value = sample_user

        result = authenticate_user(mock_db_session, "testuser", "password123")
        assert result == sample_user

    def test_authenticate_user_wrong_password(self, mock_db_session, sample_user):
        """Test authentication with wrong password"""
        mock_db_session.query.return_value.filter.return_value.first.return_value = sample_user

        result = authenticate_user(mock_db_session, "testuser", "wrongpassword")
        assert result is None

    def test_authenticate_user_not_found(self, mock_db_session):
        """Test authentication with non-existent user"""
        mock_db_session.query.return_value.filter.return_value.first.return_value = None

        result = authenticate_user(mock_db_session, "nonexistent", "password")
        assert result is None

    def test_create_user_tokens(self, sample_user):
        """Test token creation for user"""
        tokens = create_user_tokens(sample_user)

        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert "token_type" in tokens
        assert "expires_in" in tokens
        assert "user" in tokens

        assert tokens["token_type"] == "bearer"
        assert tokens["user"] == sample_user

        # Verify tokens are valid
        access_payload = security_manager.verify_token(tokens["access_token"])
        assert access_payload["sub"] == "1"
        assert access_payload["type"] == "access"

        refresh_payload = security_manager.verify_token(tokens["refresh_token"])
        assert refresh_payload["sub"] == "1"
        assert refresh_payload["type"] == "refresh"


class TestRateLimiting:
    """Test rate limiting functionality"""

    def test_rate_limiter_allows_requests_under_limit(self):
        """Test that rate limiter allows requests under the limit"""
        from core.security import rate_limiter

        # Clear any existing data
        identifier = "test_user_1"

        # Should allow requests under limit
        for i in range(5):
            assert rate_limiter.is_allowed(identifier, 10, 60)

    def test_rate_limiter_blocks_requests_over_limit(self):
        """Test that rate limiter blocks requests over the limit"""
        from core.security import rate_limiter

        identifier = "test_user_2"
        limit = 3
        window = 60

        # Use up the limit
        for i in range(limit):
            assert rate_limiter.is_allowed(identifier, limit, window)

        # Next request should be blocked
        assert not rate_limiter.is_allowed(identifier, limit, window)


class TestSecurityLogging:
    """Test security event logging"""

    @patch('core.security.logger')
    def test_security_event_logging(self, mock_logger):
        """Test that security events are logged correctly"""
        from core.security import log_security_event

        event_type = "test_event"
        details = {"user_id": 1, "action": "test_action"}

        log_security_event(event_type, details)

        # Verify logger was called
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args

        assert event_type in call_args[0][0]  # Event type in message
        assert "event_type" in call_args[1]["extra"]  # Event type in extra data
        assert call_args[1]["extra"]["event_type"] == event_type


class TestInputValidation:
    """Test input validation utilities"""

    def test_validate_email(self):
        """Test email validation"""
        from core.security import InputValidator

        # Valid emails
        assert InputValidator.validate_email("test@example.com")
        assert InputValidator.validate_email("user.name+tag@domain.co.uk")

        # Invalid emails
        assert not InputValidator.validate_email("invalid")
        assert not InputValidator.validate_email("@domain.com")
        assert not InputValidator.validate_email("user@")

    def test_validate_domain(self):
        """Test domain validation"""
        from core.security import InputValidator

        # Valid domains
        assert InputValidator.validate_domain("example.com")
        assert InputValidator.validate_domain("subdomain.example.org")
        assert InputValidator.validate_domain("test-domain.co.uk")

        # Invalid domains
        assert not InputValidator.validate_domain("")
        assert not InputValidator.validate_domain(".com")
        assert not InputValidator.validate_domain("domain.")
        assert not InputValidator.validate_domain("invalid..domain.com")

    def test_validate_ip_address(self):
        """Test IP address validation"""
        from core.security import InputValidator

        # Valid IPv4
        assert InputValidator.validate_ip_address("192.168.1.1")
        assert InputValidator.validate_ip_address("10.0.0.1")
        assert InputValidator.validate_ip_address("127.0.0.1")

        # Valid IPv6
        assert InputValidator.validate_ip_address("::1")
        assert InputValidator.validate_ip_address("2001:db8::1")

        # Invalid IPs
        assert not InputValidator.validate_ip_address("256.256.256.256")
        assert not InputValidator.validate_ip_address("not-an-ip")
        assert not InputValidator.validate_ip_address("")

    def test_validate_target_name(self):
        """Test target name validation"""
        from core.security import InputValidator

        # Valid names
        assert InputValidator.validate_target_name("Example Corp")
        assert InputValidator.validate_target_name("test-company_123")
        assert InputValidator.validate_target_name("Company.com")

        # Invalid names
        assert not InputValidator.validate_target_name("")  # Empty
        assert not InputValidator.validate_target_name("ab")  # Too short
        assert not InputValidator.validate_target_name("x" * 101)  # Too long
        assert not InputValidator.validate_target_name("test@company")  # Invalid chars


class TestThreatDetection:
    """Test threat detection functionality"""

    def test_threat_detector_initialization(self):
        """Test threat detector initialization"""
        from core.security import ThreatDetector

        detector = ThreatDetector()
        assert hasattr(detector, 'suspicious_patterns')
        assert hasattr(detector, 'threat_scores')
        assert 'scanner_user_agents' in detector.suspicious_patterns
        assert 'sql_injection_patterns' in detector.suspicious_patterns

    @patch('core.security.Request')
    def test_analyze_request_clean(self, mock_request):
        """Test analysis of clean request"""
        from core.security import ThreatDetector

        # Mock clean request
        mock_request.client.host = "192.168.1.100"
        mock_request.headers.get.return_value = "Mozilla/5.0 (Normal Browser)"
        mock_request.url.path = "/api/v1/targets"
        mock_request.method = "GET"
        mock_request.query_params = {}

        detector = ThreatDetector()
        analysis = detector.analyze_request(mock_request)

        assert analysis['threat_score'] == 0
        assert len(analysis['threats_detected']) == 0
        assert analysis['risk_level'] == "MINIMAL"

    @patch('core.security.Request')
    def test_analyze_request_with_scanner(self, mock_request):
        """Test analysis of request with scanner user agent"""
        from core.security import ThreatDetector

        # Mock scanner request
        mock_request.client.host = "10.0.0.50"
        mock_request.headers.get.return_value = "nmap script scanner"
        mock_request.url.path = "/api/v1/vulnerabilities"
        mock_request.method = "GET"
        mock_request.query_params = {}

        detector = ThreatDetector()
        analysis = detector.analyze_request(mock_request)

        assert analysis['threat_score'] > 0
        assert len(analysis['threats_detected']) > 0
        assert "Scanner detected: nmap" in analysis['threats_detected']

    @patch('core.security.Request')
    def test_analyze_request_sql_injection(self, mock_request):
        """Test analysis of request with SQL injection attempt"""
        from core.security import ThreatDetector

        # Mock SQL injection request
        mock_request.client.host = "1.2.3.4"
        mock_request.headers.get.return_value = "Mozilla/5.0"
        mock_request.url.path = "/api/v1/search"
        mock_request.method = "GET"
        mock_request.query_params = {"q": "'; DROP TABLE users; --"}

        detector = ThreatDetector()
        analysis = detector.analyze_request(mock_request)

        assert analysis['threat_score'] >= 80  # SQL injection score
        assert "SQL injection attempt detected" in analysis['threats_detected']
        assert analysis['risk_level'] in ["HIGH", "CRITICAL"]


if __name__ == "__main__":
    pytest.main([__file__])