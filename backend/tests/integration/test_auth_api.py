"""
Integration tests for authentication API endpoints
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta

from api.main import app
from api.dependencies.database import get_db
from models import Base, User
from core.security import security_manager


# Test database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_auth.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override database dependency for testing"""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


class TestAuthenticationAPI:
    """Test authentication API endpoints"""

    @pytest.fixture(scope="class")
    def setup_database(self):
        """Set up test database"""
        Base.metadata.create_all(bind=engine)
        yield
        Base.metadata.drop_all(bind=engine)

    @pytest.fixture
    def client(self, setup_database):
        """Test client"""
        return TestClient(app)

    @pytest.fixture
    def db_session(self):
        """Database session for test setup"""
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            # Clean up
            db.query(User).delete()
            db.commit()
            db.close()

    @pytest.fixture
    def test_user_data(self):
        """Test user registration data"""
        return {
            "username": "testuser",
            "email": "test@example.com",
            "password": "TestPassword123!",
            "first_name": "Test",
            "last_name": "User"
        }

    def test_user_registration_success(self, client, test_user_data):
        """Test successful user registration"""
        response = client.post("/api/v1/auth/register", json=test_user_data)

        assert response.status_code == 201
        data = response.json()

        assert "access_token" in data
        assert "refresh_token" in data
        assert "token_type" in data
        assert "expires_in" in data
        assert "user" in data

        assert data["token_type"] == "bearer"
        assert data["user"]["username"] == test_user_data["username"]
        assert data["user"]["email"] == test_user_data["email"]
        assert data["user"]["is_active"] is True

    def test_user_registration_duplicate_username(self, client, test_user_data, db_session):
        """Test registration with duplicate username"""
        # Create user first
        user = User(
            username=test_user_data["username"],
            email="different@example.com",
            password_hash=security_manager.get_password_hash("password"),
            is_active=True
        )
        db_session.add(user)
        db_session.commit()

        # Try to register with same username
        response = client.post("/api/v1/auth/register", json=test_user_data)

        assert response.status_code == 400
        assert "Username already registered" in response.json()["detail"]

    def test_user_registration_duplicate_email(self, client, test_user_data, db_session):
        """Test registration with duplicate email"""
        # Create user first
        user = User(
            username="differentuser",
            email=test_user_data["email"],
            password_hash=security_manager.get_password_hash("password"),
            is_active=True
        )
        db_session.add(user)
        db_session.commit()

        # Try to register with same email
        response = client.post("/api/v1/auth/register", json=test_user_data)

        assert response.status_code == 400
        assert "Email already registered" in response.json()["detail"]

    def test_user_registration_weak_password(self, client, test_user_data):
        """Test registration with weak password"""
        test_user_data["password"] = "weak"

        response = client.post("/api/v1/auth/register", json=test_user_data)

        assert response.status_code == 422  # Validation error

    def test_user_registration_invalid_email(self, client, test_user_data):
        """Test registration with invalid email"""
        test_user_data["email"] = "invalid-email"

        response = client.post("/api/v1/auth/register", json=test_user_data)

        assert response.status_code == 422  # Validation error

    def test_login_success(self, client, db_session):
        """Test successful login"""
        # Create test user
        password = "TestPassword123!"
        user = User(
            username="loginuser",
            email="login@example.com",
            password_hash=security_manager.get_password_hash(password),
            is_active=True,
            permissions=["scan_access"],
            roles=["user"]
        )
        db_session.add(user)
        db_session.commit()

        # Login
        login_data = {
            "username": "loginuser",
            "password": password
        }

        response = client.post("/api/v1/auth/token", data=login_data)

        assert response.status_code == 200
        data = response.json()

        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["username"] == "loginuser"

    def test_login_invalid_credentials(self, client, db_session):
        """Test login with invalid credentials"""
        # Create test user
        user = User(
            username="loginuser2",
            email="login2@example.com",
            password_hash=security_manager.get_password_hash("correct_password"),
            is_active=True
        )
        db_session.add(user)
        db_session.commit()

        # Try login with wrong password
        login_data = {
            "username": "loginuser2",
            "password": "wrong_password"
        }

        response = client.post("/api/v1/auth/token", data=login_data)

        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]

    def test_login_inactive_user(self, client, db_session):
        """Test login with inactive user"""
        # Create inactive user
        user = User(
            username="inactiveuser",
            email="inactive@example.com",
            password_hash=security_manager.get_password_hash("password"),
            is_active=False
        )
        db_session.add(user)
        db_session.commit()

        # Try login
        login_data = {
            "username": "inactiveuser",
            "password": "password"
        }

        response = client.post("/api/v1/auth/token", data=login_data)

        assert response.status_code == 403
        assert "Account is inactive" in response.json()["detail"]

    def test_login_account_lockout(self, client, db_session):
        """Test account lockout after failed attempts"""
        # Create test user
        user = User(
            username="lockoutuser",
            email="lockout@example.com",
            password_hash=security_manager.get_password_hash("correct_password"),
            is_active=True,
            failed_login_attempts=5,
            account_locked_until=datetime.utcnow() + timedelta(minutes=15)
        )
        db_session.add(user)
        db_session.commit()

        # Try login with correct password
        login_data = {
            "username": "lockoutuser",
            "password": "correct_password"
        }

        response = client.post("/api/v1/auth/token", data=login_data)

        assert response.status_code == 423
        assert "Account is temporarily locked" in response.json()["detail"]

    def test_token_refresh(self, client, db_session):
        """Test token refresh functionality"""
        # Create and login user
        password = "TestPassword123!"
        user = User(
            username="refreshuser",
            email="refresh@example.com",
            password_hash=security_manager.get_password_hash(password),
            is_active=True,
            permissions=["scan_access"],
            roles=["user"]
        )
        db_session.add(user)
        db_session.commit()

        # Login to get tokens
        login_response = client.post("/api/v1/auth/token", data={
            "username": "refreshuser",
            "password": password
        })

        assert login_response.status_code == 200
        tokens = login_response.json()

        # Use refresh token to get new access token
        refresh_data = {
            "refresh_token": tokens["refresh_token"]
        }

        refresh_response = client.post("/api/v1/auth/refresh", json=refresh_data)

        assert refresh_response.status_code == 200
        new_tokens = refresh_response.json()

        assert "access_token" in new_tokens
        assert "refresh_token" in new_tokens
        assert new_tokens["access_token"] != tokens["access_token"]  # Should be different

    def test_token_refresh_invalid_token(self, client):
        """Test token refresh with invalid token"""
        refresh_data = {
            "refresh_token": "invalid_token"
        }

        response = client.post("/api/v1/auth/refresh", json=refresh_data)

        assert response.status_code == 401
        assert "Invalid refresh token" in response.json()["detail"]

    def test_get_current_user(self, client, db_session):
        """Test getting current user info"""
        # Create and login user
        password = "TestPassword123!"
        user = User(
            username="currentuser",
            email="current@example.com",
            password_hash=security_manager.get_password_hash(password),
            is_active=True,
            first_name="Current",
            last_name="User"
        )
        db_session.add(user)
        db_session.commit()

        # Login to get token
        login_response = client.post("/api/v1/auth/token", data={
            "username": "currentuser",
            "password": password
        })

        tokens = login_response.json()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # Get current user info
        response = client.get("/api/v1/auth/me", headers=headers)

        assert response.status_code == 200
        user_data = response.json()

        assert user_data["username"] == "currentuser"
        assert user_data["email"] == "current@example.com"
        assert user_data["first_name"] == "Current"
        assert user_data["last_name"] == "User"
        assert user_data["is_active"] is True

    def test_get_current_user_no_token(self, client):
        """Test getting current user without token"""
        response = client.get("/api/v1/auth/me")

        assert response.status_code == 401

    def test_get_current_user_invalid_token(self, client):
        """Test getting current user with invalid token"""
        headers = {"Authorization": "Bearer invalid_token"}
        response = client.get("/api/v1/auth/me", headers=headers)

        assert response.status_code == 401

    def test_change_password(self, client, db_session):
        """Test password change functionality"""
        # Create user
        old_password = "OldPassword123!"
        user = User(
            username="changeuser",
            email="change@example.com",
            password_hash=security_manager.get_password_hash(old_password),
            is_active=True
        )
        db_session.add(user)
        db_session.commit()

        # Login to get token
        login_response = client.post("/api/v1/auth/token", data={
            "username": "changeuser",
            "password": old_password
        })

        tokens = login_response.json()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # Change password
        new_password = "NewPassword456!"
        change_data = {
            "current_password": old_password,
            "new_password": new_password
        }

        response = client.put("/api/v1/auth/change-password", json=change_data, headers=headers)

        assert response.status_code == 200
        assert "Password changed successfully" in response.json()["message"]

        # Verify old password no longer works
        old_login_response = client.post("/api/v1/auth/token", data={
            "username": "changeuser",
            "password": old_password
        })
        assert old_login_response.status_code == 401

        # Verify new password works
        new_login_response = client.post("/api/v1/auth/token", data={
            "username": "changeuser",
            "password": new_password
        })
        assert new_login_response.status_code == 200

    def test_change_password_wrong_current(self, client, db_session):
        """Test password change with wrong current password"""
        # Create user
        password = "TestPassword123!"
        user = User(
            username="wronguser",
            email="wrong@example.com",
            password_hash=security_manager.get_password_hash(password),
            is_active=True
        )
        db_session.add(user)
        db_session.commit()

        # Login to get token
        login_response = client.post("/api/v1/auth/token", data={
            "username": "wronguser",
            "password": password
        })

        tokens = login_response.json()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # Try to change with wrong current password
        change_data = {
            "current_password": "WrongPassword",
            "new_password": "NewPassword456!"
        }

        response = client.put("/api/v1/auth/change-password", json=change_data, headers=headers)

        assert response.status_code == 400
        assert "Current password is incorrect" in response.json()["detail"]

    def test_password_reset_request(self, client, db_session):
        """Test password reset request"""
        # Create user
        user = User(
            username="resetuser",
            email="reset@example.com",
            password_hash=security_manager.get_password_hash("password"),
            is_active=True
        )
        db_session.add(user)
        db_session.commit()

        # Request password reset
        reset_data = {
            "email": "reset@example.com"
        }

        response = client.post("/api/v1/auth/reset-password", json=reset_data)

        assert response.status_code == 200
        assert "password reset link has been sent" in response.json()["message"]

    def test_password_reset_nonexistent_email(self, client):
        """Test password reset for non-existent email"""
        reset_data = {
            "email": "nonexistent@example.com"
        }

        response = client.post("/api/v1/auth/reset-password", json=reset_data)

        # Should return success to prevent email enumeration
        assert response.status_code == 200
        assert "password reset link has been sent" in response.json()["message"]

    def test_validate_token(self, client, db_session):
        """Test token validation endpoint"""
        # Create and login user
        password = "TestPassword123!"
        user = User(
            username="validateuser",
            email="validate@example.com",
            password_hash=security_manager.get_password_hash(password),
            is_active=True
        )
        db_session.add(user)
        db_session.commit()

        # Login to get token
        login_response = client.post("/api/v1/auth/token", data={
            "username": "validateuser",
            "password": password
        })

        tokens = login_response.json()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # Validate token
        response = client.get("/api/v1/auth/validate-token", headers=headers)

        assert response.status_code == 200
        data = response.json()

        assert data["valid"] is True
        assert data["username"] == "validateuser"
        assert "exp" in data

    def test_validate_invalid_token(self, client):
        """Test validation of invalid token"""
        headers = {"Authorization": "Bearer invalid_token"}
        response = client.get("/api/v1/auth/validate-token", headers=headers)

        assert response.status_code == 401

    def test_logout(self, client, db_session):
        """Test logout functionality"""
        # Create and login user
        password = "TestPassword123!"
        user = User(
            username="logoutuser",
            email="logout@example.com",
            password_hash=security_manager.get_password_hash(password),
            is_active=True
        )
        db_session.add(user)
        db_session.commit()

        # Login to get token
        login_response = client.post("/api/v1/auth/token", data={
            "username": "logoutuser",
            "password": password
        })

        tokens = login_response.json()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # Logout
        response = client.post("/api/v1/auth/logout", headers=headers)

        assert response.status_code == 200
        assert "Successfully logged out" in response.json()["message"]


if __name__ == "__main__":
    pytest.main([__file__])