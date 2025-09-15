"""
Security utilities for Bug Bounty Automation Platform.
Handles authentication, authorization, and security validations.
"""

import base64
import ipaddress
import logging
import secrets
import hashlib
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from jose import JWTError, jwt
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from django.conf import settings
from passlib.context import CryptContext

logger = logging.getLogger(__name__)

# Password context for hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = getattr(settings, "SECRET_KEY", "fallback-secret-key")
JWT_SECRET_KEY = getattr(settings, "JWT_SECRET_KEY", SECRET_KEY)
ALGORITHM = getattr(settings, "JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = getattr(
    settings, "JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 30
)

# Security bearer for FastAPI
security = HTTPBearer()


class SecurityManager:
    """
    Centralized security management for the platform.
    """

    def __init__(self):
        self.pwd_context = pwd_context
        self.secret_key = JWT_SECRET_KEY
        self.algorithm = ALGORITHM

    # Password handling

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a plaintext password against its hash."""
        try:
            return self.pwd_context.verify(plain_password, hashed_password)
        except (ValueError, TypeError) as e:
            logger.error("Password verification error: %s", e)
            return False

    def get_password_hash(self, password: str) -> str:
        """Generate password hash."""
        return self.pwd_context.hash(password)

    def validate_password_strength(self, password: str) -> Dict[str, Any]:
        """
        Validate password strength and return detailed feedback.

        Returns:
            dict: Validation result with strength score and recommendations
        """
        score = 0
        feedback = []

        # Length check
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Password must be at least 8 characters long")

        if len(password) >= 12:
            score += 1

        # Character variety checks
        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("Password must contain lowercase letters")

        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Password must contain uppercase letters")

        if re.search(r"\d", password):
            score += 1
        else:
            feedback.append("Password must contain numbers")

        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append("Password must contain special characters")

        # Common password check (simplified)
        common_passwords = {"password", "123456", "password123", "admin", "qwerty"}
        if password.lower() in common_passwords:
            feedback.append("Password is too common")
            score = max(0, score - 2)

        strength_levels = {
            0: "Very Weak",
            1: "Very Weak",
            2: "Weak",
            3: "Fair",
            4: "Good",
            5: "Strong",
            6: "Very Strong",
        }

        return {
            "score": score,
            "max_score": 6,
            "strength": strength_levels.get(score, "Very Weak"),
            "is_valid": score >= 4,
            "feedback": feedback,
        }

    # JWT Token handling

    def create_access_token(
        self, data: dict, expires_delta: Optional[timedelta] = None
    ):
        """Create JWT access token."""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        to_encode.update({"exp": expire, "type": "access"})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def create_refresh_token(self, data: dict):
        """Create JWT refresh token."""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=7)  # Refresh tokens last longer
        to_encode.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verify JWT token and return payload.

        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError as e:
            logger.warning(f"JWT verification failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def extract_user_from_token(self, token: str) -> Optional[int]:
        """Extract user ID from JWT token."""
        try:
            payload = self.verify_token(token)
            user_id: int = payload.get("sub")
            if user_id is None:
                return None
            return int(user_id)
        except (JWTError, ValueError):
            return None

    # Input validation and sanitization

    def validate_url(self, url: str) -> bool:
        """Validate URL format for target URLs."""
        url_pattern = re.compile(
            r"^https?://"  # http:// or https://
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"  # domain...
            r"localhost|"  # localhost...
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
            r"(?::\d+)?"  # optional port
            r"(?:/?|[/?]\S+)$",
            re.IGNORECASE,
        )
        return url_pattern.match(url) is not None

    def sanitize_input(self, input_string: str, max_length: int = 1000) -> str:
        """Sanitize user input to prevent basic injection attacks."""
        if not input_string:
            return ""

        # Remove null bytes
        input_string = input_string.replace("\x00", "")

        # Limit length
        input_string = input_string[:max_length]

        # Basic HTML entity encoding for special characters
        replacements = {
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#x27;",
            "&": "&amp;",
        }

        for char, replacement in replacements.items():
            input_string = input_string.replace(char, replacement)

        return input_string.strip()

    def validate_command_injection(self, input_string: str) -> bool:
        """
        Check for potential command injection patterns.

        Returns:
            bool: True if input appears safe, False if suspicious
        """
        dangerous_patterns = [
            r";",  # Command separator
            r"\|",  # Pipe
            r"&",  # Background/AND
            r"\$\(",  # Command substitution
            r"`",  # Backtick command substitution
            r"rm\s",  # Remove command
            r"sudo\s",  # Sudo command
            r"chmod\s",  # Change permissions
            r"\.\./\.\.",  # Directory traversal
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                logger.warning(f"Potential command injection detected: {pattern}")
                return False

        return True

    # API Key management

    def generate_api_key(self) -> str:
        """Generate a secure API key."""
        return secrets.token_urlsafe(32)

    def hash_api_key(self, api_key: str) -> str:
        """Hash API key for secure storage."""
        return hashlib.sha256(api_key.encode()).hexdigest()

    def verify_api_key(self, provided_key: str, stored_hash: str) -> bool:
        """Verify API key against stored hash."""
        provided_hash = self.hash_api_key(provided_key)
        return secrets.compare_digest(provided_hash, stored_hash)


# Global security manager instance
security_manager = SecurityManager()

# FastAPI Dependencies


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Dict[str, Any]:
    """
    FastAPI dependency to get current user from JWT token.
    """
    token = credentials.credentials
    payload = security_manager.verify_token(token)

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # In a real implementation, you'd fetch user from database
    # For now, return basic user info from token
    return {
        "user_id": int(user_id),
        "username": payload.get("username"),
        "email": payload.get("email"),
        "is_active": payload.get("is_active", True),
    }


async def get_current_active_user(
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    FastAPI dependency to get current active user.
    """
    if not current_user.get("is_active"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user"
        )
    return current_user


# Permission decorators and dependencies


class RequirePermissions:
    """
    Class-based dependency for checking permissions.
    """

    def __init__(self, required_permissions: List[str]):
        self.required_permissions = required_permissions

    def __call__(self, current_user: dict = Depends(get_current_active_user)):
        user_permissions = current_user.get("permissions", [])

        missing_permissions = []
        for permission in self.required_permissions:
            if permission not in user_permissions:
                missing_permissions.append(permission)

        if missing_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permissions: {', '.join(missing_permissions)}",
            )

        return current_user


# Rate limiting utilities


class RateLimiter:
    """
    Simple in-memory rate limiter.
    In production, use Redis-based rate limiting.
    """

    def __init__(self):
        self.requests = {}

    def is_allowed(self, identifier: str, limit: int, window_seconds: int) -> bool:
        """
        Check if request is allowed based on rate limit.

        Args:
            identifier: Unique identifier (IP, user ID, etc.)
            limit: Maximum requests allowed
            window_seconds: Time window in seconds

        Returns:
            bool: True if request is allowed, False otherwise
        """
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=window_seconds)

        if identifier not in self.requests:
            self.requests[identifier] = []

        # Clean old requests
        self.requests[identifier] = [
            req_time
            for req_time in self.requests[identifier]
            if req_time > window_start
        ]

        # Check if limit exceeded
        if len(self.requests[identifier]) >= limit:
            return False

        # Add current request
        self.requests[identifier].append(now)
        return True


# Global rate limiter instance
rate_limiter = RateLimiter()

# Security middleware functions


def log_security_event(
    event_type: str, details: Dict[str, Any], user_id: Optional[int] = None
):
    """
    Log security-related events for monitoring.

    Args:
        event_type: Type of security event
        details: Additional details about the event
        user_id: Optional user ID associated with the event
    """
    logger.info(
        f"Security event: {event_type}",
        extra={
            "event_type": event_type,
            "user_id": user_id,
            "details": details,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


def validate_scan_permissions(user_data: Dict[str, Any], target_id: str) -> bool:
    """
    Validate if user has permission to scan a specific target.

    Args:
        user_data: User data from token
        target_id: Target identifier

    Returns:
        bool: True if user has permission, False otherwise
    """
    # Implement your business logic here
    # For example, check if user owns the target or has appropriate role

    user_permissions = user_data.get("permissions", [])

    # Admin users can scan any target
    if "admin" in user_permissions:
        return True

    # Regular users can only scan their own targets
    # In real implementation, you'd check database ownership
    return True  # Placeholder


def sanitize_report_data(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize report data to remove sensitive information based on user permissions.

    Args:
        report_data: Raw report data

    Returns:
        dict: Sanitized report data
    """
    sanitized_data = report_data.copy()

    # Remove sensitive fields if needed
    sensitive_fields = ["internal_ips", "credentials", "api_keys"]

    for field in sensitive_fields:
        if field in sanitized_data:
            # Either remove completely or mask the data
            sanitized_data[field] = "[REDACTED]"

    return sanitized_data


# Data encryption utilities


def encrypt_sensitive_data(data: str, key: Optional[str] = None) -> str:
    """
    Encrypt sensitive data for storage.

    Args:
        data: Data to encrypt
        key: Optional encryption key (uses default if not provided)

    Returns:
        str: Encrypted data
    """
    # In production, use proper encryption libraries like cryptography
    # This is a simplified example
    from cryptography.fernet import Fernet

    if key is None:
        # Use a key derived from SECRET_KEY
        key = hashlib.sha256(SECRET_KEY.encode()).digest()
        key = base64.urlsafe_b64encode(key[:32])

    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data.decode()


def decrypt_sensitive_data(encrypted_data: str, key: Optional[str] = None) -> str:
    """
    Decrypt sensitive data.

    Args:
        encrypted_data: Encrypted data string
        key: Optional decryption key

    Returns:
        str: Decrypted data
    """
    from cryptography.fernet import Fernet
    import base64

    if key is None:
        key = hashlib.sha256(SECRET_KEY.encode()).digest()
        key = base64.urlsafe_b64encode(key[:32])

    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data.encode())
    return decrypted_data.decode()


# Input validation schemas


class InputValidator:
    """
    Centralized input validation for the platform.
    """

    @staticmethod
    def validate_target_name(name: str) -> bool:
        """Validate target name format."""
        if not name or len(name) < 3 or len(name) > 100:
            return False
        # Allow alphanumeric, spaces, hyphens, underscores, and dots
        pattern = r"^[a-zA-Z0-9\s\-_.]+$"
        return bool(re.match(pattern, name))

    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email address format."""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format (IPv4 or IPv6)."""

        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate domain name format."""
        if not domain or len(domain) > 253:
            return False
        # Basic domain validation
        pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
        return bool(re.match(pattern, domain))


# Export commonly used items
__all__ = [
    "SecurityManager",
    "security_manager",
    "get_current_user",
    "get_current_active_user",
    "RequirePermissions",
    "RateLimiter",
    "rate_limiter",
    "log_security_event",
    "validate_scan_permissions",
    "sanitize_report_data",
    "encrypt_sensitive_data",
    "decrypt_sensitive_data",
    "InputValidator",
]
