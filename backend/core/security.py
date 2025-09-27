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
from uuid import UUID
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Set, Tuple
import bcrypt
from cryptography.fernet import Fernet
from jose import JWTError, jwt
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from django.conf import settings
from core.cache import cache_manager
from core.exceptions import BugBountyPlatformException
logger = logging.getLogger(__name__)

# Password context for hashing
# Note: Using bcrypt directly for password hashing
def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# JWT settings
SECRET_KEY = getattr(settings, "SECRET_KEY", "fallback-secret-key")
JWT_SECRET_KEY = getattr(settings, "JWT_SECRET_KEY", SECRET_KEY)
ALGORITHM = getattr(settings, "JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = getattr(
    settings, "JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 30
)

# Security bearer for FastAPI
security = HTTPBearer()


class SecurityViolation(BugBountyPlatformException):
    """Security violation exception."""

    def __init__(self, violation_type: str, details: str, client_ip: str = None):
        message = f"Security violation: {violation_type} - {details}"
        super().__init__(message, "SECURITY_VIOLATION", {
            "violation_type": violation_type,
            "details": details,
            "client_ip": client_ip,
            "timestamp": datetime.utcnow().isoformat()
        })


class ThreatDetector:
    """
    Enhanced threat detection and analysis.
    """

    def __init__(self):
        self.suspicious_patterns = {
            'scanner_user_agents': [
                'nmap', 'masscan', 'zmap', 'nuclei', 'sqlmap',
                'burp', 'dirb', 'gobuster', 'wfuzz', 'ffuf',
                'nikto', 'whatweb', 'skipfish'
            ],
            'attack_patterns': [
                'union select', 'information_schema', '@@version',
                '<script>', 'javascript:', 'onerror=',
                '../etc/passwd', '../../windows/system32',
                'cat /etc/', 'cmd.exe', 'powershell'
            ],
            'sql_injection_patterns': [
                r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)",
                r"(--|#|/\*|\*/)",
                r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
                r"(\'\s*(OR|AND)\s+\'\w+\'\s*=\s*\'\w+)"
            ],
            'xss_patterns': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"<iframe[^>]*>",
                r"<object[^>]*>"
            ]
        }

        self.threat_scores = {
            'scanner_detection': 50,
            'sql_injection_attempt': 80,
            'xss_attempt': 60,
            'path_traversal_attempt': 70,
            'command_injection_attempt': 90,
            'suspicious_user_agent': 30,
            'multiple_requests': 40,
            'blocked_country': 20
        }

    def analyze_request(self, request: Request) -> Dict[str, Any]:
        """Comprehensive threat analysis of incoming request."""
        threat_score = 0
        threats_detected = []
        analysis = {
            'client_ip': request.client.host,
            'user_agent': request.headers.get('user-agent', ''),
            'path': str(request.url.path),
            'method': request.method,
            'query_params': dict(request.query_params),
            'timestamp': datetime.utcnow()
        }

        # Analyze User-Agent for scanners
        user_agent = analysis['user_agent'].lower()
        for scanner in self.suspicious_patterns['scanner_user_agents']:
            if scanner in user_agent:
                threat_score += self.threat_scores['scanner_detection']
                threats_detected.append(f"Scanner detected: {scanner}")

        # Analyze request for attack patterns
        full_request = f"{analysis['path']} {str(analysis['query_params'])}"

        # SQL Injection detection
        for pattern in self.suspicious_patterns['sql_injection_patterns']:
            if re.search(pattern, full_request, re.IGNORECASE):
                threat_score += self.threat_scores['sql_injection_attempt']
                threats_detected.append("SQL injection attempt detected")
                break

        # XSS detection
        for pattern in self.suspicious_patterns['xss_patterns']:
            if re.search(pattern, full_request, re.IGNORECASE):
                threat_score += self.threat_scores['xss_attempt']
                threats_detected.append("XSS attempt detected")
                break

        # Check request frequency
        if self._is_high_frequency_client(analysis['client_ip']):
            threat_score += self.threat_scores['multiple_requests']
            threats_detected.append("High frequency requests detected")

        analysis.update({
            'threat_score': threat_score,
            'threats_detected': threats_detected,
            'risk_level': self._calculate_risk_level(threat_score)
        })

        return analysis

    def _is_high_frequency_client(self, client_ip: str) -> bool:
        """Check if client is making high frequency requests."""
        key = f"request_count:{client_ip}"
        current_count = cache_manager.get(key, 0)

        # More than 100 requests per minute is considered high frequency
        if current_count > 100:
            return True

        cache_manager.set(key, current_count + 1, 60)
        return False

    def _calculate_risk_level(self, threat_score: int) -> str:
        """Calculate risk level based on threat score."""
        if threat_score >= 100:
            return "CRITICAL"
        elif threat_score >= 70:
            return "HIGH"
        elif threat_score >= 40:
            return "MEDIUM"
        elif threat_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"


class SecurityManager:
    """
    Enhanced centralized security management for the platform.
    """

    def __init__(self):
        self.secret_key = JWT_SECRET_KEY
        self.algorithm = ALGORITHM
        self.threat_detector = ThreatDetector()
        self.blocked_ips: Set[str] = set()
        self._load_blocked_ips()

    def _load_blocked_ips(self):
        """Load blocked IPs from cache."""
        try:
            # Load any previously blocked IPs from cache
            pass  # Implementation would load from persistent storage
        except Exception as e:
            logger.error("Error loading blocked IPs: %s", e)

    def validate_request_security(self, request: Request) -> Tuple[bool, Dict[str, Any]]:
        """Comprehensive request security validation."""
        client_ip = request.client.host

        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            raise SecurityViolation(
                "blocked_ip",
                f"IP address {client_ip} is blocked",
                client_ip
            )

        # Perform threat analysis
        threat_analysis = self.threat_detector.analyze_request(request)

        # Block if threat score is too high
        if threat_analysis['threat_score'] >= 100:
            self.block_ip(client_ip, "High threat score")
            raise SecurityViolation(
                "high_threat_score",
                f"Threat score {threat_analysis['threat_score']} exceeds threshold",
                client_ip
            )

        # Log significant threats
        if threat_analysis['threat_score'] >= 50:
            log_security_event(
                "security_threat_detected",
                {
                    "client_ip": client_ip,
                    "threat_score": threat_analysis['threat_score'],
                    "threats": threat_analysis['threats_detected']
                }
            )

        return True, threat_analysis

    def block_ip(self, ip_address: str, reason: str) -> None:
        """Block IP address."""
        self.blocked_ips.add(ip_address)
        cache_manager.set(f"blocked_ip:{ip_address}", reason, 3600)
        log_security_event(
            "ip_blocked",
            {"ip_address": ip_address, "reason": reason}
        )

    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock IP address."""
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            cache_manager.delete(f"blocked_ip:{ip_address}")
            log_security_event(
                "ip_unblocked",
                {"ip_address": ip_address}
            )
            return True
        return False

    def enhanced_input_validation(self, data: Any, field_name: str = "input") -> Any:
        """Enhanced input validation and sanitization."""
        if isinstance(data, str):
            # Check for malicious patterns
            if not self.validate_command_injection(data):
                raise SecurityViolation(
                    "command_injection",
                    f"Potential command injection in {field_name}",
                )

            # Additional SQL injection check
            if self._check_sql_injection(data):
                raise SecurityViolation(
                    "sql_injection",
                    f"Potential SQL injection in {field_name}",
                )

            # XSS check
            if self._check_xss(data):
                raise SecurityViolation(
                    "xss_attempt",
                    f"Potential XSS in {field_name}",
                )

            # Sanitize and return
            return self.sanitize_input(data)

        elif isinstance(data, dict):
            return {k: self.enhanced_input_validation(v, f"{field_name}.{k}") for k, v in data.items()}

        elif isinstance(data, list):
            return [self.enhanced_input_validation(item, f"{field_name}[{i}]") for i, item in enumerate(data)]

        return data

    def _check_sql_injection(self, input_string: str) -> bool:
        """Enhanced SQL injection detection."""
        for pattern in self.threat_detector.suspicious_patterns['sql_injection_patterns']:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        return False

    def _check_xss(self, input_string: str) -> bool:
        """Enhanced XSS detection."""
        for pattern in self.threat_detector.suspicious_patterns['xss_patterns']:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        return False

    # Password handling

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a plaintext password against its hash."""
        try:
            return verify_password(plain_password, hashed_password)
        except (ValueError, TypeError) as e:
            logger.error("Password verification error: %s", e)
            return False

    def get_password_hash(self, password: str) -> str:
        """Generate password hash."""
        return hash_password(password)

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
            logger.warning("JWT verification failed: %s", e)
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
                logger.warning("Potential command injection detected: %s", pattern)
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

    def generate_access_token(self, user_data: Dict) -> str:
        """Generate JWT access token for user"""
        return self.create_access_token({"sub": str(user_data["id"])})

    def generate_refresh_token(self, user_data: Dict) -> str:
        """Generate JWT refresh token for user"""
        return self.create_refresh_token({"sub": str(user_data["id"])})


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

    @staticmethod
    def validate_uuid(uuid: str) -> bool:
        """Validate UUID format."""
        try:
            UUID(uuid)
            return True
        except ValueError:
            return False

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
