# Security Documentation

## Overview

The Bug Hunt Framework implements enterprise-grade security with multiple layers of protection, including authentication, authorization, threat detection, input validation, and data encryption.

## Security Architecture

### Defense in Depth Layers

```
┌─────────────────────────────────────────────┐
│         Layer 6: Monitoring & Logging        │
│    (Threat Detection, Audit Trails)         │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│         Layer 5: Data Protection            │
│    (Encryption, Secure Storage)             │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│         Layer 4: Input Validation           │
│    (XSS, SQLi, Command Injection)          │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│         Layer 3: Authorization              │
│    (RBAC, Permissions, Resource Access)    │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│         Layer 2: Authentication             │
│    (JWT Tokens, Password Security)         │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│         Layer 1: Network Security           │
│    (Rate Limiting, DDoS Protection)        │
└─────────────────────────────────────────────┘
```

## Authentication System

**Location**: `backend/core/security.py`

### JWT Token Authentication

The platform uses JSON Web Tokens (JWT) for stateless authentication.

```python
class SecurityManager:
    """Centralized security management"""

    @staticmethod
    def create_access_token(user_id: int, email: str) -> str:
        """
        Create JWT access token

        Args:
            user_id: User ID
            email: User email

        Returns:
            str: Encoded JWT token

        Token Expiration: 15 minutes
        """

    @staticmethod
    def create_refresh_token(user_id: int, email: str) -> str:
        """
        Create JWT refresh token

        Args:
            user_id: User ID
            email: User email

        Returns:
            str: Encoded JWT refresh token

        Token Expiration: 7 days
        """

    @staticmethod
    def verify_token(token: str) -> dict:
        """
        Verify and decode JWT token

        Args:
            token: JWT token string

        Returns:
            dict: Token payload

        Raises:
            jwt.ExpiredSignatureError: Token expired
            jwt.InvalidTokenError: Invalid token
        """

    @staticmethod
    def extract_user_from_token(token: str) -> dict:
        """
        Extract user information from token

        Returns:
            dict: {
                'user_id': int,
                'email': str,
                'exp': int
            }
        """
```

### Token Structure

**Access Token Payload**:
```json
{
  "user_id": 123,
  "email": "user@example.com",
  "type": "access",
  "iat": 1642252800,
  "exp": 1642253700
}
```

**Refresh Token Payload**:
```json
{
  "user_id": 123,
  "email": "user@example.com",
  "type": "refresh",
  "iat": 1642252800,
  "exp": 1642857600
}
```

### Authentication Flow

```
1. User Login (POST /api/auth/login)
   ↓
2. Validate credentials
   ↓
3. Generate access_token (15 min) + refresh_token (7 days)
   ↓
4. Return tokens to client
   ↓
5. Client includes access_token in requests
   ↓
6. Server validates token on each request
   ↓
7. When access_token expires:
   - Client sends refresh_token
   - Server generates new access_token
   - Client receives new access_token
```

### FastAPI Dependencies

```python
from api.dependencies.auth import get_current_user, get_current_active_user

@router.get("/protected")
async def protected_endpoint(
    current_user: User = Depends(get_current_user)
):
    """Endpoint requires authentication"""
    return {"user": current_user.email}

@router.get("/active-only")
async def active_users_only(
    current_user: User = Depends(get_current_active_user)
):
    """Requires active user account"""
    return {"message": "Access granted"}
```

## Password Security

### Password Hashing

```python
class SecurityManager:

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash password using bcrypt

        Args:
            password: Plain text password

        Returns:
            str: Bcrypt hashed password

        Algorithm: bcrypt with 12 rounds
        """

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """
        Verify password against hash

        Args:
            password: Plain text password
            hashed_password: Bcrypt hash

        Returns:
            bool: True if password matches
        """
```

### Password Strength Validation

```python
class SecurityManager:

    @staticmethod
    def validate_password_strength(password: str) -> dict:
        """
        Validate password strength

        Requirements:
        - Minimum 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        - Not in common password list

        Returns:
            dict: {
                'is_valid': bool,
                'strength_score': int,  # 0-6
                'feedback': list
            }
        """
```

**Strength Scoring**:
- 0-2: Weak (rejected)
- 3-4: Medium (warning)
- 5-6: Strong (accepted)

**Common Password Check**:
- Checks against top 10,000 common passwords
- Rejects passwords like "password123", "admin", etc.

## Authorization & Access Control

### Role-Based Access Control (RBAC)

**User Roles**:
```python
class UserRole:
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    PENTESTER = "pentester"
    VIEWER = "viewer"
```

**Role Permissions**:

| Operation | Admin | Security Analyst | Pentester | Viewer |
|-----------|-------|-----------------|-----------|--------|
| View Targets | ✓ | ✓ | ✓ | ✓ |
| Create Targets | ✓ | ✓ | ✗ | ✗ |
| Delete Targets | ✓ | ✗ | ✗ | ✗ |
| Run Scans | ✓ | ✓ | ✓ | ✗ |
| View Vulnerabilities | ✓ | ✓ | ✓ | ✓ |
| Verify Vulnerabilities | ✓ | ✓ | ✓ | ✗ |
| Delete Vulnerabilities | ✓ | ✓ | ✗ | ✗ |
| Generate Reports | ✓ | ✓ | ✓ | ✓ |
| Manage Users | ✓ | ✗ | ✗ | ✗ |

### Permission Checking

```python
from core.security import RequirePermissions

@router.delete("/targets/{target_id}")
async def delete_target(
    target_id: int,
    current_user: User = Depends(RequirePermissions(["admin"]))
):
    """Only admins can delete targets"""
    # Implementation
```

**Class-Based Permission Dependency**:
```python
class RequirePermissions:
    """Dependency for permission-based access control"""

    def __init__(self, required_roles: list):
        self.required_roles = required_roles

    async def __call__(self, current_user: User = Depends(get_current_user)):
        if current_user.role not in self.required_roles:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions"
            )
        return current_user
```

## Threat Detection System

**Location**: `backend/core/security.py`

### ThreatDetector Class

```python
class ThreatDetector:
    """Real-time threat detection and prevention"""

    @staticmethod
    def detect_scanner_user_agent(user_agent: str) -> bool:
        """
        Detect security scanner user agents

        Detected Scanners:
        - Nmap
        - Masscan
        - Nuclei
        - SQLMap
        - Nikto
        - Burp Suite
        - OWASP ZAP
        - Acunetix
        - And more...

        Returns:
            bool: True if scanner detected
        """

    @staticmethod
    def detect_sql_injection(input_string: str) -> bool:
        """
        Detect SQL injection patterns

        Patterns:
        - UNION SELECT
        - OR 1=1
        - ; DROP TABLE
        - ' OR '1'='1
        - -- comments
        - And more...

        Returns:
            bool: True if SQL injection detected
        """

    @staticmethod
    def detect_xss(input_string: str) -> bool:
        """
        Detect XSS patterns

        Patterns:
        - <script> tags
        - javascript: protocol
        - onerror= handlers
        - Event handlers (onclick, onload, etc.)
        - And more...

        Returns:
            bool: True if XSS detected
        """

    @staticmethod
    def detect_path_traversal(input_string: str) -> bool:
        """
        Detect path traversal patterns

        Patterns:
        - ../
        - ..\\
        - %2e%2e/
        - And encoded variants

        Returns:
            bool: True if path traversal detected
        """

    @staticmethod
    def detect_command_injection(input_string: str) -> bool:
        """
        Detect command injection patterns

        Patterns:
        - ; ls
        - | cat
        - `whoami`
        - $(command)
        - And more...

        Returns:
            bool: True if command injection detected
        """

    @staticmethod
    def calculate_threat_score(request_data: dict) -> int:
        """
        Calculate overall threat score

        Scoring:
        - Scanner UA: +50
        - SQL injection: +100
        - XSS: +75
        - Path traversal: +75
        - Command injection: +100
        - High request frequency: +50

        Returns:
            int: Threat score (0-500)
        """

    @staticmethod
    def detect_high_frequency_requests(ip: str, window_seconds: int = 60) -> bool:
        """
        Detect high-frequency requests (DDoS)

        Threshold: >100 requests per minute

        Returns:
            bool: True if high frequency detected
        """
```

### Automatic Threat Response

```python
# In middleware
threat_score = ThreatDetector.calculate_threat_score(request_data)

if threat_score >= 100:
    # Block IP
    SecurityManager.block_ip(client_ip)

    # Log security event
    logger.warning(
        f"Threat detected from {client_ip}",
        extra={
            'threat_score': threat_score,
            'user_agent': user_agent,
            'path': request.path
        }
    )

    # Return 403
    raise HTTPException(status_code=403, detail="Request blocked")
```

## Input Validation

### InputValidator Class

```python
class InputValidator:
    """Input validation and sanitization"""

    @staticmethod
    def validate_url(url: str) -> bool:
        """
        Validate URL format

        Checks:
        - Valid scheme (http, https)
        - Valid domain format
        - No invalid characters

        Returns:
            bool: True if valid URL
        """

    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Validate email format

        Returns:
            bool: True if valid email
        """

    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """
        Validate IP address (IPv4 or IPv6)

        Returns:
            bool: True if valid IP
        """

    @staticmethod
    def validate_domain(domain: str) -> bool:
        """
        Validate domain name

        Returns:
            bool: True if valid domain
        """

    @staticmethod
    def validate_uuid(uuid_string: str) -> bool:
        """
        Validate UUID format

        Returns:
            bool: True if valid UUID
        """

    @staticmethod
    def sanitize_input(input_string: str) -> str:
        """
        Sanitize user input

        Operations:
        - HTML entity encoding
        - Remove null bytes
        - Trim whitespace
        - Remove control characters

        Returns:
            str: Sanitized input
        """

    @staticmethod
    def prevent_command_injection(input_string: str) -> str:
        """
        Prevent command injection

        Actions:
        - Escape shell metacharacters
        - Remove dangerous patterns
        - Quote properly for shell

        Returns:
            str: Safe input for shell commands
        """
```

### Validation in API Endpoints

```python
from pydantic import BaseModel, validator
from core.security import InputValidator

class TargetCreate(BaseModel):
    target_name: str
    main_url: str

    @validator('main_url')
    def validate_main_url(cls, v):
        if not InputValidator.validate_url(v):
            raise ValueError('Invalid URL format')
        return v

    @validator('target_name')
    def validate_target_name(cls, v):
        sanitized = InputValidator.sanitize_input(v)
        if sanitized != v:
            raise ValueError('Invalid characters in target name')
        return sanitized
```

## Data Encryption

### Encryption Manager

```python
class SecurityManager:

    @staticmethod
    def encrypt_data(data: str) -> str:
        """
        Encrypt sensitive data

        Algorithm: Fernet (AES-128 in CBC mode)

        Args:
            data: Plain text data

        Returns:
            str: Encrypted data (base64 encoded)
        """

    @staticmethod
    def decrypt_data(encrypted_data: str) -> str:
        """
        Decrypt encrypted data

        Args:
            encrypted_data: Base64 encoded encrypted data

        Returns:
            str: Decrypted plain text

        Raises:
            InvalidToken: If decryption fails
        """
```

### API Key Management

```python
class SecurityManager:

    @staticmethod
    def generate_api_key() -> str:
        """
        Generate secure API key

        Format: 32 bytes, URL-safe base64 encoded

        Returns:
            str: API key (43 characters)
        """

    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """
        Hash API key for storage

        Algorithm: SHA-256

        Returns:
            str: Hashed API key (hex)
        """

    @staticmethod
    def verify_api_key(api_key: str, hashed_key: str) -> bool:
        """
        Verify API key

        Uses constant-time comparison

        Returns:
            bool: True if valid
        """
```

**API Key Storage**:
```python
# Never store plain API keys
api_key = SecurityManager.generate_api_key()
hashed = SecurityManager.hash_api_key(api_key)

# Store hashed version in database
ApiKey.objects.create(
    user=user,
    key_hash=hashed,
    name="My API Key"
)

# Return plain key to user (only once)
return {"api_key": api_key}
```

## Rate Limiting

**Location**: `backend/core/security.py`

### RateLimiter Class

```python
class RateLimiter:
    """In-memory rate limiting"""

    def __init__(self, max_requests: int, window_seconds: int):
        """
        Initialize rate limiter

        Args:
            max_requests: Maximum requests allowed
            window_seconds: Time window in seconds
        """

    def is_allowed(self, identifier: str) -> bool:
        """
        Check if request is allowed

        Args:
            identifier: Unique identifier (IP, user ID, etc.)

        Returns:
            bool: True if within rate limit
        """

    def get_remaining_requests(self, identifier: str) -> int:
        """
        Get remaining requests in window

        Returns:
            int: Number of requests remaining
        """

    def reset_time(self, identifier: str) -> int:
        """
        Get reset time

        Returns:
            int: Unix timestamp when limit resets
        """
```

### Rate Limit Configuration

**Global Limits** (per hour):
```python
RATE_LIMITS = {
    'anonymous': 100,
    'authenticated': 1000,
    'admin': 5000,
}
```

**Endpoint-Specific Limits** (per minute):
```python
ENDPOINT_LIMITS = {
    '/api/auth/login': 5,
    '/api/scans/': 10,
    '/api/vulnerabilities/': 50,
}
```

### Rate Limiting Middleware

```python
from core.middleware import RateLimitingMiddleware

app.add_middleware(
    RateLimitingMiddleware,
    global_limit=1000,
    window_seconds=3600,
    endpoint_limits={
        '/api/auth/login': (5, 60),
        '/api/scans/': (10, 60),
    }
)
```

**Response Headers**:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1642252800
```

## Security Middleware

### Available Middlewares

**1. Request Validation Middleware**:
```python
class RequestValidationMiddleware:
    """
    Validates all incoming requests

    Checks:
    - Request size limits (10MB max)
    - Content-Type validation
    - SQL injection detection
    - XSS detection
    - Path traversal detection
    """
```

**2. Security Headers Middleware**:
```python
class SecurityHeadersMiddleware:
    """
    Adds security headers to responses

    Headers:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection: 1; mode=block
    - Strict-Transport-Security: max-age=31536000
    - Content-Security-Policy: default-src 'self'
    """
```

**3. Threat Detection Middleware**:
```python
class ThreatDetectionMiddleware:
    """
    Real-time threat detection

    Features:
    - Scanner detection
    - Attack pattern recognition
    - Automatic IP blocking
    - Security event logging
    """
```

## Secure Configuration

### Environment Variables

**Required Security Variables**:
```bash
# Authentication
SECRET_KEY=<strong-random-key>
JWT_SECRET_KEY=<strong-random-key>
JWT_ALGORITHM=HS256

# Encryption
ENCRYPTION_KEY=<fernet-key>

# Database
DATABASE_URL=postgresql://user:pass@localhost/db
REDIS_URL=redis://localhost:6379/0

# CORS
ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
ALLOWED_HOSTS=example.com,*.example.com

# Security
ENABLE_RATE_LIMITING=true
ENABLE_THREAT_DETECTION=true
MAX_CONCURRENT_SCANS=5
```

### Secrets Management

**Never commit secrets to Git**:
```python
# Bad
SECRET_KEY = "hardcoded-secret"

# Good
import os
SECRET_KEY = os.getenv('SECRET_KEY')

if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable not set")
```

**Use secret management tools**:
- AWS Secrets Manager
- HashiCorp Vault
- Azure Key Vault
- Environment variables (for development)

## Logging & Monitoring

### Security Event Logging

```python
import logging

security_logger = logging.getLogger('security')

# Log authentication failure
security_logger.warning(
    "Failed login attempt",
    extra={
        'email': email,
        'ip': client_ip,
        'user_agent': user_agent
    }
)

# Log threat detection
security_logger.error(
    "Threat detected and blocked",
    extra={
        'ip': client_ip,
        'threat_score': threat_score,
        'patterns_detected': patterns
    }
)

# Log privilege escalation attempt
security_logger.critical(
    "Unauthorized access attempt",
    extra={
        'user_id': user_id,
        'attempted_action': action,
        'required_role': required_role,
        'user_role': user_role
    }
)
```

### Audit Trail

```python
class AuditLog(models.Model):
    """Audit trail for security-critical operations"""

    user = ForeignKey(User, on_delete=SET_NULL, null=True)
    action = CharField(max_length=100)
    resource_type = CharField(max_length=50)
    resource_id = IntegerField()
    ip_address = GenericIPAddressField()
    user_agent = TextField()
    timestamp = DateTimeField(auto_now_add=True)
    details = JSONField(default=dict)

    class Meta:
        indexes = [
            Index(fields=['user', 'timestamp']),
            Index(fields=['resource_type', 'resource_id']),
            Index(fields=['action', 'timestamp']),
        ]
```

**Logged Actions**:
- User login/logout
- Password changes
- Permission changes
- Resource creation/deletion
- Sensitive data access
- Configuration changes

## Security Best Practices

### Development

1. **Never commit secrets**: Use environment variables
2. **Validate all input**: Use Pydantic schemas and validators
3. **Sanitize output**: Prevent XSS in responses
4. **Use parameterized queries**: Prevent SQL injection
5. **Implement CSRF protection**: For state-changing operations
6. **Use HTTPS only**: Enforce TLS in production
7. **Hash passwords**: Never store plain text passwords
8. **Implement rate limiting**: Prevent abuse
9. **Log security events**: Enable audit trail
10. **Keep dependencies updated**: Regular security updates

### Production Deployment

1. **Enable all security middleware**
2. **Use strong SECRET_KEY** (32+ random bytes)
3. **Configure CORS properly** (specific origins only)
4. **Enable HTTPS/TLS** with valid certificates
5. **Set security headers** (CSP, HSTS, etc.)
6. **Implement IP whitelisting** for admin endpoints
7. **Monitor security logs** in real-time
8. **Regular security audits** and penetration testing
9. **Backup encryption keys** securely
10. **Incident response plan** documented

### Secure Coding Checklist

- [ ] All user input validated
- [ ] SQL queries parameterized
- [ ] XSS prevention in templates
- [ ] CSRF tokens on forms
- [ ] Authentication on protected endpoints
- [ ] Authorization checks implemented
- [ ] Secrets in environment variables
- [ ] Error messages don't leak info
- [ ] Rate limiting enabled
- [ ] Security headers configured
- [ ] Audit logging implemented
- [ ] Dependencies up to date

## Incident Response

### Security Incident Workflow

```
1. Detection
   ↓
2. Containment (block IP, disable account)
   ↓
3. Investigation (review logs, identify scope)
   ↓
4. Eradication (remove threat, patch vulnerability)
   ↓
5. Recovery (restore services, verify integrity)
   ↓
6. Post-Incident Review (document lessons learned)
```

### Automatic Response Actions

**High Threat Score (≥100)**:
- Block IP address automatically
- Log detailed security event
- Send alert to security team
- Terminate user session

**Failed Login Attempts (≥5)**:
- Temporary account lock (15 minutes)
- Require CAPTCHA on next attempt
- Send security alert email
- Log authentication failure

**Suspicious Activity Patterns**:
- Increase monitoring level
- Require re-authentication
- Limit API access temporarily
- Flag for manual review

## Compliance & Standards

### OWASP Top 10 (2021) Coverage

- ✓ A01:2021 - Broken Access Control
- ✓ A02:2021 - Cryptographic Failures
- ✓ A03:2021 - Injection
- ✓ A04:2021 - Insecure Design
- ✓ A05:2021 - Security Misconfiguration
- ✓ A06:2021 - Vulnerable Components
- ✓ A07:2021 - Authentication Failures
- ✓ A08:2021 - Software and Data Integrity
- ✓ A09:2021 - Logging and Monitoring Failures
- ✓ A10:2021 - Server-Side Request Forgery

### Security Standards Compliance

- **NIST Cybersecurity Framework**: Identify, Protect, Detect, Respond, Recover
- **ISO 27001**: Information Security Management
- **PCI DSS**: Payment card data protection (if applicable)
- **GDPR**: Data privacy and protection (EU)
- **SOC 2**: Security, availability, confidentiality
