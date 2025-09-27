"""
Custom exceptions for Bug Bounty Automation Platform.
"""

from typing import Optional, Dict, Any
from fastapi import HTTPException, status
import logging

logger = logging.getLogger(__name__)


# Base exceptions

class BugBountyPlatformException(Exception):
    """
    Base exception class for the bug bounty platform.
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)

    def __str__(self):
        return f"{self.error_code}: {self.message}" if self.error_code else self.message


# Database exceptions

class DatabaseException(BugBountyPlatformException):
    """Base exception for database-related errors."""
    pass


class RecordNotFoundException(DatabaseException):
    """Raised when a requested record is not found."""

    def __init__(self, model_name: str, identifier: Any):
        message = f"{model_name} with identifier '{identifier}' not found"
        super().__init__(message, "RECORD_NOT_FOUND", {"model": model_name, "id": identifier})


class DuplicateRecordException(DatabaseException):
    """Raised when attempting to create a duplicate record."""

    def __init__(self, model_name: str, field: str, value: Any):
        message = f"{model_name} with {field}='{value}' already exists"
        super().__init__(message, "DUPLICATE_RECORD", {"model": model_name, "field": field, "value": value})


class InvalidDataException(DatabaseException):
    """Raised when data validation fails."""

    def __init__(self, field: str, value: Any, reason: str):
        message = f"Invalid value for field '{field}': {reason}"
        super().__init__(message, "INVALID_DATA", {"field": field, "value": value, "reason": reason})


class ValidationError(InvalidDataException):
    """Alias for InvalidDataException for compatibility."""
    pass


class SecurityError(BugBountyPlatformException):
    """Raised when security-related errors occur."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "SECURITY_ERROR", details)


# Authentication and authorization exceptions

class AuthenticationException(BugBountyPlatformException):
    """Base exception for authentication errors."""
    pass


class InvalidCredentialsException(AuthenticationException):
    """Raised when login credentials are invalid."""

    def __init__(self):
        super().__init__(
            "Invalid username or password",
            "INVALID_CREDENTIALS"
        )


class TokenExpiredException(AuthenticationException):
    """Raised when JWT token has expired."""

    def __init__(self):
        super().__init__(
            "Token has expired",
            "TOKEN_EXPIRED"
        )


class InvalidTokenException(AuthenticationException):
    """Raised when JWT token is malformed or invalid."""

    def __init__(self):
        super().__init__(
            "Invalid token",
            "INVALID_TOKEN"
        )

class InsufficientPermissionsException(BugBountyPlatformException):
    """Raised when user lacks required permissions."""

    def __init__(self, required_permissions: list):
        message = f"Insufficient permissions. Required: {', '.join(required_permissions)}"
        super().__init__(
            message,
            "INSUFFICIENT_PERMISSIONS",
            {"required_permissions": required_permissions}
        )

# Scanning and vulnerability exceptions

class ScanningException(BugBountyPlatformException):
    """Base exception for scanning-related errors."""
    pass

class ToolNotFoundException(ScanningException):
    """Raised when a required scanning tool is not found."""

    def __init__(self, tool_name: str):
        message = f"Scanning tool '{tool_name}' not found or not executable"
        super().__init__(message, "TOOL_NOT_FOUND", {"tool": tool_name})

class ToolExecutionException(ScanningException):
    """Raised when a scanning tool fails to execute properly."""

    def __init__(self, tool_name: str, exit_code: int, stderr: str):
        message = f"Tool '{tool_name}' execution failed with exit code {exit_code}"
        super().__init__(
            message,
            "TOOL_EXECUTION_FAILED",
            {"tool": tool_name, "exit_code": exit_code, "stderr": stderr}
        )

class InvalidScanConfigurationException(ScanningException):
    """Raised when scan configuration is invalid."""

    def __init__(self, config_issue: str):
        message = f"Invalid scan configuration: {config_issue}"
        super().__init__(message, "INVALID_SCAN_CONFIG", {"issue": config_issue})

class ScanTimeoutException(ScanningException):
    """Raised when a scan times out."""

    def __init__(self, timeout_seconds: int):
        message = f"Scan timed out after {timeout_seconds} seconds"
        super().__init__(message, "SCAN_TIMEOUT", {"timeout": timeout_seconds})

class ConcurrentScanLimitException(ScanningException):
    """Raised when maximum concurrent scans limit is exceeded."""

    def __init__(self, max_concurrent: int):
        message = f"Maximum concurrent scans limit ({max_concurrent}) exceeded"
        super().__init__(message, "CONCURRENT_SCAN_LIMIT", {"max_concurrent": max_concurrent})

# Target and scope exceptions

class TargetException(BugBountyPlatformException):
    """Base exception for target-related errors."""
    pass

class InvalidTargetException(TargetException):
    """Raised when target configuration is invalid."""

    def __init__(self, reason: str):
        message = f"Invalid target configuration: {reason}"
        super().__init__(message, "INVALID_TARGET", {"reason": reason})

class OutOfScopeException(TargetException):
    """Raised when attempting to scan out-of-scope assets."""

    def __init__(self, asset: str):
        message = f"Asset '{asset}' is out of scope for this target"
        super().__init__(message, "OUT_OF_SCOPE", {"asset": asset})

class RateLimitException(TargetException):
    """Raised when rate limiting is triggered."""

    def __init__(self, limit: str, retry_after: int):
        message = f"Rate limit exceeded: {limit}"
        super().__init__(
            message,
            "RATE_LIMIT_EXCEEDED",
            {"limit": limit, "retry_after": retry_after}
        )

# Vulnerability exceptions

class VulnerabilityException(BugBountyPlatformException):
    """Base exception for vulnerability-related errors."""
    pass

class InvalidVulnerabilityDataException(VulnerabilityException):
    """Raised when vulnerability data is invalid or incomplete."""

    def __init__(self, missing_fields: list):
        message = f"Invalid vulnerability data. Missing fields: {', '.join(missing_fields)}"
        super().__init__(
            message,
            "INVALID_VULNERABILITY_DATA",
            {"missing_fields": missing_fields}
        )

class VulnerabilityProcessingException(VulnerabilityException):
    """Raised when vulnerability processing fails."""

    def __init__(self, step: str, error: str):
        message = f"Vulnerability processing failed at step '{step}': {error}"
        super().__init__(
            message,
            "VULNERABILITY_PROCESSING_FAILED",
            {"step": step, "error": error}
        )

# Report generation exceptions

class ReportException(BugBountyPlatformException):
    """Base exception for report-related errors."""
    pass

class ReportGenerationException(ReportException):
    """Raised when report generation fails."""

    def __init__(self, report_type: str, error: str):
        message = f"Failed to generate {report_type} report: {error}"
        super().__init__(
            message,
            "REPORT_GENERATION_FAILED",
            {"report_type": report_type, "error": error}
        )

class TemplateNotFoundException(ReportException):
    """Raised when report template is not found."""

    def __init__(self, template_name: str):
        message = f"Report template '{template_name}' not found"
        super().__init__(message, "TEMPLATE_NOT_FOUND", {"template": template_name})

# File handling exceptions

class FileHandlingException(BugBountyPlatformException):
    """Base exception for file handling errors."""
    pass

class FileUploadException(FileHandlingException):
    """Raised when file upload fails."""

    def __init__(self, filename: str, reason: str):
        message = f"File upload failed for '{filename}': {reason}"
        super().__init__(message, "FILE_UPLOAD_FAILED", {"filename": filename, "reason": reason})

class FileProcessingException(FileHandlingException):
    """Raised when file processing fails."""

    def __init__(self, filename: str, operation: str, error: str):
        message = f"File processing failed for '{filename}' during {operation}: {error}"
        super().__init__(
            message,
            "FILE_PROCESSING_FAILED",
            {"filename": filename, "operation": operation, "error": error}
        )

class InvalidFileFormatException(FileHandlingException):
    """Raised when file format is not supported."""

    def __init__(self, filename: str, expected_formats: list):
        message = f"Invalid file format for '{filename}'. Expected: {', '.join(expected_formats)}"
        super().__init__(
            message,
            "INVALID_FILE_FORMAT",
            {"filename": filename, "expected_formats": expected_formats}
        )

# External API exceptions

class ExternalAPIException(BugBountyPlatformException):
    """Base exception for external API errors."""
    pass

class APIRateLimitException(ExternalAPIException):
    """Raised when external API rate limit is hit."""

    def __init__(self, api_name: str, retry_after: int):
        message = f"API rate limit exceeded for {api_name}"
        super().__init__(
            message,
            "API_RATE_LIMIT",
            {"api": api_name, "retry_after": retry_after}
        )

class APITimeoutException(ExternalAPIException):
    """Raised when external API call times out."""

    def __init__(self, api_name: str, timeout: int):
        message = f"API call to {api_name} timed out after {timeout} seconds"
        super().__init__(message, "API_TIMEOUT", {"api": api_name, "timeout": timeout})

class APIAuthenticationException(ExternalAPIException):
    """Raised when external API authentication fails."""

    def __init__(self, api_name: str):
        message = f"Authentication failed for {api_name} API"
        super().__init__(message, "API_AUTH_FAILED", {"api": api_name})

# Exception handlers for FastAPI

def create_http_exception_from_platform_exception(exc: BugBountyPlatformException) -> HTTPException:
    """
    Convert platform exception to FastAPI HTTPException.
    """
    status_code_mapping = {
        "RECORD_NOT_FOUND": status.HTTP_404_NOT_FOUND,
        "DUPLICATE_RECORD": status.HTTP_409_CONFLICT,
        "INVALID_DATA": status.HTTP_400_BAD_REQUEST,
        "INVALID_CREDENTIALS": status.HTTP_401_UNAUTHORIZED,
        "TOKEN_EXPIRED": status.HTTP_401_UNAUTHORIZED,
        "INVALID_TOKEN": status.HTTP_401_UNAUTHORIZED,
        "INSUFFICIENT_PERMISSIONS": status.HTTP_403_FORBIDDEN,
        "TOOL_NOT_FOUND": status.HTTP_500_INTERNAL_SERVER_ERROR,
        "TOOL_EXECUTION_FAILED": status.HTTP_500_INTERNAL_SERVER_ERROR,
        "INVALID_SCAN_CONFIG": status.HTTP_400_BAD_REQUEST,
        "SCAN_TIMEOUT": status.HTTP_408_REQUEST_TIMEOUT,
        "CONCURRENT_SCAN_LIMIT": status.HTTP_429_TOO_MANY_REQUESTS,
        "INVALID_TARGET": status.HTTP_400_BAD_REQUEST,
        "OUT_OF_SCOPE": status.HTTP_403_FORBIDDEN,
        "RATE_LIMIT_EXCEEDED": status.HTTP_429_TOO_MANY_REQUESTS,
        "INVALID_VULNERABILITY_DATA": status.HTTP_400_BAD_REQUEST,
        "VULNERABILITY_PROCESSING_FAILED": status.HTTP_500_INTERNAL_SERVER_ERROR,
        "REPORT_GENERATION_FAILED": status.HTTP_500_INTERNAL_SERVER_ERROR,
        "TEMPLATE_NOT_FOUND": status.HTTP_404_NOT_FOUND,
        "FILE_UPLOAD_FAILED": status.HTTP_400_BAD_REQUEST,
        "FILE_PROCESSING_FAILED": status.HTTP_500_INTERNAL_SERVER_ERROR,
        "INVALID_FILE_FORMAT": status.HTTP_400_BAD_REQUEST,
        "API_RATE_LIMIT": status.HTTP_429_TOO_MANY_REQUESTS,
        "API_TIMEOUT": status.HTTP_504_GATEWAY_TIMEOUT,
        "API_AUTH_FAILED": status.HTTP_502_BAD_GATEWAY,
    }

    status_code = status_code_mapping.get(exc.error_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

    return HTTPException(
        status_code=status_code,
        detail={
            "message": exc.message,
            "error_code": exc.error_code,
            "details": exc.details
        }
    )

# Utility functions for exception handling

def log_exception(exc: Exception, context: Dict[str, Any] = None):
    """
    Log exception with context information.
    """
    logger.exception(
        f"Exception occurred: {type(exc).__name__}",
        extra={
            "exception_type": type(exc).__name__,
            "exception_message": str(exc),
            "context": context or {},
        }
    )

def handle_database_error(func):
    """
    Decorator to handle common database errors.
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Convert common database errors to platform exceptions
            if "does not exist" in str(e).lower():
                raise RecordNotFoundException("Record", "unknown")
            elif "duplicate key" in str(e).lower():
                raise DuplicateRecordException("Record", "unknown", "unknown")
            elif "validation" in str(e).lower():
                raise InvalidDataException("unknown", "unknown", str(e))
            else:
                raise DatabaseException(str(e), "DATABASE_ERROR")

    return wrapper

# Export all exception classes
__all__ = [
    # Base exceptions
    'BugBountyPlatformException',

    # Database exceptions
    'DatabaseException',
    'RecordNotFoundException',
    'DuplicateRecordException',
    'InvalidDataException',
    'ValidationError',
    'SecurityError',

    # Authentication exceptions
    'AuthenticationException',
    'InvalidCredentialsException',
    'TokenExpiredException',
    'InvalidTokenException',
    'InsufficientPermissionsException',

    # Scanning exceptions
    'ScanningException',
    'ToolNotFoundException',
    'ToolExecutionException',
    'InvalidScanConfigurationException',
    'ScanTimeoutException',
    'ConcurrentScanLimitException',

    # Target exceptions
    'TargetException',
    'InvalidTargetException',
    'OutOfScopeException',
    'RateLimitException',

    # Vulnerability exceptions
    'VulnerabilityException',
    'InvalidVulnerabilityDataException',
    'VulnerabilityProcessingException',

    # Report exceptions
    'ReportException',
    'ReportGenerationException',
    'TemplateNotFoundException',

    # File handling exceptions
    'FileHandlingException',
    'FileUploadException',
    'FileProcessingException',
    'InvalidFileFormatException',

    # External API exceptions
    'ExternalAPIException',
    'APIRateLimitException',
    'APITimeoutException',
    'APIAuthenticationException',

    # Utilities
    'create_http_exception_from_platform_exception',
    'log_exception',
    'handle_database_error',
]
