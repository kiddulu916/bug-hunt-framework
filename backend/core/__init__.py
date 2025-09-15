"""
Core functionality initialization.
This module imports and exposes core components shared across the application.
"""

# Import core modules
from . import database, security, pagination, exceptions, constants

# Import commonly used components
from .database import (
    engine,
    SessionLocal,
    Base,
    get_db,
    get_db_session,
    DatabaseManager,
    db_manager,
    check_database_health,
)

from .security import (
    SecurityManager,
    security_manager,
    InputValidator,
    RateLimiter,
    rate_limiter,
    log_security_event,
)

from .pagination import (
    CustomPageNumberPagination,
    VulnerabilityPagination,
    ScanPagination,
    FastAPIPagination,
    VulnerabilityFastAPIPagination,
    ScanFastAPIPagination,
)

from .exceptions import (
    BugBountyPlatformException,
    DatabaseException,
    RecordNotFoundException,
    DuplicateRecordException,
    InvalidDataException,
    AuthenticationException,
    InvalidCredentialsException,
    TokenExpiredException,
    InvalidTokenException,
    InsufficientPermissionsException,
    ScanningException,
    ToolNotFoundException,
    ToolExecutionException,
    InvalidScanConfigurationException,
    ScanTimeoutException,
    ConcurrentScanLimitException,
    TargetException,
    InvalidTargetException,
    OutOfScopeException,
    RateLimitException,
    VulnerabilityException,
    InvalidVulnerabilityDataException,
    VulnerabilityProcessingException,
    ReportException,
    ReportGenerationException,
    TemplateNotFoundException,
    FileHandlingException,
    FileUploadException,
    FileProcessingException,
    InvalidFileFormatException,
    ExternalAPIException,
    APIRateLimitException,
    APITimeoutException,
    APIAuthenticationException,
    create_http_exception_from_platform_exception,
    log_exception,
    handle_database_error,
)

from .constants import (
    APP_NAME,
    APP_VERSION,
    API_VERSION,
    APP_DESCRIPTION,
    RECON_PHASES,
    ToolCategory,
    TOOL_CONFIGS,
    TOOL_TIMEOUTS,
    VULNERABILITY_TYPES,
    OWASP_TOP_10_2021,
    COMMON_CWE_MAPPINGS,
    CVSS_SCORE_RANGES,
    BUG_BOUNTY_PLATFORMS,
    REPORT_TYPES,
    REPORT_FORMATS,
    NOTIFICATION_TYPES,
    STATUS_MESSAGES,
    ERROR_CODES,
)

# Core metadata
__version__ = "1.0.0"
__title__ = "Bug Bounty Platform Core"
__description__ = "Core functionality and utilities for the Bug Bounty Automation Platform"

# Export all core components
__all__ = [
    # Core modules
    "database",
    "security",
    "pagination",
    "exceptions",
    "constants",

    # Database components
    "engine",
    "SessionLocal",
    "Base",
    "get_db",
    "get_db_session",
    "DatabaseManager",
    "db_manager",
    "check_database_health",

    # Security components
    "SecurityManager",
    "security_manager",
    "InputValidator",
    "RateLimiter",
    "rate_limiter",
    "log_security_event",

    # Pagination components
    "CustomPageNumberPagination",
    "VulnerabilityPagination",
    "ScanPagination",
    "FastAPIPagination",
    "VulnerabilityFastAPIPagination",
    "ScanFastAPIPagination",

    # Base exceptions
    "BugBountyPlatformException",

    # Database exceptions
    "DatabaseException",
    "RecordNotFoundException",
    "DuplicateRecordException",
    "InvalidDataException",

    # Authentication exceptions
    "AuthenticationException",
    "InvalidCredentialsException",
    "TokenExpiredException",
    "InvalidTokenException",
    "InsufficientPermissionsException",

    # Scanning exceptions
    "ScanningException",
    "ToolNotFoundException",
    "ToolExecutionException",
    "InvalidScanConfigurationException",
    "ScanTimeoutException",
    "ConcurrentScanLimitException",

    # Target exceptions
    "TargetException",
    "InvalidTargetException",
    "OutOfScopeException",
    "RateLimitException",

    # Vulnerability exceptions
    "VulnerabilityException",
    "InvalidVulnerabilityDataException",
    "VulnerabilityProcessingException",

    # Report exceptions
    "ReportException",
    "ReportGenerationException",
    "TemplateNotFoundException",

    # File handling exceptions
    "FileHandlingException",
    "FileUploadException",
    "FileProcessingException",
    "InvalidFileFormatException",

    # External API exceptions
    "ExternalAPIException",
    "APIRateLimitException",
    "APITimeoutException",
    "APIAuthenticationException",

    # Exception utilities
    "create_http_exception_from_platform_exception",
    "log_exception",
    "handle_database_error",

    # Application constants
    "APP_NAME",
    "APP_VERSION",
    "API_VERSION",
    "APP_DESCRIPTION",
    "RECON_PHASES",
    "ToolCategory",
    "TOOL_CONFIGS",
    "TOOL_TIMEOUTS",
    "VULNERABILITY_TYPES",
    "OWASP_TOP_10_2021",
    "COMMON_CWE_MAPPINGS",
    "CVSS_SCORE_RANGES",
    "BUG_BOUNTY_PLATFORMS",
    "REPORT_TYPES",
    "REPORT_FORMATS",
    "NOTIFICATION_TYPES",
    "STATUS_MESSAGES",
    "ERROR_CODES",

    # Core metadata
    "__version__",
    "__title__",
    "__description__",
]

# Utility functions for core functionality

def get_database_session():
    """
    Get a database session for manual operations.
    Returns a context manager for safe session handling.
    """
    return get_db_session()

def validate_input(input_data, validator_type="general"):
    """
    Validate input data using the security manager.

    Args:
        input_data: Data to validate
        validator_type: Type of validation to perform

    Returns:
        bool: True if valid, False otherwise
    """
    validator = InputValidator()

    if validator_type == "email":
        return validator.validate_email(input_data)
    elif validator_type == "url":
        return validator.validate_url(input_data) if security_manager.validate_url(input_data) else False
    elif validator_type == "domain":
        return validator.validate_domain(input_data)
    elif validator_type == "ip":
        return validator.validate_ip_address(input_data)
    else:
        # General validation - check for command injection, etc.
        return security_manager.validate_command_injection(input_data)

def create_paginated_response(items, page, page_size, total_count):
    """
    Create a paginated response using FastAPI pagination.

    Args:
        items: List of items for current page
        page: Current page number
        page_size: Items per page
        total_count: Total number of items

    Returns:
        dict: Paginated response structure
    """
    pagination = FastAPIPagination(page, page_size)

    # Create mock query object for pagination
    class MockQuery:
        def count(self):
            return total_count

        def offset(self, offset):
            return self

        def limit(self, limit):
            return self

        def all(self):
            return items

    mock_query = MockQuery()
    return pagination.paginate_query(mock_query, total_count)

def log_platform_event(event_type, message, details=None, level="info"):
    """
    Log platform events with consistent formatting.

    Args:
        event_type: Type of event
        message: Event message
        details: Additional event details
        level: Log level (debug, info, warning, error, critical)
    """
    import logging

    logger = logging.getLogger("core.platform")
    log_data = {
        "event_type": event_type,
        "message": message,
        "details": details or {},
        "timestamp": database.datetime.utcnow().isoformat()
    }

    if level == "debug":
        logger.debug("{event_type}: %s", message, extra=log_data)
    elif level == "warning":
        logger.warning("{event_type}: %s", message, extra=log_data)
    elif level == "error":
        logger.error("{event_type}: %s", message, extra=log_data)
    elif level == "critical":
        logger.critical(f"{event_type}: {message}", extra=log_data)
    else:
        logger.info("{event_type}: %s", message, extra=log_data)

# Add utility functions to exports
__all__.extend([
    "get_database_session",
    "validate_input",
    "create_paginated_response",
    "log_platform_event",
])
