"""
FastAPI dependencies initialization.
This module imports and exposes all API dependencies.
"""

from .database import get_db, get_db_with_transaction, check_db_health
from .auth import (
    get_current_user,
    get_current_active_user,
    get_optional_user,
    require_permissions,
    require_roles,
    require_admin,
    require_scan_access,
    require_report_access,
    require_vulnerability_access,
    require_target_management
)

__all__ = [
    # Database dependencies
    "get_db",
    "get_db_with_transaction",
    "check_db_health",

    # Authentication dependencies
    "get_current_user",
    "get_current_active_user",
    "get_optional_user",

    # Permission dependencies
    "require_permissions",
    "require_roles",
    "require_admin",
    "require_scan_access",
    "require_report_access",
    "require_vulnerability_access",
    "require_target_management",
]
