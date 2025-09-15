"""
Authentication and authorization dependencies for FastAPI.
Handles JWT token validation and permission checking.
"""


import logging
from typing import Dict, List, Optional, Any
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError

from core.security import security_manager, log_security_event
from core.exceptions import (
    InvalidTokenException,
    TokenExpiredException
)

logger = logging.getLogger(__name__)

# Security scheme for extracting Bearer tokens
security = HTTPBearer(auto_error=False)

async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Dict[str, Any]:
    """
    Dependency to get current authenticated user from JWT token.

    Args:
        request: FastAPI request object
        credentials: HTTP Authorization credentials

    Returns:
        dict: User information from token

    Raises:
        HTTPException: If authentication fails
    """
    if not credentials:
        log_security_event(
            "authentication_failed",
            {"reason": "no_credentials", "ip": request.client.host}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # Verify token
        payload = security_manager.verify_token(credentials.credentials)

        # Extract user information
        user_id = payload.get("sub")
        username = payload.get("username")
        email = payload.get("email")
        permissions = payload.get("permissions", [])
        is_active = payload.get("is_active", True)

        if not user_id:
            raise InvalidTokenException()

        if not is_active:
            log_security_event(
                "inactive_user_access",
                {"user_id": user_id, "ip": request.client.host}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive"
            )

        user_data = {
            "user_id": int(user_id),
            "username": username,
            "email": email,
            "permissions": permissions,
            "is_active": is_active,
            "token_type": payload.get("type", "access")
        }

        # Log successful authentication
        log_security_event(
            "authentication_success",
            {"user_id": user_id, "username": username, "ip": request.client.host}
        )

        return user_data

    except JWTError as e:
        log_security_event(
            "authentication_failed",
            {"reason": "invalid_token", "error": str(e), "ip": request.client.host}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    except (InvalidTokenException, TokenExpiredException) as e:
        log_security_event(
            "authentication_failed",
            {"reason": "token_error", "error": str(e), "ip": request.client.host}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    except Exception as e:
        logger.error("Unexpected authentication error: %s", e)
        log_security_event(
            "authentication_error",
            {"error": str(e), "ip": request.client.host}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        ) from e

async def get_current_active_user(
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Dependency to get current active user.

    Args:
        current_user: User data from get_current_user dependency

    Returns:
        dict: Active user information

    Raises:
        HTTPException: If user is inactive
    """
    if not current_user.get("is_active", False):
        log_security_event(
            "inactive_user_blocked",
            {"user_id": current_user.get("user_id")}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive"
        )

    return current_user

class RequirePermissions:
    """
    Class-based dependency for checking user permissions.
    """

    def __init__(self, required_permissions: List[str], require_all: bool = False):
        """
        Initialize permission checker.

        Args:
            required_permissions: List of required permissions
            require_all: If True, user must have all permissions.
                        If False, user needs at least one permission.
        """
        self.required_permissions = required_permissions
        self.require_all = require_all

    def __call__(self, current_user: dict = Depends(get_current_active_user)):
        """
        Check user permissions.

        Args:
            current_user: Current user data

        Returns:
            dict: User data if permissions are satisfied

        Raises:
            HTTPException: If user lacks required permissions
        """
        user_permissions = current_user.get("permissions", [])

        # Admin users have all permissions
        if "admin" in user_permissions:
            return current_user

        # Check permissions
        if self.require_all:
            # User must have all required permissions
            missing_permissions = [
                perm for perm in self.required_permissions
                if perm not in user_permissions
            ]
            if missing_permissions:
                log_security_event(
                    "permission_denied",
                    {
                        "user_id": current_user.get("user_id"),
                        "required": self.required_permissions,
                        "missing": missing_permissions
                    }
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required permissions: {', '.join(missing_permissions)}"
                )
        else:
            # User needs at least one permission
            has_permission = any(
                perm in user_permissions for perm in self.required_permissions
            )
            if not has_permission:
                log_security_event(
                    "permission_denied",
                    {
                        "user_id": current_user.get("user_id"),
                        "required_any": self.required_permissions,
                        "user_permissions": user_permissions
                    }
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Requires one of: {', '.join(self.required_permissions)}"
                )

        return current_user

class RequireRole:
    """
    Class-based dependency for checking user roles.
    """

    def __init__(self, required_roles: List[str]):
        """
        Initialize role checker.

        Args:
            required_roles: List of required roles
        """
        self.required_roles = required_roles

    def __call__(self, current_user: dict = Depends(get_current_active_user)):
        """
        Check user roles.

        Args:
            current_user: Current user data

        Returns:
            dict: User data if roles are satisfied

        Raises:
            HTTPException: If user lacks required roles
        """
        user_roles = current_user.get("roles", [])

        # Check if user has any of the required roles
        has_role = any(role in user_roles for role in self.required_roles)

        if not has_role:
            log_security_event(
                "role_access_denied",
                {
                    "user_id": current_user.get("user_id"),
                    "required_roles": self.required_roles,
                    "user_roles": user_roles
                }
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(self.required_roles)}"
            )

        return current_user

async def get_optional_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[Dict[str, Any]]:
    """
    Dependency to get current user if authenticated, None otherwise.
    Useful for endpoints that work for both authenticated and anonymous users.

    Args:
        request: FastAPI request object
        credentials: Optional HTTP Authorization credentials

    Returns:
        dict or None: User information if authenticated, None otherwise
    """
    if not credentials:
        return None

    try:
        return await get_current_user(request, credentials)
    except HTTPException:
        # If authentication fails, return None instead of raising
        return None

# Common permission dependencies
require_admin = RequirePermissions(["admin"])
require_scan_access = RequirePermissions(["scan_access", "admin"])
require_report_access = RequirePermissions(["report_access", "admin"])
require_vulnerability_access = RequirePermissions(["vulnerability_access", "admin"])
require_target_management = RequirePermissions(["target_management", "admin"])

# Function-based permission dependencies for backward compatibility
def require_permissions(permissions: List[str], require_all: bool = False):
    """
    Function to create permission dependency.

    Args:
        permissions: List of required permissions
        require_all: If True, require all permissions

    Returns:
        callable: Permission dependency function
    """
    return RequirePermissions(permissions, require_all)

def require_roles(roles: List[str]):
    """
    Function to create role dependency.

    Args:
        roles: List of required roles

    Returns:
        callable: Role dependency function
    """
    return RequireRole(roles)

# Export commonly used dependencies
__all__ = [
    "get_current_user",
    "get_current_active_user",
    "get_optional_user",
    "RequirePermissions",
    "RequireRole",
    "require_permissions",
    "require_roles",
    "require_admin",
    "require_scan_access",
    "require_report_access",
    "require_vulnerability_access",
    "require_target_management",
]
