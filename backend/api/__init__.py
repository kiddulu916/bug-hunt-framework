"""
FastAPI application initialization.
This module imports and exposes the main FastAPI application and core API components.
"""

from .main import app
from . import routers, schemas, dependencies

# Import main components for easy access
from .main import app as fastapi_app
from .routers import vulnerabilities, targets, scans, reports
from .dependencies import get_db, get_current_user, require_permissions

# API metadata
__version__ = "1.0.0"
__title__ = "Bug Bounty Automation Platform API"
__description__ = "Comprehensive API for automated penetration testing and vulnerability management"

# Export main application and components
__all__ = [
    # Main FastAPI application
    "app",
    "fastapi_app",
    
    # Router modules
    "routers",
    "vulnerabilities",
    "targets", 
    "scans",
    "reports",
    
    # Schema modules
    "schemas",
    
    # Dependency modules
    "dependencies",
    "get_db",
    "get_current_user",
    "require_permissions",
    
    # API metadata
    "__version__",
    "__title__",
    "__description__",
]