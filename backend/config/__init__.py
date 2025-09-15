"""
Django configuration initialization.
This module imports and exposes Django configuration components.
"""

import os
from django.conf import settings

# Import settings modules
from .settings import base, development, production, testing

# Determine current environment
ENVIRONMENT = os.getenv('DJANGO_ENVIRONMENT', 'development')

# Import appropriate settings based on environment
if ENVIRONMENT == 'production':
    from .settings.production import *
elif ENVIRONMENT == 'testing':
    from .settings.testing import *
else:
    from .settings.development import *

# Configuration metadata
__version__ = "1.0.0"
__environment__ = ENVIRONMENT

# Export commonly used settings components
__all__ = [
    # Settings modules
    "base",
    "development", 
    "production",
    "testing",
    
    # Environment info
    "ENVIRONMENT",
    "__version__",
    "__environment__",
    
    # Django settings (available after import)
    "settings",
]

def get_setting(setting_name, default=None):
    """
    Helper function to safely get Django settings.
    
    Args:
        setting_name: Name of the setting
        default: Default value if setting doesn't exist
        
    Returns:
        Setting value or default
    """
    return getattr(settings, setting_name, default)

def is_production():
    """Check if running in production environment."""
    return ENVIRONMENT == 'production'

def is_development():
    """Check if running in development environment."""
    return ENVIRONMENT == 'development'

def is_testing():
    """Check if running in testing environment."""
    return ENVIRONMENT == 'testing'

# Add helper functions to __all__
__all__.extend([
    "get_setting",
    "is_production",
    "is_development", 
    "is_testing",
])