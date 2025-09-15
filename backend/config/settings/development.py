"""
Development settings for Bug Bounty Automation Platform.
"""

from .base import *
import os

# Debug settings
DEBUG = True
TEMPLATE_DEBUG = True

# Development-specific apps
INSTALLED_APPS += [
    'django_extensions',
    'debug_toolbar',
    'django_silk',
]

# Development middleware
MIDDLEWARE += [
    'debug_toolbar.middleware.DebugToolbarMiddleware',
    'silk.middleware.SilkyMiddleware',
]

# Debug toolbar configuration
INTERNAL_IPS = [
    '127.0.0.1',
    'localhost',
    '0.0.0.0',
]

DEBUG_TOOLBAR_CONFIG = {
    'SHOW_TOOLBAR_CALLBACK': lambda request: DEBUG,
    'SHOW_TEMPLATE_CONTEXT': True,
    'ENABLE_STACKTRACES': True,
}

# Silk profiling configuration
SILKY_PYTHON_PROFILER = True
SILKY_PYTHON_PROFILER_BINARY = True
SILKY_PYTHON_PROFILER_RESULT_PATH = BASE_DIR / 'profiles'
SILKY_META = True

# Development database settings
DATABASES['default'].update({
    'OPTIONS': {
        'options': '-c default_transaction_isolation=read_committed'
    },
    'CONN_MAX_AGE': 0,  # Disable persistent connections in development
})

# Disable caching in development
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
    }
}

# Email backend for development
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Static files served by Django in development
STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'

# Media files served by Django in development
DEFAULT_FILE_STORAGE = 'django.core.files.storage.FileSystemStorage'

# CORS settings for development
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

# Security settings relaxed for development
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
SECURE_CONTENT_TYPE_NOSNIFF = False
SECURE_BROWSER_XSS_FILTER = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# Logging configuration for development
LOGGING['handlers']['console']['level'] = 'DEBUG'
LOGGING['loggers']['django']['level'] = 'DEBUG'
LOGGING['loggers']['apps']['level'] = 'DEBUG'
LOGGING['loggers']['services']['level'] = 'DEBUG'

# Add development-specific loggers
LOGGING['loggers'].update({
    'django.db.backends': {
        'level': 'DEBUG',
        'handlers': ['console'],
        'propagate': False,
    },
    'silk': {
        'level': 'DEBUG',
        'handlers': ['console'],
        'propagate': False,
    },
})

# Celery settings for development
CELERY_TASK_ALWAYS_EAGER = env('CELERY_ALWAYS_EAGER', default=False)
CELERY_TASK_EAGER_PROPAGATES = True

# Development-specific bug bounty settings
BUG_BOUNTY_SETTINGS.update({
    'ENABLE_DEBUG_MODE': True,
    'VERBOSE_TOOL_OUTPUT': True,
    'SKIP_TOOL_VALIDATION': True,  # Skip checking if tools exist
    'MOCK_TOOL_EXECUTION': env('MOCK_TOOLS', default=False),
    'TEST_MODE': True,
})

# Django Extensions configuration
SHELL_PLUS_PRINT_SQL = True
SHELL_PLUS_PRINT_SQL_TRUNCATE = 1000

# Allow any host in development
ALLOWED_HOSTS = ['*']

# Development-specific middleware order
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'debug_toolbar.middleware.DebugToolbarMiddleware',
    'silk.middleware.SilkyMiddleware',
] + [m for m in MIDDLEWARE if m not in [
    'corsheaders.middleware.CorsMiddleware',
    'debug_toolbar.middleware.DebugToolbarMiddleware',
    'silk.middleware.SilkyMiddleware',
]]
