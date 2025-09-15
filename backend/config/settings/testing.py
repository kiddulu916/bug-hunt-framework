"""
Testing settings for Bug Bounty Automation Platform.
"""

from .base import *
import tempfile

# Test database configuration
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
        'OPTIONS': {
            'timeout': 20,
        },
        'TEST': {
            'NAME': ':memory:',
        },
    }
}

# Use in-memory cache for testing
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'test-cache',
    }
}

# Disable migrations during testing for speed
class DisableMigrations:
    def __contains__(self, item):
        return True
    
    def __getitem__(self, item):
        return None

MIGRATION_MODULES = DisableMigrations()

# Password hashers optimized for testing speed
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Disable logging during tests
LOGGING_CONFIG = None
import logging
logging.disable(logging.CRITICAL)

# Email backend for testing
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

# Static and media files for testing
STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'
DEFAULT_FILE_STORAGE = 'django.core.files.storage.FileSystemStorage'

# Use temporary directories for testing
MEDIA_ROOT = tempfile.mkdtemp()
STATIC_ROOT = tempfile.mkdtemp()

# Celery configuration for testing
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_BROKER_URL = 'memory://'
CELERY_RESULT_BACKEND = 'cache+memory://'

# Security settings for testing
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# Debug settings
DEBUG = True
TEMPLATE_DEBUG = True

# Allow all hosts during testing
ALLOWED_HOSTS = ['*']

# CORS settings for testing
CORS_ALLOW_ALL_ORIGINS = True

# Testing-specific bug bounty settings
BUG_BOUNTY_SETTINGS.update({
    'ENABLE_DEBUG_MODE': True,
    'VERBOSE_TOOL_OUTPUT': False,
    'SKIP_TOOL_VALIDATION': True,
    'MOCK_TOOL_EXECUTION': True,  # Always mock tools in tests
    'TEST_MODE': True,
    'ENABLE_MONITORING': False,
    'MAX_SCAN_DURATION_HOURS': 0.1,  # 6 minutes for testing
})

# Mock tool paths for testing
TOOL_PATHS = {tool: f'/mock/bin/{tool}' for tool in TOOL_PATHS.keys()}

# Testing-specific middleware (remove rate limiting)
MIDDLEWARE = [m for m in MIDDLEWARE if 'ratelimit' not in m]

# Disable rate limiting during tests
RATELIMIT_ENABLE = False

# Fast JWT tokens for testing
SIMPLE_JWT.update({
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
    'REFRESH_TOKEN_LIFETIME': timedelta(minutes=10),
})

# Test-specific REST framework settings
REST_FRAMEWORK.update({
    'TEST_REQUEST_DEFAULT_FORMAT': 'json',
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
})

# Health check configuration for testing
HEALTH_CHECK = {
    'DISK_USAGE_MAX': 99,  # percent
    'MEMORY_MIN': 10,     # in MB
}

# Testing constants
TEST_SETTINGS = {
    'MOCK_VULNERABILITY_DATA': True,
    'SKIP_EXTERNAL_API_CALLS': True,
    'USE_FACTORY_BOY': True,
    'ENABLE_COVERAGE': True,
}
