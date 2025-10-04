"""
Development settings for Bug Bounty Automation Platform.
"""

from .base import *

# Debug settings
DEBUG = True
TEMPLATE_DEBUG = True

# Development-specific apps
INSTALLED_APPS += [
    'django_extensions',
    'debug_toolbar',
    'silk',
]

# Development middleware
MIDDLEWARE += [
    'debug_toolbar.middleware.DebugToolbarMiddleware',
    'silk.middleware.SilkyMiddleware',
]

# Debug toolbar configuration for Docker environment
INTERNAL_IPS = [
    '127.0.0.1',
    'localhost',
    '0.0.0.0',
    'backend',
    'bugbounty_backend',
    '172.20.0.0/16',  # Docker network range
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

# Development database settings - completely replace DATABASES config
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('DB_NAME'),
        'USER': env('DB_USER'),
        'PASSWORD': env('DB_PASSWORD'),
        'HOST': env('DB_HOST'),
        'PORT': env('DB_PORT'),
        'OPTIONS': {
            'sslmode': 'disable',  # Explicitly disable SSL for development
        },
        'CONN_MAX_AGE': 0,  # Disable persistent connections in development
    }
}

# Use Redis cache in development for consistency with Docker setup
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('REDIS_URL', default='redis://redis:6379/1'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'IGNORE_EXCEPTIONS': True,  # Don't fail if Redis is unavailable
        }
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
    'SKIP_TOOL_VALIDATION': False,  # Tools are available in Docker containers
    'MOCK_TOOL_EXECUTION': env('MOCK_TOOLS', default=False),
    'TEST_MODE': True,
    'DOCKER_MODE': True,
    'TOOLS_CONTAINER_NAME': 'bugbounty_tools',
    'EVIDENCE_STORAGE_DIR': Path('/app/backend/evidence'),
    'SCAN_RESULTS_DIR': Path('/app/backend/scan_results'),
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
