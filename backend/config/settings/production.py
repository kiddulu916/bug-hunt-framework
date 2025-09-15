"""
Production settings for Bug Bounty Automation Platform.
"""

from .base import *
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration
from sentry_sdk.integrations.celery import CeleryIntegration
from sentry_sdk.integrations.logging import LoggingIntegration

# Security settings
DEBUG = False
TEMPLATE_DEBUG = False

# Security headers
SECURE_SSL_REDIRECT = env('SECURE_SSL_REDIRECT', default=True)
SECURE_HSTS_SECONDS = env('SECURE_HSTS_SECONDS', default=31536000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env('SECURE_HSTS_INCLUDE_SUBDOMAINS', default=True)
SECURE_HSTS_PRELOAD = env('SECURE_HSTS_PRELOAD', default=True)
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Cookie security
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'

# Production database settings with connection pooling
DATABASES['default'].update({
    'OPTIONS': {
        'options': '-c default_transaction_isolation=serializable',
        'sslmode': 'require',
    },
    'CONN_MAX_AGE': 600,  # 10 minutes
    'ENGINE': 'django.db.backends.postgresql',
})

# Production caching with Redis
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('REDIS_URL'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 50,
                'retry_on_timeout': True,
            },
            'SERIALIZER': 'django_redis.serializers.json.JSONSerializer',
            'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
        },
        'KEY_PREFIX': 'bugbounty',
        'TIMEOUT': 300,  # 5 minutes default timeout
    }
}

# Session configuration
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'
SESSION_COOKIE_AGE = 3600  # 1 hour

# Static files with WhiteNoise
MIDDLEWARE.insert(1, 'whitenoise.middleware.WhiteNoiseMiddleware')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
WHITENOISE_USE_FINDERS = True
WHITENOISE_AUTOREFRESH = True

# Media files with cloud storage
DEFAULT_FILE_STORAGE = 'django.core.files.storage.FileSystemStorage'
# TODO: Configure AWS S3 or similar for production media storage
# DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
# AWS_STORAGE_BUCKET_NAME = env('AWS_STORAGE_BUCKET_NAME')
# AWS_S3_REGION_NAME = env('AWS_S3_REGION_NAME', default='us-east-1')

# Email configuration for production
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = env('EMAIL_HOST')
EMAIL_PORT = env('EMAIL_PORT', default=587)
EMAIL_USE_TLS = env('EMAIL_USE_TLS', default=True)
EMAIL_HOST_USER = env('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL')

# Logging configuration for production
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'json': {
            '()': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(levelname)s %(asctime)s %(name)s %(process)d %(thread)d %(message)s'
        },
        'verbose': {
            'format': '{levelname} {asctime} {name} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'json',
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/app/logs/application.log',
            'maxBytes': 1024 * 1024 * 50,  # 50MB
            'backupCount': 10,
            'formatter': 'json',
        },
        'error_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/app/logs/error.log',
            'maxBytes': 1024 * 1024 * 50,  # 50MB
            'backupCount': 5,
            'formatter': 'json',
            'level': 'ERROR',
        },
    },
    'root': {
        'level': 'INFO',
        'handlers': ['console', 'file'],
    },
    'loggers': {
        'django': {
            'level': 'WARNING',
            'handlers': ['console', 'file'],
            'propagate': False,
        },
        'django.security': {
            'level': 'ERROR',
            'handlers': ['console', 'error_file'],
            'propagate': False,
        },
        'apps': {
            'level': 'INFO',
            'handlers': ['console', 'file'],
            'propagate': False,
        },
        'services': {
            'level': 'INFO',
            'handlers': ['console', 'file'],
            'propagate': False,
        },
        'celery': {
            'level': 'INFO',
            'handlers': ['console', 'file'],
            'propagate': False,
        },
        'celery.task': {
            'level': 'INFO',
            'handlers': ['console', 'file'],
            'propagate': False,
        },
    },
}

# Celery configuration for production
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_WORKER_MAX_TASKS_PER_CHILD = 1000
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_DISABLE_RATE_LIMITS = False
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_TASK_IGNORE_RESULT = False
CELERY_RESULT_EXPIRES = 3600  # 1 hour

# Production-specific bug bounty settings
BUG_BOUNTY_SETTINGS.update({
    'ENABLE_DEBUG_MODE': False,
    'VERBOSE_TOOL_OUTPUT': False,
    'SKIP_TOOL_VALIDATION': False,
    'MOCK_TOOL_EXECUTION': False,
    'TEST_MODE': False,
    'ENABLE_MONITORING': True,
    'MAX_CONCURRENT_SCANS': env('MAX_CONCURRENT_SCANS', default=5),
    'SCAN_TIMEOUT_HOURS': env('SCAN_TIMEOUT_HOURS', default=12),
})

# Rate limiting for production
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'

# CORS settings for production
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = env('CORS_ALLOWED_ORIGINS', default=[])
CORS_ALLOW_CREDENTIALS = True

# Sentry configuration for error tracking
SENTRY_DSN = env('SENTRY_DSN', default='')
if SENTRY_DSN:
    sentry_logging = LoggingIntegration(
        level=logging.INFO,        # Capture info and above as breadcrumbs
        event_level=logging.ERROR  # Send errors as events
    )
    
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[
            DjangoIntegration(auto_enabling=True),
            CeleryIntegration(monitor_beat_tasks=True),
            sentry_logging,
        ],
        traces_sample_rate=0.01,  # Lower sample rate for production
        send_default_pii=False,   # Don't send PII in production
        environment='production',
        release=env('APP_VERSION', default='unknown'),
        before_send=lambda event, hint: event if not DEBUG else None,
    )

# Health check configuration
HEALTH_CHECK = {
    'DISK_USAGE_MAX': 85,  # percent
    'MEMORY_MIN': 200,    # in MB
}

# Performance optimizations
CONN_MAX_AGE = 600  # Database connection pooling
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024  # 10MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024  # 10MB

# Admin security
ADMIN_URL = env('ADMIN_URL', default='admin/')  # Use custom admin URL in production
