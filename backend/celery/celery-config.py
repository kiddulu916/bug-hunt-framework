"""
Celery Worker Configuration for Bug Bounty Automation Platform
backend/celery/celery-config.py

Enhanced configuration for handling security scanning workloads.
"""

import os
from celery import Celery
from kombu import Queue, Exchange

# Celery Worker Configuration
CELERY_TASK_ROUTES = {
    # Reconnaissance tasks
    'apps.reconnaissance.tasks.subdomain_enumeration': {'queue': 'recon'},
    'apps.reconnaissance.tasks.port_scanning': {'queue': 'recon'},
    'apps.reconnaissance.tasks.service_detection': {'queue': 'recon'},
    'apps.reconnaissance.tasks.dns_enumeration': {'queue': 'recon'},

    # Scanning tasks (high priority)
    'apps.scanning.tasks.nuclei_scan': {'queue': 'scanning'},
    'apps.scanning.tasks.custom_web_scan': {'queue': 'scanning'},
    'apps.scanning.tasks.api_security_scan': {'queue': 'scanning'},
    'apps.scanning.tasks.infrastructure_scan': {'queue': 'scanning'},

    # Vulnerability analysis (medium priority)
    'apps.vulnerabilities.tasks.analyze_results': {'queue': 'analysis'},
    'apps.vulnerabilities.tasks.classify_vulnerability': {'queue': 'analysis'},
    'apps.vulnerabilities.tasks.generate_proof_of_concept': {'queue': 'analysis'},

    # Exploitation tasks (low priority, careful execution)
    'apps.exploitation.tasks.exploit_chain_builder': {'queue': 'exploitation'},
    'apps.exploitation.tasks.payload_generator': {'queue': 'exploitation'},

    # Reporting tasks
    'apps.reporting.tasks.generate_report': {'queue': 'reporting'},
    'apps.reporting.tasks.send_notification': {'queue': 'reporting'},

    # Utility tasks
    'apps.targets.tasks.validate_target': {'queue': 'utility'},
    'apps.targets.tasks.update_target_status': {'queue': 'utility'},
}

# Queue Configuration
CELERY_TASK_QUEUES = (
    Queue('default', Exchange('default'), routing_key='default'),
    Queue('recon', Exchange('recon'), routing_key='recon'),
    Queue('scanning', Exchange('scanning'), routing_key='scanning'),
    Queue('analysis', Exchange('analysis'), routing_key='analysis'),
    Queue('exploitation', Exchange('exploitation'), routing_key='exploitation'),
    Queue('reporting', Exchange('reporting'), routing_key='reporting'),
    Queue('utility', Exchange('utility'), routing_key='utility'),
)

# Task Execution Configuration
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TIMEZONE = 'UTC'
CELERY_ENABLE_UTC = True

# Task Result Configuration
CELERY_RESULT_EXPIRES = 3600 * 24 * 7  # 7 days
CELERY_RESULT_PERSISTENT = True
CELERY_RESULT_COMPRESSION = 'gzip'

# Task Execution Settings
CELERY_TASK_SOFT_TIME_LIMIT = 3600  # 1 hour soft limit
CELERY_TASK_TIME_LIMIT = 7200  # 2 hour hard limit
CELERY_TASK_MAX_RETRIES = 3
CELERY_TASK_DEFAULT_RETRY_DELAY = 60  # 1 minute

# Worker Configuration
CELERY_WORKER_CONCURRENCY = int(os.getenv('CELERY_WORKER_CONCURRENCY', 4))
CELERY_WORKER_MAX_TASKS_PER_CHILD = 50  # Restart worker after 50 tasks
CELERY_WORKER_DISABLE_RATE_LIMITS = False
CELERY_WORKER_PREFETCH_MULTIPLIER = 1  # Important for long-running tasks

# Security and Rate Limiting
CELERY_TASK_ANNOTATIONS = {
    # Reconnaissance tasks - moderate rate limiting
    'apps.reconnaissance.tasks.*': {
        'rate_limit': '10/m',
        'time_limit': 1800,  # 30 minutes
        'soft_time_limit': 1500,  # 25 minutes
    },

    # Scanning tasks - strict rate limiting
    'apps.scanning.tasks.*': {
        'rate_limit': '5/m',
        'time_limit': 3600,  # 1 hour
        'soft_time_limit': 3300,  # 55 minutes
    },

    # Exploitation tasks - very strict rate limiting
    'apps.exploitation.tasks.*': {
        'rate_limit': '2/m',
        'time_limit': 1800,  # 30 minutes
        'soft_time_limit': 1500,  # 25 minutes
    },

    # Analysis tasks - balanced rate limiting
    'apps.vulnerabilities.tasks.*': {
        'rate_limit': '15/m',
        'time_limit': 900,  # 15 minutes
        'soft_time_limit': 750,  # 12.5 minutes
    },

    # Reporting tasks - high throughput
    'apps.reporting.tasks.*': {
        'rate_limit': '30/m',
        'time_limit': 300,  # 5 minutes
        'soft_time_limit': 240,  # 4 minutes
    },
}

# Monitoring and Logging
CELERY_SEND_EVENTS = True
CELERY_SEND_TASK_SENT_EVENT = True
CELERY_TRACK_STARTED = True

# Error Handling
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_TASK_ACKS_LATE = True

# Security Settings
CELERY_TASK_ALWAYS_EAGER = False  # Never run tasks synchronously
CELERY_EAGER_PROPAGATES_EXCEPTIONS = True

# Beat Scheduler Configuration (for periodic tasks)
CELERY_BEAT_SCHEDULE = {
    # Clean up old scan results
    'cleanup-old-scan-results': {
        'task': 'apps.scanning.tasks.cleanup_old_results',
        'schedule': 3600.0 * 24,  # Daily
    },

    # Update target monitoring
    'monitor-targets': {
        'task': 'apps.targets.tasks.monitor_active_targets',
        'schedule': 3600.0 * 4,  # Every 4 hours
    },

    # Generate daily reports
    'daily-reports': {
        'task': 'apps.reporting.tasks.generate_daily_summary',
        'schedule': 3600.0 * 24,  # Daily
    },

    # Tool status health check
    'tool-health-check': {
        'task': 'backend.tools.tasks.health_check_all_tools',
        'schedule': 3600.0,  # Hourly
    },
}

# Environment-specific optimizations
if os.getenv('DJANGO_SETTINGS_MODULE') == 'config.settings.production':
    # Production optimizations
    CELERY_WORKER_CONCURRENCY = int(os.getenv('CELERY_WORKER_CONCURRENCY', 8))
    CELERY_TASK_COMPRESSION = 'gzip'
    CELERY_RESULT_COMPRESSION = 'gzip'

elif os.getenv('DJANGO_SETTINGS_MODULE') == 'config.settings.development':
    # Development settings
    CELERY_TASK_EAGER_PROPAGATES = True
    CELERY_WORKER_HIJACK_ROOT_LOGGER = False