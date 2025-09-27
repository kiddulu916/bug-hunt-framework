"""
Celery configuration for Bug Bounty Automation Platform.
Enhanced for Docker architecture with multiple service containers.
"""

import os
from celery import Celery
from django.conf import settings
from kombu import Queue, Exchange

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')

app = Celery('bugbounty')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Enhanced queue configuration for Docker architecture
app.conf.task_queues = (
    Queue('default', Exchange('default'), routing_key='default'),
    Queue('scanning', Exchange('scanning'), routing_key='scanning'),
    Queue('reconnaissance', Exchange('reconnaissance'), routing_key='reconnaissance'),
    Queue('exploitation', Exchange('exploitation'), routing_key='exploitation'),
    Queue('reporting', Exchange('reporting'), routing_key='reporting'),
    Queue('tools', Exchange('tools'), routing_key='tools'),
    Queue('analysis', Exchange('analysis'), routing_key='analysis'),
)

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Docker-specific task discovery
app.autodiscover_tasks(['backend.tools'])

@app.task(bind=True)
def debug_task(self):
    """Debug task for testing Celery configuration"""
    print(f'Request: {self.request!r}')

@app.task(name='celery.ping')
def ping():
    """Health check task"""
    return 'pong'

# Configure periodic tasks
app.conf.beat_schedule = {
    'health-check': {
        'task': 'celery.ping',
        'schedule': 30.0,  # Every 30 seconds
    },
    'cleanup-old-scan-results': {
        'task': 'apps.scanning.tasks.cleanup_old_scan_results',
        'schedule': 3600.0,  # Every hour
    },
    'update-vulnerability-feeds': {
        'task': 'apps.vulnerabilities.tasks.update_vulnerability_feeds',
        'schedule': 86400.0,  # Every 24 hours
    },
}

# Enhanced task routes for Docker architecture
app.conf.task_routes = {
    'apps.scanning.tasks.*': {'queue': 'scanning'},
    'apps.reconnaissance.tasks.*': {'queue': 'reconnaissance'},
    'apps.exploitation.tasks.*': {'queue': 'exploitation'},
    'apps.reporting.tasks.*': {'queue': 'reporting'},
    'apps.vulnerabilities.tasks.*': {'queue': 'analysis'},
    'backend.tools.tasks.*': {'queue': 'tools'},
}

# Configure priority queues
app.conf.task_default_queue = 'default'
app.conf.task_create_missing_queues = True

# Configure result backend
app.conf.result_backend_transport_options = {
    'master_name': 'mymaster',
    'visibility_timeout': 3600,
}

# Configure worker settings for Docker environment
app.conf.worker_prefetch_multiplier = 1
app.conf.worker_max_tasks_per_child = 50  # Lower for Docker containers
app.conf.task_acks_late = True
app.conf.task_reject_on_worker_lost = True

# Docker-specific settings
app.conf.broker_connection_retry_on_startup = True
app.conf.broker_connection_retry = True
app.conf.broker_connection_max_retries = 10

# Tool execution settings
app.conf.task_annotations = {
    'backend.tools.tasks.*': {
        'rate_limit': '5/m',
        'time_limit': 3600,  # 1 hour timeout
        'soft_time_limit': 3300,  # 55 minutes soft timeout
    },
    'apps.scanning.tasks.*': {
        'rate_limit': '10/m',
        'time_limit': 1800,  # 30 minutes
        'soft_time_limit': 1500,  # 25 minutes
    },
    'apps.exploitation.tasks.*': {
        'rate_limit': '2/m',
        'time_limit': 900,  # 15 minutes
        'soft_time_limit': 750,  # 12.5 minutes
    },
}