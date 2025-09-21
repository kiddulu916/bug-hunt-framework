"""
Celery configuration for Bug Bounty Automation Platform.
"""

import os
from celery import Celery
from django.conf import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')

app = Celery('bugbounty')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

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

# Configure task routes
app.conf.task_routes = {
    'apps.scanning.tasks.*': {'queue': 'scanning'},
    'apps.reconnaissance.tasks.*': {'queue': 'reconnaissance'},
    'apps.exploitation.tasks.*': {'queue': 'exploitation'},
    'apps.reporting.tasks.*': {'queue': 'reporting'},
}

# Configure priority queues
app.conf.task_default_queue = 'default'
app.conf.task_create_missing_queues = True

# Configure result backend
app.conf.result_backend_transport_options = {
    'master_name': 'mymaster',
    'visibility_timeout': 3600,
}

# Configure worker settings
app.conf.worker_prefetch_multiplier = 1
app.conf.worker_max_tasks_per_child = 1000
app.conf.task_acks_late = True
app.conf.task_reject_on_worker_lost = True