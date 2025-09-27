"""
Flower Configuration for Bug Bounty Platform
backend/flower/flower-config.py

Enhanced Flower configuration with custom views and monitoring.
"""

import os
import sys
from datetime import timedelta

# Add Django project to Python path
sys.path.insert(0, '/app')

# Set Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')

# Basic Flower Configuration
port = int(os.getenv('FLOWER_PORT', 5555))
address = '0.0.0.0'

# Authentication
basic_auth = [f"{os.getenv('FLOWER_USERNAME', 'admin')}:{os.getenv('FLOWER_PASSWORD', 'admin')}"]

# Database for persistence
db = '/app/flower-data/flower.db'
persistent = True

# Broker connection
broker = os.getenv('CELERY_BROKER_URL', 'redis://:redis@redis:6379/0')
broker_api = os.getenv('CELERY_BROKER_URL', 'redis://:redis@redis:6379/0')

# Task monitoring configuration
max_tasks = 10000
tasks_columns = [
    'name', 'uuid', 'state', 'args', 'kwargs', 'result',
    'received', 'started', 'runtime', 'worker', 'retries'
]

# Auto-refresh settings
auto_refresh = True
enable_events = True

# UI Configuration
natural_time = True
tasks_refresh_interval = 3000  # 3 seconds
workers_refresh_interval = 3000  # 3 seconds

# Security
xheaders = True
cookie_secret = os.urandom(24).hex()

# Logging configuration
logging = 'INFO'

# Custom task filters for Bug Bounty Platform
TASK_FILTERS = {
    'reconnaissance': {
        'name': 'Reconnaissance Tasks',
        'pattern': 'apps.reconnaissance.*',
        'color': 'blue'
    },
    'scanning': {
        'name': 'Security Scanning',
        'pattern': 'apps.scanning.*',
        'color': 'red'
    },
    'analysis': {
        'name': 'Vulnerability Analysis',
        'pattern': 'apps.vulnerabilities.*',
        'color': 'orange'
    },
    'exploitation': {
        'name': 'Exploitation Tasks',
        'pattern': 'apps.exploitation.*',
        'color': 'purple'
    },
    'reporting': {
        'name': 'Report Generation',
        'pattern': 'apps.reporting.*',
        'color': 'green'
    },
    'tools': {
        'name': 'Tool Management',
        'pattern': 'backend.tools.*',
        'color': 'teal'
    }
}

# Custom columns for better monitoring
CUSTOM_COLUMNS = [
    {
        'name': 'Task Category',
        'accessor': 'name',
        'formatter': 'task_category_formatter'
    },
    {
        'name': 'Target',
        'accessor': 'args',
        'formatter': 'target_formatter'
    },
    {
        'name': 'Priority',
        'accessor': 'kwargs',
        'formatter': 'priority_formatter'
    }
]

# URL prefix (for reverse proxy setup)
url_prefix = os.getenv('FLOWER_URL_PREFIX', '')

# API settings
api = True

# Prometheus metrics (if enabled)
prometheus_metrics = os.getenv('FLOWER_PROMETHEUS_ENABLED', 'false').lower() == 'true'

if prometheus_metrics:
    try:
        from prometheus_client import start_http_server, Counter, Histogram, Gauge

        # Start Prometheus metrics server
        start_http_server(8000)

        # Define custom metrics
        TASK_COUNTER = Counter('flower_tasks_total', 'Total tasks processed', ['task_type', 'state'])
        TASK_DURATION = Histogram('flower_task_duration_seconds', 'Task execution time', ['task_type'])
        ACTIVE_WORKERS = Gauge('flower_active_workers', 'Number of active workers')

        print("Prometheus metrics enabled on port 8000")
    except ImportError:
        print("Prometheus client not available, metrics disabled")

# Email notifications (if configured)
email_notifications = {
    'enabled': os.getenv('FLOWER_EMAIL_ENABLED', 'false').lower() == 'true',
    'smtp_server': os.getenv('FLOWER_SMTP_SERVER', ''),
    'smtp_port': int(os.getenv('FLOWER_SMTP_PORT', 587)),
    'username': os.getenv('FLOWER_EMAIL_USERNAME', ''),
    'password': os.getenv('FLOWER_EMAIL_PASSWORD', ''),
    'recipients': os.getenv('FLOWER_EMAIL_RECIPIENTS', '').split(',')
}

# Custom task state colors
task_state_colors = {
    'PENDING': '#f0ad4e',
    'STARTED': '#5bc0de',
    'SUCCESS': '#5cb85c',
    'FAILURE': '#d9534f',
    'RETRY': '#f0ad4e',
    'REVOKED': '#777777'
}

# Worker monitoring thresholds
worker_monitoring = {
    'high_memory_threshold': 512,  # MB
    'high_cpu_threshold': 80,      # %
    'task_timeout_threshold': 3600 # seconds
}

# Custom formatters for task display
def task_category_formatter(task_name):
    """Format task name to show category"""
    for category, config in TASK_FILTERS.items():
        if config['pattern'].replace('*', '') in task_name:
            return f"<span class='label' style='background-color:{config['color']}'>{config['name']}</span>"
    return "<span class='label label-default'>Other</span>"

def target_formatter(args):
    """Extract target information from task args"""
    if args and len(args) > 0:
        if isinstance(args[0], dict) and 'target' in args[0]:
            return args[0]['target']
        elif isinstance(args[0], str):
            return args[0][:50] + ('...' if len(args[0]) > 50 else '')
    return 'N/A'

def priority_formatter(kwargs):
    """Extract priority from task kwargs"""
    if kwargs and 'priority' in kwargs:
        priority = kwargs['priority']
        colors = {'high': 'danger', 'medium': 'warning', 'low': 'info'}
        color = colors.get(priority.lower(), 'default')
        return f"<span class='label label-{color}'>{priority.upper()}</span>"
    return "<span class='label label-default'>NORMAL</span>"

print("Flower configuration loaded for Bug Bounty Platform")