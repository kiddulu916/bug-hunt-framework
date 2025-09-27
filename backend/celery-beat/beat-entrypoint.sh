#!/bin/bash
# Celery Beat Entrypoint for Bug Bounty Platform
set -e

echo "Starting Celery Beat Scheduler for Bug Bounty Platform..."

# Wait for Redis to be ready
echo "Waiting for Redis connection..."
until python -c "
import redis
import os
import time
redis_url = os.getenv('CELERY_BROKER_URL', 'redis://:redis@redis:6379/0')
try:
    r = redis.from_url(redis_url)
    r.ping()
    print('Redis is ready!')
except Exception as e:
    print(f'Redis not ready: {e}')
    exit(1)
"; do
    echo "Redis not ready, waiting..."
    sleep 2
done

# Wait for PostgreSQL to be ready
echo "Waiting for database connection..."
until python manage.py check --database default >/dev/null 2>&1; do
    echo "Database not ready, waiting..."
    sleep 2
done

echo "Database is ready!"

# Run Django migrations (if needed)
echo "Running database migrations..."
python manage.py migrate --noinput

# Create Django-Celery-Beat tables
echo "Setting up Celery Beat database tables..."
python manage.py migrate django_celery_beat --noinput

# Initialize periodic tasks
echo "Initializing periodic tasks..."
python -c "
import os, sys
sys.path.append('/app')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')
import django
django.setup()

from django_celery_beat.models import PeriodicTask, IntervalSchedule, CrontabSchedule
from datetime import timedelta

# Create or update periodic tasks
def create_or_update_task(name, task, schedule, **kwargs):
    try:
        periodic_task, created = PeriodicTask.objects.get_or_create(
            name=name,
            defaults={'task': task, **kwargs}
        )
        if schedule:
            periodic_task.interval = schedule
            periodic_task.save()

        status = 'Created' if created else 'Updated'
        print(f'{status} periodic task: {name}')
    except Exception as e:
        print(f'Error creating task {name}: {e}')

# Daily cleanup task
daily_schedule, _ = IntervalSchedule.objects.get_or_create(
    every=1,
    period=IntervalSchedule.DAYS
)

create_or_update_task(
    name='cleanup-old-scan-results',
    task='apps.scanning.tasks.cleanup_old_results',
    schedule=daily_schedule,
    enabled=True
)

# Target monitoring every 4 hours
monitoring_schedule, _ = IntervalSchedule.objects.get_or_create(
    every=4,
    period=IntervalSchedule.HOURS
)

create_or_update_task(
    name='monitor-active-targets',
    task='apps.targets.tasks.monitor_active_targets',
    schedule=monitoring_schedule,
    enabled=True
)

# Tool health check every hour
hourly_schedule, _ = IntervalSchedule.objects.get_or_create(
    every=1,
    period=IntervalSchedule.HOURS
)

create_or_update_task(
    name='tool-health-check',
    task='backend.tools.tasks.health_check_all_tools',
    schedule=hourly_schedule,
    enabled=True
)

# Daily report generation at 2 AM
daily_report_schedule, _ = CrontabSchedule.objects.get_or_create(
    minute=0,
    hour=2,
    day_of_week='*',
    day_of_month='*',
    month_of_year='*'
)

create_or_update_task(
    name='generate-daily-reports',
    task='apps.reporting.tasks.generate_daily_summary',
    schedule=None,
    crontab=daily_report_schedule,
    enabled=True
)

print('Periodic tasks initialized successfully!')
"

# Remove old beat schedule file
rm -f /app/celerybeat-schedule.db

# Create log directory
mkdir -p /app/logs

echo "Celery Beat Configuration:"
echo "  - Broker URL: ${CELERY_BROKER_URL}"
echo "  - Result Backend: ${CELERY_RESULT_BACKEND}"
echo "  - Django Settings: ${DJANGO_SETTINGS_MODULE}"
echo "  - Schedule File: /app/celerybeat-schedule/celerybeat-schedule.db"

echo "Celery Beat Scheduler ready!"

# Execute the command
exec "$@"