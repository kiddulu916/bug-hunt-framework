#!/bin/bash
# Celery Worker Entrypoint for Bug Bounty Platform
set -e

echo "Starting Celery Worker for Bug Bounty Platform..."

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

# Set up Celery worker optimizations
export C_FORCE_ROOT=1
export CELERY_OPTIMIZATION=fair

# Create log directory
mkdir -p /app/logs

# Log startup information
echo "Celery Worker Configuration:"
echo "  - Broker URL: ${CELERY_BROKER_URL}"
echo "  - Result Backend: ${CELERY_RESULT_BACKEND}"
echo "  - Concurrency: ${CELERY_WORKER_CONCURRENCY:-4}"
echo "  - Log Level: ${CELERY_LOG_LEVEL:-info}"
echo "  - Django Settings: ${DJANGO_SETTINGS_MODULE}"

# Initialize tool framework
echo "Initializing tool framework..."
python -c "
import os, sys
sys.path.append('/app')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')
import django
django.setup()

try:
    from backend.tools import initialize_tools
    initialize_tools()
    print('Tool framework initialized successfully')
except ImportError:
    print('Tool framework not available, skipping...')
except Exception as e:
    print(f'Tool framework initialization failed: {e}')
"

echo "Celery Worker ready!"

# Execute the command
exec "$@"