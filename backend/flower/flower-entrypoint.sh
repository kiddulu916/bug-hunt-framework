#!/bin/bash
# Flower Entrypoint for Bug Bounty Platform
set -e

echo "Starting Flower monitoring dashboard for Bug Bounty Platform..."

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

# Wait for at least one Celery worker to be available
echo "Waiting for Celery workers..."
timeout=60
counter=0
until python -c "
from celery import Celery
import os
import sys
sys.path.append('/app')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')

try:
    from config.celery import app
    inspect = app.control.inspect()
    workers = inspect.active()
    if workers:
        print('Celery workers are available!')
        exit(0)
    else:
        print('No active workers found')
        exit(1)
except Exception as e:
    print(f'Error checking workers: {e}')
    exit(1)
" || [[ $counter -eq $timeout ]]; do
    if [[ $counter -eq $timeout ]]; then
        echo "Warning: No Celery workers detected after ${timeout}s, starting Flower anyway..."
        break
    fi
    echo "No workers detected yet, waiting... ($counter/${timeout}s)"
    sleep 1
    ((counter++))
done

# Set default Flower configuration
export FLOWER_PORT=${FLOWER_PORT:-5555}
export FLOWER_USERNAME=${FLOWER_USERNAME:-admin}
export FLOWER_PASSWORD=${FLOWER_PASSWORD:-admin}
export FLOWER_URL_PREFIX=${FLOWER_URL_PREFIX:-}
export FLOWER_PERSISTENT=${FLOWER_PERSISTENT:-True}

# Create logs directory
mkdir -p /app/logs

# Initialize Flower configuration
python -c "
import os, sys
sys.path.append('/app')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')

# Create custom Flower configuration
flower_config = '''
# Flower Configuration for Bug Bounty Platform

# Basic Authentication
basic_auth = ['{username}:{password}']

# Database settings for persistent mode
db = '/app/flower-data/flower.db'
persistent = True

# API settings
enable_events = True
auto_refresh = True
tasks_columns = ['name', 'uuid', 'state', 'args', 'kwargs', 'result', 'received', 'started', 'runtime', 'worker']

# UI customization
natural_time = True
tasks_refresh_interval = 3000
workers_refresh_interval = 3000

# Security
xheaders = True
cookie_secret = '{cookie_secret}'

# Logging
logging = 'INFO'
'''.format(
    username=os.getenv('FLOWER_USERNAME', 'admin'),
    password=os.getenv('FLOWER_PASSWORD', 'admin'),
    cookie_secret=os.urandom(24).hex()
)

with open('/app/flower-config.py', 'w') as f:
    f.write('# Flower configuration\\n')
    f.write('# Generated automatically\\n\\n')
    for line in flower_config.strip().split('\\n'):
        if line.strip() and not line.startswith('#'):
            f.write(line + '\\n')

print('Flower configuration generated')
"

echo "Flower Configuration:"
echo "  - Broker URL: ${CELERY_BROKER_URL}"
echo "  - Result Backend: ${CELERY_RESULT_BACKEND}"
echo "  - Port: ${FLOWER_PORT}"
echo "  - Username: ${FLOWER_USERNAME}"
echo "  - Persistent: ${FLOWER_PERSISTENT}"
echo "  - URL Prefix: ${FLOWER_URL_PREFIX}"

echo "Flower monitoring dashboard ready!"

# Build flower command with all options
FLOWER_CMD=(
    "celery"
    "-A" "config.celery"
    "flower"
    "--port=${FLOWER_PORT}"
    "--basic_auth=${FLOWER_USERNAME}:${FLOWER_PASSWORD}"
    "--persistent=True"
    "--db=/app/flower-data/flower.db"
    "--max_tasks=10000"
    "--enable_events=True"
    "--natural_time=True"
    "--xheaders=True"
)

# Add URL prefix if specified
if [[ -n "${FLOWER_URL_PREFIX}" ]]; then
    FLOWER_CMD+=("--url_prefix=${FLOWER_URL_PREFIX}")
fi

echo "Starting Flower with command: ${FLOWER_CMD[*]}"

# Execute the command
exec "${FLOWER_CMD[@]}"