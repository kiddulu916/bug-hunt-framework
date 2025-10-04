#!/bin/bash
set -e

# Run migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Start Django with Gunicorn in background
gunicorn config.wsgi:application --bind 0.0.0.0:8001 --workers 4 --timeout 300 &

# Start FastAPI with Uvicorn
uvicorn config.asgi:application --host 0.0.0.0 --port 8000 --workers 4

# Wait for background processes
wait
