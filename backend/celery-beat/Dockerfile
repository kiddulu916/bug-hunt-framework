# Celery Beat Dockerfile - Periodic Task Scheduler
FROM python:3.11-slim

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Set Python environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    libpq-dev \
    postgresql-client \
    git \
    libssl-dev \
    libffi-dev \
    python3-dev \
    pkg-config \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy Celery Beat configuration files
COPY celery-beat.py /app/celery-beat.py
COPY beat-entrypoint.sh /app/beat-entrypoint.sh
COPY beat-scheduler.py /app/beat-scheduler.py

# Copy application code
COPY ../ /app/

# Create necessary directories
RUN mkdir -p /app/logs /app/celerybeat-schedule

# Make entrypoint executable
RUN chmod +x /app/beat-entrypoint.sh

# Health check
HEALTHCHECK --interval=60s --timeout=30s --start-period=30s --retries=3 \
    CMD python -c "import os; import django; os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development'); django.setup(); from django_celery_beat.models import PeriodicTask; print('Beat scheduler healthy:', PeriodicTask.objects.count() >= 0)" || exit 1

# Set entrypoint
ENTRYPOINT ["/app/beat-entrypoint.sh"]

# Default command
CMD ["celery", "-A", "config.celery", "beat", "--loglevel=info"]