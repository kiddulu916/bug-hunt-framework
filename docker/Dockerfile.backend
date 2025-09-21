# Multi-stage build for production optimization
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    DJANGO_SETTINGS_MODULE=config.settings.production

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    postgresql-client \
    libpq-dev \
    curl \
    wget \
    git \
    # Penetration testing tools
    nmap \
    masscan \
    amass \
    subfinder \
    nuclei \
    httpx \
    gau \
    waybackurls \
    gospider \
    # Additional tools for vulnerability scanning
    sqlmap \
    nikto \
    dirb \
    gobuster \
    wpscan \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set work directory
WORKDIR /app

# Install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY backend/ .

# Create necessary directories
RUN mkdir -p media/evidence static logs \
    && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Development stage
FROM base as development
ENV DJANGO_SETTINGS_MODULE=config.settings.development
USER root
RUN pip install debugpy pytest-django factory-boy
USER appuser
EXPOSE 8000
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

# Production stage
FROM base as production
ENV DJANGO_SETTINGS_MODULE=config.settings.production

# Collect static files
RUN python manage.py collectstatic --noinput

# Run migrations (optional, can be done in docker-compose)
# RUN python manage.py migrate

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health/ || exit 1

# Production command
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "120", "config.wsgi:application"]