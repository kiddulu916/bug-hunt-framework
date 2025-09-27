# Flower Dockerfile - Celery Monitoring Dashboard
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
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Install additional Flower dependencies
RUN pip install --no-cache-dir \
    flower==2.0.1 \
    prometheus-client==0.19.0 \
    grafana-api==1.0.3

# Copy Flower configuration files
COPY flower-config.py /app/flower-config.py
COPY flower-entrypoint.sh /app/flower-entrypoint.sh
COPY flower-dashboard.py /app/flower-dashboard.py

# Copy application code (for Django integration)
COPY ../ /app/

# Create necessary directories
RUN mkdir -p /app/logs /app/flower-data

# Make entrypoint executable
RUN chmod +x /app/flower-entrypoint.sh

# Expose Flower port
EXPOSE 5555

# Health check
HEALTHCHECK --interval=60s --timeout=30s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:5555/api/workers || exit 1

# Set entrypoint
ENTRYPOINT ["/app/flower-entrypoint.sh"]

# Default command
CMD ["celery", "-A", "config.celery", "flower"]