# Celery Worker Dockerfile - Background Task Processing
FROM python:3.11-slim

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Set Python environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Install system dependencies for tools and network operations
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
    # Network tools for scanning tasks
    dnsutils \
    net-tools \
    iputils-ping \
    telnet \
    netcat-openbsd \
    # Basic utilities
    procps \
    htop \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy Celery configuration files
COPY celery-worker.py /app/celery-worker.py
COPY worker-entrypoint.sh /app/worker-entrypoint.sh
COPY celery-config.py /app/celery-config.py

# Copy application code
COPY ../ /app/

# Create necessary directories
RUN mkdir -p /app/logs /app/evidence /app/reports /app/scan_results /app/temp

# Make entrypoint executable
RUN chmod +x /app/worker-entrypoint.sh

# Expose port for monitoring
EXPOSE 5555

# Health check
HEALTHCHECK --interval=60s --timeout=30s --start-period=60s --retries=3 \
    CMD celery -A config.celery inspect ping || exit 1

# Set entrypoint
ENTRYPOINT ["/app/worker-entrypoint.sh"]

# Default command
CMD ["celery", "-A", "config.celery", "worker", "--loglevel=info"]