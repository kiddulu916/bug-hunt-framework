# Backend Dockerfile - Django/FastAPI Hybrid Service
FROM python:3.11-slim


# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Set Python environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Set working directory
WORKDIR /app


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
libgobject-2.0-0 \
libgdk-pixbuf-2.0-0 \
libpango-1.0-0 \
libpangocairo-1.0-0 \
shared-mime-info \
libmagic1 \
libmagic-dev \
&& rm -rf /var/lib/apt/lists/*

# Copy requirements first
COPY requirements.txt /app/

# Install dependencies directly to system Python
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt


# Copy application code
COPY . /app/

# Make startup script executable
RUN chmod +x /app/start.sh

# Create necessary directories
RUN mkdir -p /app/logs /app/media /app/static /app/evidence /app/reports /app/scan_results /app/profiles

# Expose ports
EXPOSE 8000 8001

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8001/admin/ || exit 1

# Default command (can be overridden in docker-compose)
CMD ["/app/start.sh"]
