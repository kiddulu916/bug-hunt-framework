# Tools Container Dockerfile - Integrated with Django Framework
# backend/tools/Dockerfile
FROM python:3.11-slim

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app:/app/backend

# Create app and tools directories
WORKDIR /app
RUN mkdir -p /opt/tools /app/evidence /app/scan_results

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y \
    # Build tools
    curl \
    wget \
    git \
    build-essential \
    libssl-dev \
    ca-certificates \
    pkg-config \
    libpcap-dev \
    libmagic1 \
    libmagic-dev \
    # Programming languages
    golang-go \
    nodejs \
    npm \
    ruby-full \
    # Network and DNS tools
    dnsutils \
    net-tools \
    iputils-ping \
    telnet \
    netcat-openbsd \
    socat \
    # Security scanning tools
    nmap \
    # Utilities
    unzip \
    zip \
    jq \
    parallel \
    rsync \
    screen \
    tmux \
    vim \
    nano \
    htop \
    && rm -rf /var/lib/apt/lists/*

# Set Go environment
ENV GOPATH=/opt/tools/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin:/opt/tools/bin

# Copy Django backend code first (for tool framework integration)
COPY . /app/backend/
COPY requirements.txt /app/requirements.txt

# Install Python dependencies (Django + tool framework)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# Copy tool installation script
COPY tools/install_tools.sh /install_tools.sh
RUN chmod +x /install_tools.sh

# Install essential penetration testing tools (skip complex wordlist downloads for now)
RUN bash -c 'set -e; \
echo "[*] Installing essential Go tools..."; \
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest; \
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest; \
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest; \
go install -v github.com/ffuf/ffuf/v2@latest; \
ln -sf $GOPATH/bin/* /opt/tools/bin/ || true; \
echo "[*] Essential tools installed successfully"'

# Create Django integration startup script
RUN cat > /start-tools.sh << 'EOF'
#!/bin/bash
set -e

echo "Starting Bug Bounty Tools Container..."

# Wait for database to be ready
echo "Waiting for database connection..."
until python /app/backend/manage.py check --database default >/dev/null 2>&1; do
    echo "Database not ready, waiting..."
    sleep 2
done

echo "Database is ready!"

# Initialize Django
cd /app/backend
export DJANGO_SETTINGS_MODULE=config.settings.development

# Run Django migrations (in case of new tool-related models)
python manage.py migrate --noinput

# Initialize tool framework
python -c "
import os, sys
sys.path.append('/app/backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')
import django
django.setup()
from backend.tools import initialize_tools
initialize_tools()
print('Tool framework initialized successfully')
"

echo "Tools container ready!"

# Keep container running
exec "$@"
EOF

RUN chmod +x /start-tools.sh


# Create volume mount points
VOLUME ["/app/evidence", "/app/scan_results", "/opt/tools/configs"]

# Expose common ports used by tools
EXPOSE 8080 8443 4444 4445

# Health check that tests both tools and Django integration
HEALTHCHECK --interval=60s --timeout=30s --start-period=120s --retries=3 \
    CMD python3 /opt/tools/bin/test_tools.py --quiet && \
        python3 /opt/tools/bin/django_tool_runner.py list >/dev/null 2>&1 || exit 1

# Set entrypoint to Django integration script
ENTRYPOINT ["/start-tools.sh"]

# Default command
CMD ["/bin/bash"]