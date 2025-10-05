# Deployment Guide

## Production Deployment

### Prerequisites

- Docker & Docker Compose
- Domain name with SSL certificate
- PostgreSQL database (managed service recommended)
- Redis instance (managed service recommended)
- Sufficient server resources (see requirements below)

### System Requirements

**Minimum Requirements**:
- CPU: 4 cores
- RAM: 8GB
- Storage: 50GB SSD
- Network: 100 Mbps

**Recommended Requirements**:
- CPU: 8+ cores
- RAM: 16GB+
- Storage: 200GB+ SSD
- Network: 1 Gbps
- Backup storage: 500GB+

## Environment Configuration

### Production Environment Variables

Create `.env.production` file:

```bash
# Application
ENVIRONMENT=production
DEBUG=False

# Security
SECRET_KEY=<strong-random-key-64-chars>
JWT_SECRET_KEY=<strong-random-jwt-key>
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
ENCRYPTION_KEY=<fernet-encryption-key>

# Database
DATABASE_URL=postgresql://user:password@postgres.example.com:5432/bughunt
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=40

# Redis
REDIS_URL=redis://redis.example.com:6379/0
REDIS_MAX_CONNECTIONS=50

# Celery
CELERY_BROKER_URL=redis://redis.example.com:6379/0
CELERY_RESULT_BACKEND=redis://redis.example.com:6379/0
CELERY_TASK_ALWAYS_EAGER=False

# CORS
CORS_ORIGINS=https://app.example.com,https://admin.example.com
ALLOWED_HOSTS=example.com,*.example.com,api.example.com

# Security
ENABLE_RATE_LIMITING=true
ENABLE_THREAT_DETECTION=true
MAX_CONCURRENT_SCANS=10
SECURE_SSL_REDIRECT=true
SESSION_COOKIE_SECURE=true
CSRF_COOKIE_SECURE=true

# External Tools
NUCLEI_PATH=/usr/local/bin/nuclei
SUBFINDER_PATH=/usr/local/bin/subfinder
HTTPX_PATH=/usr/local/bin/httpx
AMASS_PATH=/usr/local/bin/amass
NMAP_PATH=/usr/bin/nmap

# Monitoring
SENTRY_DSN=https://your-sentry-dsn
LOG_LEVEL=INFO

# Storage
MEDIA_ROOT=/app/media
STATIC_ROOT=/app/staticfiles
REPORTS_DIR=/app/reports
EVIDENCE_DIR=/app/evidence

# Email (for notifications)
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=true
EMAIL_HOST_USER=your-email@example.com
EMAIL_HOST_PASSWORD=your-app-password

# Backup
BACKUP_ENABLED=true
BACKUP_RETENTION_DAYS=30
```

### Generating Secure Keys

```bash
# SECRET_KEY (64 characters)
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"

# ENCRYPTION_KEY (Fernet key)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# JWT_SECRET_KEY (random string)
openssl rand -base64 64
```

## Docker Deployment

### Production Docker Compose

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  # PostgreSQL Database
  postgres:
    image: postgres:15-alpine
    container_name: bughunt-postgres
    environment:
      POSTGRES_DB: bughunt
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    networks:
      - bughunt-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER}"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Redis Cache/Queue
  redis:
    image: redis:7-alpine
    container_name: bughunt-redis
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    networks:
      - bughunt-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  # FastAPI Application
  api:
    build:
      context: ./backend
      dockerfile: Dockerfile.prod
    container_name: bughunt-api
    command: gunicorn api.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
    env_file:
      - .env.production
    volumes:
      - ./media:/app/media
      - ./reports:/app/reports
      - ./evidence:/app/evidence
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - bughunt-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Django Admin
  django:
    build:
      context: ./backend
      dockerfile: Dockerfile.prod
    container_name: bughunt-django
    command: gunicorn config.wsgi:application --workers 2 --bind 0.0.0.0:8001
    env_file:
      - .env.production
    volumes:
      - ./media:/app/media
      - ./static:/app/staticfiles
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - bughunt-network
    restart: unless-stopped

  # Celery Workers
  celery-worker:
    build:
      context: ./backend
      dockerfile: Dockerfile.prod
    container_name: bughunt-celery-worker
    command: celery -A backend worker --loglevel=info --concurrency=4
    env_file:
      - .env.production
    volumes:
      - ./media:/app/media
      - ./reports:/app/reports
      - ./evidence:/app/evidence
    depends_on:
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy
    networks:
      - bughunt-network
    restart: unless-stopped

  # Celery Beat Scheduler
  celery-beat:
    build:
      context: ./backend
      dockerfile: Dockerfile.prod
    container_name: bughunt-celery-beat
    command: celery -A backend beat --loglevel=info
    env_file:
      - .env.production
    depends_on:
      - redis
    networks:
      - bughunt-network
    restart: unless-stopped

  # Flower (Celery Monitor)
  flower:
    build:
      context: ./backend
      dockerfile: Dockerfile.prod
    container_name: bughunt-flower
    command: celery -A backend flower --port=5555
    env_file:
      - .env.production
    ports:
      - "5555:5555"
    depends_on:
      - redis
      - celery-worker
    networks:
      - bughunt-network
    restart: unless-stopped

  # Nginx Reverse Proxy
  nginx:
    image: nginx:alpine
    container_name: bughunt-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./static:/app/staticfiles:ro
      - ./media:/app/media:ro
    depends_on:
      - api
      - django
    networks:
      - bughunt-network
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:

networks:
  bughunt-network:
    driver: bridge
```

### Production Dockerfile

Create `backend/Dockerfile.prod`:

```dockerfile
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    curl \
    wget \
    nmap \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install security tools
RUN wget -qO- https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.1.0_linux_amd64.tar.gz | tar -xz -C /usr/local/bin/ && \
    wget -qO- https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_2.6.3_linux_amd64.tar.gz | tar -xz -C /usr/local/bin/ && \
    wget -qO- https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_1.3.7_linux_amd64.tar.gz | tar -xz -C /usr/local/bin/

# Set work directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput

# Create necessary directories
RUN mkdir -p /app/media /app/reports /app/evidence /app/logs

# Set permissions
RUN chmod +x /app/start.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run application
CMD ["/app/start.sh"]
```

### Nginx Configuration

Create `nginx/nginx.conf`:

```nginx
events {
    worker_connections 1024;
}

http {
    upstream fastapi {
        server api:8000;
    }

    upstream django {
        server django:8001;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;

    server {
        listen 80;
        server_name api.example.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name api.example.com;

        # SSL Configuration
        ssl_certificate /etc/nginx/ssl/fullchain.pem;
        ssl_certificate_key /etc/nginx/ssl/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;

        # Security Headers
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Content-Security-Policy "default-src 'self'" always;

        # Client body size
        client_max_body_size 50M;

        # FastAPI endpoints
        location /api/ {
            limit_req zone=api_limit burst=20 nodelay;
            proxy_pass http://fastapi;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # WebSocket support
        location /ws/ {
            proxy_pass http://fastapi;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
        }

        # Django admin
        location /admin/ {
            proxy_pass http://django;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        # Authentication endpoints (stricter rate limit)
        location /api/auth/ {
            limit_req zone=login_limit burst=3 nodelay;
            proxy_pass http://fastapi;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }

        # Static files
        location /static/ {
            alias /app/staticfiles/;
            expires 30d;
            add_header Cache-Control "public, immutable";
        }

        # Media files
        location /media/ {
            alias /app/media/;
            expires 7d;
        }

        # Health check
        location /health {
            proxy_pass http://fastapi;
            access_log off;
        }
    }
}
```

## Deployment Steps

### 1. Server Setup

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Create application user
sudo useradd -m -s /bin/bash bughunt
sudo usermod -aG docker bughunt
```

### 2. Application Deployment

```bash
# Clone repository
su - bughunt
git clone https://github.com/your-org/bug-hunt-framework.git
cd bug-hunt-framework

# Create environment file
cp .env.example .env.production
nano .env.production  # Edit with production values

# Create required directories
mkdir -p media reports evidence logs backups nginx/ssl

# Copy SSL certificates
cp /path/to/fullchain.pem nginx/ssl/
cp /path/to/privkey.pem nginx/ssl/

# Build and start services
docker-compose -f docker-compose.prod.yml build
docker-compose -f docker-compose.prod.yml up -d

# Run migrations
docker-compose -f docker-compose.prod.yml exec api python manage.py migrate

# Create superuser
docker-compose -f docker-compose.prod.yml exec api python manage.py createsuperuser

# Collect static files
docker-compose -f docker-compose.prod.yml exec api python manage.py collectstatic --noinput
```

### 3. Verify Deployment

```bash
# Check services status
docker-compose -f docker-compose.prod.yml ps

# View logs
docker-compose -f docker-compose.prod.yml logs -f

# Test endpoints
curl https://api.example.com/health
curl https://api.example.com/api/docs
```

## SSL/TLS Configuration

### Using Let's Encrypt

```bash
# Install Certbot
sudo apt-get install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d api.example.com -d admin.example.com

# Auto-renewal
sudo certbot renew --dry-run

# Add renewal cron job
echo "0 0 * * * certbot renew --quiet" | sudo crontab -
```

### Manual SSL Setup

```bash
# Generate private key
openssl genrsa -out privkey.pem 4096

# Generate CSR
openssl req -new -key privkey.pem -out csr.pem

# Get certificate from CA
# Copy certificate files to nginx/ssl/
cp fullchain.pem nginx/ssl/
cp privkey.pem nginx/ssl/

# Set permissions
chmod 600 nginx/ssl/privkey.pem
chmod 644 nginx/ssl/fullchain.pem
```

## Database Management

### PostgreSQL Backups

```bash
# Manual backup
docker-compose -f docker-compose.prod.yml exec postgres pg_dump -U bughunt bughunt > backup_$(date +%Y%m%d).sql

# Automated backup script
cat > backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/app/backups"
DATE=$(date +%Y%m%d_%H%M%S)
docker-compose -f docker-compose.prod.yml exec -T postgres pg_dump -U bughunt bughunt | gzip > $BACKUP_DIR/backup_$DATE.sql.gz

# Keep only last 30 days
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +30 -delete
EOF

chmod +x backup.sh

# Add to crontab (daily at 2 AM)
echo "0 2 * * * /app/backup.sh" | crontab -
```

### Database Restore

```bash
# Restore from backup
docker-compose -f docker-compose.prod.yml exec -T postgres psql -U bughunt bughunt < backup_20250115.sql

# Restore from compressed backup
gunzip -c backup_20250115.sql.gz | docker-compose -f docker-compose.prod.yml exec -T postgres psql -U bughunt bughunt
```

## Monitoring & Logging

### Application Monitoring

**Sentry Integration**:

```python
# config/settings/production.py
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration

sentry_sdk.init(
    dsn=os.getenv('SENTRY_DSN'),
    integrations=[DjangoIntegration()],
    traces_sample_rate=0.1,
    send_default_pii=True,
    environment='production'
)
```

### Log Management

```bash
# View application logs
docker-compose -f docker-compose.prod.yml logs -f api

# View specific service logs
docker-compose -f docker-compose.prod.yml logs -f celery-worker

# Save logs to file
docker-compose -f docker-compose.prod.yml logs > logs/app_$(date +%Y%m%d).log
```

**Centralized Logging** (using ELK Stack):

```yaml
# Add to docker-compose.prod.yml
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data

  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    volumes:
      - ./logstash/config:/usr/share/logstash/pipeline

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    ports:
      - "5601:5601"
```

### Performance Monitoring

**Prometheus + Grafana**:

```yaml
# Add to docker-compose.prod.yml
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
```

## Scaling

### Horizontal Scaling

**Load Balancer Configuration**:

```nginx
# nginx.conf - upstream with multiple backends
upstream fastapi {
    least_conn;
    server api-1:8000;
    server api-2:8000;
    server api-3:8000;
}
```

**Scale Services**:

```bash
# Scale API service
docker-compose -f docker-compose.prod.yml up -d --scale api=3

# Scale Celery workers
docker-compose -f docker-compose.prod.yml up -d --scale celery-worker=5
```

### Database Scaling

**Read Replicas**:

```python
# config/settings/production.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME'),
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST'),
        'PORT': os.getenv('DB_PORT', 5432),
    },
    'read_replica': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME'),
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_REPLICA_HOST'),
        'PORT': os.getenv('DB_PORT', 5432),
    }
}

# Database router for read/write splitting
DATABASE_ROUTERS = ['core.db_router.ReadWriteRouter']
```

## Security Hardening

### Firewall Configuration

```bash
# UFW firewall setup
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable

# Limit SSH attempts
sudo ufw limit 22/tcp
```

### Docker Security

```bash
# Run containers with read-only filesystem
docker run --read-only ...

# Drop capabilities
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE ...

# Use non-root user
RUN useradd -m -s /bin/bash appuser
USER appuser
```

### Environment Secrets

**Using Docker Secrets**:

```yaml
# docker-compose.prod.yml
secrets:
  db_password:
    file: ./secrets/db_password.txt
  jwt_secret:
    file: ./secrets/jwt_secret.txt

services:
  api:
    secrets:
      - db_password
      - jwt_secret
```

## Maintenance

### Updates

```bash
# Update application code
git pull origin main

# Rebuild containers
docker-compose -f docker-compose.prod.yml build

# Apply database migrations
docker-compose -f docker-compose.prod.yml exec api python manage.py migrate

# Restart services with zero downtime
docker-compose -f docker-compose.prod.yml up -d --no-deps --build api
```

### Health Checks

```bash
# Check service health
curl https://api.example.com/health

# Database connection
docker-compose -f docker-compose.prod.yml exec postgres pg_isready

# Redis connection
docker-compose -f docker-compose.prod.yml exec redis redis-cli ping
```

### Cleanup

```bash
# Remove old Docker images
docker image prune -a

# Remove unused volumes
docker volume prune

# Clean up old logs
find /app/logs -name "*.log" -mtime +30 -delete

# Clean up old backups
find /app/backups -name "backup_*.sql.gz" -mtime +30 -delete
```

## Troubleshooting

### Common Issues

**Issue**: Service won't start
```bash
# Check logs
docker-compose -f docker-compose.prod.yml logs api

# Check resource usage
docker stats

# Restart service
docker-compose -f docker-compose.prod.yml restart api
```

**Issue**: Database connection errors
```bash
# Verify database is running
docker-compose -f docker-compose.prod.yml ps postgres

# Check connection string
docker-compose -f docker-compose.prod.yml exec api env | grep DATABASE_URL

# Test connection
docker-compose -f docker-compose.prod.yml exec postgres psql -U bughunt -d bughunt
```

**Issue**: High memory usage
```bash
# Check memory usage
docker stats

# Reduce worker concurrency
# Edit celery-worker command: --concurrency=2

# Restart with new settings
docker-compose -f docker-compose.prod.yml restart celery-worker
```

## Disaster Recovery

### Backup Strategy

1. **Database**: Daily automated backups, retained for 30 days
2. **Media Files**: Weekly backups to S3/external storage
3. **Configuration**: Version controlled in Git
4. **Docker Images**: Tagged and stored in registry

### Recovery Procedure

```bash
# 1. Restore database
gunzip -c backup_20250115.sql.gz | docker-compose -f docker-compose.prod.yml exec -T postgres psql -U bughunt bughunt

# 2. Restore media files
aws s3 sync s3://backup-bucket/media /app/media

# 3. Rebuild and start services
docker-compose -f docker-compose.prod.yml up -d --build

# 4. Verify functionality
curl https://api.example.com/health
```
