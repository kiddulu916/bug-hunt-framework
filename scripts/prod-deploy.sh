#!/bin/bash

# Bug Bounty Platform - Production Deployment Script
# This script manages production deployment with docker-compose

set -e

echo "🚀 Bug Bounty Platform - Production Deployment"
echo "=============================================="

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Error: docker-compose is not installed or not in PATH"
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Error: Docker is not running"
    echo "Please start Docker and try again"
    exit 1
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "❌ Error: .env file not found"
    echo "Please copy .env.example to .env and configure production values"
    exit 1
fi

# Function to display usage
usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  deploy         Deploy production environment"
    echo "  update         Update production environment"
    echo "  stop           Stop production environment"
    echo "  restart        Restart production environment"
    echo "  logs           Show production logs"
    echo "  logs [service] Show logs for specific service"
    echo "  status         Show status of production services"
    echo "  backup         Backup database and media files"
    echo "  restore        Restore from backup"
    echo "  shell [service] Open shell in service container"
    echo "  monitoring     Start monitoring services (flower)"
    echo "  help           Show this help message"
    echo ""
    echo "Production Services:"
    echo "  db             PostgreSQL database"
    echo "  redis          Redis cache and message broker"
    echo "  django         Django web application"
    echo "  fastapi        FastAPI application"
    echo "  celery-worker  Celery worker for background tasks"
    echo "  celery-beat    Celery beat scheduler"
    echo "  nginx          Nginx reverse proxy"
}

# Compose files for production
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml"

# Default command if none provided
COMMAND=${1:-deploy}

case $COMMAND in
    deploy)
        echo "🚀 Deploying production environment..."

        # Build containers
        echo "🔨 Building production containers..."
        docker-compose $COMPOSE_FILES build

        # Start services
        echo "🔄 Starting production services..."
        docker-compose $COMPOSE_FILES up -d

        echo ""
        echo "✅ Production environment deployed!"
        echo ""
        echo "🌐 Services should be available at your configured domain"
        echo "📊 To view logs: $0 logs"
        echo "🛑 To stop: $0 stop"
        ;;
    update)
        echo "🔄 Updating production environment..."

        # Pull latest images and rebuild
        docker-compose $COMPOSE_FILES build --pull

        # Restart services
        docker-compose $COMPOSE_FILES up -d

        echo "✅ Production environment updated!"
        ;;
    stop)
        echo "🛑 Stopping production environment..."
        docker-compose $COMPOSE_FILES down
        echo "✅ Production environment stopped!"
        ;;
    restart)
        echo "🔄 Restarting production environment..."
        docker-compose $COMPOSE_FILES down
        docker-compose $COMPOSE_FILES up -d
        echo "✅ Production environment restarted!"
        ;;
    logs)
        if [ -n "$2" ]; then
            echo "📋 Showing production logs for service: $2"
            docker-compose $COMPOSE_FILES logs -f "$2"
        else
            echo "📋 Showing production logs for all services..."
            docker-compose $COMPOSE_FILES logs -f
        fi
        ;;
    status)
        echo "📊 Production service status:"
        docker-compose $COMPOSE_FILES ps
        ;;
    backup)
        echo "💾 Creating backup..."
        BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$BACKUP_DIR"

        # Backup database
        echo "📦 Backing up database..."
        docker-compose $COMPOSE_FILES exec -T db pg_dump -U postgres bugbounty_platform > "$BACKUP_DIR/database.sql"

        # Backup media files
        echo "📦 Backing up media files..."
        docker-compose $COMPOSE_FILES exec -T django tar -czf - /app/media > "$BACKUP_DIR/media.tar.gz"

        echo "✅ Backup created at: $BACKUP_DIR"
        ;;
    restore)
        if [ -z "$2" ]; then
            echo "❌ Error: Please specify backup directory"
            echo "Usage: $0 restore [backup_directory]"
            exit 1
        fi

        BACKUP_DIR="$2"
        if [ ! -d "$BACKUP_DIR" ]; then
            echo "❌ Error: Backup directory not found: $BACKUP_DIR"
            exit 1
        fi

        echo "🔄 Restoring from backup: $BACKUP_DIR"

        # Restore database
        if [ -f "$BACKUP_DIR/database.sql" ]; then
            echo "📦 Restoring database..."
            docker-compose $COMPOSE_FILES exec -T db psql -U postgres bugbounty_platform < "$BACKUP_DIR/database.sql"
        fi

        # Restore media files
        if [ -f "$BACKUP_DIR/media.tar.gz" ]; then
            echo "📦 Restoring media files..."
            docker-compose $COMPOSE_FILES exec -T django tar -xzf - -C / < "$BACKUP_DIR/media.tar.gz"
        fi

        echo "✅ Restore completed!"
        ;;
    shell)
        if [ -z "$2" ]; then
            echo "❌ Error: Please specify a service name"
            echo "Usage: $0 shell [service]"
            echo "Available services: db, redis, django, fastapi, celery-worker, celery-beat, nginx"
            exit 1
        fi
        echo "🐚 Opening shell in $2 container..."
        docker-compose $COMPOSE_FILES exec "$2" /bin/bash || docker-compose $COMPOSE_FILES exec "$2" /bin/sh
        ;;
    monitoring)
        echo "📊 Starting monitoring services..."
        docker-compose $COMPOSE_FILES --profile monitoring up -d flower
        echo "✅ Flower monitoring available at configured port"
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        echo "❌ Unknown command: $COMMAND"
        echo ""
        usage
        exit 1
        ;;
esac