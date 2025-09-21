#!/bin/bash

# Bug Bounty Platform - Development Environment Startup Script
# This script simplifies Docker Compose operations for development

set -e

echo "🚀 Bug Bounty Platform - Development Environment"
echo "================================================"

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

# Function to display usage
usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start, up      Start all services"
    echo "  stop, down     Stop all services"
    echo "  restart        Restart all services"
    echo "  build          Build all containers"
    echo "  rebuild        Rebuild all containers (no cache)"
    echo "  logs           Show logs for all services"
    echo "  logs [service] Show logs for specific service"
    echo "  status         Show status of all services"
    echo "  shell [service] Open shell in service container"
    echo "  clean          Remove all containers, volumes, and images"
    echo "  help           Show this help message"
    echo ""
    echo "Services:"
    echo "  db             PostgreSQL database"
    echo "  redis          Redis cache and message broker"
    echo "  django         Django web application"
    echo "  fastapi        FastAPI application"
    echo "  celery-worker  Celery worker for background tasks"
    echo "  celery-beat    Celery beat scheduler"
    echo "  flower         Flower monitoring (Celery)"
    echo "  nginx          Nginx reverse proxy"
}

# Default command if none provided
COMMAND=${1:-start}

case $COMMAND in
    start|up)
        echo "🔄 Starting development environment..."
        docker-compose up -d
        echo ""
        echo "✅ Development environment started!"
        echo ""
        echo "🌐 Available services:"
        echo "  - Django Admin:    http://localhost:8001/admin/"
        echo "  - FastAPI API:     http://localhost:8000/docs"
        echo "  - FastAPI Admin:   http://localhost:8000/admin"
        echo "  - Flower Monitor:  http://localhost:5555"
        echo "  - Nginx Proxy:     http://localhost"
        echo ""
        echo "📊 To view logs: $0 logs"
        echo "🛑 To stop: $0 stop"
        ;;
    stop|down)
        echo "🛑 Stopping development environment..."
        docker-compose down
        echo "✅ Development environment stopped!"
        ;;
    restart)
        echo "🔄 Restarting development environment..."
        docker-compose down
        docker-compose up -d
        echo "✅ Development environment restarted!"
        ;;
    build)
        echo "🔨 Building containers..."
        docker-compose build
        echo "✅ Build completed!"
        ;;
    rebuild)
        echo "🔨 Rebuilding containers (no cache)..."
        docker-compose build --no-cache
        echo "✅ Rebuild completed!"
        ;;
    logs)
        if [ -n "$2" ]; then
            echo "📋 Showing logs for service: $2"
            docker-compose logs -f "$2"
        else
            echo "📋 Showing logs for all services..."
            docker-compose logs -f
        fi
        ;;
    status)
        echo "📊 Service status:"
        docker-compose ps
        ;;
    shell)
        if [ -z "$2" ]; then
            echo "❌ Error: Please specify a service name"
            echo "Usage: $0 shell [service]"
            echo "Available services: db, redis, django, fastapi, celery-worker, celery-beat, flower, nginx"
            exit 1
        fi
        echo "🐚 Opening shell in $2 container..."
        docker-compose exec "$2" /bin/bash || docker-compose exec "$2" /bin/sh
        ;;
    clean)
        echo "🧹 Cleaning up all containers, volumes, and images..."
        read -p "Are you sure? This will remove all data (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            docker-compose down -v --rmi all --remove-orphans
            echo "✅ Cleanup completed!"
        else
            echo "❌ Cleanup cancelled"
        fi
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