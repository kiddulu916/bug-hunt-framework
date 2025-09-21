#!/bin/bash

# Bug Bounty Platform - Database Management Tools
# This script provides database utilities for development and production

set -e

echo "🗄️  Bug Bounty Platform - Database Tools"
echo "========================================"

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Error: docker-compose is not installed or not in PATH"
    exit 1
fi

# Function to display usage
usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  migrate        Run Django migrations"
    echo "  makemigrations Create new Django migrations"
    echo "  alembic-upgrade Run Alembic migrations (FastAPI)"
    echo "  alembic-revision Create new Alembic migration"
    echo "  createsuperuser Create Django superuser"
    echo "  dbshell        Open database shell"
    echo "  reset          Reset database (WARNING: destroys all data)"
    echo "  seed           Seed database with sample data"
    echo "  backup         Create database backup"
    echo "  restore [file] Restore database from backup"
    echo "  help           Show this help message"
    echo ""
    echo "Options:"
    echo "  --prod         Use production configuration"
}

# Determine environment
COMPOSE_FILES="-f docker-compose.yml"
ENV="development"

if [[ "$*" == *"--prod"* ]]; then
    COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml"
    ENV="production"
    # Remove --prod from arguments
    set -- "${@/--prod/}"
fi

# Default command if none provided
COMMAND=${1:-help}

echo "Environment: $ENV"
echo ""

case $COMMAND in
    migrate)
        echo "🔄 Running Django migrations..."
        docker-compose $COMPOSE_FILES exec django python manage.py migrate
        echo "✅ Django migrations completed!"
        ;;
    makemigrations)
        echo "📝 Creating Django migrations..."
        if [ -n "$2" ]; then
            docker-compose $COMPOSE_FILES exec django python manage.py makemigrations "$2"
        else
            docker-compose $COMPOSE_FILES exec django python manage.py makemigrations
        fi
        echo "✅ Django migrations created!"
        ;;
    alembic-upgrade)
        echo "🔄 Running Alembic migrations..."
        docker-compose $COMPOSE_FILES exec fastapi alembic upgrade head
        echo "✅ Alembic migrations completed!"
        ;;
    alembic-revision)
        if [ -z "$2" ]; then
            echo "❌ Error: Please provide a migration message"
            echo "Usage: $0 alembic-revision \"migration message\""
            exit 1
        fi
        echo "📝 Creating Alembic migration: $2"
        docker-compose $COMPOSE_FILES exec fastapi alembic revision --autogenerate -m "$2"
        echo "✅ Alembic migration created!"
        ;;
    createsuperuser)
        echo "👤 Creating Django superuser..."
        docker-compose $COMPOSE_FILES exec django python manage.py createsuperuser
        echo "✅ Superuser created!"
        ;;
    dbshell)
        echo "🐚 Opening database shell..."
        docker-compose $COMPOSE_FILES exec db psql -U postgres -d bugbounty_db
        ;;
    reset)
        echo "⚠️  WARNING: This will destroy ALL database data!"
        read -p "Are you sure you want to reset the database? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "🗑️  Resetting database..."
            docker-compose $COMPOSE_FILES down -v
            docker-compose $COMPOSE_FILES up -d db redis
            sleep 10
            docker-compose $COMPOSE_FILES up -d
            echo "✅ Database reset completed!"
        else
            echo "❌ Database reset cancelled"
        fi
        ;;
    seed)
        echo "🌱 Seeding database with sample data..."

        # Create a simple seed script
        cat > /tmp/seed_data.py << 'EOF'
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')
django.setup()

from django.contrib.auth import get_user_model
from targets.models import Target, Scope
from vulnerabilities.models import Vulnerability

User = get_user_model()

# Create test users
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@example.com', 'admin123')
    print("Created admin user")

if not User.objects.filter(username='testuser').exists():
    User.objects.create_user('testuser', 'test@example.com', 'test123')
    print("Created test user")

# Create sample targets
if not Target.objects.exists():
    target = Target.objects.create(
        name="Example Corp",
        description="Sample target for testing",
        target_type="web"
    )

    Scope.objects.create(
        target=target,
        scope_type="domain",
        value="example.com",
        is_included=True
    )

    Scope.objects.create(
        target=target,
        scope_type="ip_range",
        value="192.168.1.0/24",
        is_included=True
    )

    print("Created sample target and scopes")

print("Database seeding completed!")
EOF

        # Copy script to container and run it
        docker-compose $COMPOSE_FILES exec -T django python -c "$(cat /tmp/seed_data.py)"
        rm /tmp/seed_data.py

        echo "✅ Database seeding completed!"
        ;;
    backup)
        echo "💾 Creating database backup..."
        BACKUP_FILE="backup_$(date +%Y%m%d_%H%M%S).sql"
        docker-compose $COMPOSE_FILES exec -T db pg_dump -U postgres bugbounty_db > "$BACKUP_FILE"
        echo "✅ Backup created: $BACKUP_FILE"
        ;;
    restore)
        if [ -z "$2" ]; then
            echo "❌ Error: Please specify backup file"
            echo "Usage: $0 restore [backup_file.sql]"
            exit 1
        fi

        if [ ! -f "$2" ]; then
            echo "❌ Error: Backup file not found: $2"
            exit 1
        fi

        echo "🔄 Restoring database from: $2"
        docker-compose $COMPOSE_FILES exec -T db psql -U postgres bugbounty_db < "$2"
        echo "✅ Database restore completed!"
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