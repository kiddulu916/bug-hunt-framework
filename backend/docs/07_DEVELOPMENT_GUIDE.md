# Development Guide

## Getting Started

### Prerequisites

**Required Software**:
- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose (optional)
- Git

**Security Tools** (for full functionality):
- Nuclei
- Subfinder
- HTTPX
- Amass
- Nmap

### Initial Setup

#### 1. Clone Repository

```bash
git clone https://github.com/your-org/bug-hunt-framework.git
cd bug-hunt-framework
```

#### 2. Create Virtual Environment

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/Mac
# OR
.venv\Scripts\activate  # Windows
```

#### 3. Install Dependencies

```bash
cd backend

# Install Python dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt  # If available
```

#### 4. Environment Configuration

Create `.env` file in `backend/` directory:

```bash
# Database
DATABASE_URL=postgresql://bughunt:password@localhost:5432/bughunt
REDIS_URL=redis://localhost:6379/0

# Django Settings
SECRET_KEY=your-secret-key-here-change-in-production
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# FastAPI Settings
JWT_SECRET_KEY=your-jwt-secret-key-here
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Encryption
ENCRYPTION_KEY=your-fernet-encryption-key-here

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost:8000

# Celery
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Security Tools Paths
NUCLEI_PATH=/usr/local/bin/nuclei
SUBFINDER_PATH=/usr/local/bin/subfinder
HTTPX_PATH=/usr/local/bin/httpx
AMASS_PATH=/usr/local/bin/amass
NMAP_PATH=/usr/bin/nmap

# Feature Flags
ENABLE_EXPLOITATION=true
MAX_CONCURRENT_SCANS=5

# Logging
LOG_LEVEL=DEBUG
```

#### 5. Database Setup

**Option A: Using Docker**:
```bash
# Start PostgreSQL and Redis
docker-compose -f docker-compose.dev.yml up -d postgres redis
```

**Option B: Local Installation**:
```bash
# Install PostgreSQL (Ubuntu/Debian)
sudo apt-get install postgresql postgresql-contrib

# Create database and user
sudo -u postgres psql
CREATE DATABASE bughunt;
CREATE USER bughunt WITH PASSWORD 'password';
GRANT ALL PRIVILEGES ON DATABASE bughunt TO bughunt;
\q

# Install Redis
sudo apt-get install redis-server
sudo systemctl start redis
```

#### 6. Run Migrations

```bash
# Set Django settings module
export DJANGO_SETTINGS_MODULE=config.settings.development

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser
```

#### 7. Start Development Server

**Terminal 1 - Django Admin**:
```bash
python manage.py runserver 8001
```

**Terminal 2 - FastAPI**:
```bash
uvicorn api.main:app --reload --port 8000
```

**Terminal 3 - Celery Worker**:
```bash
celery -A backend worker --loglevel=info
```

**Terminal 4 - Celery Beat** (for scheduled tasks):
```bash
celery -A backend beat --loglevel=info
```

### Using Docker (Recommended)

```bash
# Start all services
./scripts/dev-start.sh start

# View logs
./scripts/dev-start.sh logs

# Stop services
./scripts/dev-start.sh stop

# Rebuild containers
./scripts/dev-start.sh rebuild
```

Services will be available at:
- FastAPI: http://localhost:8000
- Django Admin: http://localhost:8001/admin
- API Docs: http://localhost:8000/api/docs
- Flower (Celery Monitor): http://localhost:5555

## Development Workflow

### Project Structure

```
backend/
├── alembic/              # SQLAlchemy migrations
├── api/                  # FastAPI application
│   ├── dependencies/     # Dependency injection
│   ├── routers/          # API endpoints
│   ├── schemas/          # Pydantic models
│   └── main.py           # FastAPI app
├── apps/                 # Django applications
│   ├── targets/
│   ├── vulnerabilities/
│   ├── scanning/
│   └── ...
├── config/               # Django settings
│   └── settings/
│       ├── base.py
│       ├── development.py
│       ├── testing.py
│       └── production.py
├── core/                 # Core utilities
│   ├── security.py
│   ├── pagination.py
│   └── middleware.py
├── services/             # Business logic
│   ├── scanner_engines/
│   └── ...
├── tests/                # Test suite
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── manage.py
└── requirements.txt
```

### Code Style

**Use Black for formatting**:
```bash
# Format all Python files
black backend/

# Check formatting
black --check backend/
```

**Use Ruff for linting**:
```bash
# Lint code
ruff check backend/

# Auto-fix issues
ruff check --fix backend/
```

**Type Hints**:
```python
from typing import List, Optional, Dict

def get_vulnerabilities(
    target_id: int,
    severity: Optional[str] = None
) -> List[Dict]:
    """
    Get vulnerabilities for target

    Args:
        target_id: Target ID
        severity: Optional severity filter

    Returns:
        List of vulnerability dictionaries
    """
    # Implementation
```

### Creating New Features

#### 1. Create Django App

```bash
# Create new app
python manage.py startapp feature_name backend/apps/feature_name

# Add to INSTALLED_APPS in settings
INSTALLED_APPS = [
    ...
    'apps.feature_name',
]
```

#### 2. Create Models

```python
# apps/feature_name/models.py
from django.db import models

class FeatureModel(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'feature_model'
        ordering = ['-created_at']

    def __str__(self):
        return self.name
```

#### 3. Create Migrations

```bash
# Generate migration
python manage.py makemigrations

# Apply migration
python manage.py migrate

# Check migration status
python manage.py showmigrations
```

#### 4. Create Pydantic Schemas

```python
# api/schemas/feature.py
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional

class FeatureBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str

class FeatureCreate(FeatureBase):
    pass

class FeatureUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

class FeatureResponse(FeatureBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True  # Pydantic v2
```

#### 5. Create Service

```python
# services/feature_service.py
from apps.feature_name.models import FeatureModel
from typing import List, Optional

class FeatureService:
    """Service for feature operations"""

    @staticmethod
    def get_features(filters: dict = None) -> List[FeatureModel]:
        """Get features with optional filters"""
        queryset = FeatureModel.objects.all()

        if filters:
            if 'name' in filters:
                queryset = queryset.filter(name__icontains=filters['name'])

        return queryset

    @staticmethod
    def create_feature(data: dict) -> FeatureModel:
        """Create new feature"""
        return FeatureModel.objects.create(**data)

    @staticmethod
    def update_feature(feature_id: int, data: dict) -> FeatureModel:
        """Update feature"""
        feature = FeatureModel.objects.get(id=feature_id)
        for key, value in data.items():
            setattr(feature, key, value)
        feature.save()
        return feature
```

#### 6. Create API Router

```python
# api/routers/feature.py
from fastapi import APIRouter, Depends, HTTPException
from api.schemas.feature import FeatureCreate, FeatureResponse, FeatureUpdate
from services.feature_service import FeatureService
from api.dependencies.auth import get_current_user

router = APIRouter(prefix="/features", tags=["features"])

@router.get("/", response_model=List[FeatureResponse])
async def list_features(
    name: Optional[str] = None,
    current_user = Depends(get_current_user)
):
    """List features"""
    filters = {}
    if name:
        filters['name'] = name

    features = FeatureService.get_features(filters)
    return features

@router.post("/", response_model=FeatureResponse, status_code=201)
async def create_feature(
    feature: FeatureCreate,
    current_user = Depends(get_current_user)
):
    """Create feature"""
    return FeatureService.create_feature(feature.dict())

@router.get("/{feature_id}", response_model=FeatureResponse)
async def get_feature(
    feature_id: int,
    current_user = Depends(get_current_user)
):
    """Get feature by ID"""
    feature = FeatureService.get_features({'id': feature_id}).first()
    if not feature:
        raise HTTPException(status_code=404, detail="Feature not found")
    return feature

@router.put("/{feature_id}", response_model=FeatureResponse)
async def update_feature(
    feature_id: int,
    feature_update: FeatureUpdate,
    current_user = Depends(get_current_user)
):
    """Update feature"""
    try:
        return FeatureService.update_feature(
            feature_id,
            feature_update.dict(exclude_unset=True)
        )
    except FeatureModel.DoesNotExist:
        raise HTTPException(status_code=404, detail="Feature not found")
```

#### 7. Register Router

```python
# api/main.py
from api.routers import feature

app.include_router(feature.router, prefix="/api")
```

## Testing

### Test Structure

```
tests/
├── conftest.py           # Pytest fixtures
├── unit/                 # Unit tests
│   ├── test_models/
│   ├── test_services/
│   └── test_utils/
├── integration/          # Integration tests
│   ├── test_api/
│   └── test_workflows/
└── e2e/                  # End-to-end tests
    └── test_scan_flow/
```

### Running Tests

**All Tests**:
```bash
DJANGO_SETTINGS_MODULE=config.settings.testing pytest tests/ -v
```

**Specific Test Category**:
```bash
# Unit tests only
DJANGO_SETTINGS_MODULE=config.settings.testing pytest tests/unit/ -v

# Integration tests
DJANGO_SETTINGS_MODULE=config.settings.testing pytest tests/integration/ -v

# E2E tests
DJANGO_SETTINGS_MODULE=config.settings.testing pytest tests/e2e/ -v
```

**With Coverage**:
```bash
DJANGO_SETTINGS_MODULE=config.settings.testing pytest tests/ \
  --cov=. \
  --cov-report=html \
  --cov-report=term-missing
```

**Specific Test File**:
```bash
DJANGO_SETTINGS_MODULE=config.settings.testing pytest tests/unit/test_models/test_target_models.py -v
```

### Writing Tests

#### Unit Test Example

```python
# tests/unit/test_services/test_target_service.py
import pytest
from apps.targets.models import Target
from services.target_service import TargetService

@pytest.mark.django_db
class TestTargetService:
    """Test suite for TargetService"""

    def test_validate_scope_in_scope(self):
        """Test scope validation for in-scope asset"""
        target = Target.objects.create(
            target_name="test-target",
            main_url="https://example.com",
            in_scope_urls=["https://example.com/*"]
        )

        result = TargetService.validate_scope(
            target=target,
            asset="https://example.com/api/users"
        )

        assert result['in_scope'] is True
        assert result['matched_rule'] == "https://example.com/*"

    def test_validate_scope_out_of_scope(self):
        """Test out-of-scope validation"""
        target = Target.objects.create(
            target_name="test-target",
            main_url="https://example.com",
            in_scope_urls=["https://example.com/*"],
            out_of_scope_urls=["https://example.com/admin/*"]
        )

        result = TargetService.validate_scope(
            target=target,
            asset="https://example.com/admin/users"
        )

        assert result['in_scope'] is False
```

#### API Integration Test

```python
# tests/integration/test_api/test_targets_api.py
import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

@pytest.mark.integration
class TestTargetsAPI:
    """Test targets API endpoints"""

    def test_create_target(self, auth_headers):
        """Test target creation"""
        response = client.post(
            "/api/targets/",
            json={
                "target_name": "test-target",
                "main_url": "https://example.com",
                "platform": "hackerone",
                "in_scope_urls": ["https://example.com/*"]
            },
            headers=auth_headers
        )

        assert response.status_code == 201
        data = response.json()
        assert data['target_name'] == "test-target"
        assert data['platform'] == "hackerone"

    def test_list_targets(self, auth_headers):
        """Test targets listing"""
        response = client.get(
            "/api/targets/",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert 'items' in data
        assert 'total' in data
```

#### E2E Test Example

```python
# tests/e2e/test_scan_flow.py
import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

@pytest.mark.e2e
class TestScanFlow:
    """End-to-end scan workflow test"""

    def test_complete_scan_workflow(self, auth_headers, db_session):
        """Test complete scan workflow"""

        # 1. Create target
        target_response = client.post(
            "/api/targets/",
            json={
                "target_name": "e2e-target",
                "main_url": "https://example.com",
                "platform": "hackerone"
            },
            headers=auth_headers
        )
        assert target_response.status_code == 201
        target_id = target_response.json()['id']

        # 2. Create scan
        scan_response = client.post(
            "/api/scans/",
            json={
                "session_name": "E2E Test Scan",
                "target_id": target_id,
                "workflow_type": "quick"
            },
            headers=auth_headers
        )
        assert scan_response.status_code == 202
        scan_id = scan_response.json()['id']

        # 3. Check scan progress
        progress_response = client.get(
            f"/api/scans/{scan_id}/progress",
            headers=auth_headers
        )
        assert progress_response.status_code == 200

        # 4. Get results (after scan completes)
        # Note: In real E2E test, wait for scan completion
        results_response = client.get(
            f"/api/scans/{scan_id}/results",
            headers=auth_headers
        )
        # Assert results structure
```

### Test Fixtures

```python
# tests/conftest.py
import pytest
from django.contrib.auth import get_user_model
from api.main import app
from fastapi.testclient import TestClient
from core.security import SecurityManager

User = get_user_model()

@pytest.fixture
def test_user(db):
    """Create test user"""
    return User.objects.create_user(
        email='test@example.com',
        username='testuser',
        password='testpass123',
        role='security_analyst'
    )

@pytest.fixture
def auth_headers(test_user):
    """Generate auth headers with JWT token"""
    token = SecurityManager.create_access_token(
        user_id=test_user.id,
        email=test_user.email
    )
    return {'Authorization': f'Bearer {token}'}

@pytest.fixture
def api_client():
    """FastAPI test client"""
    return TestClient(app)

@pytest.fixture
def sample_target(db):
    """Create sample target"""
    from apps.targets.models import Target
    return Target.objects.create(
        target_name="sample-target",
        main_url="https://example.com",
        platform="hackerone",
        in_scope_urls=["https://example.com/*"]
    )
```

### Coverage Requirements

Minimum coverage requirements:
- **Overall**: 80%
- **Models**: 100%
- **Services**: 80%
- **API Endpoints**: 85%

Check coverage:
```bash
# Generate coverage report
DJANGO_SETTINGS_MODULE=config.settings.testing pytest --cov=. --cov-report=html

# View report
open htmlcov/index.html  # Mac
xdg-open htmlcov/index.html  # Linux
```

## Database Operations

### Creating Migrations

```bash
# Generate migration for specific app
python manage.py makemigrations targets

# Generate migration with name
python manage.py makemigrations --name add_custom_field targets

# Check what migrations will do (dry run)
python manage.py makemigrations --dry-run

# Show SQL for migration
python manage.py sqlmigrate targets 0001
```

### Applying Migrations

```bash
# Apply all migrations
python manage.py migrate

# Apply specific app migrations
python manage.py migrate targets

# Apply up to specific migration
python manage.py migrate targets 0003

# Rollback migration
python manage.py migrate targets 0002
```

### Data Migrations

```python
# Create empty migration
python manage.py makemigrations --empty targets --name migrate_data

# Edit migration file
from django.db import migrations

def migrate_data_forward(apps, schema_editor):
    Target = apps.get_model('targets', 'Target')
    for target in Target.objects.all():
        # Migrate data
        target.new_field = calculate_value(target)
        target.save()

def migrate_data_backward(apps, schema_editor):
    # Reverse migration
    pass

class Migration(migrations.Migration):
    dependencies = [
        ('targets', '0003_previous_migration'),
    ]

    operations = [
        migrations.RunPython(
            migrate_data_forward,
            migrate_data_backward
        ),
    ]
```

## Debugging

### Django Debug Toolbar

```python
# Add to INSTALLED_APPS (development only)
INSTALLED_APPS = [
    ...
    'debug_toolbar',
]

# Add middleware
MIDDLEWARE = [
    'debug_toolbar.middleware.DebugToolbarMiddleware',
    ...
]

# Configure
INTERNAL_IPS = ['127.0.0.1']
```

### Logging

```python
import logging

logger = logging.getLogger(__name__)

# Debug logging
logger.debug(f"Processing target: {target.id}")

# Info logging
logger.info(f"Scan started: {scan_session.id}")

# Warning
logger.warning(f"Rate limit reached for {ip}")

# Error
logger.error(f"Scan failed: {error}", exc_info=True)

# Critical
logger.critical(f"Security breach detected: {details}")
```

### Django Shell

```bash
# Open Django shell
python manage.py shell

# Or use IPython if installed
python manage.py shell -i ipython
```

```python
# In shell
from apps.targets.models import Target
from services.target_service import TargetService

# Query data
targets = Target.objects.all()
target = Target.objects.get(id=1)

# Test service
result = TargetService.validate_scope(target, "https://example.com/api")
print(result)
```

### Database Shell

```bash
# Open database shell
python manage.py dbshell

# Execute SQL directly
SELECT * FROM targets_target LIMIT 10;
```

## Git Workflow

### Branch Strategy

```
main (production)
  ↓
develop (integration)
  ↓
feature/feature-name (development)
```

### Creating Feature Branch

```bash
# Create and switch to feature branch
git checkout -b feature/add-new-scanner

# Make changes and commit
git add .
git commit -m "feat: add new scanner engine"

# Push to remote
git push origin feature/add-new-scanner
```

### Commit Message Convention

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance

**Examples**:
```bash
git commit -m "feat(api): add vulnerability export endpoint"
git commit -m "fix(scanner): handle timeout in nuclei execution"
git commit -m "docs: update API documentation"
git commit -m "test: add unit tests for target service"
```

## Useful Commands

### Django Management

```bash
# Create superuser
python manage.py createsuperuser

# Collect static files
python manage.py collectstatic --noinput

# Check for issues
python manage.py check

# Clear sessions
python manage.py clearsessions

# Custom management command
python manage.py custom_command
```

### Celery

```bash
# Start worker
celery -A backend worker --loglevel=info

# Start worker with specific queues
celery -A backend worker -Q scans,reports --loglevel=info

# Start beat scheduler
celery -A backend beat --loglevel=info

# Monitor with Flower
celery -A backend flower --port=5555

# Purge all tasks
celery -A backend purge
```

### Docker

```bash
# Build services
docker-compose build

# Start services
docker-compose up -d

# View logs
docker-compose logs -f api

# Execute command in container
docker-compose exec api python manage.py migrate

# Shell access
docker-compose exec api bash

# Stop services
docker-compose down

# Remove volumes
docker-compose down -v
```

## Troubleshooting

### Common Issues

**Issue**: Database connection error
```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Check connection
psql -U bughunt -d bughunt -h localhost
```

**Issue**: Redis connection error
```bash
# Check Redis is running
redis-cli ping

# Start Redis
sudo systemctl start redis
```

**Issue**: Import errors
```bash
# Ensure virtual environment is activated
source .venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

**Issue**: Migration conflicts
```bash
# Show migrations
python manage.py showmigrations

# Reset migrations (development only!)
python manage.py migrate targets zero
python manage.py migrate targets
```

## Best Practices

1. **Always use virtual environment**
2. **Keep dependencies updated**: `pip list --outdated`
3. **Run tests before committing**: `pytest tests/`
4. **Format code**: `black backend/`
5. **Check for security issues**: `bandit -r backend/`
6. **Use type hints**: Improves code quality
7. **Write documentation**: Docstrings for all functions
8. **Log important operations**: Use appropriate log levels
9. **Handle errors gracefully**: Try-except blocks
10. **Review before pushing**: `git diff`
