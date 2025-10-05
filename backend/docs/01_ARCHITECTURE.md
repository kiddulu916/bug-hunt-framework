# Architecture Overview

## System Architecture

The Bug Hunt Framework implements a sophisticated hybrid architecture combining Django and FastAPI for optimal performance and developer experience.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Client Layer                          │
│  (Web UI, CLI Tools, Third-party Integrations via REST API) │
└─────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                     API Gateway Layer                        │
│                                                              │
│  ┌──────────────────┐              ┌─────────────────────┐  │
│  │   FastAPI (8000) │              │  Django (8001)      │  │
│  │  - REST API      │              │  - Admin Interface  │  │
│  │  - WebSockets    │              │  - ORM Models       │  │
│  │  - Async Ops     │              │  - Migrations       │  │
│  └──────────────────┘              └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    Middleware Layer                          │
│  - Authentication (JWT)    - Rate Limiting                   │
│  - Security Validation     - Request Deduplication          │
│  - Performance Monitoring  - Response Caching               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                     Service Layer                            │
│                                                              │
│  ┌────────────┐ ┌──────────────┐ ┌─────────────────────┐   │
│  │   Target   │ │   Scanning   │ │   Vulnerability     │   │
│  │  Service   │ │   Service    │ │     Analyzer        │   │
│  └────────────┘ └──────────────┘ └─────────────────────┘   │
│                                                              │
│  ┌────────────┐ ┌──────────────┐ ┌─────────────────────┐   │
│  │    Recon   │ │ Exploitation │ │    Reporting        │   │
│  │  Service   │ │   Service    │ │     Service         │   │
│  └────────────┘ └──────────────┘ └─────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                  Scanner Engine Layer                        │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────────┐  │
│  │ Scan Orch-  │  │   Nuclei    │  │  Custom Web       │  │
│  │ estrator    │  │   Engine    │  │  Engine           │  │
│  └─────────────┘  └─────────────┘  └────────────────────┘  │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────────┐  │
│  │ Custom API  │  │  Custom     │  │  Recon            │  │
│  │  Engine     │  │  Infra Eng  │  │  Engine           │  │
│  └─────────────┘  └─────────────┘  └────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                  Background Processing                       │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Celery Task Queue                       │   │
│  │  - Scan Execution    - Report Generation            │   │
│  │  - Tool Execution    - Notifications                │   │
│  │  - Periodic Tasks    - Cleanup                      │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │   Celery     │  │    Celery    │  │    Flower       │   │
│  │   Workers    │  │     Beat     │  │   (Monitor)     │   │
│  └──────────────┘  └──────────────┘  └─────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    Data Layer                                │
│                                                              │
│  ┌──────────────────┐              ┌─────────────────────┐  │
│  │   PostgreSQL     │              │      Redis          │  │
│  │  - Primary DB    │              │  - Cache            │  │
│  │  - Django ORM    │              │  - Task Queue       │  │
│  │  - SQLAlchemy    │              │  - Rate Limiting    │  │
│  └──────────────────┘              └─────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              File Storage                            │   │
│  │  - Evidence Files    - Reports    - Scan Results    │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Dual-Framework Design

### Django Layer (Port 8001)

**Purpose**: Traditional web operations, admin interface, and robust ORM

**Key Responsibilities**:
- Database model definitions
- Database migrations via `manage.py migrate`
- Admin interface at `/admin/`
- Django REST Framework endpoints (legacy compatibility)
- User management and authentication base

**Entry Point**: `backend/manage.py`

**Configuration**: `backend/config/settings/`
- `base.py` - Shared settings
- `development.py` - Dev environment
- `testing.py` - Test environment
- `production.py` - Production settings

**Apps Structure**:
```
backend/apps/
├── targets/           # Bug bounty target management
├── vulnerabilities/   # Vulnerability tracking
├── scanning/          # Scan session management
├── reconnaissance/    # Recon results
├── exploitation/      # Exploit attempts
└── reporting/         # Report generation
```

### FastAPI Layer (Port 8000)

**Purpose**: High-performance async API endpoints

**Key Responsibilities**:
- RESTful API endpoints
- Real-time WebSocket connections
- Async database operations via SQLAlchemy
- Automatic OpenAPI/Swagger documentation
- High-throughput concurrent request handling

**Entry Point**: `backend/api/main.py`

**Router Structure**:
```
backend/api/routers/
├── auth.py             # Authentication endpoints
├── targets.py          # Target CRUD operations
├── scans.py            # Scan management
├── vulnerabilities.py  # Vulnerability management
├── reconnaissance.py   # Recon operations
├── exploitation.py     # Exploitation operations
├── reports.py          # Report generation
└── callbacks.py        # Callback server endpoints
```

### Integration Strategy

Both frameworks share:
- **Database**: Same PostgreSQL database
- **Models**: Django ORM models used by both
- **Authentication**: Shared JWT token system
- **Configuration**: Common settings and environment variables
- **Static Files**: Shared static file serving

**Data Flow**:
1. FastAPI receives API requests
2. FastAPI uses Django ORM models for database operations
3. FastAPI delegates complex business logic to service layer
4. Django admin provides management interface for same data
5. Both frameworks use same authentication tokens

## Design Patterns

### Service Layer Pattern

All business logic is encapsulated in service classes:

```python
# Example: VulnerabilityService
class VulnerabilityService:
    def __init__(self):
        self.analyzer = VulnerabilityAnalyzer()

    async def create_vulnerability(self, data: dict) -> Vulnerability:
        # Validate
        # Process
        # Analyze
        # Store
        # Notify
        pass
```

**Benefits**:
- Separation of concerns
- Reusable business logic
- Testable components
- Framework-agnostic code

### Repository Pattern

Data access is abstracted through repository-like services:

```python
class TargetService:
    @staticmethod
    def get_targets(filters: dict):
        queryset = Target.objects.all()
        # Apply filters
        return queryset
```

### Strategy Pattern

Scanner engines implement a common interface:

```python
class BaseScannerEngine(ABC):
    @abstractmethod
    async def execute_scan(self, context: ScanContext):
        pass

    @abstractmethod
    def parse_results(self, output: str):
        pass
```

### Observer Pattern

Event-driven notifications:

```python
# Scan completion triggers notifications
scan_completed.connect(send_notification)
vulnerability_found.connect(alert_critical)
```

### Factory Pattern

Scanner engine selection:

```python
class ScanEngineFactory:
    @staticmethod
    def get_engine(scan_type: str):
        engines = {
            'nuclei': NucleiEngine(),
            'web': CustomWebEngine(),
            'api': CustomAPIEngine(),
        }
        return engines.get(scan_type)
```

## Data Flow Architecture

### Request Processing Flow

```
Client Request
    ↓
FastAPI Route Handler
    ↓
Authentication Middleware (JWT validation)
    ↓
Security Middleware (Threat detection, validation)
    ↓
Rate Limiting Middleware
    ↓
Pydantic Schema Validation
    ↓
Service Layer (Business Logic)
    ↓
Django ORM / SQLAlchemy
    ↓
PostgreSQL Database
    ↓
Response Serialization
    ↓
Client Response
```

### Scan Execution Flow

```
User Initiates Scan (POST /scans/)
    ↓
FastAPI creates ScanSession record
    ↓
Queues Celery task (async)
    ↓
Returns 202 Accepted with scan_id
    ↓
Celery Worker picks up task
    ↓
ScanOrchestrator.execute_scan()
    ↓
Phase 1: Initialization
    ↓
Phase 2: Passive Reconnaissance
    ↓
Phase 3: Active Reconnaissance
    ↓
Phase 4: Vulnerability Testing
    ↓
Phase 5: Exploitation
    ↓
Phase 6: Reporting
    ↓
Phase 7: Cleanup
    ↓
Update ScanSession (status=completed)
    ↓
Send Notifications
    ↓
User retrieves results (GET /scans/{id}/results)
```

### Vulnerability Discovery Flow

```
Scanner Tool Execution
    ↓
Raw Output Captured
    ↓
Output Parser (tool-specific)
    ↓
Normalized Vulnerability Data
    ↓
Deduplication Check
    ↓
CVSS Score Calculation
    ↓
VulnerabilityAnalyzer.analyze()
    ↓
Context Enhancement (PoC, remediation)
    ↓
Evidence Collection (screenshots, HTTP)
    ↓
Database Storage
    ↓
Notification (if critical)
    ↓
Available in API/Reports
```

## Component Communication

### Synchronous Communication
- FastAPI ↔ Service Layer: Direct function calls
- Service Layer ↔ Django ORM: Direct model access
- API ↔ Database: SQLAlchemy (async) / Django ORM (sync)

### Asynchronous Communication
- API ↔ Celery: Task queue via Redis
- Celery Workers ↔ Services: Direct invocation
- Services ↔ Notification System: Event-driven signals

### External Communication
- Scanner Engines ↔ Security Tools: Subprocess execution
- Callback Server ↔ Exploits: HTTP/DNS callbacks
- Reporting Service ↔ File System: File I/O

## Scalability Considerations

### Horizontal Scaling
- **API Layer**: Multiple FastAPI instances behind load balancer
- **Django Admin**: Read replicas for admin interface
- **Celery Workers**: Worker pool scaling based on queue size
- **Database**: PostgreSQL replication (primary + read replicas)

### Vertical Scaling
- **Connection Pooling**: Database connection pool (10-50 connections)
- **Redis Clustering**: Redis Cluster for high availability
- **Resource Limits**: Memory limits per Celery worker
- **Queue Prioritization**: High/medium/low priority queues

### Caching Strategy
- **Redis Cache**: API responses, query results (TTL: 5-60 minutes)
- **Application Cache**: In-memory caching for constants
- **CDN**: Static files and media (if deployed)

### Performance Optimizations
- **Database Indexing**: Indexes on frequently queried fields
- **Query Optimization**: `select_related()`, `prefetch_related()`
- **Async Operations**: FastAPI async endpoints for I/O operations
- **Background Tasks**: Long-running operations in Celery
- **Response Compression**: GZIP compression middleware

## Security Architecture

### Defense in Depth

**Layer 1: Network**
- Rate limiting (per-IP, per-user, per-endpoint)
- DDoS protection
- IP allowlisting/blocklisting

**Layer 2: Authentication**
- JWT tokens (access + refresh)
- Token expiration (15 min access, 7 day refresh)
- Secure token storage

**Layer 3: Authorization**
- Role-based access control (RBAC)
- Permission-based endpoints
- Resource-level permissions

**Layer 4: Input Validation**
- Pydantic schema validation
- SQL injection prevention
- XSS prevention
- Path traversal prevention
- Command injection prevention

**Layer 5: Data Protection**
- Encryption at rest (sensitive fields)
- Encryption in transit (HTTPS/TLS)
- Secure password hashing (bcrypt)
- API key hashing (SHA-256)

**Layer 6: Monitoring**
- Threat detection system
- Security event logging
- Anomaly detection
- Audit trails

## Technology Stack Details

### Core Frameworks
- **Django**: 5.0+ (ORM, migrations, admin)
- **FastAPI**: 0.110+ (async API)
- **Pydantic**: 2.0+ (validation)
- **SQLAlchemy**: 2.0+ (async ORM)

### Database & Caching
- **PostgreSQL**: 15+ (primary database)
- **Redis**: 7+ (cache, queue, rate limiting)

### Background Processing
- **Celery**: 5.3+ (task queue)
- **Flower**: 2.0+ (monitoring)
- **Celery Beat**: Periodic task scheduling

### Security & Auth
- **PyJWT**: JWT token handling
- **Bcrypt**: Password hashing
- **Cryptography**: Data encryption

### Testing
- **Pytest**: 8.0+ (test framework)
- **Pytest-Django**: Django integration
- **Pytest-asyncio**: Async test support
- **Coverage.py**: Code coverage

### Development Tools
- **Uvicorn**: ASGI server
- **Gunicorn**: WSGI server
- **Black**: Code formatting
- **Ruff**: Linting

## Configuration Management

### Environment-Based Settings

**Development** (`config/settings/development.py`):
- Debug mode enabled
- Local database
- Verbose logging
- Hot reloading
- Permissive CORS

**Testing** (`config/settings/testing.py`):
- SQLite in-memory database
- Mock external services
- Deterministic behavior
- Isolated test environment

**Production** (`config/settings/production.py`):
- Debug mode disabled
- Production database with connection pooling
- Error logging to file/external service
- Strict CORS
- Security headers
- HTTPS enforcement

### Environment Variables

Key configuration via `.env`:
```
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/bughunt
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret
ENCRYPTION_KEY=your-encryption-key

# External Services
NUCLEI_PATH=/usr/bin/nuclei
AMASS_PATH=/usr/bin/amass

# Feature Flags
ENABLE_EXPLOITATION=true
MAX_CONCURRENT_SCANS=5
```

## Directory Structure

```
backend/
├── alembic/              # Database migrations (SQLAlchemy)
├── api/                  # FastAPI application
│   ├── dependencies/     # Dependency injection
│   ├── routers/          # API endpoints
│   ├── schemas/          # Pydantic models
│   └── main.py           # FastAPI app entry
├── apps/                 # Django applications
│   ├── targets/
│   ├── vulnerabilities/
│   ├── scanning/
│   ├── reconnaissance/
│   ├── exploitation/
│   └── reporting/
├── config/               # Django settings
│   └── settings/
├── core/                 # Core utilities
│   ├── security.py
│   ├── pagination.py
│   ├── middleware.py
│   └── constants.py
├── services/             # Business logic
│   ├── scanner_engines/  # Scanner implementations
│   ├── vulnerability_services/
│   └── *.py              # Service classes
├── tests/                # Test suite
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── tools/                # Helper scripts
├── utils/                # Utility functions
├── manage.py             # Django management
└── requirements.txt      # Dependencies
```

## Deployment Architecture

### Container Architecture

```
┌─────────────────────────────────────────────┐
│              Load Balancer                  │
│              (Nginx/Traefik)                │
└─────────────────────────────────────────────┘
              │                    │
              ↓                    ↓
    ┌─────────────────┐  ┌─────────────────┐
    │  FastAPI (x3)   │  │  Django Admin   │
    │  Port 8000      │  │  Port 8001      │
    └─────────────────┘  └─────────────────┘
              │                    │
              └──────────┬─────────┘
                         ↓
           ┌─────────────────────────┐
           │   PostgreSQL Primary    │
           └─────────────────────────┘
                         │
                         ↓
           ┌─────────────────────────┐
           │    Redis Cluster        │
           └─────────────────────────┘
                         │
                         ↓
           ┌─────────────────────────┐
           │   Celery Workers (x5)   │
           └─────────────────────────┐
                         │
                         ↓
           ┌─────────────────────────┐
           │   Celery Beat           │
           └─────────────────────────┘
```

### Docker Services

**docker-compose.yml** includes:
- `api` - FastAPI application
- `django` - Django admin
- `postgres` - PostgreSQL database
- `redis` - Redis cache/queue
- `celery-worker` - Background workers
- `celery-beat` - Periodic scheduler
- `flower` - Task monitoring UI
- `nginx` - Reverse proxy

## Best Practices

### Code Organization
- Keep services focused and single-responsibility
- Use dependency injection for testability
- Separate API schemas from database models
- Keep routers thin, logic in services

### Database
- Use migrations for all schema changes
- Index frequently queried fields
- Use `select_related()` for foreign keys
- Use `prefetch_related()` for many-to-many
- Avoid N+1 queries

### API Design
- RESTful resource naming
- Proper HTTP status codes
- Pagination for list endpoints
- Filtering and sorting support
- Comprehensive error responses

### Security
- Never commit secrets to version control
- Validate all user input
- Use parameterized queries
- Implement rate limiting
- Log security events
- Regular dependency updates

### Testing
- Maintain 80%+ code coverage
- Test all API endpoints
- Test edge cases and error conditions
- Use fixtures for test data
- Mock external dependencies

### Performance
- Profile slow endpoints
- Monitor database query performance
- Use caching strategically
- Implement background tasks for long operations
- Set appropriate timeouts
