"""
Main FastAPI application for Bug Bounty Automation Platform.
This file sets up the FastAPI app with all routers, middleware, and configuration.
"""

import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from starlette.middleware.sessions import SessionMiddleware

# Import performance optimization modules
from core.middleware import (
    create_performance_middleware,
    create_caching_middleware,
    create_rate_limiting_middleware,
    create_deduplication_middleware,
    create_validation_middleware,
    create_compression_middleware
)
from core.cache import warm_dashboard_cache, check_cache_health
from core.database_optimizer import get_database_health

# Import routers
from api.routers import auth, vulnerabilities, targets, scans, reports
from api.dependencies.database import get_db
from api.dependencies.auth import get_current_user
from core.database import engine, Base
from core.exceptions import (
    BugBountyPlatformException,
    create_http_exception_from_platform_exception,
    log_exception
)
from core.constants import APP_NAME, APP_VERSION, API_VERSION, APP_DESCRIPTION
from core.security import security_manager, rate_limiter

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for FastAPI app startup and shutdown events.
    """
    # Startup
    logger.info("Starting Bug Bounty Automation Platform API...")

    # Create database tables
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created/verified successfully")
    except Exception as e:
        logger.error("Failed to create database tables: %s", e)
        raise

    # Initialize cache and warm up frequently accessed data
    try:
        warm_dashboard_cache()
        logger.info("Cache warmed successfully")
    except Exception as e:
        logger.error("Failed to warm cache: %s", e)

    # Initialize any additional services here
    logger.info("API startup completed successfully")

    yield

    # Shutdown
    logger.info("Shutting down Bug Bounty Automation Platform API...")
    logger.info("API shutdown completed")

# Create FastAPI application
app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    openapi_url=f"/api/{API_VERSION}/openapi.json",
    docs_url=None,  # We'll create custom docs
    redoc_url=None,  # We'll create custom redoc
    lifespan=lifespan,
    contact={
        "name": "Bug Bounty Platform Team",
        "email": "support@bugbountyplatform.com",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
)

# Middleware configuration
def setup_middleware():
    """Configure all middleware for the FastAPI application."""

    # Performance optimization middleware (order matters!)

    # 1. Request validation middleware (first)
    app.add_middleware(create_validation_middleware)

    # 2. Response compression middleware
    app.add_middleware(create_compression_middleware, minimum_size=1000)

    # 3. Request deduplication middleware
    app.add_middleware(create_deduplication_middleware, dedup_window=5)

    # 4. Response caching middleware
    app.add_middleware(create_caching_middleware, default_ttl=300)

    # 5. Rate limiting middleware
    app.add_middleware(create_rate_limiting_middleware, global_limit=100, window_seconds=60)

    # 6. Performance monitoring middleware
    app.add_middleware(create_performance_middleware, slow_threshold=1.0)

    # CORS middleware
    allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
    if not allowed_origins or allowed_origins == [""]:
        allowed_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["*"],
    )

    # Trusted host middleware (for production)
    if not os.getenv("DEBUG", "True").lower() == "true":
        allowed_hosts = os.getenv("ALLOWED_HOSTS", "").split(",")
        if allowed_hosts and allowed_hosts != [""]:
            app.add_middleware(
                TrustedHostMiddleware,
                allowed_hosts=allowed_hosts
            )

    # Session middleware
    app.add_middleware(
        SessionMiddleware,
        secret_key=os.getenv("SECRET_KEY", "fallback-secret-key"),
        max_age=3600,  # 1 hour
    )

# Custom middleware for request logging and rate limiting
@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """Log all HTTP requests and responses."""
    start_time = time.time()

    # Log request
    logger.info(
        "Request: %s %s",
        request.method,
        request.url,
        extra={
            "method": request.method,
            "url": str(request.url),
            "client_ip": request.client.host,
            "user_agent": request.headers.get("user-agent"),
        }
    )

    # Process request
    response = await call_next(request)

    # Calculate response time
    process_time = time.time() - start_time

    # Log response
    logger.info(
        "Response: %s - %.4fs",
        response.status_code,
        process_time,
        extra={
            "status_code": response.status_code,
            "process_time": process_time,
        }
    )

    # Add custom headers
    response.headers["X-Process-Time"] = str(process_time)
    response.headers["X-API-Version"] = APP_VERSION

    return response

# Note: Rate limiting is now handled by RateLimitingMiddleware

# Exception handlers
@app.exception_handler(BugBountyPlatformException)
async def platform_exception_handler(request: Request, exc: BugBountyPlatformException):
    """Handle custom platform exceptions."""
    log_exception(exc, {"request_url": str(request.url)})
    http_exc = create_http_exception_from_platform_exception(exc)
    return JSONResponse(
        status_code=http_exc.status_code,
        content=http_exc.detail
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with consistent format."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "message": exc.detail,
            "error_code": f"HTTP_{exc.status_code}",
            "details": {}
        }
    )

@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Handle ValueError exceptions."""
    log_exception(exc, {"request_url": str(request.url)})
    return JSONResponse(
        status_code=400,
        content={
            "message": "Invalid input data",
            "error_code": "INVALID_INPUT",
            "details": {"error": str(exc)}
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle any unhandled exceptions."""
    log_exception(exc, {"request_url": str(request.url)})
    return JSONResponse(
        status_code=500,
        content={
            "message": "Internal server error",
            "error_code": "INTERNAL_ERROR",
            "details": {}
        }
    )

# Health check endpoints
@app.get("/health", tags=["Health"])
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": APP_VERSION,
        "timestamp": time.time()
    }

@app.get("/health/detailed", tags=["Health"])
async def detailed_health_check(db = Depends(get_db)):
    """Detailed health check including database connectivity and performance metrics."""
    from core.database import check_database_health, get_database_stats

    # Database health
    db_healthy = check_database_health()
    db_stats = get_database_stats()

    # Enhanced database health with optimizer
    db_health = get_database_health()

    # Cache health
    cache_health = check_cache_health()

    # Get middleware performance stats
    performance_stats = {}
    for middleware in app.middleware_stack:
        if hasattr(middleware, 'cls') and hasattr(middleware.cls, 'get_stats'):
            try:
                middleware_name = middleware.cls.__name__
                stats_method = getattr(middleware.cls, 'get_stats', None)
                if stats_method:
                    performance_stats[middleware_name] = stats_method()
            except Exception as e:
                logger.error(f"Error getting middleware stats: {e}")

    overall_healthy = db_healthy and cache_health.get('status') == 'healthy'

    return {
        "status": "healthy" if overall_healthy else "unhealthy",
        "service": APP_NAME,
        "version": APP_VERSION,
        "timestamp": time.time(),
        "checks": {
            "database": {
                "status": "healthy" if db_healthy else "unhealthy",
                "basic_stats": db_stats,
                "detailed_health": db_health
            },
            "cache": cache_health,
            "api": {
                "status": "healthy",
                "performance": performance_stats
            }
        }
    }

# API root endpoint
@app.get("/", tags=["Root"])
async def api_root():
    """API root endpoint with basic information."""
    return {
        "message": f"Welcome to {APP_NAME}",
        "version": APP_VERSION,
        "api_version": API_VERSION,
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc"
        },
        "endpoints": {
            "vulnerabilities": f"/api/{API_VERSION}/vulnerabilities/",
            "targets": f"/api/{API_VERSION}/targets/",
            "scans": f"/api/{API_VERSION}/scans/",
            "reports": f"/api/{API_VERSION}/reports/",
        }
    }

# Custom documentation endpoints
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    """Custom Swagger UI with authentication."""
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " - Swagger UI",
        oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
    )

@app.get("/redoc", include_in_schema=False)
async def redoc_html():
    """Custom ReDoc documentation."""
    return get_redoc_html(
        openapi_url=app.openapi_url,
        title=app.title + " - ReDoc",
        redoc_js_url="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js",
    )

# Custom OpenAPI schema
def custom_openapi():
    """Generate custom OpenAPI schema with additional information."""
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Add custom security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Enter your JWT token in the format: Bearer <token>"
        }
    }

    # Add security requirement to all endpoints
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            if method != "options":
                openapi_schema["paths"][path][method]["security"] = [
                    {"BearerAuth": []}
                ]

    # Add additional metadata
    openapi_schema["info"]["x-logo"] = {
        "url": "/static/images/logo.png"
    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Setup middleware
setup_middleware()

# Include routers
# Authentication router (no auth required)
app.include_router(
    auth.router,
    prefix=f"/api/{API_VERSION}/auth",
    tags=["Authentication"]
)

app.include_router(
    vulnerabilities.router,
    prefix=f"/api/{API_VERSION}/vulnerabilities",
    tags=["Vulnerabilities"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    targets.router,
    prefix=f"/api/{API_VERSION}/targets",
    tags=["Targets"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    scans.router,
    prefix=f"/api/{API_VERSION}/scans",
    tags=["Scans"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    reports.router,
    prefix=f"/api/{API_VERSION}/reports",
    tags=["Reports"],
    dependencies=[Depends(get_current_user)]
)

# Additional utility endpoints
@app.get("/api/info", tags=["Utility"])
async def api_info():
    """Get API information and statistics."""
    return {
        "api_name": APP_NAME,
        "version": APP_VERSION,
        "api_version": API_VERSION,
        "description": APP_DESCRIPTION,
        "endpoints_count": len(app.routes),
        "middleware_count": len(app.middleware_stack),
        "tags": ["Vulnerabilities", "Targets", "Scans", "Reports", "Health", "Root", "Utility"]
    }

@app.get("/api/status", tags=["Utility"])
async def api_status():
    """Get current API status and metrics."""
    return {
        "status": "operational",
        "uptime": time.time(),  # In production, calculate actual uptime
        "version": APP_VERSION,
        "environment": os.getenv("ENVIRONMENT", "development"),
        "debug": os.getenv("DEBUG", "True").lower() == "true"
    }


@app.get("/api/performance", tags=["Utility"])
async def api_performance_metrics():
    """Get comprehensive API performance metrics."""
    from core.database_optimizer import performance_monitor
    from core.cache import cache_manager

    # Get database performance stats
    db_performance = performance_monitor.get_performance_stats()

    # Get cache statistics
    cache_stats = cache_manager.get_stats()

    # Collect middleware statistics
    middleware_stats = {}
    for middleware in app.middleware_stack:
        if hasattr(middleware, 'cls'):
            middleware_name = middleware.cls.__name__
            if hasattr(middleware.cls, 'get_stats'):
                try:
                    stats_method = getattr(middleware.cls, 'get_stats', None)
                    if stats_method:
                        middleware_stats[middleware_name] = stats_method()
                except Exception as e:
                    logger.error(f"Error getting {middleware_name} stats: {e}")
            elif hasattr(middleware.cls, 'get_cache_stats'):
                try:
                    stats_method = getattr(middleware.cls, 'get_cache_stats', None)
                    if stats_method:
                        middleware_stats[middleware_name] = stats_method()
                except Exception as e:
                    logger.error(f"Error getting {middleware_name} cache stats: {e}")

    return {
        "timestamp": time.time(),
        "database": db_performance,
        "cache": cache_stats,
        "middleware": middleware_stats,
        "api_info": {
            "total_routes": len(app.routes),
            "middleware_count": len(app.middleware_stack)
        }
    }

if __name__ == "__main__":
    import uvicorn

    # Run the application
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
        access_log=True
    )
