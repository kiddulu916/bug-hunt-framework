"""
Enhanced middleware for Bug Bounty Platform API.
Provides compression, caching, rate limiting, and performance monitoring.
"""

import asyncio
import gzip
import time
import json
import logging
from typing import Callable, Dict, Any
from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.compression import CompressionMiddleware
import hashlib

from core.cache import cache_manager
from core.database_optimizer import performance_monitor

logger = logging.getLogger(__name__)


class PerformanceMonitoringMiddleware(BaseHTTPMiddleware):
    """
    Monitor API performance and track metrics.
    """

    def __init__(self, app, track_slow_requests: bool = True, slow_threshold: float = 1.0):
        super().__init__(app)
        self.track_slow_requests = track_slow_requests
        self.slow_threshold = slow_threshold
        self.request_stats = {
            'total_requests': 0,
            'slow_requests': 0,
            'error_requests': 0,
            'avg_response_time': 0.0
        }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()

        # Track request
        self.request_stats['total_requests'] += 1

        try:
            response = await call_next(request)

            # Calculate response time
            duration = time.time() - start_time

            # Update average response time
            self.request_stats['avg_response_time'] = (
                (self.request_stats['avg_response_time'] * (self.request_stats['total_requests'] - 1) + duration) /
                self.request_stats['total_requests']
            )

            # Track slow requests
            if duration > self.slow_threshold:
                self.request_stats['slow_requests'] += 1
                if self.track_slow_requests:
                    logger.warning(
                        f"Slow request: {request.method} {request.url.path} took {duration:.3f}s"
                    )

            # Add performance headers
            response.headers["X-Response-Time"] = f"{duration:.3f}s"
            response.headers["X-Request-ID"] = str(request.state.request_id) if hasattr(request.state, 'request_id') else ""

            return response

        except Exception as e:
            duration = time.time() - start_time
            self.request_stats['error_requests'] += 1

            logger.error(f"Request error after {duration:.3f}s: {str(e)}")
            raise

    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        return {
            **self.request_stats,
            'slow_request_percentage': (
                (self.request_stats['slow_requests'] / max(1, self.request_stats['total_requests'])) * 100
            ),
            'error_rate_percentage': (
                (self.request_stats['error_requests'] / max(1, self.request_stats['total_requests'])) * 100
            )
        }


class ResponseCachingMiddleware(BaseHTTPMiddleware):
    """
    Cache API responses based on configurable rules.
    """

    def __init__(self, app, default_ttl: int = 300):
        super().__init__(app)
        self.default_ttl = default_ttl
        self.cacheable_methods = {"GET"}
        self.cacheable_paths = {
            "/api/v1/vulnerabilities/statistics": 300,
            "/api/v1/vulnerabilities/trends": 600,
            "/api/v1/targets/": 120,
            "/health": 60
        }
        self.cache_hit_count = 0
        self.cache_miss_count = 0

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Only cache GET requests
        if request.method not in self.cacheable_methods:
            return await call_next(request)

        # Check if path is cacheable
        cache_ttl = self._get_cache_ttl(request.url.path)
        if cache_ttl is None:
            return await call_next(request)

        # Generate cache key
        cache_key = self._generate_cache_key(request)

        # Try to get from cache
        cached_response = cache_manager.get(cache_key)
        if cached_response:
            self.cache_hit_count += 1
            logger.debug(f"Cache hit for {request.url.path}")

            response = JSONResponse(
                content=cached_response['content'],
                status_code=cached_response['status_code'],
                headers=cached_response.get('headers', {})
            )
            response.headers["X-Cache"] = "HIT"
            return response

        # Cache miss - execute request
        self.cache_miss_count += 1
        response = await call_next(request)

        # Cache successful responses
        if 200 <= response.status_code < 300:
            try:
                # Read response body
                response_body = b""
                async for chunk in response.body_iterator:
                    response_body += chunk

                # Parse JSON content
                content = json.loads(response_body.decode())

                # Cache the response
                cache_data = {
                    'content': content,
                    'status_code': response.status_code,
                    'headers': dict(response.headers)
                }
                cache_manager.set(cache_key, cache_data, cache_ttl)

                # Create new response with cached data
                new_response = JSONResponse(
                    content=content,
                    status_code=response.status_code,
                    headers=response.headers
                )
                new_response.headers["X-Cache"] = "MISS"
                return new_response

            except Exception as e:
                logger.error(f"Error caching response: {e}")
                response.headers["X-Cache"] = "ERROR"

        return response

    def _get_cache_ttl(self, path: str) -> int:
        """Get cache TTL for a given path."""
        for cacheable_path, ttl in self.cacheable_paths.items():
            if path.startswith(cacheable_path):
                return ttl
        return None

    def _generate_cache_key(self, request: Request) -> str:
        """Generate cache key for request."""
        key_components = [
            request.method,
            str(request.url.path),
            str(sorted(request.query_params.items())),
        ]

        # Include user context for personalized responses
        if hasattr(request.state, 'user_id'):
            key_components.append(f"user:{request.state.user_id}")

        key_string = "|".join(key_components)
        return f"api_response:{hashlib.md5(key_string.encode()).hexdigest()}"

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get caching statistics."""
        total_requests = self.cache_hit_count + self.cache_miss_count
        hit_rate = (self.cache_hit_count / max(1, total_requests)) * 100

        return {
            'cache_hits': self.cache_hit_count,
            'cache_misses': self.cache_miss_count,
            'hit_rate_percentage': round(hit_rate, 2),
            'total_cached_requests': total_requests
        }


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Enhanced rate limiting with per-user and per-endpoint limits.
    """

    def __init__(self, app, global_limit: int = 100, window_seconds: int = 60):
        super().__init__(app)
        self.global_limit = global_limit
        self.window_seconds = window_seconds

        # Endpoint-specific limits
        self.endpoint_limits = {
            "/api/v1/vulnerabilities/": {"limit": 50, "window": 60},
            "/api/v1/scans/": {"limit": 10, "window": 60},
            "/api/v1/targets/": {"limit": 30, "window": 60},
        }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host
        user_id = getattr(request.state, 'user_id', None)

        # Create rate limit key
        rate_limit_key = f"rate_limit:{client_ip}"
        if user_id:
            rate_limit_key = f"rate_limit:user:{user_id}"

        # Check global rate limit
        if not self._check_rate_limit(rate_limit_key, self.global_limit, self.window_seconds):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Global rate limit exceeded",
                headers={"Retry-After": str(self.window_seconds)}
            )

        # Check endpoint-specific rate limit
        endpoint_config = self._get_endpoint_config(request.url.path)
        if endpoint_config:
            endpoint_key = f"{rate_limit_key}:{request.url.path}"
            if not self._check_rate_limit(
                endpoint_key,
                endpoint_config["limit"],
                endpoint_config["window"]
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Endpoint rate limit exceeded",
                    headers={"Retry-After": str(endpoint_config["window"])}
                )

        response = await call_next(request)
        return response

    def _check_rate_limit(self, key: str, limit: int, window: int) -> bool:
        """Check if request is within rate limit."""
        try:
            current_time = int(time.time())
            window_key = f"{key}:{current_time // window}"

            # Get current count
            current_count = cache_manager.get(window_key, 0)

            if current_count >= limit:
                return False

            # Increment count
            cache_manager.set(window_key, current_count + 1, window + 10)
            return True

        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            return True  # Allow request if rate limiting fails

    def _get_endpoint_config(self, path: str) -> Dict[str, int]:
        """Get rate limit configuration for endpoint."""
        for endpoint_path, config in self.endpoint_limits.items():
            if path.startswith(endpoint_path):
                return config
        return None


class RequestDeduplicationMiddleware(BaseHTTPMiddleware):
    """
    Prevent duplicate requests from being processed simultaneously.
    """

    def __init__(self, app, dedup_window: int = 5):
        super().__init__(app)
        self.dedup_window = dedup_window
        self.processing_requests = set()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Only deduplicate idempotent methods
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            return await call_next(request)

        # Generate request fingerprint
        fingerprint = self._generate_fingerprint(request)
        cache_key = f"dedup:{fingerprint}"

        # Check if request is already being processed
        if fingerprint in self.processing_requests:
            # Wait for ongoing request to complete
            cached_response = await self._wait_for_response(cache_key)
            if cached_response:
                response = JSONResponse(
                    content=cached_response['content'],
                    status_code=cached_response['status_code']
                )
                response.headers["X-Deduplicated"] = "true"
                return response

        # Mark request as processing
        self.processing_requests.add(fingerprint)

        try:
            response = await call_next(request)

            # Cache successful responses for deduplication
            if 200 <= response.status_code < 300:
                try:
                    response_body = b""
                    async for chunk in response.body_iterator:
                        response_body += chunk

                    content = json.loads(response_body.decode())
                    cache_data = {
                        'content': content,
                        'status_code': response.status_code
                    }
                    cache_manager.set(cache_key, cache_data, self.dedup_window)

                    # Create new response
                    new_response = JSONResponse(
                        content=content,
                        status_code=response.status_code,
                        headers=response.headers
                    )
                    return new_response

                except Exception as e:
                    logger.error(f"Error in request deduplication: {e}")

            return response

        finally:
            # Remove from processing set
            self.processing_requests.discard(fingerprint)

    def _generate_fingerprint(self, request: Request) -> str:
        """Generate unique fingerprint for request."""
        components = [
            request.method,
            str(request.url.path),
            str(sorted(request.query_params.items())),
        ]

        if hasattr(request.state, 'user_id'):
            components.append(f"user:{request.state.user_id}")

        fingerprint_string = "|".join(components)
        return hashlib.md5(fingerprint_string.encode()).hexdigest()

    async def _wait_for_response(self, cache_key: str) -> Dict[str, Any]:
        """Wait for cached response from ongoing request."""
        for _ in range(20):  # Wait up to 2 seconds
            cached_response = cache_manager.get(cache_key)
            if cached_response:
                return cached_response
            await asyncio.sleep(0.1)
        return None


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Enhanced request validation and security checks.
    """

    def __init__(self, app):
        super().__init__(app)
        self.max_request_size = 10 * 1024 * 1024  # 10MB
        self.blocked_user_agents = [
            'scanner', 'bot', 'crawler', 'scraper'
        ]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Check request size
        content_length = request.headers.get('content-length')
        if content_length and int(content_length) > self.max_request_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Request too large"
            )

        # Check user agent
        user_agent = request.headers.get('user-agent', '').lower()
        if any(blocked in user_agent for blocked in self.blocked_user_agents):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Blocked user agent"
            )

        # Validate content type for POST/PUT requests
        if request.method in {'POST', 'PUT', 'PATCH'}:
            content_type = request.headers.get('content-type', '')
            if not content_type.startswith(('application/json', 'multipart/form-data')):
                raise HTTPException(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    detail="Unsupported content type"
                )

        return await call_next(request)


# Response compression with intelligent content-type handling
class IntelligentCompressionMiddleware(CompressionMiddleware):
    """
    Enhanced compression middleware with intelligent content-type detection.
    """

    def __init__(self, app, minimum_size: int = 500, exclude_content_types: list = None):
        super().__init__(app, minimum_size)
        self.exclude_content_types = exclude_content_types or [
            'image/', 'video/', 'audio/', 'application/zip', 'application/gzip'
        ]

    def should_compress(self, response) -> bool:
        """Determine if response should be compressed."""
        content_type = response.headers.get('content-type', '')

        # Don't compress already compressed content
        if any(excluded in content_type for excluded in self.exclude_content_types):
            return False

        # Don't compress small responses
        content_length = response.headers.get('content-length')
        if content_length and int(content_length) < self.minimum_size:
            return False

        return True


# Middleware factory functions
def create_performance_middleware(app, **kwargs):
    """Create performance monitoring middleware."""
    return PerformanceMonitoringMiddleware(app, **kwargs)


def create_caching_middleware(app, **kwargs):
    """Create response caching middleware."""
    return ResponseCachingMiddleware(app, **kwargs)


def create_rate_limiting_middleware(app, **kwargs):
    """Create rate limiting middleware."""
    return RateLimitingMiddleware(app, **kwargs)


def create_deduplication_middleware(app, **kwargs):
    """Create request deduplication middleware."""
    return RequestDeduplicationMiddleware(app, **kwargs)


def create_validation_middleware(app, **kwargs):
    """Create request validation middleware."""
    return RequestValidationMiddleware(app, **kwargs)


def create_compression_middleware(app, **kwargs):
    """Create intelligent compression middleware."""
    return IntelligentCompressionMiddleware(app, **kwargs)


# Export middleware components
__all__ = [
    'PerformanceMonitoringMiddleware',
    'ResponseCachingMiddleware',
    'RateLimitingMiddleware',
    'RequestDeduplicationMiddleware',
    'RequestValidationMiddleware',
    'IntelligentCompressionMiddleware',
    'create_performance_middleware',
    'create_caching_middleware',
    'create_rate_limiting_middleware',
    'create_deduplication_middleware',
    'create_validation_middleware',
    'create_compression_middleware'
]