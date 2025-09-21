"""
Enhanced caching module for Bug Bounty Platform.
Provides Redis-based caching with decorators and optimized query result caching.
"""

import functools
import hashlib
import json
import logging
import pickle
import time
from typing import Any, Callable, Dict, List, Optional, Union
import redis
from contextlib import contextmanager
import os

logger = logging.getLogger(__name__)


class CacheManager:
    """
    Enhanced cache manager with Redis backend.
    Provides result caching, query optimization, and cache invalidation.
    """

    def __init__(self):
        self.redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/1')
        self.redis_client = redis.from_url(self.redis_url, decode_responses=False)
        self.default_ttl = int(os.getenv('CACHE_DEFAULT_TTL', '300'))  # 5 minutes
        self.key_prefix = os.getenv('CACHE_KEY_PREFIX', 'bbp:cache:')

        # Cache statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'deletes': 0
        }

    def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache."""
        try:
            full_key = f"{self.key_prefix}{key}"
            value = self.redis_client.get(full_key)

            if value is not None:
                self.stats['hits'] += 1
                return pickle.loads(value)
            else:
                self.stats['misses'] += 1
                return default

        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            self.stats['misses'] += 1
            return default

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache with optional TTL."""
        try:
            full_key = f"{self.key_prefix}{key}"
            serialized_value = pickle.dumps(value)
            ttl = ttl or self.default_ttl

            result = self.redis_client.setex(full_key, ttl, serialized_value)
            if result:
                self.stats['sets'] += 1
            return result

        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            return False

    def delete(self, key: str) -> bool:
        """Delete value from cache."""
        try:
            full_key = f"{self.key_prefix}{key}"
            result = self.redis_client.delete(full_key)
            if result:
                self.stats['deletes'] += 1
            return bool(result)

        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            return False

    def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern."""
        try:
            full_pattern = f"{self.key_prefix}{pattern}"
            keys = self.redis_client.keys(full_pattern)
            if keys:
                result = self.redis_client.delete(*keys)
                self.stats['deletes'] += result
                return result
            return 0

        except Exception as e:
            logger.error(f"Cache delete pattern error for {pattern}: {e}")
            return 0

    def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        try:
            full_key = f"{self.key_prefix}{key}"
            return bool(self.redis_client.exists(full_key))
        except Exception as e:
            logger.error(f"Cache exists error for key {key}: {e}")
            return False

    def ttl(self, key: str) -> int:
        """Get time to live for key."""
        try:
            full_key = f"{self.key_prefix}{key}"
            return self.redis_client.ttl(full_key)
        except Exception as e:
            logger.error(f"Cache TTL error for key {key}: {e}")
            return -1

    def flush_all(self) -> bool:
        """Flush all cache entries with our prefix."""
        try:
            keys = self.redis_client.keys(f"{self.key_prefix}*")
            if keys:
                result = self.redis_client.delete(*keys)
                self.stats['deletes'] += result
                return True
            return True
        except Exception as e:
            logger.error(f"Cache flush error: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.stats['hits'] + self.stats['misses']
        hit_rate = (self.stats['hits'] / total_requests * 100) if total_requests > 0 else 0

        return {
            'hits': self.stats['hits'],
            'misses': self.stats['misses'],
            'sets': self.stats['sets'],
            'deletes': self.stats['deletes'],
            'hit_rate_percent': round(hit_rate, 2),
            'total_requests': total_requests
        }

    @contextmanager
    def pipeline(self):
        """Context manager for Redis pipeline operations."""
        pipe = self.redis_client.pipeline()
        try:
            yield pipe
            pipe.execute()
        except Exception as e:
            logger.error(f"Cache pipeline error: {e}")
            raise


# Global cache manager instance
cache_manager = CacheManager()


def cache_key_generator(*args, **kwargs) -> str:
    """Generate cache key from function arguments."""
    # Create a stable key from arguments
    key_data = {
        'args': str(args),
        'kwargs': sorted(kwargs.items()) if kwargs else []
    }
    key_string = json.dumps(key_data, sort_keys=True)
    return hashlib.md5(key_string.encode()).hexdigest()


def cache_result(ttl: int = 300, key_prefix: str = "func"):
    """
    Decorator to cache function results.

    Args:
        ttl: Time to live in seconds
        key_prefix: Prefix for cache key
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            func_name = f"{func.__module__}.{func.__qualname__}"
            arg_key = cache_key_generator(*args, **kwargs)
            cache_key = f"{key_prefix}:{func_name}:{arg_key}"

            # Try to get from cache
            cached_result = cache_manager.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache hit for {func_name}")
                return cached_result

            # Execute function and cache result
            logger.debug(f"Cache miss for {func_name}, executing function")
            result = func(*args, **kwargs)

            # Cache the result
            cache_manager.set(cache_key, result, ttl)

            return result

        # Add cache control methods
        wrapper.cache_clear = lambda: cache_manager.delete_pattern(f"{key_prefix}:{func.__module__}.{func.__qualname__}:*")
        wrapper.cache_key = lambda *args, **kwargs: f"{key_prefix}:{func.__module__}.{func.__qualname__}:{cache_key_generator(*args, **kwargs)}"

        return wrapper
    return decorator


def invalidate_cache_on_change(cache_patterns: List[str]):
    """
    Decorator to invalidate cache patterns when function is called.

    Args:
        cache_patterns: List of cache key patterns to invalidate
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Execute function first
            result = func(*args, **kwargs)

            # Invalidate cache patterns
            for pattern in cache_patterns:
                deleted_count = cache_manager.delete_pattern(pattern)
                logger.debug(f"Invalidated {deleted_count} cache entries for pattern: {pattern}")

            return result
        return wrapper
    return decorator


class QueryCache:
    """
    Specialized cache for database query results.
    Provides automatic cache invalidation based on model changes.
    """

    def __init__(self, cache_manager: CacheManager = None):
        self.cache_manager = cache_manager or globals()['cache_manager']
        self.model_cache_mappings = {
            'vulnerability': ['vuln:*', 'stats:*', 'trends:*'],
            'scan_session': ['scan:*', 'progress:*', 'stats:*'],
            'target': ['target:*', 'scan:*'],
            'tool_execution': ['tool:*', 'progress:*'],
            'report': ['report:*']
        }

    def get_query_cache_key(self, model_name: str, query_hash: str, filters: Dict = None) -> str:
        """Generate cache key for query results."""
        filter_hash = hashlib.md5(json.dumps(filters or {}, sort_keys=True).encode()).hexdigest()[:8]
        return f"query:{model_name}:{query_hash}:{filter_hash}"

    def cache_query_result(self, model_name: str, query_hash: str,
                          result: Any, ttl: int = 300, filters: Dict = None) -> None:
        """Cache query result."""
        cache_key = self.get_query_cache_key(model_name, query_hash, filters)
        self.cache_manager.set(cache_key, result, ttl)

    def get_cached_query_result(self, model_name: str, query_hash: str, filters: Dict = None) -> Any:
        """Get cached query result."""
        cache_key = self.get_query_cache_key(model_name, query_hash, filters)
        return self.cache_manager.get(cache_key)

    def invalidate_model_cache(self, model_name: str) -> int:
        """Invalidate all cache entries for a model."""
        patterns = self.model_cache_mappings.get(model_name.lower(), [f"{model_name.lower()}:*"])
        total_deleted = 0

        for pattern in patterns:
            deleted = self.cache_manager.delete_pattern(pattern)
            total_deleted += deleted
            logger.info(f"Invalidated {deleted} cache entries for pattern: {pattern}")

        return total_deleted


# Global query cache instance
query_cache = QueryCache()


def cached_query(model_name: str, ttl: int = 300):
    """
    Decorator for caching database query results.

    Args:
        model_name: Name of the model for cache invalidation
        ttl: Time to live in seconds
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Generate query hash from function and arguments
            func_signature = f"{func.__module__}.{func.__qualname__}"
            arg_hash = cache_key_generator(*args, **kwargs)
            query_hash = hashlib.md5(f"{func_signature}:{arg_hash}".encode()).hexdigest()

            # Try to get from cache
            cached_result = query_cache.get_cached_query_result(
                model_name, query_hash, kwargs
            )
            if cached_result is not None:
                logger.debug(f"Query cache hit for {func_signature}")
                return cached_result

            # Execute query and cache result
            logger.debug(f"Query cache miss for {func_signature}, executing query")
            result = func(*args, **kwargs)

            query_cache.cache_query_result(
                model_name, query_hash, result, ttl, kwargs
            )

            return result

        return wrapper
    return decorator


# Cache warming functions
def warm_vulnerability_cache():
    """Pre-warm frequently accessed vulnerability data."""
    from apps.vulnerabilities.models import Vulnerability
    from django.db.models import Count

    try:
        # Cache severity statistics
        severity_stats = list(
            Vulnerability.objects.values('severity').annotate(count=Count('id'))
        )
        cache_manager.set('stats:vulnerability:severity', severity_stats, 3600)

        # Cache recent vulnerabilities
        recent_vulns = list(
            Vulnerability.objects.order_by('-discovered_at')[:100]
            .values('id', 'vulnerability_name', 'severity', 'discovered_at')
        )
        cache_manager.set('vuln:recent:100', recent_vulns, 600)

        logger.info("Vulnerability cache warmed successfully")

    except Exception as e:
        logger.error(f"Error warming vulnerability cache: {e}")


def warm_scan_cache():
    """Pre-warm frequently accessed scan session data."""
    from apps.scanning.models import ScanSession
    from django.db.models import Count

    try:
        # Cache active scans
        active_scans = list(
            ScanSession.objects.filter(status__in=['queued', 'running'])
            .values('id', 'session_name', 'status', 'total_progress')
        )
        cache_manager.set('scan:active', active_scans, 60)

        # Cache scan statistics
        scan_stats = {
            'total': ScanSession.objects.count(),
            'active': ScanSession.objects.filter(status__in=['queued', 'running']).count(),
            'completed': ScanSession.objects.filter(status='completed').count(),
            'failed': ScanSession.objects.filter(status='failed').count()
        }
        cache_manager.set('stats:scan:summary', scan_stats, 300)

        logger.info("Scan cache warmed successfully")

    except Exception as e:
        logger.error(f"Error warming scan cache: {e}")


def warm_dashboard_cache():
    """Pre-warm dashboard data."""
    try:
        warm_vulnerability_cache()
        warm_scan_cache()
        logger.info("Dashboard cache warmed successfully")
    except Exception as e:
        logger.error(f"Error warming dashboard cache: {e}")


# Cache health check
def check_cache_health() -> Dict[str, Any]:
    """Check cache system health."""
    try:
        # Test basic operations
        test_key = "health_check"
        test_value = {"timestamp": time.time()}

        # Test set
        set_result = cache_manager.set(test_key, test_value, 10)

        # Test get
        get_result = cache_manager.get(test_key)

        # Test delete
        delete_result = cache_manager.delete(test_key)

        # Get stats
        stats = cache_manager.get_stats()

        return {
            'status': 'healthy' if set_result and get_result and delete_result else 'unhealthy',
            'redis_connection': True,
            'operations': {
                'set': set_result,
                'get': get_result is not None,
                'delete': delete_result
            },
            'statistics': stats
        }

    except Exception as e:
        logger.error(f"Cache health check failed: {e}")
        return {
            'status': 'unhealthy',
            'redis_connection': False,
            'error': str(e),
            'statistics': {'hits': 0, 'misses': 0, 'sets': 0, 'deletes': 0}
        }


# Export main components
__all__ = [
    'CacheManager',
    'cache_manager',
    'cache_result',
    'invalidate_cache_on_change',
    'QueryCache',
    'query_cache',
    'cached_query',
    'warm_vulnerability_cache',
    'warm_scan_cache',
    'warm_dashboard_cache',
    'check_cache_health'
]