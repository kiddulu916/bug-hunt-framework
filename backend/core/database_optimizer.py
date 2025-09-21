"""
Database query optimizer and performance monitoring.
Provides query optimization, performance tracking, and database health monitoring.
"""

import logging
import time
import functools
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple
from contextlib import contextmanager
from collections import defaultdict, deque
from datetime import datetime, timedelta
import statistics

from sqlalchemy import event, text
from sqlalchemy.orm import Session
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from core.cache import cache_manager, cached_query
from core.database import engine, SessionLocal

logger = logging.getLogger(__name__)


class QueryPerformanceMonitor:
    """
    Monitor and track database query performance.
    """

    def __init__(self, max_history: int = 1000):
        self.query_history = deque(maxlen=max_history)
        self.slow_query_threshold = 1.0  # seconds
        self.slow_queries = deque(maxlen=100)
        self.query_stats = defaultdict(list)
        self.lock = threading.Lock()

    def record_query(self, query: str, duration: float, result_count: int = None):
        """Record query execution details."""
        with self.lock:
            query_info = {
                'query': query[:500],  # Truncate long queries
                'duration': duration,
                'result_count': result_count,
                'timestamp': datetime.utcnow(),
                'is_slow': duration > self.slow_query_threshold
            }

            self.query_history.append(query_info)

            # Track slow queries separately
            if duration > self.slow_query_threshold:
                self.slow_queries.append(query_info)

            # Update statistics
            query_type = self._get_query_type(query)
            self.query_stats[query_type].append(duration)

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics."""
        with self.lock:
            if not self.query_history:
                return {'status': 'no_data'}

            durations = [q['duration'] for q in self.query_history]

            stats = {
                'total_queries': len(self.query_history),
                'slow_queries': len(self.slow_queries),
                'average_duration': statistics.mean(durations),
                'median_duration': statistics.median(durations),
                'max_duration': max(durations),
                'min_duration': min(durations),
                'slow_query_percentage': (len(self.slow_queries) / len(self.query_history)) * 100,
                'queries_by_type': {}
            }

            # Statistics by query type
            for query_type, type_durations in self.query_stats.items():
                if type_durations:
                    stats['queries_by_type'][query_type] = {
                        'count': len(type_durations),
                        'average_duration': statistics.mean(type_durations),
                        'max_duration': max(type_durations)
                    }

            return stats

    def get_slow_queries(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent slow queries."""
        with self.lock:
            return list(self.slow_queries)[-limit:]

    def _get_query_type(self, query: str) -> str:
        """Determine query type from SQL."""
        query_lower = query.lower().strip()
        if query_lower.startswith('select'):
            return 'SELECT'
        elif query_lower.startswith('insert'):
            return 'INSERT'
        elif query_lower.startswith('update'):
            return 'UPDATE'
        elif query_lower.startswith('delete'):
            return 'DELETE'
        else:
            return 'OTHER'


# Global performance monitor
performance_monitor = QueryPerformanceMonitor()


class DatabaseOptimizer:
    """
    Database optimization utilities and query enhancement.
    """

    def __init__(self):
        self.connection_pool_stats = {}
        self.query_cache_enabled = True

    def optimize_connection_pool(self) -> Dict[str, Any]:
        """Optimize database connection pool settings."""
        pool = engine.pool
        current_stats = {
            'pool_size': pool.size(),
            'checked_in': pool.checkedin(),
            'checked_out': pool.checkedout(),
            'overflow': pool.overflow(),
            'invalid': pool.invalidated()
        }

        # Calculate optimization recommendations
        utilization = (current_stats['checked_out'] / (current_stats['pool_size'] + current_stats['overflow'])) * 100

        recommendations = []
        if utilization > 80:
            recommendations.append("Consider increasing pool size")
        if current_stats['overflow'] > current_stats['pool_size'] * 0.5:
            recommendations.append("Consider increasing max_overflow")
        if current_stats['invalid'] > 0:
            recommendations.append("Check for connection issues")

        return {
            'current_stats': current_stats,
            'utilization_percent': round(utilization, 2),
            'recommendations': recommendations
        }

    def analyze_table_statistics(self, session: Session) -> Dict[str, Any]:
        """Analyze table statistics for optimization opportunities."""
        try:
            # Get table sizes and row counts
            table_stats = {}

            # PostgreSQL specific queries
            if 'postgresql' in str(engine.url):
                result = session.execute(text("""
                    SELECT
                        table_name,
                        pg_size_pretty(pg_total_relation_size(quote_ident(table_name))) as size,
                        (SELECT reltuples::bigint FROM pg_class WHERE relname = table_name) as row_count
                    FROM information_schema.tables
                    WHERE table_schema = 'public'
                    AND table_type = 'BASE TABLE'
                    ORDER BY pg_total_relation_size(quote_ident(table_name)) DESC
                """))

                for row in result:
                    table_stats[row.table_name] = {
                        'size': row.size,
                        'row_count': row.row_count or 0
                    }

            return {
                'table_statistics': table_stats,
                'total_tables': len(table_stats),
                'analysis_timestamp': datetime.utcnow()
            }

        except Exception as e:
            logger.error(f"Error analyzing table statistics: {e}")
            return {'error': str(e)}

    def suggest_indexes(self, session: Session) -> List[Dict[str, Any]]:
        """Suggest database indexes based on query patterns."""
        suggestions = []

        try:
            # Analyze slow queries for index opportunities
            slow_queries = performance_monitor.get_slow_queries(50)

            for query_info in slow_queries:
                query = query_info['query'].lower()

                # Look for WHERE clauses without indexes
                if 'where' in query and query_info['duration'] > 2.0:
                    suggestions.append({
                        'type': 'missing_index',
                        'query': query_info['query'][:200],
                        'duration': query_info['duration'],
                        'suggestion': 'Consider adding index on WHERE clause columns'
                    })

                # Look for JOINs that might benefit from indexes
                if 'join' in query and query_info['duration'] > 1.5:
                    suggestions.append({
                        'type': 'join_optimization',
                        'query': query_info['query'][:200],
                        'duration': query_info['duration'],
                        'suggestion': 'Consider adding indexes on JOIN columns'
                    })

        except Exception as e:
            logger.error(f"Error suggesting indexes: {e}")

        return suggestions

    def optimize_query_plan(self, query: str, session: Session) -> Dict[str, Any]:
        """Analyze and optimize query execution plan."""
        try:
            # Get query execution plan (PostgreSQL)
            if 'postgresql' in str(engine.url):
                explain_result = session.execute(text(f"EXPLAIN ANALYZE {query}"))
                plan_lines = [row[0] for row in explain_result]

                # Analyze plan for optimization opportunities
                optimizations = []
                for line in plan_lines:
                    if 'Seq Scan' in line:
                        optimizations.append("Sequential scan detected - consider adding index")
                    if 'cost=' in line and 'cost=0.00' not in line:
                        cost = line.split('cost=')[1].split(' ')[0]
                        if float(cost.split('..')[1]) > 1000:
                            optimizations.append(f"High cost operation detected: {cost}")

                return {
                    'execution_plan': plan_lines,
                    'optimizations': optimizations,
                    'analysis_timestamp': datetime.utcnow()
                }

        except Exception as e:
            logger.error(f"Error optimizing query plan: {e}")
            return {'error': str(e)}

        return {'message': 'Query plan optimization not available for this database'}


# Global optimizer instance
db_optimizer = DatabaseOptimizer()


def monitor_query_performance(func: Callable) -> Callable:
    """
    Decorator to monitor query performance.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time

            # Try to determine result count
            result_count = None
            if hasattr(result, '__len__'):
                result_count = len(result)
            elif hasattr(result, 'count'):
                result_count = result.count()

            # Record performance
            performance_monitor.record_query(
                str(func.__name__), duration, result_count
            )

            # Log slow queries
            if duration > performance_monitor.slow_query_threshold:
                logger.warning(
                    f"Slow query detected: {func.__name__} took {duration:.2f}s"
                )

            return result

        except Exception as e:
            duration = time.time() - start_time
            performance_monitor.record_query(
                f"{func.__name__} (ERROR)", duration
            )
            raise

    return wrapper


@contextmanager
def optimized_session():
    """
    Context manager for optimized database sessions.
    """
    session = SessionLocal()
    try:
        # Configure session for optimal performance
        session.execute(text("SET statement_timeout = '30s'"))
        session.execute(text("SET lock_timeout = '10s'"))

        yield session
        session.commit()

    except Exception as e:
        session.rollback()
        logger.error(f"Database session error: {e}")
        raise
    finally:
        session.close()


class BulkOperationOptimizer:
    """
    Optimize bulk database operations.
    """

    @staticmethod
    def bulk_insert_vulnerabilities(vulnerabilities: List[Dict], session: Session) -> int:
        """Optimized bulk insert for vulnerabilities."""
        try:
            from apps.vulnerabilities.models import Vulnerability

            # Use bulk_insert_mappings for better performance
            session.bulk_insert_mappings(Vulnerability, vulnerabilities)
            session.commit()

            # Invalidate related caches
            cache_manager.delete_pattern('vuln:*')
            cache_manager.delete_pattern('stats:*')

            return len(vulnerabilities)

        except Exception as e:
            session.rollback()
            logger.error(f"Bulk insert error: {e}")
            raise

    @staticmethod
    def bulk_update_scan_progress(updates: List[Dict], session: Session) -> int:
        """Optimized bulk update for scan progress."""
        try:
            from apps.scanning.models import ScanSession

            # Use bulk_update_mappings for better performance
            session.bulk_update_mappings(ScanSession, updates)
            session.commit()

            # Invalidate related caches
            cache_manager.delete_pattern('scan:*')
            cache_manager.delete_pattern('progress:*')

            return len(updates)

        except Exception as e:
            session.rollback()
            logger.error(f"Bulk update error: {e}")
            raise


# Database event listeners for performance monitoring
@event.listens_for(Engine, "before_cursor_execute")
def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    """Track query start time."""
    context._query_start_time = time.time()


@event.listens_for(Engine, "after_cursor_execute")
def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    """Track query completion and performance."""
    total_time = time.time() - context._query_start_time

    # Record query performance
    performance_monitor.record_query(statement, total_time, cursor.rowcount)

    # Log slow queries
    if total_time > performance_monitor.slow_query_threshold:
        logger.warning(
            f"Slow query executed in {total_time:.3f}s: {statement[:100]}..."
        )


def get_database_health() -> Dict[str, Any]:
    """Get comprehensive database health information."""
    try:
        with optimized_session() as session:
            # Test basic connectivity
            session.execute(text("SELECT 1"))

            # Get performance stats
            perf_stats = performance_monitor.get_performance_stats()

            # Get connection pool stats
            pool_stats = db_optimizer.optimize_connection_pool()

            # Get table statistics
            table_stats = db_optimizer.analyze_table_statistics(session)

            return {
                'status': 'healthy',
                'connection': True,
                'performance': perf_stats,
                'connection_pool': pool_stats,
                'tables': table_stats,
                'timestamp': datetime.utcnow()
            }

    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            'status': 'unhealthy',
            'connection': False,
            'error': str(e),
            'timestamp': datetime.utcnow()
        }


# Cached query implementations for common operations
@cached_query('vulnerability', ttl=300)
def get_vulnerability_statistics():
    """Get cached vulnerability statistics."""
    from apps.vulnerabilities.models import Vulnerability
    from django.db.models import Count

    with optimized_session() as session:
        # This would be adapted for SQLAlchemy
        # For now, return mock data
        return {
            'total': 1500,
            'critical': 45,
            'high': 230,
            'medium': 680,
            'low': 545,
            'verified': 1200
        }


@cached_query('scan_session', ttl=60)
def get_active_scans():
    """Get cached active scan sessions."""
    from apps.scanning.models import ScanSession

    with optimized_session() as session:
        # This would be adapted for SQLAlchemy
        # For now, return mock data
        return [
            {'id': 'scan-1', 'name': 'Test Scan', 'progress': 45.2},
            {'id': 'scan-2', 'name': 'Weekly Scan', 'progress': 78.9}
        ]


# Export main components
__all__ = [
    'QueryPerformanceMonitor',
    'performance_monitor',
    'DatabaseOptimizer',
    'db_optimizer',
    'monitor_query_performance',
    'optimized_session',
    'BulkOperationOptimizer',
    'get_database_health',
    'get_vulnerability_statistics',
    'get_active_scans'
]