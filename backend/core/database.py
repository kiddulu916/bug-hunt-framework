"""
Database configuration and session management for SQLAlchemy.
This module handles database connections for both Django and FastAPI.
"""

from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from typing import Generator
import os
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

# Database URL from environment
DATABASE_URL = os.getenv(
    'DATABASE_URL',
    'postgresql://bugbounty_user:password@localhost:5432/bugbounty_platform'
)

# Create SQLAlchemy engine with optimized settings
engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=300,
    echo=os.getenv('SQL_ECHO', 'False').lower() == 'true',
    future=True,
)

# Create SessionLocal class
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)

# Base class for SQLAlchemy models
Base = declarative_base()

def get_db() -> Generator[Session, None, None]:
    """
    Dependency function to get database session for FastAPI.
    Yields a SQLAlchemy session and ensures it's closed after use.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error("Database error: %s", e)
        db.rollback()
        raise
    finally:
        db.close()

@contextmanager
def get_db_session():
    """
    Context manager for database sessions.
    Use this for manual database operations outside of FastAPI dependencies.

    Example:
        with get_db_session() as db:
            user = db.query(User).first()
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        logger.error("Database session error: %s", e)
        db.rollback()
        raise
    finally:
        db.close()

class DatabaseManager:
    """Database manager for handling connections and transactions."""

    def __init__(self):
        self.engine = engine
        self.SessionLocal = SessionLocal

    def create_tables(self):
        """Create all tables defined in models."""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error("Error creating database tables: %s", e)
            raise

    def drop_tables(self):
        """Drop all tables (use with caution!)"""
        try:
            Base.metadata.drop_all(bind=self.engine)
            logger.warning("All database tables dropped")
        except Exception as e:
            logger.error("Error dropping database tables: %s", e)
            raise

    def get_session(self) -> Session:
        """Get a new database session."""
        return self.SessionLocal()

    def close_all_sessions(self):
        """Close all database sessions."""
        self.SessionLocal.close_all()

    def execute_raw_sql(self, sql: str, params: dict = None):
        """Execute raw SQL query."""
        with get_db_session() as db:
            result = db.execute(sql, params or {})
            return result

# Database event listeners
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Set SQLite pragmas for better performance (if using SQLite)."""
    if 'sqlite' in DATABASE_URL:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA cache_size=1000")
        cursor.execute("PRAGMA temp_store=memory")
        cursor.close()

@event.listens_for(engine, "checkout")
def receive_checkout(dbapi_connection, connection_record, connection_proxy):
    """Log database connection checkout."""
    logger.debug("Database connection checked out from pool")

@event.listens_for(engine, "checkin")
def receive_checkin(dbapi_connection, connection_record):
    """Log database connection checkin."""
    logger.debug("Database connection returned to pool")

# Health check function
def check_database_health() -> bool:
    """
    Check database connectivity and health.
    Returns True if database is accessible, False otherwise.
    """
    try:
        with get_db_session() as db:
            db.execute("SELECT 1")
        return True
    except Exception as e:
        logger.error("Database health check failed: %s", e)
        return False

# Database statistics
def get_database_stats():
    """Get database connection pool statistics."""
    pool = engine.pool
    return {
        'pool_size': pool.size(),
        'checked_in': pool.checkedin(),
        'checked_out': pool.checkedout(),
        'overflow': pool.overflow(),
    }

# Initialize database manager
db_manager = DatabaseManager()

# Export commonly used items
__all__ = [
    'engine',
    'SessionLocal',
    'Base',
    'get_db',
    'get_db_session',
    'DatabaseManager',
    'db_manager',
    'check_database_health',
    'get_database_stats',
]
