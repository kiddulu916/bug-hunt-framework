"""
Test database utilities for handling SQLAlchemy model compatibility with SQLite
"""

import uuid
import os
from sqlalchemy import create_engine, String, Column
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.dialects import sqlite
from sqlalchemy.types import TypeDecorator, CHAR


class SQLiteUUID(TypeDecorator):
    """
    Platform-independent UUID type.
    Uses PostgreSQL's UUID type if available, otherwise CHAR(36)
    """
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(UUID())
        else:
            return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return str(value)
        else:
            if not isinstance(value, uuid.UUID):
                return str(uuid.UUID(value))
            return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        else:
            if not isinstance(value, uuid.UUID):
                return uuid.UUID(value)
            return value


def patch_uuid_for_sqlite():
    """
    Monkey patch UUID type for SQLite compatibility in tests
    """
    # Import the models module to patch it
    import sys
    import models

    # Replace the UUID type with our SQLite-compatible version
    models.UUID = SQLiteUUID

    # Also patch any modules that might have imported UUID
    for module_name in list(sys.modules.keys()):
        if hasattr(sys.modules[module_name], 'UUID'):
            setattr(sys.modules[module_name], 'UUID', SQLiteUUID)


def get_test_db_session():
    """
    Get a test database session with SQLite UUID compatibility
    """
    # Check if we should use PostgreSQL for tests
    database_url = os.getenv('DATABASE_URL')
    if database_url and 'postgresql' in database_url:
        # Use PostgreSQL
        engine = create_engine(database_url)
    else:
        # Use SQLite with UUID compatibility
        patch_uuid_for_sqlite()
        engine = create_engine("sqlite:///./test.db", connect_args={"check_same_thread": False})

    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Import and create all tables
    from core.database import Base
    Base.metadata.create_all(bind=engine)

    return TestingSessionLocal, engine


def override_get_db():
    """
    Database dependency override for FastAPI tests
    """
    TestingSessionLocal, _ = get_test_db_session()

    def _override():
        try:
            db = TestingSessionLocal()
            yield db
        finally:
            db.close()

    return _override