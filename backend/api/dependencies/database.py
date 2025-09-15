"""
Database dependencies for FastAPI.
Provides database session management and transaction handling.
"""

import logging
from typing import Generator

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from core.database import SessionLocal, check_database_health
from core.exceptions import DatabaseException

logger = logging.getLogger(__name__)

def get_db() -> Generator[Session, None, None]:
    """
    Dependency function to get database session.

    Yields:
        Session: SQLAlchemy database session

    Raises:
        HTTPException: If database connection fails
    """
    db = SessionLocal()
    try:
        yield db
    except DatabaseException as e:
        logger.error("Database error in dependency: %s", e)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database operation failed"
        ) from e
    except Exception as e:
        logger.error("Unexpected error in database dependency: %s", e)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        ) from e
    finally:
        db.close()

def get_db_with_transaction() -> Generator[Session, None, None]:
    """
    Dependency function to get database session with automatic transaction management.
    Commits on success, rolls back on error.

    Yields:
        Session: SQLAlchemy database session

    Raises:
        HTTPException: If database connection or transaction fails
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except DatabaseException as e:
        logger.error("Database error in transaction dependency: %s", e)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database transaction failed"
        ) from e
    except Exception as e:
        logger.error("Unexpected error in transaction dependency: %s", e)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        ) from e
    finally:
        db.close()

async def check_db_health():
    """
    Dependency to check database health before processing requests.

    Raises:
        HTTPException: If database is not healthy
    """
    if not check_database_health():
        logger.error("Database health check failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable"
        )


class DatabaseHealthCheck:
    """
    Class-based dependency for database health checking.
    Can be configured with different health check parameters.
    """

    def __init__(self, critical: bool = False):
        """
        Initialize health check dependency.

        Args:
            critical: If True, raises 503 on health check failure.
                     If False, logs warning and continues.
        """
        self.critical = critical

    async def __call__(self):
        """
        Perform database health check.

        Raises:
            HTTPException: If critical=True and health check fails
        """
        is_healthy = check_database_health()

        if not is_healthy:
            if self.critical:
                logger.error("Critical database health check failed")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Database service unavailable"
                )
            logger.warning("Database health check failed, continuing with degraded service")


# Pre-configured health check dependencies
db_health_check = DatabaseHealthCheck(critical=True)
db_health_check_non_critical = DatabaseHealthCheck(critical=False)
