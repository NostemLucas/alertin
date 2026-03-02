"""
Database connection management.

Handles SQLAlchemy engine and session creation.
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from contextlib import contextmanager
from typing import Generator
import logging

from ..config.settings import get_settings
from ..models.database import Base

logger = logging.getLogger(__name__)


class DatabaseConnection:
    """
    Database connection manager.

    Handles engine creation, session management, and connection pooling.
    """

    def __init__(self, database_url: str | None = None):
        """
        Initialize database connection.

        Args:
            database_url: Database URL (defaults to settings)
        """
        settings = get_settings()
        self.database_url = database_url or settings.database_url

        # Create engine with connection pooling
        self.engine = create_engine(
            self.database_url,
            poolclass=QueuePool,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_pre_ping=True,  # Test connections before using
            echo=False,  # Set to True for SQL debugging
        )

        # Create session factory
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )

        # Register connection listeners
        self._register_listeners()

        logger.info(f"Database connection initialized: {self._get_safe_url()}")

    def _get_safe_url(self) -> str:
        """Get database URL with password masked."""
        url = str(self.database_url)
        if '@' in url:
            # Mask password
            parts = url.split('@')
            if ':' in parts[0]:
                user_pass = parts[0].split(':')
                return f"{user_pass[0]}:****@{parts[1]}"
        return url

    def _register_listeners(self):
        """Register SQLAlchemy event listeners."""

        @event.listens_for(self.engine, "connect")
        def receive_connect(dbapi_conn, connection_record):
            """Handle new connection."""
            logger.debug("New database connection established")

        @event.listens_for(self.engine, "checkout")
        def receive_checkout(dbapi_conn, connection_record, connection_proxy):
            """Handle connection checkout from pool."""
            logger.debug("Connection checked out from pool")

    async def initialize(self):
        """
        Initialize database (create tables if needed).

        Note: In production, use Alembic migrations instead.
        """
        logger.info("Initializing database schema...")
        Base.metadata.create_all(bind=self.engine)
        logger.info("Database schema initialized")

    def create_tables(self):
        """
        Create all tables (synchronous).

        WARNING: This is for development only. Use Alembic in production.
        """
        logger.warning("Creating tables directly (use Alembic in production)")
        Base.metadata.create_all(bind=self.engine)

    def drop_tables(self):
        """
        Drop all tables (synchronous).

        WARNING: This will delete all data!
        """
        logger.warning("Dropping all tables - DATA WILL BE LOST")
        Base.metadata.drop_all(bind=self.engine)

    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """
        Get a database session with automatic cleanup.

        Usage:
            with db.get_session() as session:
                session.query(CVERecord).all()

        Yields:
            SQLAlchemy session
        """
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Session error: {e}")
            raise
        finally:
            session.close()

    def get_raw_session(self) -> Session:
        """
        Get a raw session (manual cleanup required).

        Returns:
            SQLAlchemy session (must be closed manually)
        """
        return self.SessionLocal()

    async def close(self):
        """Close database connection and dispose engine."""
        logger.info("Closing database connections...")
        self.engine.dispose()
        logger.info("Database connections closed")

    def health_check(self) -> bool:
        """
        Check database connectivity.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            from sqlalchemy import text
            with self.get_session() as session:
                session.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False


# Global database instance
_db_instance: DatabaseConnection | None = None


def get_database() -> DatabaseConnection:
    """
    Get global database instance (singleton).

    Returns:
        DatabaseConnection instance
    """
    global _db_instance
    if _db_instance is None:
        _db_instance = DatabaseConnection()
    return _db_instance


def reset_database():
    """Reset global database instance (for testing)."""
    global _db_instance
    if _db_instance:
        _db_instance.engine.dispose()
    _db_instance = None
