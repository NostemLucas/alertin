"""
Database connection management.

Handles async SQLAlchemy engine and session creation.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import event, text
from sqlalchemy.pool import AsyncAdaptedQueuePool
from contextlib import asynccontextmanager
from typing import AsyncGenerator
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
        Initialize async database connection.

        Args:
            database_url: Database URL (defaults to settings)
        """
        settings = get_settings()
        raw_url = database_url or settings.database_url

        # Convert to async URL (postgresql+asyncpg://)
        if raw_url.startswith("postgresql://"):
            self.database_url = raw_url.replace("postgresql://", "postgresql+asyncpg://", 1)
        elif raw_url.startswith("postgresql+asyncpg://"):
            self.database_url = raw_url
        else:
            self.database_url = raw_url

        # Create async engine with connection pooling
        self.engine = create_async_engine(
            self.database_url,
            poolclass=AsyncAdaptedQueuePool,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_pre_ping=True,  # Test connections before using
            echo=False,  # Set to True for SQL debugging
        )

        # Create async session factory
        self.SessionLocal = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        logger.info(f"Async database connection initialized: {self._get_safe_url()}")

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


    async def initialize(self):
        """
        Initialize database (create tables if needed).

        Note: In production, use Alembic migrations instead.
        """
        logger.info("Initializing database schema...")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all, checkfirst=True)
        logger.info("Database schema initialized")

    async def create_tables(self):
        """
        Create all tables (async).

        WARNING: This is for development only. Use Alembic in production.
        """
        logger.warning("Creating tables directly (use Alembic in production)")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all, checkfirst=True)

    async def drop_tables(self):
        """
        Drop all tables (async).

        WARNING: This will delete all data!
        """
        logger.warning("Dropping all tables - DATA WILL BE LOST")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Get an async database session with automatic cleanup.

        Usage:
            async with db.get_session() as session:
                result = await session.execute(select(CVERecord))

        Yields:
            Async SQLAlchemy session
        """
        session = self.SessionLocal()
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"Session error: {e}")
            raise
        finally:
            await session.close()

    def get_raw_session(self) -> AsyncSession:
        """
        Get a raw async session (manual cleanup required).

        Returns:
            Async SQLAlchemy session (must be closed manually)
        """
        return self.SessionLocal()

    async def close(self):
        """Close database connection and dispose engine."""
        logger.info("Closing database connections...")
        await self.engine.dispose()
        logger.info("Database connections closed")

    async def health_check(self) -> bool:
        """
        Check database connectivity (async).

        Returns:
            True if connection successful, False otherwise
        """
        try:
            async with self.get_session() as session:
                await session.execute(text("SELECT 1"))
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
