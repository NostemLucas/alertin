"""
Database connection management.

Handles async SQLAlchemy engine and session creation with advanced features:
- Connection pooling with event listeners
- Automatic retry on connection failures
- Health checks and monitoring
- Graceful shutdown handling
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker, AsyncEngine
from sqlalchemy import event, text, exc as sa_exc
from sqlalchemy.pool import AsyncAdaptedQueuePool, Pool
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional, Dict, Any
from dataclasses import dataclass, field
import logging
import asyncio
from datetime import datetime

from ..config.settings import get_settings
from ..models.database import Base
from ..models.statistics import PoolStatistics

logger = logging.getLogger(__name__)


@dataclass
class PoolMetrics:
    """
    Connection pool metrics.

    Replaces dictionary-based stats to avoid string-based key access
    and provide type safety.
    """
    total_checkouts: int = 0
    total_checkins: int = 0
    current_checked_out: int = 0
    last_error: str | None = None
    last_error_time: datetime | None = None


@dataclass
class HealthCheckResult:
    """
    Health check result with type safety.

    Replaces dictionary-based result to avoid string-based key access
    and provide type safety.
    """
    healthy: bool = False
    latency_ms: float | None = None
    error: str | None = None
    error_type: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    pool_stats: Dict[str, Any] | None = None
    database_url: str | None = None


class DatabaseConnection:
    """
    Database connection manager with advanced features.

    Features:
    - Async connection pooling
    - Automatic reconnection on failures
    - Connection pool monitoring
    - Health checks and metrics
    - Graceful shutdown
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

        # Connection pool metrics (type-safe dataclass)
        self._pool_stats = PoolMetrics()

        # Create async engine with advanced pooling
        self.engine = create_async_engine(
            self.database_url,
            poolclass=AsyncAdaptedQueuePool,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_pre_ping=True,  # Test connections before using
            pool_recycle=3600,   # Recycle connections after 1 hour
            pool_timeout=30,     # Wait max 30s for connection
            echo=False,          # Set to True for SQL debugging
            echo_pool=False,     # Set to True for pool debugging
            connect_args={
                "timeout": 60,   # Connection timeout
                "command_timeout": 60,  # Command execution timeout
                "server_settings": {
                    "application_name": "soc_alerting",
                    "jit": "off",  # Disable JIT for better cold start
                }
            }
        )

        # Setup pool event listeners
        self._setup_pool_listeners()

        # Create async session factory
        self.SessionLocal = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,  # Manual flush for better control
        )

        logger.info(f"Async database connection initialized: {self._get_safe_url()}")
        logger.info(f"Pool config: size={settings.database_pool_size}, overflow={settings.database_max_overflow}")

    def _setup_pool_listeners(self):
        """Setup connection pool event listeners for monitoring."""

        @event.listens_for(self.engine.sync_engine.pool, "connect")
        def on_connect(dbapi_conn, connection_record):  # noqa: ARG001
            """Called when a new DB-API connection is created."""
            logger.debug("New database connection created")

        @event.listens_for(self.engine.sync_engine.pool, "checkout")
        def on_checkout(dbapi_conn, connection_record, connection_proxy):  # noqa: ARG001
            """Called when a connection is retrieved from the pool."""
            self._pool_stats.total_checkouts += 1
            self._pool_stats.current_checked_out += 1
            logger.debug(f"Connection checked out (total: {self._pool_stats.current_checked_out})")

        @event.listens_for(self.engine.sync_engine.pool, "checkin")
        def on_checkin(dbapi_conn, connection_record):  # noqa: ARG001
            """Called when a connection is returned to the pool."""
            self._pool_stats.total_checkins += 1
            self._pool_stats.current_checked_out -= 1
            logger.debug(f"Connection checked in (total: {self._pool_stats.current_checked_out})")

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

    def get_pool_stats(self) -> PoolStatistics:
        """
        Get connection pool statistics.

        Returns:
            PoolStatistics dataclass with pool metrics
        """
        pool = self.engine.sync_engine.pool
        return PoolStatistics(
            total_checkouts=self._pool_stats.total_checkouts,
            total_checkins=self._pool_stats.total_checkins,
            current_checked_out=self._pool_stats.current_checked_out,
            last_error=self._pool_stats.last_error,
            last_error_time=self._pool_stats.last_error_time.isoformat() if self._pool_stats.last_error_time else None,
            pool_size=pool.size(),
            checked_out_connections=pool.checkedout(),
            overflow_connections=pool.overflow(),
            queue_size=pool.size() - pool.checkedout(),
        )


    # ============================================================================
    # Schema management removed - Use Alembic migrations exclusively
    # ============================================================================
    # Previously: initialize(), create_tables(), drop_tables()
    # Now: Run `alembic upgrade head` to manage schema
    # ============================================================================

    @asynccontextmanager
    async def get_session(self, auto_commit: bool = True) -> AsyncGenerator[AsyncSession, None]:
        """
        Get an async database session with automatic cleanup and error handling.

        Args:
            auto_commit: Automatically commit on success (default: True)

        Usage:
            async with db.get_session() as session:
                result = await session.execute(select(CVERecord))

        Yields:
            Async SQLAlchemy session

        Raises:
            SQLAlchemy exceptions on database errors
        """
        session = self.SessionLocal()
        try:
            yield session
            if auto_commit:
                await session.commit()
        except sa_exc.OperationalError as e:
            await session.rollback()
            self._pool_stats.last_error = str(e)
            self._pool_stats.last_error_time = datetime.utcnow()
            logger.error(f"Database operational error: {e}", exc_info=True)
            raise
        except sa_exc.IntegrityError as e:
            await session.rollback()
            logger.error(f"Database integrity error: {e}", exc_info=True)
            raise
        except sa_exc.DataError as e:
            await session.rollback()
            logger.error(f"Database data error: {e}", exc_info=True)
            raise
        except Exception as e:
            await session.rollback()
            self._pool_stats.last_error = str(e)
            self._pool_stats.last_error_time = datetime.utcnow()
            logger.error(f"Unexpected session error: {e}", exc_info=True)
            raise
        finally:
            await session.close()

    async def execute_with_retry(
        self,
        operation,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        backoff_factor: float = 2.0
    ):
        """
        Execute a database operation with automatic retry on transient failures.

        Args:
            operation: Async callable that takes a session as argument
            max_retries: Maximum number of retry attempts
            retry_delay: Initial delay between retries (seconds)
            backoff_factor: Multiplier for retry delay on each attempt

        Returns:
            Result from the operation

        Raises:
            Last exception if all retries fail

        Example:
            async def my_operation(session):
                result = await session.execute(select(CVERecord))
                return result.scalars().all()

            cves = await db.execute_with_retry(my_operation)
        """
        last_exception = None
        delay = retry_delay

        for attempt in range(max_retries + 1):
            try:
                async with self.get_session() as session:
                    result = await operation(session)
                    return result
            except (sa_exc.OperationalError, asyncio.TimeoutError) as e:
                last_exception = e
                if attempt < max_retries:
                    logger.warning(
                        f"Database operation failed (attempt {attempt + 1}/{max_retries + 1}): {e}. "
                        f"Retrying in {delay}s..."
                    )
                    await asyncio.sleep(delay)
                    delay *= backoff_factor
                else:
                    logger.error(f"Database operation failed after {max_retries + 1} attempts")
                    raise
            except Exception as e:
                # Don't retry on non-transient errors
                logger.error(f"Non-retryable database error: {e}")
                raise

        # Should never reach here, but just in case
        if last_exception:
            raise last_exception

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

    async def health_check(self, detailed: bool = False) -> HealthCheckResult:
        """
        Check database connectivity with optional detailed metrics.

        Args:
            detailed: Include detailed pool statistics

        Returns:
            HealthCheckResult dataclass with health check results
        """
        start_time = datetime.utcnow()
        result = HealthCheckResult(timestamp=start_time.isoformat())

        try:
            async with self.get_session() as session:
                # Simple connectivity check
                await session.execute(text("SELECT 1"))

            end_time = datetime.utcnow()
            latency = (end_time - start_time).total_seconds() * 1000

            result.healthy = True
            result.latency_ms = round(latency, 2)

            if detailed:
                pool_stats = self.get_pool_stats()
                result.pool_stats = pool_stats.to_dict()
                result.database_url = self._get_safe_url()

            logger.debug(f"Health check passed (latency: {result.latency_ms}ms)")
            return result

        except Exception as e:
            result.error = str(e)
            result.error_type = type(e).__name__
            logger.error(f"Health check failed: {e}")
            return result



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
