"""
SOC Alert System - Main Entry Point

This is the main entry point for the SOC alert system.
Starts the FastAPI web server for CVE visualization and processing.
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parents[2]))

from soc_alerting.config.settings import get_settings
from soc_alerting.config.logging_config import setup_logging
from soc_alerting.database.connection import get_database
from soc_alerting.api.app import create_app

# Setup logging
settings = get_settings()
setup_logging(
    level=settings.log_level,
    log_file=settings.log_file,
    json_format=settings.log_json
)

logger = logging.getLogger(__name__)


async def main():
    """
    Main entry point for the application (async).

    Performs database health check and starts FastAPI server with uvicorn.
    """
    logger.info("=" * 80)
    logger.info("SOC Alert System - Starting")
    logger.info("=" * 80)

    # Log configuration
    logger.info(f"Log Level: {settings.log_level}")
    logger.info(f"Database URL: {settings.database_url.split('@')[1] if '@' in settings.database_url else 'N/A'}")
    logger.info(f"HuggingFace Model: {settings.hf_model_name}")
    logger.info(f"Update Interval: {settings.update_interval_minutes} minutes")
    logger.info(f"Enrichment Enabled: {settings.enable_enrichment}")
    logger.info(f"Scheduler Enabled: {settings.enable_scheduler}")

    # Initialize database
    logger.info("Initializing database connection...")
    db = get_database()

    # Health check (async)
    logger.info("Performing database health check...")
    health_result = await db.health_check()
    if health_result.get("healthy"):
        logger.info(f"✓ Database connection healthy (latency: {health_result.get('latency_ms', 'N/A')}ms)")
    else:
        logger.error("✗ Database connection failed!")
        sys.exit(1)

    logger.info("")
    logger.info("=" * 80)
    logger.info("SOC Alert System - Ready")
    logger.info("=" * 80)
    logger.info("")
    logger.info("FastAPI Server Starting...")
    logger.info("API Documentation: http://localhost:8000/docs")
    logger.info("API Root: http://localhost:8000")
    logger.info("")

    # Start FastAPI with uvicorn
    import uvicorn

    app = create_app()

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level=settings.log_level.lower(),
        access_log=True,
    )


if __name__ == "__main__":
    asyncio.run(main())
