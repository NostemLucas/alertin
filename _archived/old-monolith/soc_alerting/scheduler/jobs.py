"""
Background job scheduler for CVE sync and enrichment tasks.

Uses asyncio for scheduling (no external dependencies like APScheduler or Celery).
"""

import asyncio
import logging
from typing import Optional

from ..config.settings import get_settings
from ..services.cve_sync_service import CVESyncService
from ..services.enrichment_service import create_enrichment_service_from_settings
from ..database.connection import get_database

logger = logging.getLogger(__name__)


class JobScheduler:
    """
    Simple async job scheduler for CVE sync and enrichment.

    Jobs:
    - Hourly sync: Fetch CVEs from NIST/CISA
    - Daily enrichment: Enrich CVEs with NLP

    Uses Python's asyncio (no Redis/RabbitMQ needed).
    """

    def __init__(self):
        """Initialize job scheduler."""
        self.settings = get_settings()
        self.running = False
        self._tasks: list[asyncio.Task] = []

    async def start(self):
        """Start scheduler background tasks."""
        if not self.settings.enable_scheduler:
            logger.info("Scheduler disabled in settings (ENABLE_SCHEDULER=false)")
            return

        logger.info("Starting job scheduler...")
        self.running = True

        # Schedule hourly sync job
        self._tasks.append(asyncio.create_task(self._hourly_sync_job()))
        logger.info("Scheduled: Hourly sync job")

        # Schedule daily enrichment job (if enabled)
        if self.settings.enable_enrichment:
            self._tasks.append(asyncio.create_task(self._daily_enrichment_job()))
            logger.info("Scheduled: Daily enrichment job")

        logger.info(f"Scheduler started with {len(self._tasks)} background jobs")

    async def stop(self):
        """Stop scheduler and cancel all tasks."""
        logger.info("Stopping job scheduler...")
        self.running = False

        # Cancel all tasks
        for task in self._tasks:
            task.cancel()

        # Wait for tasks to complete cancellation
        await asyncio.gather(*self._tasks, return_exceptions=True)

        logger.info("Scheduler stopped")

    async def _hourly_sync_job(self):
        """
        Run CVE sync every hour.

        Fetches CVEs modified in the last hour from NIST/CISA.
        """
        while self.running:
            try:
                logger.info("======== Starting hourly sync job ========")

                # Calculate hours based on update interval
                hours_back = max(self.settings.update_interval_minutes // 60, 1)

                async with CVESyncService() as sync_service:
                    stats = await sync_service.sync_recent_cves(
                        hours_back=hours_back,
                        checkpoint_type="scheduler_hourly"
                    )

                logger.info(
                    f"Hourly sync completed: {stats['cves_processed']} CVEs processed, "
                    f"{stats['cves_created']} created, {stats['cves_updated']} updated, "
                    f"checkpoint={stats['checkpoint_id']}"
                )

            except Exception as e:
                logger.error(f"Hourly sync job failed: {e}", exc_info=True)

            # Wait 1 hour before next run
            await asyncio.sleep(3600)

    async def _daily_enrichment_job(self):
        """
        Run enrichment once per day at 2 AM (or immediately, then every 24h).

        Enriches CVEs added/updated in the last 24 hours.
        """
        while self.running:
            try:
                logger.info("======== Starting daily enrichment job ========")

                enrichment_service = create_enrichment_service_from_settings()
                db = get_database()

                async with db.get_session() as session:
                    stats = await enrichment_service.enrich_recent_cves(
                        session=session,
                        hours_back=24  # Last 24 hours
                    )

                logger.info(
                    f"Daily enrichment completed: {stats['enriched']} enriched, "
                    f"{stats['skipped']} skipped, {stats['failed']} failed "
                    f"({stats['total_time_ms']}ms total)"
                )

                # Unload NLP models to free memory
                enrichment_service.unload_models()
                logger.info("NLP models unloaded from memory")

            except Exception as e:
                logger.error(f"Daily enrichment job failed: {e}", exc_info=True)

            # Wait 24 hours before next run
            await asyncio.sleep(86400)


# Singleton instance
_scheduler: Optional[JobScheduler] = None


def get_scheduler() -> JobScheduler:
    """
    Get scheduler singleton instance.

    Returns:
        JobScheduler instance
    """
    global _scheduler
    if _scheduler is None:
        _scheduler = JobScheduler()
    return _scheduler
