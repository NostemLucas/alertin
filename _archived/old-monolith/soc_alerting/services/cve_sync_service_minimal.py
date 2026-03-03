"""
Minimal CVE Synchronization Service - Simple and fast.

Syncs CVEs from NIST, enriches with CISA KEV, saves to minimal schema.
No complex relationships, no NLP enrichment in this service.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
import uuid

from ..clients.nist_client import NISTClient
from ..clients.cisa_client import CISAClient
from ..database.repositories.cve_repository_minimal import CVERepositoryMinimal
from ..database.connection import get_database
from ..models.domain_minimal import CVEMinimal, SeverityLevel
from ..models.database_minimal import ProcessingLog

logger = logging.getLogger(__name__)


class CVESyncServiceMinimal:
    """
    Minimal CVE synchronization service.

    Flow:
    1. Fetch CVEs from NIST NVD (by modified date)
    2. Convert to minimal domain model (17 fields + attack vectors)
    3. Check each CVE against CISA KEV catalog
    4. Apply CISA KEV enrichment (KEV → CRITICAL)
    5. Save to database (single table with JSONB)
    6. Return sync statistics
    """

    def __init__(self):
        """Initialize minimal sync service."""
        self.nist_client: Optional[NISTClient] = None
        self.cisa_client: Optional[CISAClient] = None

    async def __aenter__(self):
        """Async context manager entry."""
        self.nist_client = NISTClient()
        self.cisa_client = CISAClient()
        await self.nist_client.__aenter__()
        await self.cisa_client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.nist_client:
            await self.nist_client.__aexit__(exc_type, exc_val, exc_tb)
        if self.cisa_client:
            await self.cisa_client.__aexit__(exc_type, exc_val, exc_tb)

    async def sync_recent_cves(
        self,
        hours_back: int = 24,
        max_cves: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Synchronize CVEs modified in the last N hours.

        This is the main method for incremental sync updates.

        Args:
            hours_back: Hours to look back for modified CVEs
            max_cves: Maximum CVEs to process (None = all)

        Returns:
            Statistics dictionary with sync results
        """
        logger.info(f"Starting minimal CVE sync: last {hours_back} hours...")

        # Create processing log
        run_id = uuid.uuid4()
        start_time = datetime.utcnow()

        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(hours=hours_back)

        # Fetch from NIST
        logger.info(f"Fetching CVEs from NIST (modified: {start_date} to {end_date})")
        nist_vulnerabilities = await self.nist_client.fetch_cves_by_modified_date(
            start_date=start_date,
            end_date=end_date,
            max_results=max_cves,
        )

        logger.info(f"Fetched {len(nist_vulnerabilities)} CVEs from NIST")

        if not nist_vulnerabilities:
            logger.info("No CVEs to sync")
            return {
                "run_id": str(run_id),
                "cves_fetched": 0,
                "cves_processed": 0,
                "cves_created": 0,
                "cves_updated": 0,
                "cves_in_kev": 0,
                "by_severity": {},
                "duration_seconds": 0,
            }

        # Process CVEs
        return await self._sync_cve_list(
            nist_vulnerabilities=nist_vulnerabilities,
            run_id=run_id,
            start_time=start_time,
        )

    async def sync_specific_cve(self, cve_id: str) -> Optional[CVEMinimal]:
        """
        Synchronize a specific CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            Synced CVE domain model or None if not found
        """
        logger.info(f"Syncing specific CVE: {cve_id}")

        # Fetch from NIST
        nist_vuln = await self.nist_client.fetch_cve_by_id(cve_id)
        if not nist_vuln:
            logger.warning(f"CVE not found in NIST: {cve_id}")
            return None

        # Check if in CISA KEV
        is_in_kev = await self.cisa_client.is_cve_in_kev(cve_id)

        # Convert to minimal domain model
        cve = self.nist_client.convert_to_minimal_domain_model(
            nist_vuln,
            is_in_cisa_kev=is_in_kev
        )

        # Enrich with CISA KEV if applicable
        if is_in_kev:
            cve = await self.cisa_client.enrich_cve_minimal(cve)

        # Get database connection
        db = get_database()

        async with db.get_session() as session:
            repo = CVERepositoryMinimal(session)

            # Save to database
            await repo.save(cve)

            # Commit
            await session.commit()

        logger.info(
            f"Synced {cve_id}: severity={cve.severity}, "
            f"in_kev={cve.is_in_cisa_kev}, risk_score={cve.risk_score}"
        )

        return cve

    async def _sync_cve_list(
        self,
        nist_vulnerabilities: list,
        run_id: uuid.UUID,
        start_time: datetime,
    ) -> Dict[str, Any]:
        """
        Sync a list of NIST vulnerabilities.

        Args:
            nist_vulnerabilities: List of NISTVulnerability objects
            run_id: Processing run ID
            start_time: Processing start time

        Returns:
            Statistics dictionary
        """
        stats = {
            "run_id": str(run_id),
            "cves_fetched": len(nist_vulnerabilities),
            "cves_processed": 0,
            "cves_created": 0,
            "cves_updated": 0,
            "cves_in_kev": 0,
            "by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "NONE": 0,
            },
            "errors": [],
        }

        # Fetch CISA KEV catalog once (cached)
        logger.info("Fetching CISA KEV catalog...")
        kev_catalog = await self.cisa_client.fetch_kev_catalog()
        kev_ids = kev_catalog.get_cve_ids()
        logger.info(f"CISA KEV catalog loaded: {len(kev_ids)} CVEs")

        # Get database connection
        db = get_database()

        async with db.get_session() as session:
            # Create processing log
            proc_log = ProcessingLog(
                id=run_id,
                run_started_at=start_time,
                status="RUNNING",
                cves_processed=0,
                run_metadata={
                    "hours_back": (datetime.utcnow() - start_time).total_seconds() / 3600,
                    "total_cves": len(nist_vulnerabilities),
                }
            )
            session.add(proc_log)
            await session.flush()

            try:
                repo = CVERepositoryMinimal(session)

                for i, nist_vuln in enumerate(nist_vulnerabilities):
                    try:
                        # Check if in KEV
                        is_in_kev = nist_vuln.id in kev_ids

                        # Convert to minimal domain model
                        cve = self.nist_client.convert_to_minimal_domain_model(
                            nist_vuln,
                            is_in_cisa_kev=is_in_kev
                        )

                        # If in KEV, enrich with CISA data
                        if is_in_kev:
                            cve = await self.cisa_client.enrich_cve_minimal(cve)
                            stats["cves_in_kev"] += 1

                        # Check if exists in DB
                        existing = await repo.get_by_id(cve.cve_id)

                        # Save to database
                        await repo.save(cve)

                        # Update stats
                        if existing:
                            if existing.last_modified_date != cve.last_modified_date:
                                stats["cves_updated"] += 1
                        else:
                            stats["cves_created"] += 1

                        stats["cves_processed"] += 1
                        stats["by_severity"][cve.severity.value] += 1

                        # Log progress
                        if stats["cves_processed"] % 10 == 0:
                            logger.info(
                                f"Processed {stats['cves_processed']}/{stats['cves_fetched']} CVEs | "
                                f"Created: {stats['cves_created']} | Updated: {stats['cves_updated']} | "
                                f"KEV: {stats['cves_in_kev']}"
                            )

                    except Exception as e:
                        logger.error(f"Error processing CVE {nist_vuln.id}: {e}")
                        stats["errors"].append({
                            "cve_id": nist_vuln.id,
                            "error": str(e),
                        })
                        continue

                # Update processing log
                end_time = datetime.utcnow()
                proc_log.run_completed_at = end_time
                proc_log.status = "SUCCESS" if not stats["errors"] else "PARTIAL"
                proc_log.cves_processed = stats["cves_processed"]
                proc_log.cves_created = stats["cves_created"]
                proc_log.cves_updated = stats["cves_updated"]
                proc_log.cves_in_kev = stats["cves_in_kev"]
                proc_log.errors_count = len(stats["errors"])

                if stats["errors"]:
                    proc_log.error_summary = {
                        "total_errors": len(stats["errors"]),
                        "sample_errors": stats["errors"][:5],  # First 5 errors
                    }

                # Commit all changes
                await session.commit()

                # Calculate duration
                duration = (end_time - start_time).total_seconds()
                stats["duration_seconds"] = duration

                logger.info(
                    f"Sync complete in {duration:.1f}s | "
                    f"Processed: {stats['cves_processed']} | "
                    f"Created: {stats['cves_created']} | "
                    f"Updated: {stats['cves_updated']} | "
                    f"KEV: {stats['cves_in_kev']} | "
                    f"Errors: {len(stats['errors'])}"
                )

                return stats

            except Exception as e:
                # Mark processing log as failed
                proc_log.status = "FAILED"
                proc_log.run_completed_at = datetime.utcnow()
                proc_log.errors_count = len(stats["errors"]) + 1
                proc_log.error_summary = {
                    "fatal_error": str(e),
                    "partial_stats": stats,
                }
                await session.commit()

                logger.error(f"Sync failed: {e}", exc_info=True)
                raise

    async def get_sync_statistics(self) -> Dict[str, Any]:
        """
        Get database statistics.

        Returns:
            Statistics dictionary with counts and metadata
        """
        db = get_database()

        async with db.get_session() as session:
            repo = CVERepositoryMinimal(session)
            stats = await repo.get_statistics()

        return stats

    async def get_recent_processing_logs(
        self,
        limit: int = 10
    ) -> list:
        """
        Get recent processing run logs.

        Args:
            limit: Maximum number of logs to retrieve

        Returns:
            List of processing logs (dicts)
        """
        db = get_database()

        from sqlalchemy import select, desc

        async with db.get_session() as session:
            result = await session.execute(
                select(ProcessingLog)
                .order_by(desc(ProcessingLog.run_started_at))
                .limit(limit)
            )
            logs = result.scalars().all()

            return [log.to_dict() for log in logs]
