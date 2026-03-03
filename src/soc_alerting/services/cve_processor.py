"""
CVE Processing Service - Main pipeline orchestrator.

Coordinates fetching from NIST, enrichment with CISA KEV, NLP enrichment, and database storage.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from ..clients.nist_client import NISTClient
from ..clients.cisa_client import CISAClient
from ..database.repositories.cve_repository import CVERepository
from ..database.connection import get_database
from ..models.domain import CVE, SeverityLevel
from .enrichment_service import create_enrichment_service_from_settings

logger = logging.getLogger(__name__)


class CVEProcessor:
    """
    Main CVE processing pipeline.

    Flow:
    1. Fetch CVEs from NIST NVD (by modified date)
    2. Check each CVE against CISA KEV catalog
    3. Apply CISA KEV override (KEV → CRITICAL)
    4. Save to database (create or update)
    5. NLP Enrichment (translation, NER, keywords, attack analysis)
    6. Return statistics
    """

    def __init__(self, enable_nlp_enrichment: bool = True):
        """
        Initialize processor.

        Args:
            enable_nlp_enrichment: Enable NLP enrichment (default: True)
        """
        self.nist_client: Optional[NISTClient] = None
        self.cisa_client: Optional[CISAClient] = None
        self.enable_nlp_enrichment = enable_nlp_enrichment

        # Initialize NLP enrichment service
        if self.enable_nlp_enrichment:
            self.enrichment_service = create_enrichment_service_from_settings()
            logger.info("NLP enrichment enabled")
        else:
            self.enrichment_service = None
            logger.info("NLP enrichment disabled")

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

    async def process_recent_cves(
        self,
        hours_back: int = 24,
        max_cves: Optional[int] = None,
    ) -> dict:
        """
        Process CVEs modified in the last N hours.

        This is the main method for incremental updates.

        Args:
            hours_back: Hours to look back for modified CVEs
            max_cves: Maximum CVEs to process (None = all)

        Returns:
            Statistics dictionary with processing results
        """
        logger.info(f"Processing CVEs from last {hours_back} hours...")

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
            logger.info("No CVEs to process")
            return {
                "cves_fetched": 0,
                "cves_processed": 0,
                "cves_created": 0,
                "cves_updated": 0,
                "cves_in_kev": 0,
                "by_severity": {},
            }

        # Process CVEs
        return await self.process_cve_list(nist_vulnerabilities)

    async def process_specific_cve(self, cve_id: str, force_enrich: bool = False) -> Optional[CVE]:
        """
        Process a specific CVE by ID with optional NLP enrichment.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")
            force_enrich: Force NLP enrichment even if below severity threshold

        Returns:
            Processed CVE domain model or None if not found
        """
        logger.info(f"Processing specific CVE: {cve_id}")

        # Fetch from NIST
        nist_vuln = await self.nist_client.fetch_cve_by_id(cve_id)
        if not nist_vuln:
            logger.warning(f"CVE not found in NIST: {cve_id}")
            return None

        # Convert to domain model
        cve = self.nist_client.convert_to_domain_model(nist_vuln)

        # Enrich with CISA KEV
        cve = await self.cisa_client.enrich_cve_with_kev_data(cve)

        # Get database connection
        db = get_database()

        async with db.get_session() as session:
            repo = CVERepository(session)

            # Save to database (complete with references and CISA data)
            await repo.save_complete_cve(cve)

            # Commit before enrichment
            await session.commit()

            # NLP Enrichment
            if self.enable_nlp_enrichment:
                logger.info(f"{cve_id}: Starting NLP enrichment...")
                try:
                    enrichment = await self.enrichment_service.enrich_cve(
                        session=session,
                        cve=cve,
                        force=force_enrich
                    )
                    if enrichment:
                        logger.info(f"{cve_id}: NLP enrichment completed")
                    else:
                        logger.info(f"{cve_id}: NLP enrichment skipped (below threshold)")
                except Exception as e:
                    logger.error(f"{cve_id}: NLP enrichment failed: {e}", exc_info=True)

        logger.info(
            f"Processed {cve_id}: severity={cve.final_severity}, "
            f"in_kev={cve.is_in_cisa_kev}, "
            f"enriched={self.enable_nlp_enrichment}"
        )

        return cve

    async def process_cve_list(self, nist_vulnerabilities: list) -> dict:
        """
        Process a list of NIST vulnerabilities with optional NLP enrichment.

        Args:
            nist_vulnerabilities: List of NISTVulnerability objects

        Returns:
            Statistics dictionary including NLP enrichment stats
        """
        stats = {
            "cves_fetched": len(nist_vulnerabilities),
            "cves_processed": 0,
            "cves_created": 0,
            "cves_updated": 0,
            "cves_in_kev": 0,
            "cves_enriched": 0,  # NEW: NLP enrichment count
            "enrichment_skipped": 0,  # NEW: Below threshold
            "enrichment_failed": 0,  # NEW: Enrichment errors
            "by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "NONE": 0,
            },
        }

        # Fetch CISA KEV catalog once (cached)
        logger.info("Fetching CISA KEV catalog...")
        kev_catalog = await self.cisa_client.fetch_kev_catalog()
        kev_ids = kev_catalog.get_cve_ids()
        logger.info(f"CISA KEV catalog loaded: {len(kev_ids)} CVEs")

        # Get database connection
        db = get_database()

        # Process each CVE and collect for batch enrichment
        cves_to_enrich = []

        async with db.get_session() as session:
            repo = CVERepository(session)

            for nist_vuln in nist_vulnerabilities:
                try:
                    # Check if in KEV
                    is_in_kev = nist_vuln.id in kev_ids

                    # Convert to domain model
                    cve = self.nist_client.convert_to_domain_model(
                        nist_vuln, is_in_cisa_kev=is_in_kev
                    )

                    # If in KEV, enrich with CISA data
                    if is_in_kev:
                        cve = await self.cisa_client.enrich_cve_with_kev_data(cve)
                        stats["cves_in_kev"] += 1

                    # Check if exists in DB
                    existing = await repo.get_by_id(cve.cve_id)

                    # Save to database (uses save_complete_cve for 3-table insert)
                    await repo.save_complete_cve(cve)

                    # Update stats
                    if existing:
                        if existing.last_modified_date != cve.last_modified_date:
                            stats["cves_updated"] += 1
                    else:
                        stats["cves_created"] += 1

                    stats["cves_processed"] += 1
                    stats["by_severity"][cve.final_severity.value] += 1

                    # Collect CVE for NLP enrichment
                    if self.enable_nlp_enrichment:
                        cves_to_enrich.append(cve)

                    # Log progress
                    if stats["cves_processed"] % 10 == 0:
                        logger.info(
                            f"Processed {stats['cves_processed']}/{stats['cves_fetched']} CVEs"
                        )

                except Exception as e:
                    logger.error(f"Error processing CVE {nist_vuln.id}: {e}")
                    continue

            # Commit CVE inserts before enrichment
            await session.commit()

            # NLP Batch Enrichment
            if self.enable_nlp_enrichment and cves_to_enrich:
                logger.info(
                    f"Starting NLP enrichment for {len(cves_to_enrich)} CVEs..."
                )

                try:
                    nlp_stats = await self.enrichment_service.batch_enrich(
                        session=session,
                        cves=cves_to_enrich,
                        force=False  # Respect severity threshold
                    )

                    stats["cves_enriched"] = nlp_stats["enriched"]
                    stats["enrichment_skipped"] = nlp_stats["skipped"]
                    stats["enrichment_failed"] = nlp_stats["failed"]

                    logger.info(
                        f"NLP enrichment complete: {nlp_stats['enriched']} enriched, "
                        f"{nlp_stats['skipped']} skipped, {nlp_stats['failed']} failed"
                    )

                except Exception as e:
                    logger.error(f"Batch NLP enrichment failed: {e}", exc_info=True)
                    stats["enrichment_failed"] = len(cves_to_enrich)

        logger.info(f"Processing complete: {stats}")
        return stats

    async def get_cve_summary(self, cve_id: str) -> Optional[dict]:
        """
        Get comprehensive summary of a CVE.

        Fetches from NIST, enriches with CISA, but doesn't save to DB.
        Useful for on-demand analysis.

        Args:
            cve_id: CVE identifier

        Returns:
            Dictionary with CVE summary including both sources
        """
        logger.info(f"Getting summary for: {cve_id}")

        # Fetch from NIST
        nist_vuln = await self.nist_client.fetch_cve_by_id(cve_id)
        if not nist_vuln:
            return None

        # Convert to domain model
        cve = self.nist_client.convert_to_domain_model(nist_vuln)

        # Check CISA KEV
        kev_entry = await self.cisa_client.get_kev_entry(cve_id)

        summary = {
            "cve_id": cve.cve_id,
            "description": cve.description,
            "published": cve.published_date.isoformat(),
            "modified": cve.last_modified_date.isoformat(),
            "nist": {
                "cvss_score": cve.cvss_v3_score,
                "cvss_vector": cve.cvss_v3_vector,
                "severity": cve.severity_nist.value,
                "references": cve.references[:5],  # First 5 refs
            },
            "cisa_kev": {
                "in_catalog": kev_entry is not None,
                "date_added": kev_entry.dateAdded.isoformat() if kev_entry else None,
                "due_date": kev_entry.dueDate.isoformat() if kev_entry else None,
                "required_action": kev_entry.requiredAction if kev_entry else None,
                "known_ransomware": kev_entry.is_known_ransomware if kev_entry else False,
            },
            "classification": {
                "final_severity": cve.final_severity.value,
                "is_critical": cve.final_severity == SeverityLevel.CRITICAL,
                "sources": [s.value for s in cve.classification_sources],
            },
        }

        return summary
