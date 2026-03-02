"""
CVE Repository - Async CRUD operations for CVE records.

Handles async database operations for CVE storage and retrieval.
"""

import logging
from typing import Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from sqlalchemy.orm import selectinload

from ..connection import get_database
from ...models.database import CVERecord, CVEEnrichmentRecord, CISAKEVMetadata
from ...models.domain import CVE, SeverityLevel

logger = logging.getLogger(__name__)


class CVERepository:
    """Async repository for CVE database operations."""

    def __init__(self, session: Optional[AsyncSession] = None):
        """
        Initialize async repository.

        Args:
            session: Optional async SQLAlchemy session. If None, uses default DB connection.
        """
        self.session = session
        self._owns_session = session is None

    async def __aenter__(self):
        """Async context manager entry."""
        if self._owns_session:
            db = get_database()
            self.session = db.get_raw_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._owns_session and self.session:
            if exc_type is None:
                await self.session.commit()
            else:
                await self.session.rollback()
            await self.session.close()

    async def create_or_update(self, cve: CVE) -> CVERecord:
        """
        Create or update CVE record (async).

        If CVE exists and has been modified, updates it.
        Otherwise, creates new record.

        Note: CISA KEV metadata should be handled separately via upsert_cisa_metadata()

        Args:
            cve: Domain CVE model

        Returns:
            Database CVE record
        """
        result = await self.session.execute(
            select(CVERecord).filter_by(cve_id=cve.cve_id)
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Check if modified
            if existing.last_modified_date != cve.last_modified_date:
                logger.info(f"Updating CVE {cve.cve_id} (modified: {cve.last_modified_date})")
                await self._update_record(existing, cve)
            else:
                logger.debug(f"CVE {cve.cve_id} unchanged, skipping")
            return existing
        else:
            logger.info(f"Creating new CVE record: {cve.cve_id}")
            return await self._create_record(cve)

    async def _create_record(self, cve: CVE) -> CVERecord:
        """
        Create new CVE record from domain model (async).

        Note: CISA fields removed - now stored in cisa_kev_metadata table.
        Note: References removed - now stored in cve_references table.
        """
        record = CVERecord(
            cve_id=cve.cve_id,
            description=cve.description,
            published_date=cve.published_date,
            last_modified_date=cve.last_modified_date,
            cvss_v3_score=cve.cvss_v3_score,
            cvss_v3_vector=cve.cvss_v3_vector,
            cvss_v2_score=cve.cvss_v2_score,
            cvss_v2_vector=cve.cvss_v2_vector,
            severity_nist=cve.severity_nist.value,
            is_in_cisa_kev=cve.is_in_cisa_kev,
            final_severity=cve.final_severity.value,
            classification_sources=[s.value for s in cve.classification_sources],
            source_identifier=cve.source_identifier,
            vuln_status=cve.vuln_status,
        )

        self.session.add(record)
        await self.session.flush()  # Get ID without committing
        return record

    async def _update_record(self, record: CVERecord, cve: CVE):
        """
        Update existing CVE record (async).

        Note: CISA fields removed - now stored in cisa_kev_metadata table.
        Note: References removed - now stored in cve_references table.
        """
        record.description = cve.description
        record.last_modified_date = cve.last_modified_date
        record.cvss_v3_score = cve.cvss_v3_score
        record.cvss_v3_vector = cve.cvss_v3_vector
        record.cvss_v2_score = cve.cvss_v2_score
        record.cvss_v2_vector = cve.cvss_v2_vector
        record.severity_nist = cve.severity_nist.value
        record.is_in_cisa_kev = cve.is_in_cisa_kev
        record.final_severity = cve.final_severity.value
        record.classification_sources = [s.value for s in cve.classification_sources]
        record.source_identifier = cve.source_identifier
        record.vuln_status = cve.vuln_status
        record.updated_at = datetime.utcnow()

        await self.session.flush()

    async def get_by_id(self, cve_id: str) -> Optional[CVERecord]:
        """
        Get CVE by ID (async).

        Args:
            cve_id: CVE identifier

        Returns:
            CVE record or None
        """
        result = await self.session.execute(
            select(CVERecord).filter_by(cve_id=cve_id)
        )
        return result.scalar_one_or_none()

    async def get_all(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[SeverityLevel] = None,
        in_cisa_kev: Optional[bool] = None,
    ) -> list[CVERecord]:
        """
        Get all CVEs with optional filtering (async).

        Args:
            limit: Maximum results
            offset: Results offset
            severity: Filter by severity level
            in_cisa_kev: Filter by CISA KEV membership

        Returns:
            List of CVE records
        """
        query = select(CVERecord)

        if severity:
            query = query.filter_by(final_severity=severity.value)

        if in_cisa_kev is not None:
            query = query.filter_by(is_in_cisa_kev=in_cisa_kev)

        query = query.order_by(desc(CVERecord.published_date))
        query = query.limit(limit).offset(offset)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_critical_cves(self, limit: int = 50) -> list[CVERecord]:
        """
        Get CRITICAL severity CVEs (async).

        Args:
            limit: Maximum results

        Returns:
            List of critical CVE records
        """
        query = (
            select(CVERecord)
            .filter_by(final_severity=SeverityLevel.CRITICAL.value)
            .order_by(desc(CVERecord.published_date))
            .limit(limit)
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_cisa_kev_cves(self, limit: int = 100) -> list[CVERecord]:
        """
        Get CVEs in CISA KEV catalog (async).

        Args:
            limit: Maximum results

        Returns:
            List of KEV CVE records
        """
        query = (
            select(CVERecord)
            .filter_by(is_in_cisa_kev=True)
            .order_by(desc(CVERecord.published_date))
            .limit(limit)
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_recent_cves(self, hours: int = 24, limit: int = 100) -> list[CVERecord]:
        """
        Get recently published CVEs (async).

        Args:
            hours: Look back hours
            limit: Maximum results

        Returns:
            List of recent CVE records
        """
        from datetime import timedelta

        cutoff = datetime.utcnow() - timedelta(hours=hours)

        query = (
            select(CVERecord)
            .filter(CVERecord.published_date >= cutoff)
            .order_by(desc(CVERecord.published_date))
            .limit(limit)
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_statistics(self) -> dict:
        """
        Get CVE database statistics (async).

        Returns:
            Dictionary with statistics
        """
        # Total count
        total_result = await self.session.execute(
            select(func.count(CVERecord.cve_id))
        )
        total = total_result.scalar()

        # By severity
        severity_result = await self.session.execute(
            select(
                CVERecord.final_severity,
                func.count(CVERecord.cve_id).label("count"),
            ).group_by(CVERecord.final_severity)
        )
        by_severity = severity_result.all()

        # KEV count
        kev_result = await self.session.execute(
            select(func.count(CVERecord.cve_id)).filter_by(is_in_cisa_kev=True)
        )
        kev_count = kev_result.scalar()

        stats = {
            "total_cves": total or 0,
            "in_cisa_kev": kev_count or 0,
            "by_severity": {severity: count for severity, count in by_severity},
        }

        return stats

    async def delete_by_id(self, cve_id: str) -> bool:
        """
        Delete CVE by ID (async).

        Args:
            cve_id: CVE identifier

        Returns:
            True if deleted, False if not found
        """
        record = await self.get_by_id(cve_id)
        if record:
            await self.session.delete(record)
            await self.session.flush()
            logger.info(f"Deleted CVE: {cve_id}")
            return True
        return False

    async def count(self) -> int:
        """Get total CVE count (async)."""
        result = await self.session.execute(
            select(func.count(CVERecord.cve_id))
        )
        return result.scalar() or 0
