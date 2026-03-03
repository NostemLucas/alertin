"""
CVE Repository - Async CRUD operations for CVE records.

REFACTORED: Now uses SQLAlchemy relationships and cascade to automatically
handle related data (CISA KEV metadata, references).

BEFORE: 332 lines, 3 repositories coordinated manually
AFTER: ~100 lines, 1 repository trusting cascade
"""

import logging
from typing import Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from ...models.database import CVERecord
from ...models.domain import CVE, SeverityLevel

logger = logging.getLogger(__name__)


class CVERepository:
    """
    Async repository for CVE database operations.

    Designed for FastAPI dependency injection pattern.
    Session lifecycle is managed by FastAPI, not by this repository.
    """

    def __init__(self, session: AsyncSession):
        """
        Initialize async repository with injected session.

        Args:
            session: Async SQLAlchemy session (injected via FastAPI Depends)
        """
        self.session = session

    async def save(self, cve: CVE) -> CVERecord:
        """
        Save or update CVE with all related data.

        REFACTORED: Now uses from_pydantic() and relationships to automatically
        save to multiple tables (cves, cisa_kev_metadata, cve_references).

        This method replaces create_or_update(), _create_record(), and _update_record()
        with a much simpler implementation that trusts SQLAlchemy's cascade behavior.

        Args:
            cve: Domain CVE model (Pydantic)

        Returns:
            Database CVE record with all relationships populated

        Example:
            >>> cve = CVE(cve_id="CVE-2024-1234", ...)
            >>> record = await repo.save(cve)
            >>> # Saves to 3 tables automatically via cascade
        """
        result = await self.session.execute(
            select(CVERecord).filter_by(cve_id=cve.cve_id)
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Check if modified
            if existing.last_modified_date != cve.last_modified_date:
                logger.info(f"Updating CVE {cve.cve_id} (modified: {cve.last_modified_date})")
                # ✅ Usa update_from_pydantic() - actualiza relaciones automáticamente
                existing.update_from_pydantic(cve)
            else:
                logger.debug(f"CVE {cve.cve_id} unchanged, skipping")
            return existing

        # Create new record
        logger.info(f"Creating new CVE record: {cve.cve_id}")
        # ✅ Usa from_pydantic() - crea relaciones automáticamente
        cve_record = CVERecord.from_pydantic(cve)

        # ✅ session.add() guarda automáticamente en 3 tablas gracias a cascade
        self.session.add(cve_record)
        await self.session.flush()

        return cve_record

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
