"""
CISA KEV Metadata Repository - CRUD operations for CISA KEV metadata.

Handles async database operations for CISA KEV metadata storage.
"""

import logging
from typing import Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from ...models.database import CISAKEVMetadata
from ...models.domain import CVE

logger = logging.getLogger(__name__)


class CISAKEVRepository:
    """
    Async repository for CISA KEV metadata operations.

    Handles the separated CISA metadata table for CVEs in Known Exploited Vulnerabilities.
    """

    def __init__(self, session: AsyncSession):
        """
        Initialize async repository with injected session.

        Args:
            session: Async SQLAlchemy session (injected via FastAPI Depends)
        """
        self.session = session

    async def upsert_cisa_metadata(self, cve: CVE) -> Optional[CISAKEVMetadata]:
        """
        Insert or update CISA KEV metadata for a CVE.

        Uses PostgreSQL's ON CONFLICT DO UPDATE for efficient upserts.

        Args:
            cve: Domain CVE model with CISA data

        Returns:
            CISAKEVMetadata record or None if CVE not in KEV
        """
        if not cve.is_in_cisa_kev:
            logger.debug(f"{cve.cve_id} not in CISA KEV, skipping metadata")
            return None

        if not cve.cisa_exploit_add or not cve.cisa_required_action:
            logger.warning(
                f"{cve.cve_id} marked as in KEV but missing required CISA fields"
            )
            return None

        logger.info(f"Upserting CISA KEV metadata for {cve.cve_id}")

        # Prepare values for upsert
        values = {
            "cve_id": cve.cve_id,
            "exploit_add": cve.cisa_exploit_add,
            "action_due": cve.cisa_action_due,
            "required_action": cve.cisa_required_action,
            "vulnerability_name": cve.cisa_vulnerability_name,
            "known_ransomware": cve.cisa_known_ransomware or False,
            "notes": None,  # Could be extended in the future
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }

        # PostgreSQL-specific upsert
        stmt = insert(CISAKEVMetadata).values(**values)
        stmt = stmt.on_conflict_do_update(
            index_elements=["cve_id"],
            set_={
                "exploit_add": stmt.excluded.exploit_add,
                "action_due": stmt.excluded.action_due,
                "required_action": stmt.excluded.required_action,
                "vulnerability_name": stmt.excluded.vulnerability_name,
                "known_ransomware": stmt.excluded.known_ransomware,
                "updated_at": stmt.excluded.updated_at,
            },
        )

        await self.session.execute(stmt)
        await self.session.flush()

        # Fetch the inserted/updated record
        result = await self.session.execute(
            select(CISAKEVMetadata).filter_by(cve_id=cve.cve_id)
        )
        record = result.scalar_one_or_none()

        logger.info(f"CISA KEV metadata for {cve.cve_id} upserted successfully")
        return record

    async def get_by_cve_id(self, cve_id: str) -> Optional[CISAKEVMetadata]:
        """
        Get CISA KEV metadata for a specific CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            CISA KEV metadata or None if not in KEV
        """
        result = await self.session.execute(
            select(CISAKEVMetadata).filter_by(cve_id=cve_id)
        )
        return result.scalar_one_or_none()

    async def delete_by_cve_id(self, cve_id: str) -> bool:
        """
        Delete CISA KEV metadata for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            True if deleted, False if not found
        """
        record = await self.get_by_cve_id(cve_id)
        if record:
            await self.session.delete(record)
            await self.session.flush()
            logger.info(f"Deleted CISA KEV metadata for: {cve_id}")
            return True
        return False

    async def get_all_kev_metadata(self, limit: int = 100) -> list[CISAKEVMetadata]:
        """
        Get all CISA KEV metadata records.

        Args:
            limit: Maximum results

        Returns:
            List of CISA KEV metadata records
        """
        result = await self.session.execute(
            select(CISAKEVMetadata)
            .order_by(CISAKEVMetadata.exploit_add.desc())
            .limit(limit)
        )
        return list(result.scalars().all())
