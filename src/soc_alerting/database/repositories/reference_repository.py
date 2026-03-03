"""
CVE References Repository - CRUD operations for CVE references.

Handles async database operations for normalized CVE references.
"""

import logging
import uuid
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from ...models.database import CVEReference
from ...models.domain import CVE

logger = logging.getLogger(__name__)


class CVEReferenceRepository:
    """
    Async repository for CVE references operations.

    Handles the normalized references table for CVEs.
    """

    def __init__(self, session: AsyncSession):
        """
        Initialize async repository with injected session.

        Args:
            session: Async SQLAlchemy session (injected via FastAPI Depends)
        """
        self.session = session

    async def bulk_upsert_references(self, cve: CVE) -> list[CVEReference]:
        """
        Insert or update all references for a CVE.

        Deletes existing references and inserts new ones for simplicity.

        Args:
            cve: Domain CVE model with references

        Returns:
            List of CVEReference records created
        """
        if not cve.references:
            logger.debug(f"{cve.cve_id} has no references, skipping")
            return []

        logger.info(f"Upserting {len(cve.references)} references for {cve.cve_id}")

        # Delete existing references for this CVE
        await self.session.execute(
            select(CVEReference).filter_by(cve_id=cve.cve_id)
        )
        # Simple approach: delete all and re-insert
        # (More efficient than checking each URL individually)

        records = []
        for url in cve.references:
            # Use PostgreSQL upsert to avoid duplicates
            values = {
                "id": uuid.uuid4(),
                "cve_id": cve.cve_id,
                "url": url,
                "source": "NIST",  # Default source
                "reference_type": None,  # Could be enhanced with type detection
                "tags": None,
                "created_at": datetime.utcnow(),
            }

            stmt = insert(CVEReference).values(**values)
            stmt = stmt.on_conflict_do_nothing(
                index_elements=["cve_id", "url"]
            )

            await self.session.execute(stmt)

        await self.session.flush()

        # Fetch inserted records
        result = await self.session.execute(
            select(CVEReference).filter_by(cve_id=cve.cve_id)
        )
        records = list(result.scalars().all())

        logger.info(f"Upserted {len(records)} references for {cve.cve_id}")
        return records

    async def get_by_cve_id(self, cve_id: str) -> list[CVEReference]:
        """
        Get all references for a specific CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            List of CVE references
        """
        result = await self.session.execute(
            select(CVEReference)
            .filter_by(cve_id=cve_id)
            .order_by(CVEReference.created_at)
        )
        return list(result.scalars().all())

    async def delete_by_cve_id(self, cve_id: str) -> int:
        """
        Delete all references for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            Number of references deleted
        """
        result = await self.session.execute(
            select(CVEReference).filter_by(cve_id=cve_id)
        )
        references = result.scalars().all()

        count = 0
        for ref in references:
            await self.session.delete(ref)
            count += 1

        await self.session.flush()
        logger.info(f"Deleted {count} references for {cve_id}")
        return count
