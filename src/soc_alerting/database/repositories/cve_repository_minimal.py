"""
Minimal CVE Repository - Simple CRUD for streamlined schema.

This repository works with the minimal 17-field CVE model,
without complex relationships or normalized tables.
"""

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, and_, or_

from ...models.database_minimal import CVERecord, CVEUpdateHistory, ProcessingLog
from ...models.domain_minimal import CVEMinimal, SeverityLevel

logger = logging.getLogger(__name__)


class CVERepositoryMinimal:
    """
    Minimal async repository for CVE operations.

    Designed for FastAPI dependency injection and high-performance operations.
    """

    def __init__(self, session: AsyncSession):
        """
        Initialize repository with async session.

        Args:
            session: Async SQLAlchemy session
        """
        self.session = session

    async def save(self, cve: CVEMinimal) -> CVERecord:
        """
        Save or update CVE record.

        If CVE exists and is modified, tracks change in update_history.

        Args:
            cve: Minimal CVE domain model

        Returns:
            Database CVE record
        """
        result = await self.session.execute(
            select(CVERecord).filter_by(cve_id=cve.cve_id)
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Check if actually modified
            if existing.last_modified_date != cve.last_modified_date:
                logger.info(f"Updating CVE {cve.cve_id} (modified: {cve.last_modified_date})")

                # Track changes
                await self._track_changes(existing, cve)

                # Update fields
                existing.description = cve.description
                existing.cwe_id = cve.cwe_id
                existing.cvss_score = cve.cvss_score
                existing.cvss_vector = cve.cvss_vector
                existing.severity = cve.severity.value
                existing.attack_vector = cve.attack_vector.value if cve.attack_vector else None
                existing.attack_complexity = cve.attack_complexity.value if cve.attack_complexity else None
                existing.requires_auth = cve.requires_auth
                existing.user_interaction_required = cve.user_interaction_required
                existing.affected_products = cve.affected_products
                existing.status_nist = cve.status_nist
                existing.source = cve.source
                existing.last_modified_date = cve.last_modified_date
                existing.last_checked_at = datetime.utcnow()
                existing.is_in_cisa_kev = cve.is_in_cisa_kev
                existing.cisa_date_added = cve.cisa_date_added
                existing.cisa_due_date = cve.cisa_due_date
                existing.cisa_required_action = cve.cisa_required_action
                existing.cisa_known_ransomware = cve.cisa_known_ransomware
                existing.primary_reference = cve.primary_reference
                existing.references = cve.references
                existing.version += 1
                existing.updated_at = datetime.utcnow()

                await self.session.flush()
            else:
                logger.debug(f"CVE {cve.cve_id} unchanged")

            return existing

        # Create new record
        logger.info(f"Creating new CVE: {cve.cve_id}")
        record = CVERecord(
            cve_id=cve.cve_id,
            description=cve.description,
            cwe_id=cve.cwe_id,
            cvss_score=cve.cvss_score,
            cvss_vector=cve.cvss_vector,
            severity=cve.severity.value,
            attack_vector=cve.attack_vector.value if cve.attack_vector else None,
            attack_complexity=cve.attack_complexity.value if cve.attack_complexity else None,
            requires_auth=cve.requires_auth,
            user_interaction_required=cve.user_interaction_required,
            affected_products=cve.affected_products,
            version=cve.version,
            status_nist=cve.status_nist,
            source=cve.source,
            published_date=cve.published_date,
            last_modified_date=cve.last_modified_date,
            last_checked_at=cve.last_checked_at,
            is_in_cisa_kev=cve.is_in_cisa_kev,
            cisa_date_added=cve.cisa_date_added,
            cisa_due_date=cve.cisa_due_date,
            cisa_required_action=cve.cisa_required_action,
            cisa_known_ransomware=cve.cisa_known_ransomware,
            primary_reference=cve.primary_reference,
            references=cve.references,
        )

        self.session.add(record)
        await self.session.flush()

        return record

    async def _track_changes(self, existing: CVERecord, new_cve: CVEMinimal):
        """
        Track critical changes in update history.

        Args:
            existing: Existing CVE record
            new_cve: New CVE data
        """
        # Track CVSS score change
        if existing.cvss_score != new_cve.cvss_score:
            history = CVEUpdateHistory(
                cve_id=existing.cve_id,
                change_type="SCORE_CHANGED",
                old_value=str(existing.cvss_score) if existing.cvss_score else "None",
                new_value=str(new_cve.cvss_score) if new_cve.cvss_score else "None",
                previous_version=existing.version,
                new_version=existing.version + 1,
            )
            self.session.add(history)

        # Track severity change
        if existing.severity != new_cve.severity.value:
            history = CVEUpdateHistory(
                cve_id=existing.cve_id,
                change_type="SEVERITY_CHANGED",
                old_value=existing.severity,
                new_value=new_cve.severity.value,
                previous_version=existing.version,
                new_version=existing.version + 1,
            )
            self.session.add(history)

        # Track KEV addition
        if not existing.is_in_cisa_kev and new_cve.is_in_cisa_kev:
            history = CVEUpdateHistory(
                cve_id=existing.cve_id,
                change_type="ADDED_TO_KEV",
                old_value="false",
                new_value="true",
                previous_version=existing.version,
                new_version=existing.version + 1,
            )
            self.session.add(history)

        # Track status change
        if existing.status_nist != new_cve.status_nist:
            history = CVEUpdateHistory(
                cve_id=existing.cve_id,
                change_type="STATUS_UPDATED",
                old_value=existing.status_nist,
                new_value=new_cve.status_nist,
                previous_version=existing.version,
                new_version=existing.version + 1,
            )
            self.session.add(history)

    async def get_by_id(self, cve_id: str) -> Optional[CVERecord]:
        """Get CVE by ID."""
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
        min_cvss: Optional[float] = None,
        attack_vector: Optional[str] = None,
    ) -> List[CVERecord]:
        """
        Get all CVEs with optional filtering.

        Args:
            limit: Maximum results
            offset: Results offset
            severity: Filter by severity
            in_cisa_kev: Filter by KEV membership
            min_cvss: Minimum CVSS score
            attack_vector: Filter by attack vector

        Returns:
            List of CVE records
        """
        query = select(CVERecord)

        if severity:
            query = query.filter_by(severity=severity.value)

        if in_cisa_kev is not None:
            query = query.filter_by(is_in_cisa_kev=in_cisa_kev)

        if min_cvss is not None:
            query = query.where(CVERecord.cvss_score >= min_cvss)

        if attack_vector:
            query = query.filter_by(attack_vector=attack_vector)

        query = query.order_by(desc(CVERecord.published_date))
        query = query.limit(limit).offset(offset)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_critical_cves(self, limit: int = 50) -> List[CVERecord]:
        """Get CRITICAL severity CVEs."""
        query = (
            select(CVERecord)
            .filter_by(severity="CRITICAL")
            .order_by(desc(CVERecord.published_date))
            .limit(limit)
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_cisa_kev_cves(self, limit: int = 100) -> List[CVERecord]:
        """Get all CVEs in CISA KEV catalog."""
        query = (
            select(CVERecord)
            .filter_by(is_in_cisa_kev=True)
            .order_by(desc(CVERecord.cisa_date_added))
            .limit(limit)
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_high_risk_cves(
        self,
        min_risk_score: int = 70,
        limit: int = 100
    ) -> List[CVERecord]:
        """
        Get high-risk CVEs based on composite risk score.

        Risk factors:
        - CVSS score
        - CISA KEV membership
        - Attack vector
        - Authentication requirements

        Args:
            min_risk_score: Minimum risk score (0-100)
            limit: Maximum results

        Returns:
            List of high-risk CVEs
        """
        # Query for potentially high-risk CVEs
        query = (
            select(CVERecord)
            .where(
                or_(
                    CVERecord.is_in_cisa_kev == True,  # noqa: E712
                    CVERecord.cvss_score >= 7.0,
                    and_(
                        CVERecord.attack_vector == "NETWORK",
                        CVERecord.requires_auth == False,  # noqa: E712
                    )
                )
            )
            .order_by(desc(CVERecord.cvss_score))
            .limit(limit * 2)  # Fetch more than needed, filter by risk score
        )

        result = await self.session.execute(query)
        cves = list(result.scalars().all())

        # Filter by calculated risk score
        high_risk = [cve for cve in cves if cve.risk_score >= min_risk_score]
        return high_risk[:limit]

    async def get_recent_cves(
        self,
        days: int = 7,
        limit: int = 100
    ) -> List[CVERecord]:
        """Get CVEs published in the last N days."""
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        query = (
            select(CVERecord)
            .where(CVERecord.published_date >= cutoff_date)
            .order_by(desc(CVERecord.published_date))
            .limit(limit)
        )

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get database statistics.

        Returns:
            Dict with counts by severity, KEV status, etc.
        """
        # Total count
        total_result = await self.session.execute(
            select(func.count(CVERecord.cve_id))
        )
        total = total_result.scalar()

        # By severity
        severity_result = await self.session.execute(
            select(CVERecord.severity, func.count(CVERecord.cve_id))
            .group_by(CVERecord.severity)
        )
        by_severity = dict(severity_result.all())

        # KEV count
        kev_result = await self.session.execute(
            select(func.count(CVERecord.cve_id))
            .where(CVERecord.is_in_cisa_kev == True)  # noqa: E712
        )
        kev_count = kev_result.scalar()

        # By attack vector
        vector_result = await self.session.execute(
            select(CVERecord.attack_vector, func.count(CVERecord.cve_id))
            .where(CVERecord.attack_vector.is_not(None))
            .group_by(CVERecord.attack_vector)
        )
        by_attack_vector = dict(vector_result.all())

        # Recent (last 7 days)
        cutoff = datetime.utcnow() - timedelta(days=7)
        recent_result = await self.session.execute(
            select(func.count(CVERecord.cve_id))
            .where(CVERecord.published_date >= cutoff)
        )
        recent_count = recent_result.scalar()

        return {
            "total_cves": total,
            "by_severity": by_severity,
            "in_cisa_kev": kev_count,
            "by_attack_vector": by_attack_vector,
            "recent_7_days": recent_count,
        }

    async def search_by_product(
        self,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        limit: int = 100
    ) -> List[CVERecord]:
        """
        Search CVEs by affected product (JSONB search).

        Args:
            vendor: Vendor name (case-insensitive partial match)
            product: Product name (case-insensitive partial match)
            limit: Maximum results

        Returns:
            List of matching CVEs
        """
        from sqlalchemy.dialects.postgresql import JSONB

        query = select(CVERecord)

        if vendor:
            # Search in JSONB array for vendor match
            query = query.where(
                func.jsonb_path_exists(
                    CVERecord.affected_products,
                    f'$[*].vendor ? (@ like_regex "{vendor}" flag "i")'
                )
            )

        if product:
            # Search in JSONB array for product match
            query = query.where(
                func.jsonb_path_exists(
                    CVERecord.affected_products,
                    f'$[*].product ? (@ like_regex "{product}" flag "i")'
                )
            )

        query = query.order_by(desc(CVERecord.published_date)).limit(limit)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def count_total(self) -> int:
        """Get total CVE count."""
        result = await self.session.execute(
            select(func.count(CVERecord.cve_id))
        )
        return result.scalar()
