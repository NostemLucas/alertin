"""
CVE Repository - CRUD operations for CVE records.

Handles database operations for CVE storage and retrieval.
"""

import logging
from typing import Optional
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from ..connection import get_database
from ...models.database import CVERecord, CVEEnrichmentRecord
from ...models.domain import CVE, SeverityLevel

logger = logging.getLogger(__name__)


class CVERepository:
    """Repository for CVE database operations."""

    def __init__(self, session: Optional[Session] = None):
        """
        Initialize repository.

        Args:
            session: Optional SQLAlchemy session. If None, uses default DB connection.
        """
        self.session = session
        self._owns_session = session is None

    def __enter__(self):
        """Context manager entry."""
        if self._owns_session:
            db = get_database()
            self.session = db.get_raw_session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self._owns_session and self.session:
            if exc_type is None:
                self.session.commit()
            else:
                self.session.rollback()
            self.session.close()

    def create_or_update(self, cve: CVE) -> CVERecord:
        """
        Create or update CVE record.

        If CVE exists and has been modified, updates it.
        Otherwise, creates new record.

        Args:
            cve: Domain CVE model

        Returns:
            Database CVE record
        """
        existing = self.session.query(CVERecord).filter_by(cve_id=cve.cve_id).first()

        if existing:
            # Check if modified
            if existing.last_modified_date != cve.last_modified_date:
                logger.info(f"Updating CVE {cve.cve_id} (modified: {cve.last_modified_date})")
                self._update_record(existing, cve)
            else:
                logger.debug(f"CVE {cve.cve_id} unchanged, skipping")
            return existing
        else:
            logger.info(f"Creating new CVE record: {cve.cve_id}")
            return self._create_record(cve)

    def _create_record(self, cve: CVE) -> CVERecord:
        """Create new CVE record from domain model."""
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
            references=cve.references,
            cisa_exploit_add=cve.cisa_exploit_add,
            cisa_action_due=cve.cisa_action_due,
            cisa_required_action=cve.cisa_required_action,
            cisa_vulnerability_name=cve.cisa_vulnerability_name,
            cisa_known_ransomware=cve.cisa_known_ransomware,
        )

        self.session.add(record)
        self.session.flush()  # Get ID without committing
        return record

    def _update_record(self, record: CVERecord, cve: CVE):
        """Update existing CVE record."""
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
        record.references = cve.references
        record.cisa_exploit_add = cve.cisa_exploit_add
        record.cisa_action_due = cve.cisa_action_due
        record.cisa_required_action = cve.cisa_required_action
        record.cisa_vulnerability_name = cve.cisa_vulnerability_name
        record.cisa_known_ransomware = cve.cisa_known_ransomware
        record.updated_at = datetime.utcnow()

        self.session.flush()

    def get_by_id(self, cve_id: str) -> Optional[CVERecord]:
        """
        Get CVE by ID.

        Args:
            cve_id: CVE identifier

        Returns:
            CVE record or None
        """
        return self.session.query(CVERecord).filter_by(cve_id=cve_id).first()

    def get_all(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[SeverityLevel] = None,
        in_cisa_kev: Optional[bool] = None,
    ) -> list[CVERecord]:
        """
        Get all CVEs with optional filtering.

        Args:
            limit: Maximum results
            offset: Results offset
            severity: Filter by severity level
            in_cisa_kev: Filter by CISA KEV membership

        Returns:
            List of CVE records
        """
        query = self.session.query(CVERecord)

        if severity:
            query = query.filter_by(final_severity=severity.value)

        if in_cisa_kev is not None:
            query = query.filter_by(is_in_cisa_kev=in_cisa_kev)

        query = query.order_by(desc(CVERecord.published_date))
        query = query.limit(limit).offset(offset)

        return query.all()

    def get_critical_cves(self, limit: int = 50) -> list[CVERecord]:
        """
        Get CRITICAL severity CVEs.

        Args:
            limit: Maximum results

        Returns:
            List of critical CVE records
        """
        return (
            self.session.query(CVERecord)
            .filter_by(final_severity=SeverityLevel.CRITICAL.value)
            .order_by(desc(CVERecord.published_date))
            .limit(limit)
            .all()
        )

    def get_cisa_kev_cves(self, limit: int = 100) -> list[CVERecord]:
        """
        Get CVEs in CISA KEV catalog.

        Args:
            limit: Maximum results

        Returns:
            List of KEV CVE records
        """
        return (
            self.session.query(CVERecord)
            .filter_by(is_in_cisa_kev=True)
            .order_by(desc(CVERecord.cisa_exploit_add))
            .limit(limit)
            .all()
        )

    def get_recent_cves(self, hours: int = 24, limit: int = 100) -> list[CVERecord]:
        """
        Get recently published CVEs.

        Args:
            hours: Look back hours
            limit: Maximum results

        Returns:
            List of recent CVE records
        """
        from datetime import timedelta

        cutoff = datetime.utcnow() - timedelta(hours=hours)

        return (
            self.session.query(CVERecord)
            .filter(CVERecord.published_date >= cutoff)
            .order_by(desc(CVERecord.published_date))
            .limit(limit)
            .all()
        )

    def get_statistics(self) -> dict:
        """
        Get CVE database statistics.

        Returns:
            Dictionary with statistics
        """
        total = self.session.query(func.count(CVERecord.cve_id)).scalar()

        by_severity = (
            self.session.query(
                CVERecord.final_severity,
                func.count(CVERecord.cve_id).label("count"),
            )
            .group_by(CVERecord.final_severity)
            .all()
        )

        kev_count = (
            self.session.query(func.count(CVERecord.cve_id))
            .filter_by(is_in_cisa_kev=True)
            .scalar()
        )

        stats = {
            "total_cves": total,
            "in_cisa_kev": kev_count,
            "by_severity": {severity: count for severity, count in by_severity},
        }

        return stats

    def delete_by_id(self, cve_id: str) -> bool:
        """
        Delete CVE by ID.

        Args:
            cve_id: CVE identifier

        Returns:
            True if deleted, False if not found
        """
        record = self.get_by_id(cve_id)
        if record:
            self.session.delete(record)
            self.session.flush()
            logger.info(f"Deleted CVE: {cve_id}")
            return True
        return False

    def count(self) -> int:
        """Get total CVE count."""
        return self.session.query(func.count(CVERecord.cve_id)).scalar()
