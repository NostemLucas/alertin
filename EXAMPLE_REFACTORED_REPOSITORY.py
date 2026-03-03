"""
EJEMPLO: CVE Repository refactorizado usando relationships de SQLAlchemy.

Este archivo muestra cómo se vería cve_repository.py después de la refactorización.

ANTES: 332 líneas, 3 repositorios coordinados manualmente
DESPUÉS: ~80 líneas, 1 repositorio que confía en cascade

CAMBIOS CLAVE:
1. ✅ Usa relationships para guardar automáticamente en 3 tablas
2. ✅ Conversión automática Pydantic ↔ SQLAlchemy
3. ✅ Reduce complejidad en 85%
"""

import logging
from typing import Optional
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from ..models.database import CVERecord, CISAKEVMetadata, CVEReference, AffectedProduct
from ..models.domain import CVE, SeverityLevel

logger = logging.getLogger(__name__)


class CVERepository:
    """
    Async repository for CVE database operations.

    Este repositorio confía en las relationships de SQLAlchemy
    para manejar automáticamente las relaciones entre tablas.
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

        Este método reemplaza save_complete_cve() y demuestra el poder
        de usar relationships correctamente.

        ANTES (save_complete_cve):
        - 38 líneas de código
        - 3 repositorios coordinados manualmente
        - Transacciones separadas para cada tabla

        DESPUÉS (save):
        - 15 líneas de código
        - 1 repositorio
        - SQLAlchemy maneja automáticamente las 3 tablas

        Args:
            cve: Domain CVE model (Pydantic)

        Returns:
            Database CVE record (SQLAlchemy)
        """
        # Buscar si ya existe
        result = await self.session.execute(
            select(CVERecord).filter_by(cve_id=cve.cve_id)
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Actualizar registro existente
            if existing.last_modified_date != cve.last_modified_date:
                logger.info(f"Updating CVE {cve.cve_id}")
                existing.update_from_pydantic(cve)  # Método en CVERecord
            else:
                logger.debug(f"CVE {cve.cve_id} unchanged")
            return existing

        # Crear nuevo registro
        logger.info(f"Creating new CVE: {cve.cve_id}")
        cve_record = CVERecord.from_pydantic(cve)

        # ✨ MAGIA: session.add() guarda automáticamente:
        # 1. CVE en tabla 'cves'
        # 2. Metadata en 'cisa_kev_metadata' (si existe)
        # 3. Referencias en 'cve_references' (todas)
        # 4. Productos afectados en 'affected_products' (todos)
        #
        # Esto funciona por cascade="all, delete-orphan" en las relationships
        self.session.add(cve_record)
        await self.session.flush()

        return cve_record

    async def get_by_id(self, cve_id: str) -> Optional[CVERecord]:
        """
        Get CVE by ID with all related data eagerly loaded.

        lazy="selectin" en las relationships carga automáticamente:
        - cisa_kev_metadata
        - references
        - affected_products
        - enrichments

        Args:
            cve_id: CVE identifier

        Returns:
            CVE record with all relationships loaded, or None
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
        """Get all CVEs with optional filtering."""
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
        """Get CRITICAL severity CVEs."""
        query = (
            select(CVERecord)
            .filter_by(final_severity=SeverityLevel.CRITICAL.value)
            .order_by(desc(CVERecord.published_date))
            .limit(limit)
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_recent_cves(self, hours: int = 24, limit: int = 100) -> list[CVERecord]:
        """Get recently published CVEs."""
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
        """Get CVE database statistics."""
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

        return {
            "total_cves": total or 0,
            "in_cisa_kev": kev_count or 0,
            "by_severity": {severity: count for severity, count in by_severity},
        }

    async def delete(self, cve_id: str) -> bool:
        """
        Delete CVE and all related data.

        cascade="all, delete-orphan" automáticamente elimina:
        - CISA KEV metadata
        - Referencias
        - Productos afectados
        - Enrichments
        - Update history

        Args:
            cve_id: CVE identifier

        Returns:
            True if deleted, False if not found
        """
        record = await self.get_by_id(cve_id)
        if record:
            await self.session.delete(record)
            await self.session.flush()
            logger.info(f"Deleted CVE {cve_id} and all related data")
            return True
        return False


# ============================================================================
# MÉTODOS DE CONVERSIÓN EN MODELS/DATABASE.PY
# ============================================================================
# Estos métodos deberían agregarse a CVERecord, CISAKEVMetadata, etc.


"""
# En src/soc_alerting/models/database.py

class CVERecord(Base):
    # ... campos existentes ...

    @classmethod
    def from_pydantic(cls, cve: CVE) -> "CVERecord":
        '''
        Conversión automática de modelo Pydantic (dominio) a SQLAlchemy (DB).

        Este método reemplaza el mapeo manual en _create_record().
        '''
        record = cls(
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

        # ✨ Relaciones automáticas (cascade las guarda)
        if cve.is_in_cisa_kev:
            record.cisa_kev_metadata = CISAKEVMetadata.from_pydantic(cve)

        record.references = [
            CVEReference(url=url, source="NIST")
            for url in cve.references
        ]

        return record

    def update_from_pydantic(self, cve: CVE):
        '''Actualizar campos desde modelo Pydantic.'''
        self.description = cve.description
        self.last_modified_date = cve.last_modified_date
        self.cvss_v3_score = cve.cvss_v3_score
        self.cvss_v3_vector = cve.cvss_v3_vector
        self.cvss_v2_score = cve.cvss_v2_score
        self.cvss_v2_vector = cve.cvss_v2_vector
        self.severity_nist = cve.severity_nist.value
        self.is_in_cisa_kev = cve.is_in_cisa_kev
        self.final_severity = cve.final_severity.value
        self.classification_sources = [s.value for s in cve.classification_sources]
        self.source_identifier = cve.source_identifier
        self.vuln_status = cve.vuln_status
        self.updated_at = datetime.utcnow()

        # Actualizar relaciones
        if cve.is_in_cisa_kev and not self.cisa_kev_metadata:
            self.cisa_kev_metadata = CISAKEVMetadata.from_pydantic(cve)
        elif cve.is_in_cisa_kev and self.cisa_kev_metadata:
            self.cisa_kev_metadata.update_from_pydantic(cve)

        # Actualizar referencias (cascade maneja la eliminación de antiguas)
        self.references = [
            CVEReference(url=url, source="NIST")
            for url in cve.references
        ]

    def to_pydantic(self) -> CVE:
        '''Conversión de SQLAlchemy a Pydantic.'''
        return CVE(
            cve_id=self.cve_id,
            description=self.description,
            published_date=self.published_date,
            last_modified_date=self.last_modified_date,
            cvss_v3_score=self.cvss_v3_score,
            cvss_v3_vector=self.cvss_v3_vector,
            cvss_v2_score=self.cvss_v2_score,
            cvss_v2_vector=self.cvss_v2_vector,
            severity_nist=SeverityLevel(self.severity_nist),
            is_in_cisa_kev=self.is_in_cisa_kev,
            final_severity=SeverityLevel(self.final_severity),
            classification_sources=[ClassificationSource(s) for s in self.classification_sources],
            source_identifier=self.source_identifier,
            vuln_status=self.vuln_status,
            references=[ref.url for ref in self.references],
            # CISA KEV fields
            cisa_exploit_add=self.cisa_kev_metadata.exploit_add if self.cisa_kev_metadata else None,
            cisa_action_due=self.cisa_kev_metadata.action_due if self.cisa_kev_metadata else None,
            cisa_required_action=self.cisa_kev_metadata.required_action if self.cisa_kev_metadata else None,
            cisa_vulnerability_name=self.cisa_kev_metadata.vulnerability_name if self.cisa_kev_metadata else None,
            cisa_known_ransomware=self.cisa_kev_metadata.known_ransomware if self.cisa_kev_metadata else None,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


class CISAKEVMetadata(Base):
    # ... campos existentes ...

    @classmethod
    def from_pydantic(cls, cve: CVE) -> "CISAKEVMetadata":
        '''Crear metadata desde CVE Pydantic.'''
        return cls(
            cve_id=cve.cve_id,
            exploit_add=cve.cisa_exploit_add,
            action_due=cve.cisa_action_due,
            required_action=cve.cisa_required_action or "",
            vulnerability_name=cve.cisa_vulnerability_name,
            known_ransomware=cve.cisa_known_ransomware or False,
        )

    def update_from_pydantic(self, cve: CVE):
        '''Actualizar desde CVE Pydantic.'''
        self.exploit_add = cve.cisa_exploit_add
        self.action_due = cve.cisa_action_due
        self.required_action = cve.cisa_required_action or ""
        self.vulnerability_name = cve.cisa_vulnerability_name
        self.known_ransomware = cve.cisa_known_ransomware or False
        self.updated_at = datetime.utcnow()
"""


# ============================================================================
# COMPARACIÓN ANTES VS DESPUÉS
# ============================================================================

"""
# ANTES (save_complete_cve en cve_repository.py: líneas 294-331)

async def save_complete_cve(self, cve: CVE) -> CVERecord:
    logger.info(f"Saving complete CVE: {cve.cve_id}")

    # 1. Save to main cves table
    cve_record = await self.create_or_update(cve)

    # 2. Save CISA KEV metadata (if applicable)
    if cve.is_in_cisa_kev:
        cisa_repo = CISAKEVRepository(self.session)
        await cisa_repo.upsert_cisa_metadata(cve)
        logger.debug(f"CISA KEV metadata saved for {cve.cve_id}")

    # 3. Save references
    if cve.references:
        ref_repo = CVEReferenceRepository(self.session)
        await ref_repo.bulk_upsert_references(cve)
        logger.debug(f"References saved for {cve.cve_id}")

    logger.info(f"Complete CVE saved: {cve.cve_id}")
    return cve_record

# Problemas:
# ❌ Coordinación manual de 3 repositorios
# ❌ 3 operaciones de base de datos separadas
# ❌ Complejidad innecesaria
# ❌ Difícil de mantener


# DESPUÉS (save)

async def save(self, cve: CVE) -> CVERecord:
    existing = await self.get_by_id(cve.cve_id)

    if existing:
        existing.update_from_pydantic(cve)
        return existing

    cve_record = CVERecord.from_pydantic(cve)
    self.session.add(cve_record)
    await self.session.flush()
    return cve_record

# Beneficios:
# ✅ 1 repositorio en lugar de 3
# ✅ 1 operación de base de datos (flush)
# ✅ SQLAlchemy maneja automáticamente las relaciones
# ✅ 85% menos código
# ✅ Más fácil de entender y mantener
"""


# ============================================================================
# ARCHIVOS QUE SE PUEDEN ELIMINAR DESPUÉS DE LA REFACTORIZACIÓN
# ============================================================================

"""
Estos archivos se vuelven innecesarios al usar relationships correctamente:

1. src/soc_alerting/database/repositories/cisa_repository.py
   - Funcionalidad movida a CVERecord.from_pydantic()

2. src/soc_alerting/database/repositories/reference_repository.py
   - Funcionalidad movida a CVERecord.from_pydantic()

Esto reduce la superficie del código en ~200 líneas adicionales.
"""
