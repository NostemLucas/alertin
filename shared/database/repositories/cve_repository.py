"""
CVE Repository - Versioned Model (Cabecera + Versiones)

Maneja CVEs con sistema de versiones completo.
"""

import logging
from typing import Optional, List, Tuple
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from sqlalchemy.orm import selectinload
from sqlalchemy.exc import IntegrityError

from ...models.db_models import CVE as CVEModel, CVEVersion
from ...models.domain import CVE, SeverityLevel
from ...models.statistics import CVEStatistics

logger = logging.getLogger(__name__)


class CVERepositoryVersioned:
    """
    Repository for versioned CVE operations.

    Arquitectura:
    - CVEModel: Cabecera con identidad única
    - CVEVersion: Cada actualización crea una nueva versión
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def save(self, cve_data: CVE, max_retries: int = 3) -> Tuple[CVEModel, CVEVersion]:
        """
        Save or update CVE with race condition protection.

        Si el CVE no existe: Crea CVE (cabecera) + CVEVersion v1
        Si ya existe: Crea CVEVersion vN, actualiza current_version_id

        Args:
            cve_data: CVE domain model
            max_retries: Maximum retry attempts on conflict (default: 3)

        Returns:
            Tupla (CVE header, nueva CVEVersion creada)

        Raises:
            IntegrityError: If unique constraint violated after all retries
        """
        # Use single timestamp for entire transaction
        now = datetime.utcnow()

        for attempt in range(max_retries):
            try:
                # SELECT FOR UPDATE: Lock row to prevent race conditions
                result = await self.session.execute(
                    select(CVEModel)
                    .options(selectinload(CVEModel.versions))
                    .filter_by(cve_id=cve_data.cve_id)
                    .with_for_update()  # CRITICAL: Locks row until transaction commits
                )
                existing_cve = result.scalar_one_or_none()

                if existing_cve:
                    # CVE existe - crear nueva versión
                    return await self._create_new_version(existing_cve, cve_data, now)
                else:
                    # CVE nuevo - crear cabecera + versión 1
                    return await self._create_new_cve(cve_data, now)

            except IntegrityError as e:
                # Race condition: Another process created same version
                await self.session.rollback()

                if attempt < max_retries - 1:
                    logger.warning(
                        f"Conflict on {cve_data.cve_id}, retry {attempt + 1}/{max_retries}: {e}"
                    )
                    continue  # Retry
                else:
                    logger.error(
                        f"Failed to save {cve_data.cve_id} after {max_retries} attempts: {e}"
                    )
                    raise  # Give up

    async def _create_new_cve(self, cve_data: CVE, now: datetime) -> Tuple[CVEModel, CVEVersion]:
        """
        Create new CVE header + version 1.

        Args:
            cve_data: CVE domain model
            now: Timestamp for this transaction (single source of truth)

        Returns:
            Tupla (CVEModel, CVEVersion)
        """
        logger.info(f"Creating new CVE: {cve_data.cve_id}")

        # 1. Crear cabecera
        cve_header = CVEModel(
            cve_id=cve_data.cve_id,
            first_seen=now,
            created_at=now,
            current_version_id=None  # Se actualizará después
        )
        self.session.add(cve_header)
        await self.session.flush()  # Para obtener el ID

        # 2. Crear versión 1 - Mapping explícito
        version = CVEVersion(
            cve_id=cve_data.cve_id,
            version=1,
            created_at=now,
            # Content
            description=cve_data.description,
            cwe_id=cve_data.cwe_id,
            # Criticality
            cvss_score=cve_data.cvss_score,
            cvss_vector=cve_data.cvss_vector,
            severity=cve_data.severity.value,
            # Attack Vector
            attack_vector=cve_data.attack_vector.value if cve_data.attack_vector else None,
            attack_complexity=cve_data.attack_complexity.value if cve_data.attack_complexity else None,
            requires_auth=cve_data.requires_auth,
            user_interaction_required=cve_data.user_interaction_required,
            # Products
            affected_products=cve_data.affected_products,
            # Tracking
            status_nist=cve_data.status_nist,
            source=cve_data.source,
            published_date=cve_data.published_date,
            last_modified_date=cve_data.last_modified_date,
            # CISA KEV
            is_in_cisa_kev=cve_data.is_in_cisa_kev,
            cisa_date_added=cve_data.cisa_date_added,
            cisa_due_date=cve_data.cisa_due_date,
            cisa_required_action=cve_data.cisa_required_action,
            cisa_known_ransomware=cve_data.cisa_known_ransomware,
            # References
            primary_reference=cve_data.primary_reference,
            references=cve_data.references,
        )
        self.session.add(version)
        await self.session.flush()

        # 3. Actualizar puntero current_version_id
        cve_header.current_version_id = version.id
        await self.session.flush()

        logger.info(f"Created {cve_data.cve_id} v1 (severity={cve_data.severity.value})")
        return cve_header, version

    async def _create_new_version(
        self,
        cve_header: CVEModel,
        cve_data: CVE,
        now: datetime
    ) -> Tuple[CVEModel, CVEVersion]:
        """
        Create new version for existing CVE.

        Args:
            cve_header: Existing CVE header
            cve_data: New CVE data
            now: Timestamp for this transaction (single source of truth)

        Returns:
            Tupla (CVE, nueva CVEVersion)
        """
        # Obtener última versión
        last_version = cve_header.current_version

        if not last_version:
            # Esto no debería pasar, pero por seguridad
            logger.warning(f"{cve_header.cve_id}: No version found, creating v1")
            return await self._create_new_cve(cve_data)

        # Verificar si realmente cambió algo importante
        if not self._has_significant_changes(last_version, cve_data):
            logger.debug(f"{cve_header.cve_id}: No significant changes, skipping version")
            return cve_header, last_version

        # Crear nueva versión
        new_version_number = last_version.version + 1
        logger.info(
            f"Creating {cve_header.cve_id} v{new_version_number} "
            f"(was v{last_version.version})"
        )

        # Detectar cambios críticos para logging
        changes = self._detect_critical_changes(last_version, cve_data)
        if changes:
            logger.info(f"{cve_header.cve_id} critical changes: {', '.join(changes)}")

        # Crear nueva versión - Mapping explícito
        new_version = CVEVersion(
            cve_id=cve_header.cve_id,
            version=new_version_number,
            created_at=now,
            # Content
            description=cve_data.description,
            cwe_id=cve_data.cwe_id,
            # Criticality
            cvss_score=cve_data.cvss_score,
            cvss_vector=cve_data.cvss_vector,
            severity=cve_data.severity.value,
            # Attack Vector
            attack_vector=cve_data.attack_vector.value if cve_data.attack_vector else None,
            attack_complexity=cve_data.attack_complexity.value if cve_data.attack_complexity else None,
            requires_auth=cve_data.requires_auth,
            user_interaction_required=cve_data.user_interaction_required,
            # Products
            affected_products=cve_data.affected_products,
            # Tracking
            status_nist=cve_data.status_nist,
            source=cve_data.source,
            published_date=cve_data.published_date,
            last_modified_date=cve_data.last_modified_date,
            # CISA KEV
            is_in_cisa_kev=cve_data.is_in_cisa_kev,
            cisa_date_added=cve_data.cisa_date_added,
            cisa_due_date=cve_data.cisa_due_date,
            cisa_required_action=cve_data.cisa_required_action,
            cisa_known_ransomware=cve_data.cisa_known_ransomware,
            # References
            primary_reference=cve_data.primary_reference,
            references=cve_data.references,
        )
        self.session.add(new_version)
        await self.session.flush()

        # Actualizar puntero current_version_id
        cve_header.current_version_id = new_version.id
        await self.session.flush()

        return cve_header, new_version

    def _has_significant_changes(
        self,
        old_version: CVEVersion,
        new_data: CVE
    ) -> bool:
        """
        Determina si hay cambios significativos que justifiquen una nueva versión.

        Args:
            old_version: Versión anterior
            new_data: Nuevos datos

        Returns:
            True si hay cambios significativos
        """
        # Campos críticos a verificar
        return (
            old_version.cvss_score != new_data.cvss_score
            or old_version.severity != new_data.severity.value
            or old_version.is_in_cisa_kev != new_data.is_in_cisa_kev
            or old_version.status_nist != new_data.status_nist
            or old_version.description != new_data.description
            or old_version.attack_vector != (new_data.attack_vector.value if new_data.attack_vector else None)
        )

    def _detect_critical_changes(
        self,
        old_version: CVEVersion,
        new_data: CVE
    ) -> List[str]:
        """
        Detecta qué cambios críticos ocurrieron.

        Args:
            old_version: Versión anterior
            new_data: Nuevos datos

        Returns:
            Lista de cambios críticos
        """
        changes = []

        if old_version.cvss_score != new_data.cvss_score:
            changes.append(f"CVSS {old_version.cvss_score} → {new_data.cvss_score}")

        if old_version.severity != new_data.severity.value:
            changes.append(f"Severity {old_version.severity} → {new_data.severity.value}")

        if not old_version.is_in_cisa_kev and new_data.is_in_cisa_kev:
            changes.append("ADDED TO CISA KEV")

        if old_version.status_nist != new_data.status_nist:
            changes.append(f"Status {old_version.status_nist} → {new_data.status_nist}")

        return changes

    async def get_by_id(self, cve_id: str, version: Optional[int] = None) -> Optional[CVEVersion]:
        """
        Get CVE by ID.

        Args:
            cve_id: CVE identifier
            version: Versión específica (None = última versión)

        Returns:
            CVEVersion or None
        """
        if version is None:
            # JOIN directo a current_version usando current_version_id (eficiente)
            # Solo trae la versión actual, no todas las versiones
            result = await self.session.execute(
                select(CVEVersion)
                .join(CVEModel, CVEModel.current_version_id == CVEVersion.id)
                .where(CVEModel.cve_id == cve_id)
            )
            return result.scalar_one_or_none()
        else:
            # Obtener versión específica
            result = await self.session.execute(
                select(CVEVersion)
                .filter_by(cve_id=cve_id, version=version)
            )
            return result.scalar_one_or_none()

    async def get_version_history(self, cve_id: str) -> List[CVEVersion]:
        """
        Get all versions of a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            Lista de versiones ordenadas (v1, v2, v3...)
        """
        result = await self.session.execute(
            select(CVEVersion)
            .filter_by(cve_id=cve_id)
            .order_by(CVEVersion.version)
        )
        return list(result.scalars().all())

    async def get_all(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[SeverityLevel] = None,
        in_cisa_kev: Optional[bool] = None,
        min_cvss: Optional[float] = None,
        attack_vector: Optional[str] = None,
    ) -> List[CVEVersion]:
        """
        Get CVEs (última versión de cada uno).

        Args:
            limit: Maximum results
            offset: Results offset
            severity: Filter by severity
            in_cisa_kev: Filter by KEV membership
            min_cvss: Minimum CVSS score
            attack_vector: Filter by attack vector

        Returns:
            Lista de CVEVersion (última versión de cada CVE)
        """
        # Query sobre cve_versions con JOIN a cves para obtener current_version
        query = (
            select(CVEVersion)
            .join(CVEModel, CVEModel.cve_id == CVEVersion.cve_id)
            .where(CVEModel.current_version_id == CVEVersion.id)
        )

        # Filtros
        if severity:
            query = query.filter(CVEVersion.severity == severity.value)

        if in_cisa_kev is not None:
            query = query.filter(CVEVersion.is_in_cisa_kev == in_cisa_kev)

        if min_cvss is not None:
            query = query.where(CVEVersion.cvss_score >= min_cvss)

        if attack_vector:
            query = query.filter(CVEVersion.attack_vector == attack_vector)

        query = query.order_by(desc(CVEVersion.published_date))
        query = query.limit(limit).offset(offset)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_recent_updates(
        self,
        hours: int = 24,
        limit: int = 100
    ) -> List[CVEVersion]:
        """
        Get CVEs that were updated recently (nuevas versiones).

        Args:
            hours: Buscar últimas N horas
            limit: Máximo de resultados

        Returns:
            Lista de nuevas versiones creadas recientemente
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        query = (
            select(CVEVersion)
            .where(CVEVersion.created_at >= cutoff)
            .where(CVEVersion.version > 1)  # Solo actualizaciones, no v1
            .order_by(desc(CVEVersion.created_at))
            .limit(limit)
        )

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_statistics(self) -> CVEStatistics:
        """Get database statistics."""
        # Total CVEs únicos
        total_result = await self.session.execute(
            select(func.count(CVEModel.cve_id))
        )
        total = total_result.scalar()

        # Por severity (usando current version)
        severity_query = (
            select(CVEVersion.severity, func.count(CVEVersion.cve_id))
            .join(CVEModel, CVEModel.current_version_id == CVEVersion.id)
            .group_by(CVEVersion.severity)
        )
        severity_result = await self.session.execute(severity_query)
        by_severity = dict(severity_result.all())

        # KEV count
        kev_query = (
            select(func.count(CVEVersion.cve_id))
            .join(CVEModel, CVEModel.current_version_id == CVEVersion.id)
            .where(CVEVersion.is_in_cisa_kev == True)  # noqa: E712
        )
        kev_result = await self.session.execute(kev_query)
        kev_count = kev_result.scalar()

        # By attack vector
        vector_query = (
            select(CVEVersion.attack_vector, func.count(CVEVersion.cve_id))
            .join(CVEModel, CVEModel.current_version_id == CVEVersion.id)
            .where(CVEVersion.attack_vector.is_not(None))
            .group_by(CVEVersion.attack_vector)
        )
        vector_result = await self.session.execute(vector_query)
        by_attack_vector = dict(vector_result.all())

        # Recent (last 7 days)
        cutoff = datetime.utcnow() - timedelta(days=7)
        recent_query = (
            select(func.count(CVEModel.cve_id))
            .where(CVEModel.first_seen >= cutoff)
        )
        recent_result = await self.session.execute(recent_query)
        recent_count = recent_result.scalar()

        return CVEStatistics(
            total_cves=total,
            by_severity=by_severity,
            in_cisa_kev=kev_count,
            by_attack_vector=by_attack_vector,
            recent_7_days=recent_count,
        )
