"""
FastAPI application for SOC Alerting System.

Provides REST API to visualize CVEs, processing results, and statistics.
"""

import logging
from typing import Optional, AsyncGenerator
from datetime import datetime

from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..database.connection import get_database
from ..database.repositories.cve_repository import CVERepository
from ..services.cve_processor import CVEProcessor
from ..models.domain import SeverityLevel
from ..config.settings import get_settings

logger = logging.getLogger(__name__)


# Dependency Injection: Database session
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for database session.

    Yields async SQLAlchemy session with automatic cleanup.
    """
    db = get_database()
    async with db.get_session() as session:
        yield session


# Response models
class CVEResponse(BaseModel):
    """CVE API response model."""

    cve_id: str
    description: str
    published_date: datetime
    last_modified_date: datetime
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    cvss_v2_vector: Optional[str] = None
    severity_nist: str
    final_severity: str
    is_in_cisa_kev: bool
    classification_sources: list[str] = []
    source_identifier: str
    vuln_status: str
    references: list[str] = []
    cisa_exploit_add: Optional[datetime] = None
    cisa_action_due: Optional[datetime] = None
    cisa_required_action: Optional[str] = None
    cisa_vulnerability_name: Optional[str] = None
    cisa_known_ransomware: Optional[bool] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class StatisticsResponse(BaseModel):
    """Statistics API response."""

    total_cves: int
    in_cisa_kev: int
    by_severity: dict


class ProcessingStatsResponse(BaseModel):
    """Processing statistics response."""

    cves_fetched: int
    cves_processed: int
    cves_created: int
    cves_updated: int
    cves_in_kev: int
    by_severity: dict


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="SOC Alerting System API",
        description="API para gestión y visualización de CVEs con clasificación NIST + CISA KEV",
        version="1.0.0",
    )

    # Enable CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/")
    async def root():
        """API root - health check."""
        return {
            "name": "SOC Alerting System API",
            "version": "1.0.0",
            "status": "running",
            "endpoints": {
                "docs": "/docs",
                "cves": "/cves",
                "statistics": "/statistics",
                "process": "/process",
            },
        }

    @app.get("/health")
    async def health_check():
        """Health check endpoint (async)."""
        from ..database.connection import get_database

        db = get_database()
        db_healthy = await db.health_check()

        return {
            "status": "healthy" if db_healthy else "unhealthy",
            "database": "connected" if db_healthy else "disconnected",
            "timestamp": datetime.utcnow().isoformat(),
        }

    @app.get("/statistics", response_model=StatisticsResponse)
    async def get_statistics(session: AsyncSession = Depends(get_db_session)):
        """
        Obtener estadísticas de CVEs en base de datos (async).

        Retorna:
        - Total de CVEs
        - CVEs en CISA KEV
        - Distribución por severidad
        """
        repo = CVERepository(session)
        stats = await repo.get_statistics()
        return stats

    @app.get("/cves", response_model=list[CVEResponse])
    async def list_cves(
        session: AsyncSession = Depends(get_db_session),
        limit: int = Query(default=50, ge=1, le=500, description="Máximo de resultados"),
        offset: int = Query(default=0, ge=0, description="Offset para paginación"),
        severity: Optional[str] = Query(default=None, description="Filtrar por severidad"),
        in_cisa_kev: Optional[bool] = Query(default=None, description="Filtrar por CISA KEV"),
    ):
        """
        Listar CVEs con filtros opcionales (async with DI).

        Parámetros:
        - limit: Cantidad máxima de resultados (default: 50)
        - offset: Offset para paginación (default: 0)
        - severity: Filtrar por severidad (CRITICAL, HIGH, MEDIUM, LOW, NONE)
        - in_cisa_kev: Filtrar por presencia en CISA KEV (true/false)
        """
        try:
            severity_filter = None
            if severity:
                try:
                    severity_filter = SeverityLevel(severity.upper())
                except ValueError:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Severidad inválida. Use: {', '.join([s.value for s in SeverityLevel])}",
                    )

            repo = CVERepository(session)
            cves = await repo.get_all(
                limit=limit,
                offset=offset,
                severity=severity_filter,
                in_cisa_kev=in_cisa_kev,
            )
            # Convert to Pydantic models (session still active via DI)
            result = [CVEResponse.model_validate(cve) for cve in cves]

            logger.info(f"Retrieved {len(result)} CVEs from database")
            return result
        except Exception as e:
            logger.error(f"Error in list_cves: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/cves/debug")
    async def debug_cves(
        session: AsyncSession = Depends(get_db_session),
        limit: int = Query(default=1, ge=1, le=10)
    ):
        """Debug endpoint - return raw CVE data without validation (async with DI)."""
        try:
            repo = CVERepository(session)
            cves = await repo.get_all(limit=limit)

            if not cves:
                return {"message": "No CVEs found"}

            # Try to convert manually
            result = []
            for cve in cves:
                try:
                    # Convert to CVEResponse
                    cve_response = CVEResponse.model_validate(cve)
                    result.append(cve_response.model_dump())
                except Exception as e:
                    logger.error(f"Error validating CVE {cve.cve_id}: {str(e)}")
                    return {
                        "error": f"Validation failed for {cve.cve_id}",
                        "details": str(e),
                        "cve_id": cve.cve_id,
                    }

            return {"count": len(result), "cves": result}
        except Exception as e:
            logger.error(f"Debug endpoint error: {str(e)}")
            return {"error": str(e), "type": type(e).__name__}

    @app.get("/cves/critical", response_model=list[CVEResponse])
    async def list_critical_cves(
        session: AsyncSession = Depends(get_db_session),
        limit: int = Query(default=50, ge=1, le=500, description="Máximo de resultados"),
    ):
        """
        Listar CVEs CRITICAL (async with DI).

        Los CVEs CRITICAL incluyen:
        - CVEs con CVSS >= 9.0
        - Todos los CVEs en CISA KEV (override automático)
        """
        repo = CVERepository(session)
        cves = await repo.get_critical_cves(limit=limit)
        return [CVEResponse.model_validate(cve) for cve in cves]

    @app.get("/cves/cisa-kev", response_model=list[CVEResponse])
    async def list_cisa_kev_cves(
        session: AsyncSession = Depends(get_db_session),
        limit: int = Query(default=100, ge=1, le=500, description="Máximo de resultados"),
    ):
        """
        Listar CVEs en CISA Known Exploited Vulnerabilities (async with DI).

        Estos CVEs tienen explotación confirmada en la vida real y
        son clasificados automáticamente como CRITICAL.
        """
        repo = CVERepository(session)
        cves = await repo.get_cisa_kev_cves(limit=limit)
        return [CVEResponse.model_validate(cve) for cve in cves]

    @app.get("/cves/recent", response_model=list[CVEResponse])
    async def list_recent_cves(
        session: AsyncSession = Depends(get_db_session),
        hours: int = Query(default=24, ge=1, le=168, description="Horas hacia atrás"),
        limit: int = Query(default=100, ge=1, le=500, description="Máximo de resultados"),
    ):
        """
        Listar CVEs publicados recientemente (async with DI).

        Parámetros:
        - hours: Horas hacia atrás (default: 24, max: 168 = 1 semana)
        - limit: Máximo de resultados
        """
        repo = CVERepository(session)
        cves = await repo.get_recent_cves(hours=hours, limit=limit)
        return [CVEResponse.model_validate(cve) for cve in cves]

    @app.get("/cves/{cve_id}", response_model=CVEResponse)
    async def get_cve(
        cve_id: str,
        session: AsyncSession = Depends(get_db_session)
    ):
        """
        Obtener detalles de un CVE específico (async with DI).

        Parámetros:
        - cve_id: Identificador CVE (ej: CVE-2021-44228)
        """
        repo = CVERepository(session)
        cve = await repo.get_by_id(cve_id)
        if not cve:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} no encontrado")
        return CVEResponse.model_validate(cve)

    @app.get("/cves/{cve_id}/summary")
    async def get_cve_summary(cve_id: str):
        """
        Obtener resumen completo de un CVE con datos de NIST y CISA.

        Este endpoint consulta directamente las APIs (no la BD),
        útil para análisis on-demand.

        Retorna:
        - Datos de NIST (CVSS, descripción, referencias)
        - Datos de CISA KEV (si aplica)
        - Clasificación final
        """
        async with CVEProcessor() as processor:
            summary = await processor.get_cve_summary(cve_id)

        if not summary:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} no encontrado en NIST")

        return summary

    @app.post("/process/recent", response_model=ProcessingStatsResponse)
    async def process_recent_cves(
        hours: int = Query(default=24, ge=1, le=168, description="Horas hacia atrás"),
        max_cves: Optional[int] = Query(
            default=None, ge=1, le=1000, description="Máximo de CVEs a procesar"
        ),
    ):
        """
        Procesar CVEs modificados recientemente.

        Este endpoint ejecuta el pipeline completo:
        1. Fetch de NIST NVD (CVEs modificados en últimas N horas)
        2. Verificación con CISA KEV
        3. Aplicación de regla de override (KEV → CRITICAL)
        4. Guardado en base de datos

        Parámetros:
        - hours: Horas hacia atrás para buscar CVEs (default: 24)
        - max_cves: Máximo de CVEs a procesar (default: todos)

        Retorna estadísticas del procesamiento.
        """
        logger.info(f"Iniciando procesamiento: last {hours}h, max {max_cves} CVEs")

        async with CVEProcessor() as processor:
            stats = await processor.process_recent_cves(
                hours_back=hours,
                max_cves=max_cves,
            )

        logger.info(f"Procesamiento completado: {stats}")
        return stats

    @app.post("/process/cve/{cve_id}")
    async def process_specific_cve(cve_id: str):
        """
        Procesar un CVE específico.

        Ejecuta el pipeline completo para un CVE individual:
        1. Fetch de NIST
        2. Verificación CISA KEV
        3. Guardado en BD

        Parámetros:
        - cve_id: Identificador CVE (ej: CVE-2021-44228)
        """
        async with CVEProcessor() as processor:
            cve = await processor.process_specific_cve(cve_id)

        if not cve:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} no encontrado en NIST")

        return {
            "cve_id": cve.cve_id,
            "severity_nist": cve.severity_nist.value,
            "final_severity": cve.final_severity.value,
            "is_in_cisa_kev": cve.is_in_cisa_kev,
            "message": f"CVE {cve_id} procesado exitosamente",
        }

    return app
