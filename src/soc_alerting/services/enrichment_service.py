"""
CVE Enrichment Service with NLP Pipeline.

Provides comprehensive NLP enrichment for CVE descriptions including:
- Translation (EN → ES)
- Entity extraction (NER)
- Keyword extraction
- Attack analysis
- CIA impact assessment
"""

import logging
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from .nlp import get_nlp_pipeline, NLPEnrichmentPipeline
from ..models.database import CVERecord, CVEEnrichmentRecord
from ..models.domain import CVE, SeverityLevel
from ..config.settings import get_settings

logger = logging.getLogger(__name__)


class EnrichmentService:
    """
    Service for enriching CVEs with NLP analysis.

    Coordinates NLP pipeline execution and database persistence.
    """

    def __init__(
        self,
        enable_translation: bool = True,
        enable_ner: bool = True,
        enable_keywords: bool = True,
        device: str = "cpu",
        enrich_severity_threshold: str = "LOW"
    ):
        """
        Initialize enrichment service.

        Args:
            enable_translation: Enable translation EN→ES
            enable_ner: Enable named entity recognition
            enable_keywords: Enable keyword extraction
            device: 'cpu' or 'cuda' for model execution
            enrich_severity_threshold: Minimum severity to enrich (LOW/MEDIUM/HIGH)
        """
        self.enable_translation = enable_translation
        self.enable_ner = enable_ner
        self.enable_keywords = enable_keywords
        self.device = device
        self.enrich_severity_threshold = SeverityLevel(enrich_severity_threshold)

        # Lazy-load NLP pipeline
        self._nlp_pipeline: Optional[NLPEnrichmentPipeline] = None

        logger.info(
            f"EnrichmentService initialized "
            f"(translation={enable_translation}, ner={enable_ner}, "
            f"keywords={enable_keywords}, device={device}, "
            f"min_severity={enrich_severity_threshold})"
        )

    @property
    def nlp_pipeline(self) -> NLPEnrichmentPipeline:
        """Lazy-load NLP pipeline on first use."""
        if self._nlp_pipeline is None:
            self._nlp_pipeline = get_nlp_pipeline(
                device=self.device,
                enable_translation=self.enable_translation,
                enable_ner=self.enable_ner,
                enable_keywords=self.enable_keywords
            )
        return self._nlp_pipeline

    def should_enrich(self, cve: CVE) -> bool:
        """
        Determine if CVE should be enriched based on severity threshold.

        Args:
            cve: CVE domain model

        Returns:
            True if CVE meets enrichment criteria
        """
        severity_order = {
            SeverityLevel.NONE: 0,
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4,
        }

        return severity_order[cve.final_severity] >= severity_order[self.enrich_severity_threshold]

    async def enrich_cve(
        self,
        session: AsyncSession,
        cve: CVE,
        force: bool = False
    ) -> Optional[CVEEnrichmentRecord]:
        """
        Enrich a single CVE with NLP analysis.

        Args:
            session: Async database session
            cve: CVE domain model
            force: Force enrichment even if below severity threshold

        Returns:
            CVEEnrichmentRecord if enrichment was performed, None otherwise
        """
        # Check if should enrich
        if not force and not self.should_enrich(cve):
            logger.debug(
                f"{cve.cve_id}: Skipping enrichment (severity={cve.final_severity}, "
                f"threshold={self.enrich_severity_threshold})"
            )
            return None

        logger.info(f"{cve.cve_id}: Starting NLP enrichment")

        try:
            # Run NLP pipeline (async)
            enrichment_result = await self.nlp_pipeline.enrich_cve(
                cve_id=cve.cve_id,
                description_en=cve.description
            )

            # Check for errors
            if enrichment_result.get("errors"):
                logger.warning(
                    f"{cve.cve_id}: NLP enrichment completed with errors: "
                    f"{enrichment_result['errors']}"
                )

            # Create enrichment record
            enrichment_record = self._create_enrichment_record(cve.cve_id, enrichment_result)

            # Save to database
            session.add(enrichment_record)
            await session.flush()

            logger.info(
                f"{cve.cve_id}: NLP enrichment completed "
                f"({enrichment_result['processing_time_ms']}ms)"
            )

            return enrichment_record

        except Exception as e:
            logger.error(f"{cve.cve_id}: NLP enrichment failed: {e}", exc_info=True)
            return None

    def _create_enrichment_record(
        self,
        cve_id: str,
        enrichment_result: dict
    ) -> CVEEnrichmentRecord:
        """
        Create CVEEnrichmentRecord from NLP pipeline result.

        Args:
            cve_id: CVE identifier
            enrichment_result: NLP pipeline output

        Returns:
            CVEEnrichmentRecord instance
        """
        record = CVEEnrichmentRecord(cve_id=cve_id)

        # Translation fields
        if enrichment_result.get("translation"):
            trans = enrichment_result["translation"]
            record.description_es = trans.get("description_es")
            record.translation_confidence = trans.get("translation_confidence")
            record.translation_model = trans.get("translation_model")

        # Entity extraction
        if enrichment_result.get("entities"):
            entities = enrichment_result["entities"]
            record.affected_products_ner = entities.get("affected_products_ner", [])
            record.organizations = entities.get("organizations", [])
            record.versions = entities.get("versions", [])
            record.cve_references = entities.get("cve_references", [])
            record.ner_model = entities.get("ner_model")

        # Keywords
        if enrichment_result.get("keywords"):
            keywords = enrichment_result["keywords"]
            record.technical_keywords = keywords.get("all_keywords", [])
            record.attack_vectors = keywords.get("attack_vectors", [])
            record.technical_protocols = keywords.get("technical_protocols", [])
            record.vulnerability_types = keywords.get("vulnerability_types", [])

        # Attack analysis
        if enrichment_result.get("attack_analysis"):
            attack = enrichment_result["attack_analysis"]
            record.attack_type = attack.get("attack_type")
            record.attack_complexity = attack.get("attack_complexity")
            record.requires_authentication = attack.get("requires_authentication")
            record.network_accessible = attack.get("network_accessible")

        # CIA impact
        if enrichment_result.get("cia_impact"):
            record.cia_impact = enrichment_result["cia_impact"]

        # Processing metadata
        record.processing_time_ms = enrichment_result.get("processing_time_ms")

        # Store full enrichment data
        record.enrichment_data = enrichment_result

        return record

    async def batch_enrich(
        self,
        session: AsyncSession,
        cves: list[CVE],
        force: bool = False
    ) -> dict:
        """
        Enrich multiple CVEs in batch.

        Args:
            session: Async database session
            cves: List of CVE domain models
            force: Force enrichment even if below severity threshold

        Returns:
            Dictionary with enrichment statistics
        """
        stats = {
            "total": len(cves),
            "enriched": 0,
            "skipped": 0,
            "failed": 0,
            "total_time_ms": 0
        }

        logger.info(f"Starting batch enrichment for {len(cves)} CVEs")

        for cve in cves:
            try:
                enrichment_record = await self.enrich_cve(session, cve, force=force)

                if enrichment_record:
                    stats["enriched"] += 1
                    stats["total_time_ms"] += enrichment_record.processing_time_ms or 0
                else:
                    stats["skipped"] += 1

            except Exception as e:
                logger.error(f"Batch enrichment failed for {cve.cve_id}: {e}")
                stats["failed"] += 1

        logger.info(
            f"Batch enrichment completed: {stats['enriched']} enriched, "
            f"{stats['skipped']} skipped, {stats['failed']} failed "
            f"({stats['total_time_ms']}ms total)"
        )

        return stats

    async def re_enrich_cve(
        self,
        session: AsyncSession,
        cve_id: str,
        description: str
    ) -> Optional[CVEEnrichmentRecord]:
        """
        Re-enrich an existing CVE with latest NLP models.

        Args:
            session: Async database session
            cve_id: CVE identifier
            description: CVE description

        Returns:
            New enrichment record
        """
        logger.info(f"{cve_id}: Re-enriching with latest NLP models")

        try:
            # Run NLP pipeline
            enrichment_result = self.nlp_pipeline.enrich_cve(
                cve_id=cve_id,
                description_en=description
            )

            # Create new enrichment record
            enrichment_record = self._create_enrichment_record(cve_id, enrichment_result)

            # Save to database (creates new record, keeps history)
            session.add(enrichment_record)
            await session.flush()

            logger.info(f"{cve_id}: Re-enrichment completed")

            return enrichment_record

        except Exception as e:
            logger.error(f"{cve_id}: Re-enrichment failed: {e}", exc_info=True)
            return None

    def unload_models(self):
        """Unload NLP models from memory to free resources."""
        if self._nlp_pipeline:
            self._nlp_pipeline.unload_models()
            self._nlp_pipeline = None
            logger.info("NLP models unloaded from memory")


def create_enrichment_service_from_settings() -> EnrichmentService:
    """
    Create EnrichmentService configured from application settings.

    Returns:
        Configured EnrichmentService instance
    """
    settings = get_settings()

    return EnrichmentService(
        enable_translation=getattr(settings, "nlp_enable_translation", True),
        enable_ner=getattr(settings, "nlp_enable_ner", True),
        enable_keywords=getattr(settings, "nlp_enable_keywords", True),
        device=getattr(settings, "nlp_device", "cpu"),
        enrich_severity_threshold=getattr(settings, "enrich_severity_threshold", "LOW")
    )
