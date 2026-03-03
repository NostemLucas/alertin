"""
NLP Enrichment Pipeline for CVE processing.

Coordinates all NLP components to provide comprehensive CVE enrichment:
1. Translation (EN → ES)
2. Entity extraction (NER)
3. Keyword extraction
4. Attack analysis

REFACTORED: Now uses Pydantic models for type-safe, validated results.
All operations run asynchronously to avoid blocking the FastAPI event loop.
"""

import logging
import asyncio
from typing import Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from .translator import get_translator, CVETranslator
from .entity_extractor import get_entity_extractor, CVEEntityExtractor
from .keyword_extractor import get_keyword_extractor, CVEKeywordExtractor

# Import Pydantic models for validated results
from ...models.nlp import (
    NLPEnrichmentResult,
    TranslationResult,
    EntityExtractionResult,
    KeywordExtractionResult,
    AttackAnalysisResult,
    CIAImpactResult,
    NLPEnrichmentBatchResult,
)

logger = logging.getLogger(__name__)

# Thread pool for NLP tasks
_nlp_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="nlp_pipeline")


class NLPEnrichmentPipeline:
    """
    Complete NLP enrichment pipeline for CVE descriptions.

    Provides:
    - Automatic translation (EN → ES)
    - Named entity recognition
    - Technical keyword extraction
    - Attack vector analysis
    - CIA impact assessment
    """

    def __init__(
        self,
        translation_model: str = "Helsinki-NLP/opus-mt-en-es",
        ner_model: str = "dslim/bert-base-NER",
        device: str = "cpu",
        enable_translation: bool = True,
        enable_ner: bool = True,
        enable_keywords: bool = True
    ):
        """
        Initialize NLP pipeline with configurable components.

        Args:
            translation_model: HuggingFace translation model
            ner_model: HuggingFace NER model
            device: 'cpu' or 'cuda'
            enable_translation: Enable translation component
            enable_ner: Enable NER component
            enable_keywords: Enable keyword extraction
        """
        self.device = device
        self.enable_translation = enable_translation
        self.enable_ner = enable_ner
        self.enable_keywords = enable_keywords

        # Initialize components (lazy-loaded)
        self._translator: Optional[CVETranslator] = None
        self._entity_extractor: Optional[CVEEntityExtractor] = None
        self._keyword_extractor: Optional[CVEKeywordExtractor] = None

        self.translation_model = translation_model
        self.ner_model = ner_model

        logger.info(
            f"NLPEnrichmentPipeline initialized "
            f"(translation={enable_translation}, ner={enable_ner}, "
            f"keywords={enable_keywords}, device={device})"
        )

    @property
    def translator(self) -> CVETranslator:
        """Lazy-load translator."""
        if self._translator is None and self.enable_translation:
            self._translator = get_translator(
                model_name=self.translation_model,
                device=self.device
            )
        return self._translator

    @property
    def entity_extractor(self) -> CVEEntityExtractor:
        """Lazy-load entity extractor."""
        if self._entity_extractor is None and self.enable_ner:
            self._entity_extractor = get_entity_extractor(
                model_name=self.ner_model,
                device=self.device
            )
        return self._entity_extractor

    @property
    def keyword_extractor(self) -> CVEKeywordExtractor:
        """Lazy-load keyword extractor."""
        if self._keyword_extractor is None and self.enable_keywords:
            self._keyword_extractor = get_keyword_extractor()
        return self._keyword_extractor

    async def enrich_cve(
        self,
        cve_id: str,
        description_en: str,
        min_confidence: float = 0.5
    ) -> NLPEnrichmentResult:
        """
        Perform complete NLP enrichment on a CVE description.

        REFACTORED: Now returns a validated Pydantic model instead of dict[str, any].

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-12345)
            description_en: English CVE description
            min_confidence: Minimum confidence threshold for NER

        Returns:
            NLPEnrichmentResult with all enrichment data:
                - translation: Translation results (validated)
                - entities: Extracted entities (validated)
                - keywords: Extracted keywords (validated)
                - attack_analysis: Attack type and characteristics (validated)
                - cia_impact: Confidentiality, Integrity, Availability impact (validated)
                - processing_time_ms: Total processing time
                - errors: List of any errors encountered

        Example:
            >>> pipeline = NLPEnrichmentPipeline()
            >>> result = await pipeline.enrich_cve(
            ...     "CVE-2021-44228",
            ...     "Apache Log4j2 JNDI features do not protect..."
            ... )
            >>> print(result.translation.description_es)  # ✅ Autocompletado
            "Las funcionalidades JNDI de Apache Log4j2 no protegen..."
            >>> print(result.enrichment_coverage)  # ✅ Propiedad calculada
            0.95
        """
        start_time = datetime.utcnow()

        logger.info(f"Starting NLP enrichment for {cve_id}")

        # Variables para acumular resultados validados
        translation_result: Optional[TranslationResult] = None
        entity_result: Optional[EntityExtractionResult] = None
        keyword_result: Optional[KeywordExtractionResult] = None
        attack_result: Optional[AttackAnalysisResult] = None
        cia_result: Optional[CIAImpactResult] = None
        errors: list[str] = []

        # 1. Translation (EN → ES)
        if self.enable_translation:
            try:
                logger.debug(f"{cve_id}: Starting translation")
                translation_data = await self.translator.translate_cve(description_en)

                # ✅ Crear modelo Pydantic validado
                translation_result = TranslationResult(
                    description_es=translation_data["translated_text"],
                    confidence=translation_data["confidence"],  # Validado: 0.0-1.0
                    model=self.translation_model
                )
                logger.debug(
                    f"{cve_id}: Translation completed "
                    f"(confidence: {translation_result.confidence:.2f})"
                )
            except Exception as e:
                logger.error(f"{cve_id}: Translation failed: {e}", exc_info=True)
                errors.append(f"Translation error: {str(e)}")

        # 2. Entity Extraction (NER)
        if self.enable_ner:
            try:
                logger.debug(f"{cve_id}: Starting entity extraction")
                entities_data = await self.entity_extractor.extract_entities(
                    description_en,
                    min_confidence=min_confidence
                )

                # Also extract affected products
                affected_products = await self.entity_extractor.extract_affected_products(
                    description_en
                )

                # ✅ Crear modelo Pydantic validado
                entity_result = EntityExtractionResult(
                    organizations=entities_data["organizations"],
                    versions=entities_data["versions"],
                    cve_references=entities_data["cve_references"],
                    urls=entities_data["urls"],
                    technical_terms=entities_data["technical_terms"],
                    affected_products_ner=affected_products,
                    entity_count=entities_data["entity_counts"]["total"],
                    model=self.ner_model
                )
                logger.debug(
                    f"{cve_id}: Entity extraction completed "
                    f"({entity_result.entity_count} entities)"
                )
            except Exception as e:
                logger.error(f"{cve_id}: Entity extraction failed: {e}", exc_info=True)
                errors.append(f"Entity extraction error: {str(e)}")

        # 3. Keyword Extraction
        if self.enable_keywords:
            try:
                logger.debug(f"{cve_id}: Starting keyword extraction")
                keywords_data = self.keyword_extractor.extract_keywords(description_en)

                # ✅ Crear modelo Pydantic validado
                keyword_result = KeywordExtractionResult(
                    attack_vectors=keywords_data["attack_vectors"],
                    technical_protocols=keywords_data["technical_protocols"],
                    programming_concepts=keywords_data["programming_concepts"],
                    vulnerability_types=keywords_data["vulnerability_types"],
                    all_keywords=keywords_data["all_keywords"][:10],  # Top 10
                    keyword_count=keywords_data["keyword_count"]
                )
                logger.debug(
                    f"{cve_id}: Keyword extraction completed "
                    f"({keyword_result.keyword_count} keywords)"
                )
            except Exception as e:
                logger.error(f"{cve_id}: Keyword extraction failed: {e}", exc_info=True)
                errors.append(f"Keyword extraction error: {str(e)}")

        # 4. Attack Analysis
        if self.enable_keywords:
            try:
                logger.debug(f"{cve_id}: Starting attack analysis")
                attack_data = self.keyword_extractor.identify_attack_type(description_en)

                # ✅ Crear modelo Pydantic validado
                attack_result = AttackAnalysisResult(
                    attack_type=attack_data["primary_attack_type"],
                    secondary_attack_types=attack_data["secondary_types"],
                    attack_complexity=attack_data["attack_complexity"],
                    requires_authentication=attack_data["requires_authentication"],
                    network_accessible=attack_data["network_accessible"],
                    confidence=attack_data["confidence"]  # Validado: 0.0-1.0
                )
                logger.debug(
                    f"{cve_id}: Attack analysis completed "
                    f"(type: {attack_result.attack_type})"
                )
            except Exception as e:
                logger.error(f"{cve_id}: Attack analysis failed: {e}", exc_info=True)
                errors.append(f"Attack analysis error: {str(e)}")

        # 5. CIA Impact Assessment
        if self.enable_keywords:
            try:
                logger.debug(f"{cve_id}: Starting CIA impact assessment")
                cia_data = self.keyword_extractor.extract_cia_impact(description_en)

                # ✅ Crear modelo Pydantic validado
                cia_result = CIAImpactResult(
                    confidentiality=cia_data["confidentiality"],
                    integrity=cia_data["integrity"],
                    availability=cia_data["availability"],
                    overall_impact=cia_data.get("overall_impact", "UNKNOWN")
                )
                logger.debug(
                    f"{cve_id}: CIA impact completed "
                    f"(C:{cia_result.confidentiality}, "
                    f"I:{cia_result.integrity}, "
                    f"A:{cia_result.availability})"
                )
            except Exception as e:
                logger.error(f"{cve_id}: CIA impact assessment failed: {e}", exc_info=True)
                errors.append(f"CIA impact error: {str(e)}")

        # Calculate total processing time
        end_time = datetime.utcnow()
        processing_time_ms = int((end_time - start_time).total_seconds() * 1000)

        # ✅ Construir resultado final validado
        result = NLPEnrichmentResult(
            cve_id=cve_id,
            enriched_at=start_time,
            translation=translation_result,
            entities=entity_result,
            keywords=keyword_result,
            attack_analysis=attack_result,
            cia_impact=cia_result,
            processing_time_ms=processing_time_ms,
            errors=errors
        )

        logger.info(
            f"{cve_id}: NLP enrichment completed in {processing_time_ms}ms "
            f"(coverage: {result.enrichment_coverage:.0%}, errors: {len(errors)})"
        )

        return result  # ✅ Tipo validado NLPEnrichmentResult

    async def batch_enrich(
        self,
        cves: list[tuple[str, str]],
        min_confidence: float = 0.5
    ) -> NLPEnrichmentBatchResult:
        """
        Enrich multiple CVEs in batch asynchronously.

        REFACTORED: Now returns NLPEnrichmentBatchResult with aggregate metrics.

        Args:
            cves: List of (cve_id, description) tuples
            min_confidence: Minimum confidence threshold

        Returns:
            NLPEnrichmentBatchResult with:
                - Individual enrichment results
                - Aggregate metrics (total, successful, failed)
                - Processing time statistics

        Note:
            Processes CVEs concurrently using asyncio.gather for better performance.
        """
        start_time = datetime.utcnow()
        logger.info(f"Starting batch enrichment for {len(cves)} CVEs")

        # Process all CVEs concurrently
        tasks = [
            self.enrich_cve(cve_id, description, min_confidence)
            for cve_id, description in cves
        ]

        # Gather results, catching exceptions
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Separate successful and failed results
        successful_results: list[NLPEnrichmentResult] = []
        failed_count = 0

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                cve_id = cves[i][0]
                logger.error(f"Batch enrichment failed for {cve_id}: {result}", exc_info=True)
                # Create error result
                error_result = NLPEnrichmentResult(
                    cve_id=cve_id,
                    enriched_at=datetime.utcnow(),
                    processing_time_ms=0,
                    errors=[f"Enrichment failed: {str(result)}"]
                )
                successful_results.append(error_result)
                failed_count += 1
            else:
                successful_results.append(result)
                if result.has_errors:
                    failed_count += 1

        end_time = datetime.utcnow()
        total_time_ms = int((end_time - start_time).total_seconds() * 1000)

        # ✅ Construir resultado de batch validado
        batch_result = NLPEnrichmentBatchResult(
            total_cves=len(cves),
            successful=len(cves) - failed_count,
            failed=failed_count,
            results=successful_results,
            total_processing_time_ms=total_time_ms
        )

        logger.info(
            f"Batch enrichment completed: {len(cves)} CVEs in {total_time_ms}ms "
            f"(success rate: {batch_result.success_rate:.0%}, "
            f"avg time: {batch_result.average_processing_time_ms:.0f}ms)"
        )

        return batch_result  # ✅ Tipo validado NLPEnrichmentBatchResult

    def unload_models(self):
        """Unload all models from memory to free resources."""
        if self._translator:
            self._translator.unload_model()
            self._translator = None

        if self._entity_extractor:
            self._entity_extractor.unload_model()
            self._entity_extractor = None

        logger.info("All NLP models unloaded from memory")


# Global pipeline instance
_pipeline_instance: Optional[NLPEnrichmentPipeline] = None


def get_nlp_pipeline(
    translation_model: str = "Helsinki-NLP/opus-mt-en-es",
    ner_model: str = "dslim/bert-base-NER",
    device: str = "cpu",
    enable_translation: bool = True,
    enable_ner: bool = True,
    enable_keywords: bool = True
) -> NLPEnrichmentPipeline:
    """
    Get singleton NLP pipeline instance.

    Args:
        translation_model: HuggingFace translation model
        ner_model: HuggingFace NER model
        device: 'cpu' or 'cuda'
        enable_translation: Enable translation
        enable_ner: Enable NER
        enable_keywords: Enable keyword extraction

    Returns:
        NLPEnrichmentPipeline instance
    """
    global _pipeline_instance

    if _pipeline_instance is None:
        _pipeline_instance = NLPEnrichmentPipeline(
            translation_model=translation_model,
            ner_model=ner_model,
            device=device,
            enable_translation=enable_translation,
            enable_ner=enable_ner,
            enable_keywords=enable_keywords
        )

    return _pipeline_instance
