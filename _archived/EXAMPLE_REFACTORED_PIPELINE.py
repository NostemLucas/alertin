"""
EJEMPLO: NLP Pipeline refactorizado usando modelos Pydantic.

Este archivo muestra cómo se vería nlp/pipeline.py después de la refactorización.

ANTES: Devuelve dict[str, any] - sin validación, sin autocompletado
DESPUÉS: Devuelve NLPEnrichmentResult - validado, type-safe, autocompleta

CAMBIOS CLAVE:
1. ✅ Usa modelos Pydantic en lugar de diccionarios
2. ✅ Validación automática de resultados
3. ✅ Autocompletado en IDE
4. ✅ Errores en tiempo de desarrollo, no en producción
"""

import logging
import asyncio
from typing import Optional
from datetime import datetime
from dataclasses import dataclass

from .translator import CVETranslator, get_translator
from .entity_extractor import CVEEntityExtractor, get_entity_extractor
from .keyword_extractor import CVEKeywordExtractor, get_keyword_extractor

# ✨ IMPORTAR LOS NUEVOS MODELOS PYDANTIC
from ..models.nlp import (
    NLPEnrichmentResult,
    TranslationResult,
    EntityExtractionResult,
    KeywordExtractionResult,
    AttackAnalysisResult,
    CIAImpactResult,
    NLPEnrichmentBatchResult,
)

logger = logging.getLogger(__name__)


@dataclass
class NLPPipeline:
    """
    NLP enrichment pipeline usando inyección de dependencias.

    ANTES: Clase con lazy-loading complejo
    DESPUÉS: Dataclass simple con dependencias inyectadas

    Beneficios:
    - Más fácil de testear (mock de dependencias)
    - Más claro qué componentes se necesitan
    - No más lazy-loading misterioso
    """

    translator: CVETranslator
    entity_extractor: CVEEntityExtractor
    keyword_extractor: CVEKeywordExtractor

    async def enrich_cve(
        self,
        cve_id: str,
        description_en: str,
        min_confidence: float = 0.5
    ) -> NLPEnrichmentResult:
        """
        Perform complete NLP enrichment on a CVE description.

        ANTES: Devolvía dict[str, any]
        DESPUÉS: Devuelve NLPEnrichmentResult (Pydantic)

        Args:
            cve_id: CVE identifier
            description_en: English CVE description
            min_confidence: Minimum confidence threshold for NER

        Returns:
            Validated NLPEnrichmentResult with all enrichment data

        Example:
            >>> pipeline = get_nlp_pipeline()
            >>> result = await pipeline.enrich_cve(
            ...     "CVE-2021-44228",
            ...     "Apache Log4j2 JNDI features do not protect..."
            ... )
            >>> print(result.translation.description_es)  # ✅ Autocompletado
            >>> print(result.enrichment_coverage)  # ✅ Propiedad calculada
        """
        start_time = datetime.utcnow()
        logger.info(f"Starting NLP enrichment for {cve_id}")

        # Variables para acumular resultados
        translation_result: Optional[TranslationResult] = None
        entity_result: Optional[EntityExtractionResult] = None
        keyword_result: Optional[KeywordExtractionResult] = None
        attack_result: Optional[AttackAnalysisResult] = None
        cia_result: Optional[CIAImpactResult] = None
        errors: list[str] = []

        # 1. Translation (EN → ES)
        try:
            logger.debug(f"{cve_id}: Starting translation")
            translation_data = await self.translator.translate_cve(description_en)

            # ✨ CREAR MODELO PYDANTIC VALIDADO
            translation_result = TranslationResult(
                description_es=translation_data["translated_text"],
                confidence=translation_data["confidence"],
                model=self.translator.model_name
            )
            logger.debug(f"{cve_id}: Translation completed (confidence: {translation_result.confidence:.2f})")

        except Exception as e:
            logger.error(f"{cve_id}: Translation failed: {e}", exc_info=True)
            errors.append(f"Translation error: {str(e)}")

        # 2. Entity Extraction (NER)
        try:
            logger.debug(f"{cve_id}: Starting entity extraction")
            entities_data = await self.entity_extractor.extract_entities(
                description_en,
                min_confidence=min_confidence
            )
            affected_products = await self.entity_extractor.extract_affected_products(description_en)

            # ✨ CREAR MODELO PYDANTIC VALIDADO
            entity_result = EntityExtractionResult(
                organizations=entities_data["organizations"],
                versions=entities_data["versions"],
                cve_references=entities_data["cve_references"],
                urls=entities_data["urls"],
                technical_terms=entities_data["technical_terms"],
                affected_products_ner=affected_products,
                entity_count=entities_data["entity_counts"]["total"],
                model=self.entity_extractor.model_name
            )
            logger.debug(f"{cve_id}: Entity extraction completed ({entity_result.entity_count} entities)")

        except Exception as e:
            logger.error(f"{cve_id}: Entity extraction failed: {e}", exc_info=True)
            errors.append(f"Entity extraction error: {str(e)}")

        # 3. Keyword Extraction
        try:
            logger.debug(f"{cve_id}: Starting keyword extraction")
            keywords_data = self.keyword_extractor.extract_keywords(description_en)

            # ✨ CREAR MODELO PYDANTIC VALIDADO
            keyword_result = KeywordExtractionResult(
                attack_vectors=keywords_data["attack_vectors"],
                technical_protocols=keywords_data["technical_protocols"],
                programming_concepts=keywords_data["programming_concepts"],
                vulnerability_types=keywords_data["vulnerability_types"],
                all_keywords=keywords_data["all_keywords"][:10],  # Top 10
                keyword_count=keywords_data["keyword_count"]
            )
            logger.debug(f"{cve_id}: Keyword extraction completed ({keyword_result.keyword_count} keywords)")

        except Exception as e:
            logger.error(f"{cve_id}: Keyword extraction failed: {e}", exc_info=True)
            errors.append(f"Keyword extraction error: {str(e)}")

        # 4. Attack Analysis
        try:
            logger.debug(f"{cve_id}: Starting attack analysis")
            attack_data = self.keyword_extractor.identify_attack_type(description_en)

            # ✨ CREAR MODELO PYDANTIC VALIDADO
            attack_result = AttackAnalysisResult(
                attack_type=attack_data["primary_attack_type"],
                secondary_attack_types=attack_data["secondary_types"],
                attack_complexity=attack_data["attack_complexity"],
                requires_authentication=attack_data["requires_authentication"],
                network_accessible=attack_data["network_accessible"],
                confidence=attack_data["confidence"]
            )
            logger.debug(f"{cve_id}: Attack analysis completed (type: {attack_result.attack_type})")

        except Exception as e:
            logger.error(f"{cve_id}: Attack analysis failed: {e}", exc_info=True)
            errors.append(f"Attack analysis error: {str(e)}")

        # 5. CIA Impact Assessment
        try:
            logger.debug(f"{cve_id}: Starting CIA impact assessment")
            cia_data = self.keyword_extractor.extract_cia_impact(description_en)

            # ✨ CREAR MODELO PYDANTIC VALIDADO
            cia_result = CIAImpactResult(
                confidentiality=cia_data["confidentiality"],
                integrity=cia_data["integrity"],
                availability=cia_data["availability"],
                overall_impact=cia_data["overall_impact"]
            )
            logger.debug(
                f"{cve_id}: CIA impact completed "
                f"(C:{cia_result.confidentiality}, I:{cia_result.integrity}, A:{cia_result.availability})"
            )

        except Exception as e:
            logger.error(f"{cve_id}: CIA impact assessment failed: {e}", exc_info=True)
            errors.append(f"CIA impact error: {str(e)}")

        # Calculate total processing time
        end_time = datetime.utcnow()
        processing_time_ms = int((end_time - start_time).total_seconds() * 1000)

        # ✨ CONSTRUIR RESULTADO FINAL VALIDADO
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

        return result  # ✅ Tipo validado, autocompletado funciona

    async def batch_enrich(
        self,
        cves: list[tuple[str, str]],
        min_confidence: float = 0.5
    ) -> NLPEnrichmentBatchResult:
        """
        Enrich multiple CVEs in batch asynchronously.

        NUEVO: Devuelve NLPEnrichmentBatchResult con métricas agregadas

        Args:
            cves: List of (cve_id, description) tuples
            min_confidence: Minimum confidence threshold

        Returns:
            Batch result with all individual enrichments and aggregate metrics
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

        # ✨ CONSTRUIR RESULTADO DE BATCH VALIDADO
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

        return batch_result  # ✅ Métricas agregadas automáticas


# ============================================================================
# DEPENDENCY INJECTION PATTERN
# ============================================================================

_pipeline_instance: Optional[NLPPipeline] = None


def get_nlp_pipeline(
    translation_model: str = "Helsinki-NLP/opus-mt-en-es",
    ner_model: str = "dslim/bert-base-NER",
    device: str = "cpu",
) -> NLPPipeline:
    """
    Get singleton NLP pipeline instance.

    ANTES: NLPEnrichmentPipeline con lazy-loading interno
    DESPUÉS: NLPPipeline con dependencias inyectadas

    Args:
        translation_model: HuggingFace translation model
        ner_model: HuggingFace NER model
        device: 'cpu' or 'cuda'

    Returns:
        NLPPipeline instance
    """
    global _pipeline_instance

    if _pipeline_instance is None:
        # Crear dependencias
        translator = get_translator(model_name=translation_model, device=device)
        entity_extractor = get_entity_extractor(model_name=ner_model, device=device)
        keyword_extractor = get_keyword_extractor()

        # Inyectar dependencias
        _pipeline_instance = NLPPipeline(
            translator=translator,
            entity_extractor=entity_extractor,
            keyword_extractor=keyword_extractor
        )

    return _pipeline_instance


# ============================================================================
# COMPARACIÓN ANTES VS DESPUÉS
# ============================================================================

"""
# ❌ ANTES (pipeline.py: líneas 108-279)

async def enrich_cve(
    self,
    cve_id: str,
    description_en: str,
    min_confidence: float = 0.5
) -> dict[str, any]:  # ❌ Diccionario ciego
    result = {
        "cve_id": cve_id,
        "enriched_at": start_time.isoformat(),
        "translation": None,
        "entities": None,
        "keywords": None,
        "attack_analysis": None,
        "cia_impact": None,
        "processing_time_ms": 0,
        "errors": []
    }

    # ... procesamiento ...

    result["translation"] = {
        "description_es": translation_result["translated_text"],  # ❌ KeyError posible
        "translation_confidence": translation_result["confidence"],  # ❌ Sin validación
        "translation_model": self.translation_model
    }

    return result  # ❌ dict[str, any]

# Problemas:
# ❌ No hay autocompletado: result["translation"]["description_es"]
# ❌ Sin validación de tipos
# ❌ Errores aparecen en runtime
# ❌ Difícil de documentar


# ✅ DESPUÉS

async def enrich_cve(
    self,
    cve_id: str,
    description_en: str,
    min_confidence: float = 0.5
) -> NLPEnrichmentResult:  # ✅ Modelo Pydantic validado

    # ... procesamiento ...

    translation_result = TranslationResult(
        description_es=translation_data["translated_text"],
        confidence=translation_data["confidence"],  # ✅ Validado: 0.0-1.0
        model=self.translator.model_name
    )

    return NLPEnrichmentResult(
        cve_id=cve_id,
        translation=translation_result,
        # ... otros campos validados ...
    )  # ✅ NLPEnrichmentResult

# Beneficios:
# ✅ Autocompletado: result.translation.description_es
# ✅ Validación automática: confidence debe estar entre 0.0-1.0
# ✅ Errores en desarrollo (type checker)
# ✅ Documentación automática con FastAPI
# ✅ Propiedades calculadas: result.enrichment_coverage
"""


# ============================================================================
# USO EN CÓDIGO REAL
# ============================================================================

"""
# ANTES: Sin autocompletado, sin validación

async def process_cve(cve_id: str):
    pipeline = get_nlp_pipeline()
    result = await pipeline.enrich_cve(cve_id, description)

    # ❌ KeyError posible si translation falló
    translated_text = result["translation"]["description_es"]

    # ❌ Sin validación de tipo
    confidence = result["translation"]["translation_confidence"]

    # ❌ Sin autocompletado
    if result["errors"]:  # IDE no sabe qué campos hay
        ...


# DESPUÉS: Autocompletado, validado, type-safe

async def process_cve(cve_id: str):
    pipeline = get_nlp_pipeline()
    result = await pipeline.enrich_cve(cve_id, description)

    # ✅ IDE autocompleta result.translation
    # ✅ Type checker detecta si translation es None
    if result.translation:
        translated_text = result.translation.description_es  # ✅ Autocompletado
        confidence = result.translation.confidence  # ✅ Tipo validado (float)

    # ✅ Propiedades calculadas
    if result.has_errors:
        logger.warning(f"Enrichment had errors: {result.errors}")

    coverage = result.enrichment_coverage  # ✅ Calculado automáticamente
    if coverage < 0.5:
        logger.warning(f"Low enrichment coverage: {coverage:.0%}")
"""
