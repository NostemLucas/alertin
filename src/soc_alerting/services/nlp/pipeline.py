"""
NLP Enrichment Pipeline for CVE processing.

Coordinates all NLP components to provide comprehensive CVE enrichment:
1. Translation (EN → ES)
2. Entity extraction (NER)
3. Keyword extraction
4. Attack analysis
"""

import logging
from typing import Optional
from datetime import datetime

from .translator import get_translator, CVETranslator
from .entity_extractor import get_entity_extractor, CVEEntityExtractor
from .keyword_extractor import get_keyword_extractor, CVEKeywordExtractor

logger = logging.getLogger(__name__)


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

    def enrich_cve(
        self,
        cve_id: str,
        description_en: str,
        min_confidence: float = 0.5
    ) -> dict[str, any]:
        """
        Perform complete NLP enrichment on a CVE description.

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-12345)
            description_en: English CVE description
            min_confidence: Minimum confidence threshold for NER

        Returns:
            Dictionary with all enrichment results:
                - cve_id: CVE identifier
                - enriched_at: Timestamp
                - translation: Translation results (if enabled)
                - entities: Extracted entities (if enabled)
                - keywords: Extracted keywords (if enabled)
                - attack_analysis: Attack type and characteristics
                - cia_impact: Confidentiality, Integrity, Availability impact
                - processing_time_ms: Total processing time

        Example:
            >>> pipeline = NLPEnrichmentPipeline()
            >>> result = pipeline.enrich_cve(
            ...     "CVE-2021-44228",
            ...     "Apache Log4j2 JNDI features do not protect..."
            ... )
            >>> print(result["translation"]["translated_text"])
            "Las funcionalidades JNDI de Apache Log4j2 no protegen..."
        """
        start_time = datetime.utcnow()

        logger.info(f"Starting NLP enrichment for {cve_id}")

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

        # 1. Translation (EN → ES)
        if self.enable_translation:
            try:
                logger.debug(f"{cve_id}: Starting translation")
                translation_result = self.translator.translate_cve(description_en)
                result["translation"] = {
                    "description_es": translation_result["translated_text"],
                    "translation_confidence": translation_result["confidence"],
                    "translation_model": self.translation_model
                }
                logger.debug(
                    f"{cve_id}: Translation completed "
                    f"(confidence: {translation_result['confidence']:.2f})"
                )
            except Exception as e:
                logger.error(f"{cve_id}: Translation failed: {e}", exc_info=True)
                result["errors"].append(f"Translation error: {str(e)}")

        # 2. Entity Extraction (NER)
        if self.enable_ner:
            try:
                logger.debug(f"{cve_id}: Starting entity extraction")
                entities = self.entity_extractor.extract_entities(
                    description_en,
                    min_confidence=min_confidence
                )

                # Also extract affected products
                affected_products = self.entity_extractor.extract_affected_products(
                    description_en
                )

                result["entities"] = {
                    "organizations": entities["organizations"],
                    "versions": entities["versions"],
                    "cve_references": entities["cve_references"],
                    "urls": entities["urls"],
                    "technical_terms": entities["technical_terms"],
                    "affected_products_ner": affected_products,
                    "entity_count": entities["entity_counts"]["total"],
                    "ner_model": self.ner_model
                }
                logger.debug(
                    f"{cve_id}: Entity extraction completed "
                    f"({entities['entity_counts']['total']} entities)"
                )
            except Exception as e:
                logger.error(f"{cve_id}: Entity extraction failed: {e}", exc_info=True)
                result["errors"].append(f"Entity extraction error: {str(e)}")

        # 3. Keyword Extraction
        if self.enable_keywords:
            try:
                logger.debug(f"{cve_id}: Starting keyword extraction")
                keywords = self.keyword_extractor.extract_keywords(description_en)

                result["keywords"] = {
                    "attack_vectors": keywords["attack_vectors"],
                    "technical_protocols": keywords["technical_protocols"],
                    "programming_concepts": keywords["programming_concepts"],
                    "vulnerability_types": keywords["vulnerability_types"],
                    "all_keywords": keywords["all_keywords"][:10],  # Top 10
                    "keyword_count": keywords["keyword_count"]
                }
                logger.debug(
                    f"{cve_id}: Keyword extraction completed "
                    f"({keywords['keyword_count']} keywords)"
                )
            except Exception as e:
                logger.error(f"{cve_id}: Keyword extraction failed: {e}", exc_info=True)
                result["errors"].append(f"Keyword extraction error: {str(e)}")

        # 4. Attack Analysis
        if self.enable_keywords:
            try:
                logger.debug(f"{cve_id}: Starting attack analysis")
                attack_info = self.keyword_extractor.identify_attack_type(description_en)

                result["attack_analysis"] = {
                    "attack_type": attack_info["primary_attack_type"],
                    "secondary_attack_types": attack_info["secondary_types"],
                    "attack_complexity": attack_info["attack_complexity"],
                    "requires_authentication": attack_info["requires_authentication"],
                    "network_accessible": attack_info["network_accessible"],
                    "analysis_confidence": attack_info["confidence"]
                }
                logger.debug(
                    f"{cve_id}: Attack analysis completed "
                    f"(type: {attack_info['primary_attack_type']})"
                )
            except Exception as e:
                logger.error(f"{cve_id}: Attack analysis failed: {e}", exc_info=True)
                result["errors"].append(f"Attack analysis error: {str(e)}")

        # 5. CIA Impact Assessment
        if self.enable_keywords:
            try:
                logger.debug(f"{cve_id}: Starting CIA impact assessment")
                cia_impact = self.keyword_extractor.extract_cia_impact(description_en)

                result["cia_impact"] = cia_impact
                logger.debug(
                    f"{cve_id}: CIA impact completed "
                    f"(C:{cia_impact['confidentiality']}, "
                    f"I:{cia_impact['integrity']}, "
                    f"A:{cia_impact['availability']})"
                )
            except Exception as e:
                logger.error(f"{cve_id}: CIA impact assessment failed: {e}", exc_info=True)
                result["errors"].append(f"CIA impact error: {str(e)}")

        # Calculate total processing time
        end_time = datetime.utcnow()
        processing_time_ms = int((end_time - start_time).total_seconds() * 1000)
        result["processing_time_ms"] = processing_time_ms

        logger.info(
            f"{cve_id}: NLP enrichment completed in {processing_time_ms}ms "
            f"({len(result['errors'])} errors)"
        )

        return result

    def batch_enrich(
        self,
        cves: list[tuple[str, str]],
        min_confidence: float = 0.5
    ) -> list[dict[str, any]]:
        """
        Enrich multiple CVEs in batch.

        Args:
            cves: List of (cve_id, description) tuples
            min_confidence: Minimum confidence threshold

        Returns:
            List of enrichment result dictionaries
        """
        results = []

        logger.info(f"Starting batch enrichment for {len(cves)} CVEs")

        for cve_id, description in cves:
            try:
                result = self.enrich_cve(cve_id, description, min_confidence)
                results.append(result)
            except Exception as e:
                logger.error(f"Batch enrichment failed for {cve_id}: {e}", exc_info=True)
                results.append({
                    "cve_id": cve_id,
                    "enriched_at": datetime.utcnow().isoformat(),
                    "errors": [f"Enrichment failed: {str(e)}"]
                })

        logger.info(f"Batch enrichment completed: {len(results)} CVEs processed")

        return results

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
