"""
Named Entity Recognition (NER) for CVE descriptions.

Extracts technical entities from CVE descriptions including:
- Product names (software, libraries, frameworks)
- Version numbers
- Organizations (vendors)
- Technical terms and protocols

IMPORTANT: Uses run_in_executor to avoid blocking the event loop.
"""

import logging
import re
import asyncio
from typing import Optional
from concurrent.futures import ThreadPoolExecutor
from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline
import torch

logger = logging.getLogger(__name__)

# Thread pool for NER tasks
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="nlp_ner")


class CVEEntityExtractor:
    """
    Extracts named entities from CVE descriptions.

    Uses dslim/bert-base-NER for general entity recognition combined with
    custom regex patterns for CVE-specific entities (versions, CVE IDs, etc.).
    """

    def __init__(
        self,
        model_name: str = "dslim/bert-base-NER",
        device: str = "cpu",
        aggregation_strategy: str = "simple"
    ):
        """
        Initialize NER extractor.

        Args:
            model_name: HuggingFace NER model
            device: 'cpu' or 'cuda'
            aggregation_strategy: How to merge subword tokens ('simple', 'first', 'average', 'max')
        """
        self.model_name = model_name
        self.device = device if device == "cuda" and torch.cuda.is_available() else "cpu"
        self.aggregation_strategy = aggregation_strategy
        self._pipeline: Optional[pipeline] = None

        # Custom regex patterns for CVE-specific entities
        self.patterns = {
            "version": re.compile(
                r'\b\d+\.\d+(?:\.\d+)*(?:-(?:alpha|beta|rc|dev)\d*)?\b',
                re.IGNORECASE
            ),
            "cve_id": re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE),
            "cvss_score": re.compile(r'\b(?:CVSS|cvss)\s*(?:v[23])?\s*:\s*(\d+(?:\.\d+)?)\b'),
            "port_number": re.compile(r'\b(?:port|PORT)\s+(\d{1,5})\b'),
            "ip_address": re.compile(
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ),
            "url": re.compile(
                r'https?://[^\s<>"{}|\\^`\[\]]+',
                re.IGNORECASE
            ),
        }

        logger.info(f"CVEEntityExtractor initialized (model: {model_name}, device: {self.device})")

    def _lazy_load_model(self):
        """Lazy load NER model on first use."""
        if self._pipeline is None:
            logger.info(f"Loading NER model: {self.model_name}")
            try:
                tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                model = AutoModelForTokenClassification.from_pretrained(self.model_name)

                self._pipeline = pipeline(
                    "ner",
                    model=model,
                    tokenizer=tokenizer,
                    aggregation_strategy=self.aggregation_strategy,
                    device=0 if self.device == "cuda" else -1
                )

                logger.info(f"NER model loaded on {self.device}")

            except Exception as e:
                logger.error(f"Failed to load NER model: {e}", exc_info=True)
                raise

    def _extract_entities_sync(self, text: str, min_confidence: float = 0.5) -> dict[str, any]:
        """
        Extract entities from text using both NER model and regex patterns (synchronous).

        Args:
            text: Text to analyze
            min_confidence: Minimum confidence threshold for NER entities

        Returns:
            Dictionary with extracted entities

        Note:
            This is the synchronous version. Use extract_entities() for async calls.
        """
        if not text or not text.strip():
            return self._empty_result()

        # Lazy load model
        self._lazy_load_model()

        try:
            # 1. Extract entities using NER model
            ner_entities = self._pipeline(text)

            # 2. Extract entities using regex patterns
            pattern_entities = self._extract_with_patterns(text)

            # 3. Categorize and merge entities
            categorized = self._categorize_entities(ner_entities, pattern_entities, min_confidence)

            # 4. Add entity counts
            categorized["entity_counts"] = {
                "organizations": len(categorized["organizations"]),
                "products": len(categorized["products"]),
                "versions": len(categorized["versions"]),
                "cve_references": len(categorized["cve_references"]),
                "technical_terms": len(categorized["technical_terms"]),
                "total": len(categorized["all_entities"])
            }

            logger.debug(f"Extracted {categorized['entity_counts']['total']} entities from text")

            return categorized

        except Exception as e:
            logger.error(f"Entity extraction failed: {e}", exc_info=True)
            return {**self._empty_result(), "error": str(e)}

    async def extract_entities(self, text: str, min_confidence: float = 0.5) -> dict[str, any]:
        """
        Extract entities from text asynchronously (non-blocking).

        Runs entity extraction in executor to avoid blocking the event loop.

        Args:
            text: Text to analyze
            min_confidence: Minimum confidence threshold for NER entities

        Returns:
            Dictionary with extracted entities:
                - organizations: List of org names (vendors, companies)
                - products: List of software/product names
                - persons: List of person names (usually empty for CVEs)
                - locations: List of locations
                - versions: List of version numbers
                - cve_references: List of mentioned CVE IDs
                - technical_terms: List of technical keywords
                - urls: List of URLs
                - all_entities: Complete list with metadata

        Example:
            >>> extractor = CVEEntityExtractor()
            >>> result = await extractor.extract_entities(
            ...     "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features"
            ... )
            >>> print(result["products"])
            ["Apache Log4j2"]
            >>> print(result["versions"])
            ["2.0", "2.15.0"]

        Note:
            This method is safe to call from FastAPI endpoints as it won't
            block the event loop during model inference.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _executor,
            self._extract_entities_sync,
            text,
            min_confidence
        )

    def _extract_with_patterns(self, text: str) -> dict[str, list]:
        """
        Extract entities using regex patterns.

        Args:
            text: Text to analyze

        Returns:
            Dictionary with pattern-matched entities
        """
        results = {}

        for entity_type, pattern in self.patterns.items():
            matches = pattern.findall(text)
            # Remove duplicates while preserving order
            results[entity_type] = list(dict.fromkeys(matches))

        return results

    def _categorize_entities(
        self,
        ner_entities: list[dict],
        pattern_entities: dict[str, list],
        min_confidence: float
    ) -> dict[str, list]:
        """
        Categorize and merge entities from NER and patterns.

        Args:
            ner_entities: Entities from NER model
            pattern_entities: Entities from regex patterns
            min_confidence: Minimum confidence threshold

        Returns:
            Categorized entities dictionary
        """
        result = {
            "organizations": [],
            "products": [],
            "persons": [],
            "locations": [],
            "versions": pattern_entities.get("version", []),
            "cve_references": pattern_entities.get("cve_id", []),
            "urls": pattern_entities.get("url", []),
            "technical_terms": [],
            "all_entities": []
        }

        # Process NER entities
        for entity in ner_entities:
            if entity["score"] < min_confidence:
                continue

            entity_type = entity["entity_group"]
            text = entity["word"].strip()

            # Map BERT NER labels to our categories
            if entity_type == "ORG":
                result["organizations"].append(text)
            elif entity_type == "PER":
                result["persons"].append(text)
            elif entity_type == "LOC":
                result["locations"].append(text)
            elif entity_type == "MISC":
                # MISC often contains product names and technical terms
                result["technical_terms"].append(text)

            # Add to all_entities with metadata
            result["all_entities"].append({
                "text": text,
                "type": entity_type,
                "confidence": round(entity["score"], 3),
                "start": entity["start"],
                "end": entity["end"],
                "source": "ner_model"
            })

        # Add pattern entities to all_entities
        for entity_type, entities in pattern_entities.items():
            for text in entities:
                result["all_entities"].append({
                    "text": text,
                    "type": entity_type,
                    "confidence": 1.0,  # Regex matches have full confidence
                    "source": "regex_pattern"
                })

        # Remove duplicates
        for key in ["organizations", "products", "persons", "locations", "technical_terms"]:
            result[key] = list(dict.fromkeys(result[key]))  # Preserve order

        return result

    async def extract_affected_products(self, text: str) -> list[dict[str, any]]:
        """
        Extract affected products with version information (async).

        Combines organization names, product hints, and versions to identify
        affected software products.

        Args:
            text: CVE description text

        Returns:
            List of dictionaries:
                - name: Product name
                - vendor: Vendor/organization (if identified)
                - versions: List of affected versions
                - confidence: Confidence score

        Example:
            >>> extractor = CVEEntityExtractor()
            >>> products = await extractor.extract_affected_products(
            ...     "Apache Log4j2 2.0-beta9 through 2.15.0"
            ... )
            >>> print(products[0])
            {
                "name": "Apache Log4j2",
                "vendor": "Apache",
                "versions": ["2.0-beta9", "2.15.0"],
                "confidence": 0.85
            }
        """
        entities = await self.extract_entities(text)

        products = []

        # Try to match organizations with nearby product names
        orgs = entities["organizations"]
        versions = entities["versions"]
        tech_terms = entities["technical_terms"]

        # Heuristic: if org name appears before version numbers, it's likely a product
        for org in orgs:
            product_entry = {
                "name": org,
                "vendor": org,
                "versions": versions if versions else [],
                "confidence": 0.7
            }
            products.append(product_entry)

        # Add technical terms that look like product names
        for term in tech_terms:
            # Simple heuristic: capitalized terms near version numbers
            if term[0].isupper() and any(char.isdigit() for char in text):
                product_entry = {
                    "name": term,
                    "vendor": None,
                    "versions": versions if versions else [],
                    "confidence": 0.6
                }
                products.append(product_entry)

        logger.debug(f"Extracted {len(products)} affected products")
        return products

    def _empty_result(self) -> dict[str, list]:
        """Return empty result structure."""
        return {
            "organizations": [],
            "products": [],
            "persons": [],
            "locations": [],
            "versions": [],
            "cve_references": [],
            "urls": [],
            "technical_terms": [],
            "all_entities": [],
            "entity_counts": {
                "organizations": 0,
                "products": 0,
                "versions": 0,
                "cve_references": 0,
                "technical_terms": 0,
                "total": 0
            }
        }

    def unload_model(self):
        """Unload model from memory."""
        if self._pipeline is not None:
            del self._pipeline
            self._pipeline = None

            if torch.cuda.is_available():
                torch.cuda.empty_cache()

            logger.info("NER model unloaded from memory")


# Singleton instance
_extractor_instance: Optional[CVEEntityExtractor] = None


def get_entity_extractor(
    model_name: str = "dslim/bert-base-NER",
    device: str = "cpu"
) -> CVEEntityExtractor:
    """
    Get singleton entity extractor instance.

    Args:
        model_name: HuggingFace NER model
        device: 'cpu' or 'cuda'

    Returns:
        CVEEntityExtractor instance
    """
    global _extractor_instance

    if _extractor_instance is None:
        _extractor_instance = CVEEntityExtractor(model_name=model_name, device=device)

    return _extractor_instance
