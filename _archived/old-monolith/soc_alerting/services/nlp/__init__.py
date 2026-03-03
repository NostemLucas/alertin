"""
NLP enrichment modules for CVE analysis.

Provides advanced NLP capabilities including:
- Translation (EN → ES)
- Named Entity Recognition (NER)
- Keyword extraction
- Attack vector analysis
- CIA impact assessment
"""

from .pipeline import NLPEnrichmentPipeline, get_nlp_pipeline
from .translator import CVETranslator, get_translator
from .entity_extractor import CVEEntityExtractor, get_entity_extractor
from .keyword_extractor import CVEKeywordExtractor, get_keyword_extractor

__all__ = [
    # Pipeline
    "NLPEnrichmentPipeline",
    "get_nlp_pipeline",
    # Components
    "CVETranslator",
    "get_translator",
    "CVEEntityExtractor",
    "get_entity_extractor",
    "CVEKeywordExtractor",
    "get_keyword_extractor",
]
