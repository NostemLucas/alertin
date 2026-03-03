"""
Domain Service: Severity Classification Engine

Pure business logic for CVE severity classification.
No database access, no API calls - only domain rules.

This centralizes the scattered severity logic that was previously split across:
- NISTClient.parse() → initial severity
- CVEProcessor → CISA override
- CVERepository → final save

Now: ONE place, ONE source of truth.
"""

from dataclasses import dataclass
from typing import Optional
from datetime import datetime
from enum import Enum

from ...models.domain import SeverityLevel


class ClassificationSource(str, Enum):
    """Source of severity classification."""
    NIST = "NIST"
    CISA_KEV = "CISA_KEV"
    CVSS_SCORE = "CVSS_SCORE"
    NLP_PREDICTION = "NLP_PREDICTION"


@dataclass(frozen=True)
class SeverityClassification:
    """
    Result of severity classification with audit trail.

    Immutable dataclass that explains HOW and WHY a severity was assigned.
    """
    final_severity: SeverityLevel
    classification_reason: str
    override_applied: bool
    sources: list[ClassificationSource]
    cvss_score: Optional[float] = None
    cisa_date_added: Optional[datetime] = None

    def __post_init__(self):
        """Validate invariants."""
        if not self.sources:
            raise ValueError("At least one classification source is required")

        if self.override_applied and ClassificationSource.CISA_KEV not in self.sources:
            raise ValueError("Override flag requires CISA_KEV source")

    @property
    def is_critical(self) -> bool:
        """Check if severity is CRITICAL."""
        return self.final_severity == SeverityLevel.CRITICAL

    @property
    def is_high_or_critical(self) -> bool:
        """Check if severity is HIGH or CRITICAL."""
        return self.final_severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)

    @property
    def needs_immediate_attention(self) -> bool:
        """
        Determine if CVE needs immediate attention.

        Returns True if:
        - In CISA KEV (actively exploited)
        - CVSS >= 9.0
        """
        if ClassificationSource.CISA_KEV in self.sources:
            return True

        if self.cvss_score and self.cvss_score >= 9.0:
            return True

        return False


class SeverityEngine:
    """
    Pure domain service for CVE severity classification.

    This is a stateless, side-effect-free service that implements
    business rules for severity determination.

    Design principles:
    - Pure functions (no I/O, no mutations)
    - Single Responsibility (only classification logic)
    - Testable without mocks
    - Auditable results (includes reasoning)
    """

    # Classification thresholds
    CRITICAL_CVSS_THRESHOLD = 9.0
    HIGH_CVSS_THRESHOLD = 7.0
    MEDIUM_CVSS_THRESHOLD = 4.0

    @classmethod
    def classify(
        cls,
        cvss_score: Optional[float] = None,
        nist_severity: Optional[SeverityLevel] = None,
        is_in_cisa_kev: bool = False,
        cisa_date_added: Optional[datetime] = None,
        nlp_predicted_severity: Optional[SeverityLevel] = None
    ) -> SeverityClassification:
        """
        Classify CVE severity using multiple sources with priority order.

        Priority order (highest to lowest):
        1. CISA KEV catalog (actively exploited) → CRITICAL
        2. CVSS score >= 9.0 → CRITICAL
        3. CVSS score >= 7.0 → HIGH
        4. NIST severity (from NVD)
        5. NLP prediction (fallback)

        Args:
            cvss_score: CVSS v3 base score (0.0-10.0)
            nist_severity: NIST/NVD severity rating
            is_in_cisa_kev: Whether CVE is in CISA KEV catalog
            cisa_date_added: When CVE was added to KEV
            nlp_predicted_severity: ML-predicted severity (optional)

        Returns:
            SeverityClassification with reasoning

        Examples:
            >>> # CISA KEV override
            >>> result = SeverityEngine.classify(
            ...     cvss_score=7.5,
            ...     nist_severity=SeverityLevel.HIGH,
            ...     is_in_cisa_kev=True
            ... )
            >>> result.final_severity
            SeverityLevel.CRITICAL
            >>> result.override_applied
            True

            >>> # CVSS-based
            >>> result = SeverityEngine.classify(cvss_score=9.8)
            >>> result.final_severity
            SeverityLevel.CRITICAL
        """
        sources = []

        # Rule 1: CISA KEV Override (highest priority)
        if is_in_cisa_kev:
            sources.append(ClassificationSource.CISA_KEV)

            date_info = ""
            if cisa_date_added:
                date_info = f" (added {cisa_date_added.strftime('%Y-%m-%d')})"

            return SeverityClassification(
                final_severity=SeverityLevel.CRITICAL,
                classification_reason=(
                    f"CVE is in CISA KEV catalog - actively exploited in the wild{date_info}"
                ),
                override_applied=True,
                sources=sources,
                cvss_score=cvss_score,
                cisa_date_added=cisa_date_added
            )

        # Rule 2: CVSS Score-based Classification
        if cvss_score is not None:
            sources.append(ClassificationSource.CVSS_SCORE)

            if cvss_score >= cls.CRITICAL_CVSS_THRESHOLD:
                return SeverityClassification(
                    final_severity=SeverityLevel.CRITICAL,
                    classification_reason=(
                        f"CVSS score {cvss_score} >= {cls.CRITICAL_CVSS_THRESHOLD} (CRITICAL threshold)"
                    ),
                    override_applied=False,
                    sources=sources,
                    cvss_score=cvss_score
                )

            if cvss_score >= cls.HIGH_CVSS_THRESHOLD:
                return SeverityClassification(
                    final_severity=SeverityLevel.HIGH,
                    classification_reason=(
                        f"CVSS score {cvss_score} >= {cls.HIGH_CVSS_THRESHOLD} (HIGH threshold)"
                    ),
                    override_applied=False,
                    sources=sources,
                    cvss_score=cvss_score
                )

            if cvss_score >= cls.MEDIUM_CVSS_THRESHOLD:
                return SeverityClassification(
                    final_severity=SeverityLevel.MEDIUM,
                    classification_reason=(
                        f"CVSS score {cvss_score} >= {cls.MEDIUM_CVSS_THRESHOLD} (MEDIUM threshold)"
                    ),
                    override_applied=False,
                    sources=sources,
                    cvss_score=cvss_score
                )

            # CVSS < 4.0 → LOW
            return SeverityClassification(
                final_severity=SeverityLevel.LOW,
                classification_reason=f"CVSS score {cvss_score} < {cls.MEDIUM_CVSS_THRESHOLD}",
                override_applied=False,
                sources=sources,
                cvss_score=cvss_score
            )

        # Rule 3: NIST Severity (from NVD metadata)
        if nist_severity is not None:
            sources.append(ClassificationSource.NIST)

            return SeverityClassification(
                final_severity=nist_severity,
                classification_reason="NIST/NVD severity rating",
                override_applied=False,
                sources=sources
            )

        # Rule 4: NLP Prediction (fallback)
        if nlp_predicted_severity is not None:
            sources.append(ClassificationSource.NLP_PREDICTION)

            return SeverityClassification(
                final_severity=nlp_predicted_severity,
                classification_reason="ML-predicted severity (no CVSS or NIST data available)",
                override_applied=False,
                sources=sources
            )

        # Rule 5: No data available → NONE
        return SeverityClassification(
            final_severity=SeverityLevel.NONE,
            classification_reason="No severity data available from any source",
            override_applied=False,
            sources=[]
        )

    @classmethod
    def should_prioritize(cls, classification: SeverityClassification) -> bool:
        """
        Determine if CVE should be prioritized for response.

        Prioritization criteria:
        - In CISA KEV (actively exploited)
        - CRITICAL severity with high CVSS
        - HIGH severity in CISA KEV

        Args:
            classification: SeverityClassification result

        Returns:
            True if CVE should be prioritized
        """
        # Always prioritize CISA KEV
        if ClassificationSource.CISA_KEV in classification.sources:
            return True

        # CRITICAL with CVSS >= 9.0
        if (classification.is_critical and
            classification.cvss_score and
            classification.cvss_score >= cls.CRITICAL_CVSS_THRESHOLD):
            return True

        return False

    @classmethod
    def get_priority_score(cls, classification: SeverityClassification) -> int:
        """
        Calculate numeric priority score for sorting.

        Higher score = higher priority

        Score calculation:
        - CISA KEV: +1000
        - CRITICAL: +100
        - HIGH: +50
        - CVSS score: +10 per point above 7.0

        Args:
            classification: SeverityClassification result

        Returns:
            Priority score (0-1100+)
        """
        score = 0

        # CISA KEV bonus
        if ClassificationSource.CISA_KEV in classification.sources:
            score += 1000

        # Severity bonus
        if classification.is_critical:
            score += 100
        elif classification.final_severity == SeverityLevel.HIGH:
            score += 50
        elif classification.final_severity == SeverityLevel.MEDIUM:
            score += 20

        # CVSS bonus (above 7.0)
        if classification.cvss_score and classification.cvss_score >= 7.0:
            score += int((classification.cvss_score - 7.0) * 10)

        return score
