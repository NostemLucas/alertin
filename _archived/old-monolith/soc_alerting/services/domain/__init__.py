"""
Domain Services

Pure business logic with no external dependencies (no DB, no APIs).
These services implement core domain rules and can be tested in isolation.
"""

from .severity_engine import (
    SeverityEngine,
    SeverityClassification,
    ClassificationSource,
)

__all__ = [
    "SeverityEngine",
    "SeverityClassification",
    "ClassificationSource",
]
