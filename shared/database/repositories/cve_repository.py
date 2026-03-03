"""
CVE Repository - Compatibility layer.

This module provides backwards compatibility by re-exporting
the minimal repository as the default.

For new code, import directly from cve_repository_minimal.py
"""

# Re-export minimal repository as default
from .cve_repository_minimal import CVERepositoryMinimal as CVERepository

__all__ = ["CVERepository"]
