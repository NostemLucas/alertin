"""
CVE Sync Service - Compatibility layer.

This module provides backwards compatibility by re-exporting
the minimal service as the default.

For new code, import directly from cve_sync_service_minimal.py
"""

# Re-export minimal service as default
from .cve_sync_service_minimal import CVESyncServiceMinimal as CVESyncService

__all__ = ["CVESyncService"]
