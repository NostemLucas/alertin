"""
CISA KEV (Known Exploited Vulnerabilities) client.

Fetches CISA's catalog of known exploited vulnerabilities.
Data source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from pydantic import ValidationError
from cachetools import TTLCache

from .base_client import BaseAPIClient
from ..config.settings import get_settings
from ..models.cisa import CISAKEVCatalog, CISAVulnerability
from ..models.domain import CVE, SeverityLevel, ClassificationSource

logger = logging.getLogger(__name__)


class CISAClient(BaseAPIClient):
    """
    Client for CISA KEV catalog.

    Features:
    - Fetches CISA's Known Exploited Vulnerabilities catalog
    - In-memory caching with configurable TTL (default 1 hour)
    - CVE enrichment with CISA metadata
    - No rate limiting needed (single JSON file)
    """

    def __init__(self, cache_ttl: Optional[int] = None):
        """
        Initialize CISA KEV client.

        Args:
            cache_ttl: Cache time-to-live in seconds (defaults to settings)
        """
        settings = get_settings()

        # CISA KEV is just a static JSON file, no complex API
        super().__init__(
            base_url=settings.cisa_kev_url.rsplit('/', 1)[0],  # Extract base URL
            timeout=30.0,
        )

        self.kev_url = settings.cisa_kev_url
        self.cache_ttl = cache_ttl or settings.cisa_cache_ttl

        # Initialize cache (stores catalog by URL)
        # TTLCache automatically expires entries after cache_ttl seconds
        self._cache: TTLCache = TTLCache(maxsize=1, ttl=self.cache_ttl)

        logger.info(
            f"CISA KEV client initialized (cache TTL: {self.cache_ttl}s / "
            f"{self.cache_ttl / 3600:.1f}h)"
        )

    async def fetch_kev_catalog(
        self,
        force_refresh: bool = False,
    ) -> CISAKEVCatalog:
        """
        Fetch CISA KEV catalog.

        Uses in-memory cache to avoid repeated downloads. Cache automatically
        expires after TTL (default 1 hour).

        Args:
            force_refresh: Bypass cache and fetch fresh data

        Returns:
            CISA KEV catalog

        Raises:
            httpx.HTTPError: On request failure
            ValidationError: On parsing failure
        """
        cache_key = "kev_catalog"

        # Check cache
        if not force_refresh and cache_key in self._cache:
            logger.info("Using cached CISA KEV catalog")
            return self._cache[cache_key]

        # Fetch from API using BaseAPIClient's _request method
        # This gives us retries, timeout handling, and connection pooling
        logger.info(f"Fetching CISA KEV catalog from {self.kev_url}")

        try:
            # Use inherited _request method with full URL
            # (BaseAPIClient supports both relative and absolute URLs)
            response = await self._request("GET", self.kev_url)
            data = response.json()

            # Parse into Pydantic model
            catalog = CISAKEVCatalog(**data)

            logger.info(
                f"Fetched CISA KEV catalog: {len(catalog.vulnerabilities)} "
                f"known exploited vulnerabilities "
                f"(version: {catalog.catalogVersion}, "
                f"date: {catalog.dateReleased})"
            )

            # Cache the result
            self._cache[cache_key] = catalog

            return catalog

        except ValidationError as e:
            logger.error(f"Failed to parse CISA KEV catalog: {e}")
            raise

    async def is_cve_in_kev(self, cve_id: str) -> bool:
        """
        Check if a CVE is in the CISA KEV catalog.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-12345")

        Returns:
            True if CVE is in KEV, False otherwise
        """
        catalog = await self.fetch_kev_catalog()
        cve_ids = catalog.get_cve_ids()
        return cve_id in cve_ids

    async def get_kev_entry(self, cve_id: str) -> Optional[CISAVulnerability]:
        """
        Get CISA KEV entry for a specific CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            CISA vulnerability entry or None if not in KEV
        """
        catalog = await self.fetch_kev_catalog()

        for vuln in catalog.vulnerabilities:
            if vuln.cveID == cve_id:
                return vuln

        return None

    async def enrich_cve_with_kev_data(self, cve: CVE) -> CVE:
        """
        Enrich CVE domain model with CISA KEV data.

        If the CVE is in CISA KEV:
        - Sets is_in_cisa_kev = True
        - Adds CISA metadata (dateAdded, dueDate, requiredAction)
        - Updates classification_sources
        - final_severity will be automatically set to CRITICAL by Pydantic validator

        Args:
            cve: CVE domain model

        Returns:
            Enriched CVE (same object, modified in place)
        """
        kev_entry = await self.get_kev_entry(cve.cve_id)

        if kev_entry:
            logger.info(
                f"{cve.cve_id} found in CISA KEV "
                f"(added: {kev_entry.dateAdded}, action: {kev_entry.requiredAction[:50]}...)"
            )

            # Update CVE with CISA data
            cve.is_in_cisa_kev = True
            cve.cisa_exploit_add = kev_entry.dateAdded
            cve.cisa_action_due = kev_entry.dueDate
            cve.cisa_required_action = kev_entry.requiredAction

            # Add CISA to sources
            if ClassificationSource.CISA_KEV not in cve.classification_sources:
                cve.classification_sources.append(ClassificationSource.CISA_KEV)

            # Recalculate final severity (CRITICAL because in KEV)
            cve.final_severity = SeverityLevel.CRITICAL

            logger.info(
                f"{cve.cve_id} enriched with CISA KEV data: "
                f"severity changed to {cve.final_severity}"
            )
        else:
            logger.debug(f"{cve.cve_id} not in CISA KEV")

        return cve

    async def get_kev_statistics(self) -> dict:
        """
        Get statistics about CISA KEV catalog.

        Returns:
            Dictionary with statistics:
            - total_vulnerabilities: Total KEV entries
            - catalog_version: Catalog version
            - date_released: Release date
            - vendors: Number of unique vendors
            - products: Number of unique products
        """
        catalog = await self.fetch_kev_catalog()

        # Count unique vendors and products
        vendors = set(v.vendorProject for v in catalog.vulnerabilities)
        products = set(v.product for v in catalog.vulnerabilities)

        stats = {
            "total_vulnerabilities": len(catalog.vulnerabilities),
            "catalog_version": catalog.catalogVersion,
            "date_released": catalog.dateReleased,
            "unique_vendors": len(vendors),
            "unique_products": len(products),
        }

        logger.info(f"CISA KEV statistics: {stats}")
        return stats

    def clear_cache(self):
        """Clear the KEV catalog cache."""
        self._cache.clear()
        logger.info("CISA KEV cache cleared")
