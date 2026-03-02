"""
NIST NVD API 2.0 client.

Fetches CVE data from the National Vulnerability Database.
API Documentation: https://nvd.nist.gov/developers/vulnerabilities
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from pydantic import ValidationError

from .base_client import RateLimitedClient
from ..config.settings import get_settings
from ..models.nist import NISTAPIResponse, NISTVulnerability
from ..models.domain import CVE, SeverityLevel, ClassificationSource

logger = logging.getLogger(__name__)


class NISTClient(RateLimitedClient):
    """
    Client for NIST NVD API 2.0.

    Features:
    - Automatic rate limiting (6s delay for free tier, 0.6s with API key)
    - Retry with exponential backoff
    - Pagination support
    - Date range filtering
    - CVE-to-domain model conversion
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NIST NVD client.

        Args:
            api_key: NIST API key (optional but recommended)
                     Get one at: https://nvd.nist.gov/developers/request-an-api-key
        """
        settings = get_settings()

        # Determine rate limit based on API key
        # Free tier: 5 requests per 30 seconds = 6 seconds between requests
        # With API key: 50 requests per 30 seconds = 0.6 seconds between requests
        rate_limit_delay = 0.6 if api_key else settings.nist_rate_limit_delay

        super().__init__(
            base_url=settings.nist_api_base_url,
            rate_limit_delay=rate_limit_delay,
            timeout=60.0,  # NIST API can be slow
        )

        self.api_key = api_key or settings.nist_api_key

        if self.api_key:
            logger.info("NIST client initialized with API key (50 req/30s)")
        else:
            logger.warning(
                "NIST client initialized WITHOUT API key (5 req/30s). "
                "Consider getting one at: https://nvd.nist.gov/developers/request-an-api-key"
            )

    def _get_headers(self) -> dict[str, str]:
        """
        Get HTTP headers including API key if available.

        Returns:
            Headers dict
        """
        headers = {
            "Accept": "application/json",
            "User-Agent": "SOC-Alerting-System/1.0",
        }

        if self.api_key and self.api_key != "your_api_key_here":
            headers["apiKey"] = self.api_key

        return headers

    @staticmethod
    def _format_datetime(dt: datetime) -> str:
        """
        Format datetime for NIST API.

        NIST requires ISO 8601 format: YYYY-MM-DDTHH:MM:SS.000
        Timezone must be UTC (indicated by .000 suffix or Z)

        Args:
            dt: Datetime to format

        Returns:
            ISO 8601 formatted string
        """
        # Ensure UTC
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)  # Remove timezone info for formatting

        # Format with milliseconds
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000")

    async def fetch_cves_by_modified_date(
        self,
        start_date: datetime,
        end_date: Optional[datetime] = None,
        results_per_page: int = 2000,
        max_results: Optional[int] = None,
    ) -> list[NISTVulnerability]:
        """
        Fetch CVEs modified within a date range.

        This is the primary method for incremental updates - fetches only
        CVEs that were modified within the specified time window.

        Args:
            start_date: Start of modification date range (UTC)
            end_date: End of modification date range (UTC). Defaults to now.
            results_per_page: Results per page (max 2000)
            max_results: Maximum total results to fetch (None = all)

        Returns:
            List of NIST vulnerability objects

        Raises:
            httpx.HTTPError: On API request failure
            ValidationError: On response parsing failure
        """
        if end_date is None:
            end_date = datetime.utcnow()

        logger.info(
            f"Fetching CVEs modified between {start_date} and {end_date}"
        )

        params = {
            "lastModStartDate": self._format_datetime(start_date),
            "lastModEndDate": self._format_datetime(end_date),
            "resultsPerPage": min(results_per_page, 2000),  # API max is 2000
            "startIndex": 0,
        }

        return await self._fetch_paginated(params, max_results)

    async def fetch_cves_by_published_date(
        self,
        start_date: datetime,
        end_date: Optional[datetime] = None,
        results_per_page: int = 2000,
        max_results: Optional[int] = None,
    ) -> list[NISTVulnerability]:
        """
        Fetch CVEs published within a date range.

        Use this for initial database population or historical analysis.
        For incremental updates, use fetch_cves_by_modified_date instead.

        Args:
            start_date: Start of publication date range (UTC)
            end_date: End of publication date range (UTC). Defaults to now.
            results_per_page: Results per page (max 2000)
            max_results: Maximum total results to fetch (None = all)

        Returns:
            List of NIST vulnerability objects
        """
        if end_date is None:
            end_date = datetime.utcnow()

        logger.info(
            f"Fetching CVEs published between {start_date} and {end_date}"
        )

        params = {
            "pubStartDate": self._format_datetime(start_date),
            "pubEndDate": self._format_datetime(end_date),
            "resultsPerPage": min(results_per_page, 2000),
            "startIndex": 0,
        }

        return await self._fetch_paginated(params, max_results)

    async def fetch_cve_by_id(self, cve_id: str) -> Optional[NISTVulnerability]:
        """
        Fetch a single CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-12345")

        Returns:
            NIST vulnerability object or None if not found
        """
        logger.info(f"Fetching CVE: {cve_id}")

        try:
            params = {"cveId": cve_id}
            response_data = await self.get("", params=params, headers=self._get_headers())

            # Parse response
            api_response = NISTAPIResponse(**response_data)

            if api_response.totalResults == 0:
                logger.warning(f"CVE not found: {cve_id}")
                return None

            # Extract CVE object from VulnerabilityItem wrapper
            cve_objects = api_response.get_cve_objects()
            if cve_objects:
                return cve_objects[0]

            return None

        except ValidationError as e:
            logger.error(f"Failed to parse CVE {cve_id}: {e}")
            raise

    async def _fetch_paginated(
        self,
        base_params: dict,
        max_results: Optional[int] = None,
    ) -> list[NISTVulnerability]:
        """
        Fetch paginated results from NIST API.

        Handles pagination automatically, fetching all pages until:
        - All results are retrieved
        - max_results limit is reached
        - An error occurs

        Args:
            base_params: Base query parameters (will add pagination params)
            max_results: Maximum results to fetch (None = all)

        Returns:
            List of all fetched vulnerabilities
        """
        all_vulnerabilities = []
        start_index = 0
        results_per_page = base_params.get("resultsPerPage", 2000)

        while True:
            # Update pagination params
            params = {**base_params, "startIndex": start_index}

            try:
                # Make request
                response_data = await self.get("", params=params, headers=self._get_headers())

                # Parse response
                api_response = NISTAPIResponse(**response_data)

                # Extract CVE objects from VulnerabilityItem wrappers
                cve_objects = api_response.get_cve_objects()

                logger.info(
                    f"Fetched page: {len(cve_objects)} results "
                    f"(total available: {api_response.totalResults}, "
                    f"fetched so far: {len(all_vulnerabilities)})"
                )

                # Add to results
                all_vulnerabilities.extend(cve_objects)

                # Check stopping conditions
                if max_results and len(all_vulnerabilities) >= max_results:
                    logger.info(f"Reached max_results limit: {max_results}")
                    return all_vulnerabilities[:max_results]

                if len(cve_objects) < results_per_page:
                    # Last page (partial results)
                    logger.info("Reached last page")
                    break

                if len(all_vulnerabilities) >= api_response.totalResults:
                    # Got all results
                    logger.info("Fetched all available results")
                    break

                # Move to next page
                start_index += results_per_page

            except ValidationError as e:
                logger.error(f"Failed to parse NIST response at index {start_index}: {e}")
                raise
            except Exception as e:
                logger.error(f"Error fetching page at index {start_index}: {e}")
                raise

        logger.info(f"Total CVEs fetched: {len(all_vulnerabilities)}")
        return all_vulnerabilities

    def convert_to_domain_model(
        self,
        nist_vuln: NISTVulnerability,
        is_in_cisa_kev: bool = False,
    ) -> CVE:
        """
        Convert NIST vulnerability to domain CVE model.

        Extracts key fields and calculates NIST severity based on CVSS score.

        Args:
            nist_vuln: NIST vulnerability object
            is_in_cisa_kev: Whether CVE is in CISA KEV catalog

        Returns:
            Domain CVE model
        """
        # Get CVSS data
        cvss_score = nist_vuln.get_primary_cvss_v3()
        cvss_vector = nist_vuln.get_primary_cvss_v3_vector()

        # Calculate NIST severity from CVSS score
        severity_nist = self._cvss_to_severity(cvss_score)

        # Calculate final severity (CISA KEV override)
        if is_in_cisa_kev:
            final_severity = SeverityLevel.CRITICAL
        else:
            final_severity = severity_nist

        # Create domain model
        cve = CVE(
            cve_id=nist_vuln.id,
            description=nist_vuln.get_english_description(),
            published_date=nist_vuln.published,
            last_modified_date=nist_vuln.lastModified,
            cvss_v3_score=cvss_score,
            cvss_v3_vector=cvss_vector,
            severity_nist=severity_nist,
            is_in_cisa_kev=is_in_cisa_kev,
            final_severity=final_severity,
            classification_sources=[ClassificationSource.NIST_CVSS],
            source_identifier=nist_vuln.sourceIdentifier,
            vuln_status=nist_vuln.vulnStatus,
            references=nist_vuln.get_reference_urls(),
            # CISA fields will be added by CISA client if applicable
            cisa_exploit_add=None,
            cisa_action_due=None,
            cisa_required_action=None,
        )

        logger.debug(
            f"Converted {cve.cve_id}: "
            f"CVSS={cvss_score}, severity={severity_nist}, "
            f"in_kev={is_in_cisa_kev}, final={cve.final_severity}"
        )

        return cve

    @staticmethod
    def _cvss_to_severity(cvss_score: Optional[float]) -> SeverityLevel:
        """
        Convert CVSS score to severity level.

        CVSS v3 ranges:
        - None: 0.0
        - Low: 0.1-3.9
        - Medium: 4.0-6.9
        - High: 7.0-8.9
        - Critical: 9.0-10.0

        Args:
            cvss_score: CVSS v3 base score (0-10)

        Returns:
            Severity level
        """
        if cvss_score is None or cvss_score == 0.0:
            return SeverityLevel.NONE

        if cvss_score < 4.0:
            return SeverityLevel.LOW
        elif cvss_score < 7.0:
            return SeverityLevel.MEDIUM
        elif cvss_score < 9.0:
            return SeverityLevel.HIGH
        else:
            return SeverityLevel.CRITICAL
