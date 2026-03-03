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
from ..models.domain_minimal import (
    CVEMinimal,
    SeverityLevel as SeverityLevelMinimal,
    AttackVector,
    AttackComplexity,
    cvss_score_to_severity,
    parse_cvss_vector,
    parse_cpe_to_simple_product,
)

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

    def convert_to_minimal_domain_model(
        self,
        nist_vuln: NISTVulnerability,
        is_in_cisa_kev: bool = False,
    ) -> CVEMinimal:
        """
        Convert NIST vulnerability to MINIMAL domain CVE model.

        Extracts 17 critical fields including:
        - CWE ID
        - CVSS vector components (attack_vector, attack_complexity, etc.)
        - Simplified affected products
        - Primary reference

        Args:
            nist_vuln: NIST vulnerability object
            is_in_cisa_kev: Whether CVE is in CISA KEV catalog

        Returns:
            Minimal CVE domain model
        """
        # Get CVSS data
        cvss_score = nist_vuln.get_primary_cvss_v3()
        cvss_vector = nist_vuln.get_primary_cvss_v3_vector()

        # Calculate severity from CVSS score
        severity = cvss_score_to_severity(cvss_score)

        # Extract CWE ID (primary only)
        cwe_ids = nist_vuln.get_cwe_ids()
        cwe_id = cwe_ids[0] if cwe_ids else None

        # Parse CVSS vector to extract attack characteristics
        vector_components = parse_cvss_vector(cvss_vector)

        # Map attack vector
        attack_vector_str = vector_components.get("attack_vector")
        attack_vector = None
        if attack_vector_str:
            try:
                attack_vector = AttackVector(attack_vector_str)
            except ValueError:
                attack_vector = None

        # Map attack complexity
        attack_complexity_str = vector_components.get("attack_complexity")
        attack_complexity = None
        if attack_complexity_str:
            try:
                attack_complexity = AttackComplexity(attack_complexity_str)
            except ValueError:
                attack_complexity = None

        # Requires authentication? (PR != N means auth required)
        privileges_required = vector_components.get("privileges_required")
        requires_auth = privileges_required not in (None, "N", "NONE")

        # User interaction required? (UI != N means required)
        user_interaction = vector_components.get("user_interaction")
        user_interaction_required = user_interaction not in (None, "N", "NONE")

        # Extract affected products (simplified)
        affected_products = self._extract_simple_affected_products(nist_vuln)

        # Get references
        reference_urls = nist_vuln.get_reference_urls()
        primary_reference = reference_urls[0] if reference_urls else None

        # Create minimal domain model
        cve = CVEMinimal(
            cve_id=nist_vuln.id,
            description=nist_vuln.get_english_description(),
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            requires_auth=requires_auth,
            user_interaction_required=user_interaction_required,
            affected_products=affected_products,
            version=1,
            status_nist=nist_vuln.vulnStatus,
            source=nist_vuln.sourceIdentifier,
            published_date=nist_vuln.published,
            last_modified_date=nist_vuln.lastModified,
            is_in_cisa_kev=is_in_cisa_kev,
            primary_reference=primary_reference,
            references=reference_urls,
        )

        logger.debug(
            f"Converted to minimal: {cve.cve_id} | "
            f"CVSS={cvss_score} | Severity={severity} | "
            f"CWE={cwe_id} | Vector={attack_vector} | "
            f"KEV={is_in_cisa_kev} | Risk={cve.risk_score}"
        )

        return cve

    @staticmethod
    def _extract_simple_affected_products(nist_vuln: NISTVulnerability) -> list[dict]:
        """
        Extract simplified affected products from CPE data.

        Groups by vendor/product and collects versions.

        Returns:
            List of dicts: [{"vendor": "apache", "product": "log4j", "versions": ["2.0", "2.14.1"]}]
        """
        products_map = {}  # Key: (vendor, product), Value: set of versions

        # Iterate through all configurations
        for config in nist_vuln.configurations:
            for node in config.nodes:
                for cpe_match in node.cpeMatch:
                    if not cpe_match.vulnerable:
                        continue

                    # Parse CPE URI
                    product_info = parse_cpe_to_simple_product(cpe_match.criteria)
                    if not product_info:
                        continue

                    vendor = product_info["vendor"]
                    product = product_info["product"]
                    version = product_info.get("version")

                    # Create key
                    key = (vendor, product)

                    # Initialize set if needed
                    if key not in products_map:
                        products_map[key] = set()

                    # Add version (handle ranges)
                    if version:
                        products_map[key].add(version)

                    # Add version range info if present
                    if cpe_match.versionStartIncluding:
                        products_map[key].add(f">={cpe_match.versionStartIncluding}")
                    if cpe_match.versionStartExcluding:
                        products_map[key].add(f">{cpe_match.versionStartExcluding}")
                    if cpe_match.versionEndIncluding:
                        products_map[key].add(f"<={cpe_match.versionEndIncluding}")
                    if cpe_match.versionEndExcluding:
                        products_map[key].add(f"<{cpe_match.versionEndExcluding}")

        # Convert to list format
        products = []
        for (vendor, product), versions in products_map.items():
            products.append({
                "vendor": vendor,
                "product": product,
                "versions": sorted(list(versions))
            })

        return products

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
