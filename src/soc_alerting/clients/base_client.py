"""
Base HTTP client with retry logic and error handling.

Provides common functionality for all API clients.
"""

import logging
from typing import Any, Optional
from datetime import datetime, timedelta

import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

from ..config.settings import get_settings

logger = logging.getLogger(__name__)


class BaseAPIClient:
    """
    Base API ccon reintentos y rate

    Features:
    - Reintentos automáticos con tenacity
    - Rate limiting support
    - Error handling and logging
    - Configurable timeouts
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 30.0,
        max_retries: int | None = None,
        retry_delay: float | None = None,
    ):
        """
        Initialize base API client.

        Args:
            base_url: Base URL for the API
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts (defaults to settings)
            retry_delay: Initial retry delay (defaults to settings)
        """
        settings = get_settings()
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries or settings.max_retries
        self.retry_delay = retry_delay or settings.retry_delay_seconds

        # Create HTTP client
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
        )

        logger.info(
            f"Initialized API client: {self.base_url} "
            f"(timeout={timeout}s, max_retries={self.max_retries})"
        )

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
        logger.debug("HTTP client closed")

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
        stop=stop_after_attempt(3),  # Will be overridden by instance max_retries
        wait=wait_exponential(multiplier=1, min=2, max=30),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )
    async def _request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """
        Make HTTP request with retry logic.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (relative to base_url)
            params: Query parameters
            headers: HTTP headers
            json_data: JSON request body

        Returns:
            HTTP response

        Raises:
            httpx.HTTPError: On request failure after retries
        """
        # Support both relative and absolute URLs
        # If endpoint starts with http://, use it as-is
        # Otherwise, combine with base_url
        if endpoint.startswith(('http://', 'https://')):
            url = endpoint
        else:
            url = f"{self.base_url}/{endpoint.lstrip('/')}"

        logger.debug(f"{method} {url} (params={params})")

        try:
            response = await self.client.request(
                method=method,
                url=url,  # Use the constructed URL, not just endpoint
                params=params,
                headers=headers,
                json=json_data,
            )
            response.raise_for_status()

            logger.debug(
                f"Response: {response.status_code} "
                f"(size={len(response.content)} bytes)"
            )

            return response

        except httpx.HTTPStatusError as e:
            logger.error(
                f"HTTP error {e.response.status_code}: {e.response.text[:200]}"
            )
            raise
        except httpx.TimeoutException as e:
            logger.error(f"Request timeout: {url}")
            raise
        except httpx.HTTPError as e:
            logger.error(f"HTTP error: {e}")
            raise

    async def get(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """
        GET request.

        Args:
            endpoint: API endpoint
            params: Query parameters
            headers: HTTP headers

        Returns:
            JSON response as dict
        """
        response = await self._request("GET", endpoint, params=params, headers=headers)
        return response.json()

    async def post(
        self,
        endpoint: str,
        json_data: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """
        POST request.

        Args:
            endpoint: API endpoint
            json_data: JSON request body
            headers: HTTP headers

        Returns:
            JSON response as dict
        """
        response = await self._request(
            "POST", endpoint, headers=headers, json_data=json_data
        )
        return response.json()


class RateLimitedClient(BaseAPIClient):
    """
    API client with rate limiting support.

    Enforces minimum delay between requests to comply with API rate limits.
    """

    def __init__(
        self,
        base_url: str,
        rate_limit_delay: float = 0.0,
        **kwargs,
    ):
        """
        Initialize rate-limited client.

        Args:
            base_url: Base URL for the API
            rate_limit_delay: Minimum seconds between requests
            **kwargs: Additional arguments for BaseAPIClient
        """
        super().__init__(base_url, **kwargs)
        self.rate_limit_delay = rate_limit_delay
        self.last_request_time: Optional[datetime] = None

        logger.info(f"Rate limiting enabled: {rate_limit_delay}s between requests")

    async def _enforce_rate_limit(self):
        """
        Enforce rate limit by sleeping if necessary.

        Ensures minimum delay between consecutive requests.
        """
        if self.last_request_time is None:
            self.last_request_time = datetime.utcnow()
            return

        elapsed = (datetime.utcnow() - self.last_request_time).total_seconds()
        if elapsed < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - elapsed
            logger.debug(f"Rate limit: sleeping {sleep_time:.2f}s")

            import asyncio
            await asyncio.sleep(sleep_time)

        self.last_request_time = datetime.utcnow()

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """
        Make rate-limited HTTP request.

        Args:
            method: HTTP method
            endpoint: API endpoint
            params: Query parameters
            headers: HTTP headers
            json_data: JSON request body

        Returns:
            HTTP response
        """
        await self._enforce_rate_limit()
        return await super()._request(method, endpoint, params, headers, json_data)
