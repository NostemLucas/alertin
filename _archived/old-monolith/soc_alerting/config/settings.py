"""
Application configuration using Pydantic Settings.

Loads configuration from environment variables with validation.
"""

from pydantic_settings import BaseSettings
from pydantic import Field, field_validator
from typing import Optional


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables.

    Uses .env file if present, with environment variables taking precedence.
    """

    # Database
    database_url: str = Field(
        default="postgresql://soc_user:password@localhost:5432/soc_alerting",
        description="PostgreSQL connection URL"
    )
    database_pool_size: int = Field(default=5, ge=1, le=50, description="DB connection pool size")
    database_max_overflow: int = Field(default=10, ge=0, le=100, description="DB max overflow connections")

    # NIST NVD API
    nist_api_key: Optional[str] = Field(
        default=None,
        description="NIST NVD API key (optional but recommended for higher rate limits)"
    )
    nist_api_base_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        description="NIST NVD API base URL"
    )
    nist_rate_limit_delay: float = Field(
        default=6.0,
        ge=0.0,
        description="Delay between NIST API requests (seconds) - 6s = 10 req/min"
    )

    # CISA KEV
    cisa_kev_url: str = Field(
        default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        description="CISA KEV catalog URL"
    )
    cisa_cache_ttl: int = Field(
        default=3600,
        ge=60,
        description="CISA catalog cache TTL (seconds) - 3600 = 1 hour"
    )

    # HuggingFace
    hf_model_name: str = Field(
        default="distilbert-base-uncased",
        description="HuggingFace model for text classification"
    )
    hf_cache_dir: Optional[str] = Field(
        default=None,
        description="HuggingFace model cache directory"
    )
    hf_device: int = Field(
        default=-1,
        ge=-1,
        description="Device for HuggingFace: -1 for CPU, 0+ for GPU"
    )
    hf_max_length: int = Field(
        default=512,
        ge=128,
        le=2048,
        description="Max token length for HuggingFace models"
    )

    # Processing
    update_interval_minutes: int = Field(
        default=60,
        ge=1,
        le=1440,
        description="CVE update interval (minutes)"
    )
    enrich_severity_threshold: str = Field(
        default="HIGH",
        description="Minimum severity to enrich: LOW, MEDIUM, HIGH, CRITICAL"
    )
    batch_size: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="CVEs to process per batch"
    )
    enable_enrichment: bool = Field(
        default=True,
        description="Enable HuggingFace enrichment"
    )

    # Retry configuration
    max_retries: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Maximum API request retries"
    )
    retry_delay_seconds: int = Field(
        default=5,
        ge=1,
        le=60,
        description="Delay between retries (seconds)"
    )
    retry_exponential_backoff: bool = Field(
        default=True,
        description="Use exponential backoff for retries"
    )

    # Logging
    log_level: str = Field(
        default="INFO",
        description="Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL"
    )
    log_file: Optional[str] = Field(
        default=None,
        description="Log file path (None = stdout only)"
    )
    log_json: bool = Field(
        default=False,
        description="Use JSON structured logging"
    )

    # Features
    enable_scheduler: bool = Field(
        default=True,
        description="Enable hourly scheduler"
    )
    enable_update_history: bool = Field(
        default=True,
        description="Track CVE update history"
    )

    # Security & Environment
    environment: str = Field(
        default="production",
        description="Environment: development, staging, production"
    )
    debug_endpoints_enabled: bool = Field(
        default=False,
        description="Enable debug endpoints (SECURITY: only for development!)"
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level is valid."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"log_level must be one of {valid_levels}")
        return v_upper

    @field_validator("enrich_severity_threshold")
    @classmethod
    def validate_severity_threshold(cls, v: str) -> str:
        """Validate severity threshold."""
        valid_severities = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        v_upper = v.upper()
        if v_upper not in valid_severities:
            raise ValueError(f"enrich_severity_threshold must be one of {valid_severities}")
        return v_upper

    @property
    def is_nist_api_key_configured(self) -> bool:
        """Check if NIST API key is configured."""
        return self.nist_api_key is not None and len(self.nist_api_key) > 0

    @property
    def should_enrich_cve(self) -> bool:
        """Check if enrichment is enabled."""
        return self.enable_enrichment

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False  # Allow case-insensitive env vars
        extra = "ignore"  # Ignore extra fields from .env (e.g., Docker-specific vars)


# Singleton instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """
    Get application settings singleton.

    Returns:
        Settings instance
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    """
    Reload settings from environment.

    Useful for testing or configuration changes.

    Returns:
        New Settings instance
    """
    global _settings
    _settings = Settings()
    return _settings
