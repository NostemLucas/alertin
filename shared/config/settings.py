"""
Shared configuration settings for SOC Alerting System.

Loads configuration from environment variables with sensible defaults.
This is the main configuration module used across all services.
"""

import os
from functools import lru_cache
from typing import Optional


class Settings:
    """
    Shared application settings loaded from environment variables.

    This class provides centralized configuration management for the entire
    SOC Alerting system. All settings can be overridden via environment variables.
    """

    def __init__(self):
        # ===== Database Configuration =====
        self.database_url: str = os.getenv(
            "DATABASE_URL",
            "postgresql://soc_user:secure_password@localhost:5433/soc_alerting"
        )
        self.database_pool_size: int = int(os.getenv("DATABASE_POOL_SIZE", "5"))
        self.database_max_overflow: int = int(os.getenv("DATABASE_MAX_OVERFLOW", "10"))

        # ===== NIST NVD API Configuration =====
        self.nist_api_base_url: str = os.getenv(
            "NIST_API_BASE_URL",
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
        )
        self.nist_api_key: Optional[str] = os.getenv("NIST_API_KEY")
        self.nist_rate_limit_delay: float = float(os.getenv("NIST_RATE_LIMIT_DELAY", "6.0"))

        # ===== CISA KEV Configuration =====
        self.cisa_kev_url: str = os.getenv(
            "CISA_KEV_URL",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        )
        self.cisa_cache_ttl: int = int(os.getenv("CISA_CACHE_TTL", "3600"))

        # ===== HuggingFace Configuration =====
        self.hf_model_name: str = os.getenv("HF_MODEL_NAME", "PEASEC/CVE-BERT")
        self.hf_cache_dir: str = os.getenv("HF_CACHE_DIR", "/opt/models")
        self.hf_device: int = int(os.getenv("HF_DEVICE", "-1"))  # -1 = CPU, 0 = GPU
        self.hf_max_length: int = int(os.getenv("HF_MAX_LENGTH", "512"))

        # ===== Processing Configuration =====
        self.update_interval_minutes: int = int(os.getenv("UPDATE_INTERVAL_MINUTES", "60"))
        self.enrich_severity_threshold: str = os.getenv("ENRICH_SEVERITY_THRESHOLD", "HIGH")
        self.batch_size: int = int(os.getenv("BATCH_SIZE", "100"))
        self.enable_enrichment: bool = os.getenv("ENABLE_ENRICHMENT", "true").lower() == "true"
        self.enable_scheduler: bool = os.getenv("ENABLE_SCHEDULER", "true").lower() == "true"
        self.enable_update_history: bool = os.getenv("ENABLE_UPDATE_HISTORY", "true").lower() == "true"

        # ===== Retry Configuration =====
        self.max_retries: int = int(os.getenv("MAX_RETRIES", "3"))
        self.retry_delay_seconds: float = float(os.getenv("RETRY_DELAY_SECONDS", "5"))
        self.retry_exponential_backoff: bool = os.getenv("RETRY_EXPONENTIAL_BACKOFF", "true").lower() == "true"

        # ===== Logging Configuration =====
        self.log_level: str = os.getenv("LOG_LEVEL", "INFO")
        self.log_file: Optional[str] = os.getenv("LOG_FILE")
        self.log_json: bool = os.getenv("LOG_JSON", "false").lower() == "true"

        # ===== Redis Configuration (Optional) =====
        self.redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.redis_password: Optional[str] = os.getenv("REDIS_PASSWORD")

    def __repr__(self) -> str:
        """String representation masking sensitive data."""
        db_url_masked = self._mask_db_url(self.database_url)
        api_key_masked = "***" if self.nist_api_key else "None"
        return (
            f"Settings("
            f"database_url={db_url_masked}, "
            f"nist_api_base_url={self.nist_api_base_url}, "
            f"nist_api_key={api_key_masked}, "
            f"log_level={self.log_level})"
        )

    @staticmethod
    def _mask_db_url(url: str) -> str:
        """Mask password in database URL for safe logging."""
        if "@" in url and "://" in url:
            protocol, rest = url.split("://", 1)
            if "@" in rest:
                creds, host_db = rest.split("@", 1)
                if ":" in creds:
                    user, _ = creds.split(":", 1)
                    return f"{protocol}://{user}:***@{host_db}"
        return url


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.

    Uses lru_cache to ensure settings are only loaded once per application lifecycle.
    This is the recommended way to access settings throughout the application.

    Returns:
        Settings instance

    Example:
        >>> from shared.config import get_settings
        >>> settings = get_settings()
        >>> print(settings.database_url)
    """
    return Settings()
