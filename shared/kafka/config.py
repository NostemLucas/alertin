"""
Kafka configuration for SOC Alerting System.
"""
import os
from dataclasses import dataclass
from typing import List


@dataclass
class KafkaConfig:
    """Kafka configuration."""

    bootstrap_servers: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    client_id: str = os.getenv("KAFKA_CLIENT_ID", "soc-alerting")

    # Producer settings
    producer_acks: str = "all"
    producer_retries: int = 3
    producer_max_in_flight: int = 5
    producer_compression: str = "gzip"

    # Consumer settings
    consumer_group_id: str = os.getenv("KAFKA_CONSUMER_GROUP_ID", "soc-alerting-group")
    consumer_auto_offset_reset: str = "earliest"
    consumer_enable_auto_commit: bool = True
    consumer_max_poll_records: int = 100


class KafkaTopics:
    """Kafka topic names."""

    CVE_RAW = "cve.raw"                   # CVEs crudos desde NIST/CISA
    CVE_ENRICHED = "cve.enriched"         # CVEs enriquecidos con NLP
    CVE_ALERTS = "cve.alerts"             # Alertas generadas
    CVE_NOTIFICATIONS = "cve.notifications"  # Notificaciones (email, Slack)
    CVE_DLQ = "cve.dlq"                   # Dead Letter Queue (errores)
