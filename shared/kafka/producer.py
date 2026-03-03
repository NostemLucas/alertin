"""
Kafka producer client for SOC Alerting System.
"""
import json
import logging
from typing import Dict, Any, Optional
from kafka import KafkaProducer
from kafka.errors import KafkaError

from .config import KafkaConfig

logger = logging.getLogger(__name__)


class KafkaProducerClient:
    """Kafka producer for sending messages."""

    def __init__(self, config: Optional[KafkaConfig] = None):
        """Initialize Kafka producer.

        Args:
            config: Kafka configuration. If None, uses default.
        """
        self.config = config or KafkaConfig()
        self.producer = self._create_producer()

    def _create_producer(self) -> KafkaProducer:
        """Create Kafka producer instance."""
        return KafkaProducer(
            bootstrap_servers=self.config.bootstrap_servers.split(","),
            client_id=f"{self.config.client_id}-producer",
            acks=self.config.producer_acks,
            retries=self.config.producer_retries,
            max_in_flight_requests_per_connection=self.config.producer_max_in_flight,
            compression_type=self.config.producer_compression,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
        )

    def send_message(
        self,
        topic: str,
        message: Dict[str, Any],
        key: Optional[str] = None,
    ) -> bool:
        """Send a message to Kafka topic.

        Args:
            topic: Kafka topic name
            message: Message payload (will be JSON serialized)
            key: Optional message key for partitioning

        Returns:
            True if message sent successfully, False otherwise
        """
        try:
            future = self.producer.send(topic, value=message, key=key)
            # Wait for confirmation (synchronous send)
            record_metadata = future.get(timeout=10)

            logger.debug(
                f"Message sent to {topic} "
                f"[partition={record_metadata.partition}, "
                f"offset={record_metadata.offset}]"
            )
            return True

        except KafkaError as e:
            logger.error(f"Failed to send message to {topic}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending message to {topic}: {e}")
            return False

    def send_cve_raw(self, cve_data: Dict[str, Any]) -> bool:
        """Send raw CVE data.

        Args:
            cve_data: CVE data from NIST/CISA

        Returns:
            True if sent successfully
        """
        from .config import KafkaTopics
        cve_id = cve_data.get("cve_id")
        return self.send_message(
            topic=KafkaTopics.CVE_RAW,
            message=cve_data,
            key=cve_id,
        )

    def send_cve_enriched(self, cve_data: Dict[str, Any]) -> bool:
        """Send enriched CVE data.

        Args:
            cve_data: Enriched CVE data with NLP analysis

        Returns:
            True if sent successfully
        """
        from .config import KafkaTopics
        cve_id = cve_data.get("cve_id")
        return self.send_message(
            topic=KafkaTopics.CVE_ENRICHED,
            message=cve_data,
            key=cve_id,
        )

    def send_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send alert.

        Args:
            alert_data: Alert data

        Returns:
            True if sent successfully
        """
        from .config import KafkaTopics
        cve_id = alert_data.get("cve_id")
        return self.send_message(
            topic=KafkaTopics.CVE_ALERTS,
            message=alert_data,
            key=cve_id,
        )

    def flush(self):
        """Flush pending messages."""
        self.producer.flush()

    def close(self):
        """Close producer connection."""
        self.producer.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
