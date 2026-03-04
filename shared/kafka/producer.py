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
        async_send: bool = False,
    ) -> bool:
        """Send a message to Kafka topic.

        Args:
            topic: Kafka topic name
            message: Message payload (will be JSON serialized)
            key: Optional message key for partitioning
            async_send: If True, sends without waiting for confirmation (higher throughput)

        Returns:
            True if message sent successfully (or queued if async), False otherwise

        Note:
            - Synchronous (async_send=False): Blocks until Kafka confirms. Slower but safer.
            - Asynchronous (async_send=True): Fire-and-forget. Faster but may lose messages
              if producer crashes. Use flush() periodically to ensure delivery.
        """
        try:
            future = self.producer.send(topic, value=message, key=key)

            if async_send:
                # Fire-and-forget: No esperamos confirmación
                # Mucho más rápido, útil para alto volumen
                logger.debug(f"Message queued to {topic} (async mode)")
                return True
            else:
                # Synchronous: Wait for confirmation (safer)
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

    def send_message_with_callback(
        self,
        topic: str,
        message: Dict[str, Any],
        key: Optional[str] = None,
        on_success: Optional[callable] = None,
        on_error: Optional[callable] = None,
    ):
        """Send message asynchronously with callbacks.

        Útil para alto volumen con monitoreo de errores.

        Args:
            topic: Kafka topic name
            message: Message payload
            key: Optional message key
            on_success: Callback on successful send: on_success(metadata)
            on_error: Callback on error: on_error(exception)

        Example:
            def on_ok(metadata):
                logger.info(f"Sent to partition {metadata.partition}")

            def on_fail(ex):
                logger.error(f"Failed: {ex}")

            producer.send_message_with_callback(
                "cve.raw", cve_data, key=cve_id,
                on_success=on_ok, on_error=on_fail
            )
        """
        future = self.producer.send(topic, value=message, key=key)

        # Attach callbacks
        if on_success:
            future.add_callback(on_success)
        if on_error:
            future.add_errback(on_error)

    def flush(self, timeout: Optional[int] = None):
        """Flush pending messages.

        Args:
            timeout: Maximum time to wait in seconds. None = wait indefinitely.
        """
        self.producer.flush(timeout=timeout)

    def close(self):
        """Close producer connection."""
        self.producer.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
