"""
Kafka consumer client for SOC Alerting System.
"""
import json
import logging
from typing import Dict, Any, Callable, List, Optional
from kafka import KafkaConsumer
from kafka.errors import KafkaError

from .config import KafkaConfig

logger = logging.getLogger(__name__)


class KafkaConsumerClient:
    """Kafka consumer for receiving messages."""

    def __init__(
        self,
        topics: List[str],
        group_id: str,
        config: Optional[KafkaConfig] = None,
    ):
        """Initialize Kafka consumer.

        Args:
            topics: List of topics to subscribe to
            group_id: Consumer group ID
            config: Kafka configuration. If None, uses default.
        """
        self.topics = topics
        self.group_id = group_id
        self.config = config or KafkaConfig()
        self.consumer = self._create_consumer()

    def _create_consumer(self) -> KafkaConsumer:
        """Create Kafka consumer instance."""
        return KafkaConsumer(
            *self.topics,
            bootstrap_servers=self.config.bootstrap_servers.split(","),
            client_id=f"{self.config.client_id}-consumer",
            group_id=self.group_id,
            auto_offset_reset=self.config.consumer_auto_offset_reset,
            enable_auto_commit=self.config.consumer_enable_auto_commit,
            max_poll_records=self.config.consumer_max_poll_records,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            key_deserializer=lambda k: k.decode("utf-8") if k else None,
        )

    def consume(
        self,
        handler: Callable[[Dict[str, Any]], bool],
        error_handler: Optional[Callable[[Exception, Dict[str, Any]], None]] = None,
    ):
        """Consume messages from subscribed topics.

        Args:
            handler: Function to process each message. Should return True on success.
            error_handler: Optional function to handle processing errors.
        """
        logger.info(f"Starting consumer for topics: {self.topics}")

        try:
            for message in self.consumer:
                try:
                    logger.debug(
                        f"Received message from {message.topic} "
                        f"[partition={message.partition}, offset={message.offset}]"
                    )

                    # Process message
                    success = handler(message.value)

                    if not success:
                        logger.warning(
                            f"Handler returned False for message: {message.key}"
                        )
                        if error_handler:
                            error_handler(
                                Exception("Handler returned False"),
                                message.value
                            )

                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    if error_handler:
                        error_handler(e, message.value)

        except KeyboardInterrupt:
            logger.info("Consumer interrupted by user")
        except KafkaError as e:
            logger.error(f"Kafka error: {e}")
            raise
        finally:
            self.close()

    def consume_batch(
        self,
        batch_handler: Callable[[List[Dict[str, Any]]], bool],
        batch_size: int = 100,
        timeout_ms: int = 1000,
    ):
        """Consume messages in batches.

        Args:
            batch_handler: Function to process batch of messages
            batch_size: Maximum batch size
            timeout_ms: Poll timeout in milliseconds
        """
        logger.info(f"Starting batch consumer for topics: {self.topics}")

        try:
            while True:
                message_batch = self.consumer.poll(
                    timeout_ms=timeout_ms,
                    max_records=batch_size
                )

                if not message_batch:
                    continue

                # Flatten messages from all partitions
                messages = []
                for partition_messages in message_batch.values():
                    messages.extend([msg.value for msg in partition_messages])

                if messages:
                    logger.debug(f"Processing batch of {len(messages)} messages")
                    batch_handler(messages)

        except KeyboardInterrupt:
            logger.info("Batch consumer interrupted by user")
        except KafkaError as e:
            logger.error(f"Kafka error: {e}")
            raise
        finally:
            self.close()

    def close(self):
        """Close consumer connection."""
        logger.info("Closing Kafka consumer")
        self.consumer.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
