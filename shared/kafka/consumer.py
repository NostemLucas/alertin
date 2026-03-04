"""
Kafka consumer client for SOC Alerting System.
"""
import json
import logging
import time
from typing import Dict, Any, Callable, List, Optional
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

from .config import KafkaConfig, KafkaTopics

logger = logging.getLogger(__name__)


class KafkaConsumerClient:
    """Kafka consumer for receiving messages."""

    def __init__(
        self,
        topics: List[str],
        group_id: str,
        config: Optional[KafkaConfig] = None,
        enable_dlq: bool = True,
    ):
        """Initialize Kafka consumer.

        Args:
            topics: List of topics to subscribe to
            group_id: Consumer group ID
            config: Kafka configuration. If None, uses default.
            enable_dlq: Enable Dead Letter Queue for failed messages
        """
        self.topics = topics
        self.group_id = group_id
        self.config = config or KafkaConfig()
        self.enable_dlq = enable_dlq
        self.consumer = self._create_consumer()

        # Initialize DLQ producer if enabled
        self.dlq_producer = self._create_dlq_producer() if enable_dlq else None

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

    def _create_dlq_producer(self) -> KafkaProducer:
        """Create Kafka producer for Dead Letter Queue."""
        return KafkaProducer(
            bootstrap_servers=self.config.bootstrap_servers.split(","),
            client_id=f"{self.config.client_id}-dlq-producer",
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
        )

    def _send_to_dlq(
        self,
        message_key: Optional[str],
        message_value: Dict[str, Any],
        error: Exception,
        retry_count: int
    ):
        """Send failed message to Dead Letter Queue.

        Args:
            message_key: Original message key
            message_value: Original message value
            error: Exception that caused the failure
            retry_count: Number of retries attempted
        """
        if not self.dlq_producer:
            logger.warning("DLQ not enabled, cannot send failed message")
            return

        dlq_message = {
            "original_message": message_value,
            "error": str(error),
            "error_type": type(error).__name__,
            "retry_count": retry_count,
            "timestamp": time.time(),
        }

        try:
            self.dlq_producer.send(
                KafkaTopics.CVE_DLQ,
                value=dlq_message,
                key=message_key
            )
            self.dlq_producer.flush()
            logger.info(f"Sent message {message_key} to DLQ after {retry_count} retries")
        except Exception as dlq_error:
            logger.error(f"Failed to send message to DLQ: {dlq_error}")

    def consume(
        self,
        handler: Callable[[Dict[str, Any]], bool],
        error_handler: Optional[Callable[[Exception, Dict[str, Any]], None]] = None,
    ):
        """Consume messages from subscribed topics with manual commit.

        Features:
        - Manual commit only on successful processing
        - Retry logic with exponential backoff
        - Dead Letter Queue for permanently failed messages
        - At-least-once delivery guarantee

        Args:
            handler: Function to process each message. Should return True on success.
            error_handler: Optional function to handle processing errors.
        """
        logger.info(
            f"Starting consumer for topics: {self.topics} "
            f"(manual_commit={not self.config.consumer_enable_auto_commit}, "
            f"max_retries={self.config.consumer_max_retries})"
        )

        try:
            for message in self.consumer:
                retry_count = 0
                success = False

                logger.debug(
                    f"Received message from {message.topic} "
                    f"[partition={message.partition}, offset={message.offset}, key={message.key}]"
                )

                # Retry loop con exponential backoff
                while retry_count <= self.config.consumer_max_retries and not success:
                    try:
                        # Process message
                        success = handler(message.value)

                        if success:
                            # ✅ SUCCESS: Commit offset manualmente
                            if not self.config.consumer_enable_auto_commit:
                                self.consumer.commit()
                                logger.debug(f"✅ Committed offset {message.offset} for {message.key}")
                        else:
                            logger.warning(
                                f"Handler returned False for {message.key} "
                                f"(retry {retry_count + 1}/{self.config.consumer_max_retries + 1})"
                            )
                            retry_count += 1

                            if retry_count <= self.config.consumer_max_retries:
                                # Exponential backoff: 1s, 2s, 4s...
                                backoff = 2 ** (retry_count - 1)
                                logger.info(f"Retrying in {backoff}s...")
                                time.sleep(backoff)

                    except Exception as e:
                        logger.error(
                            f"Error processing message {message.key}: {e} "
                            f"(retry {retry_count + 1}/{self.config.consumer_max_retries + 1})"
                        )

                        retry_count += 1

                        if error_handler:
                            error_handler(e, message.value)

                        if retry_count <= self.config.consumer_max_retries:
                            # Exponential backoff
                            backoff = 2 ** (retry_count - 1)
                            logger.info(f"Retrying in {backoff}s...")
                            time.sleep(backoff)

                # Si agotamos todos los reintentos, enviar a DLQ
                if not success:
                    logger.error(
                        f"❌ Message {message.key} failed after {retry_count} retries, "
                        f"sending to DLQ"
                    )
                    self._send_to_dlq(
                        message.key,
                        message.value,
                        Exception("Max retries exceeded"),
                        retry_count
                    )

                    # ⚠️ IMPORTANTE: Commit el offset incluso si falla
                    # Para no procesar el mismo mensaje indefinidamente
                    if not self.config.consumer_enable_auto_commit:
                        self.consumer.commit()
                        logger.debug(f"Committed offset {message.offset} (failed message)")

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
        """Close consumer and DLQ producer connections."""
        logger.info("Closing Kafka consumer")
        self.consumer.close()

        if self.dlq_producer:
            logger.info("Closing DLQ producer")
            self.dlq_producer.close()

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        self.close()
