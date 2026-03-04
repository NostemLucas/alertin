"""
Alert Manager - Evaluates enriched CVEs against rules and generates alerts.
"""
import logging
import sys
from typing import Dict, Any, List
from datetime import datetime, timezone

# Add shared to path
sys.path.insert(0, "/app/shared")

from shared.kafka import KafkaConsumerClient, KafkaProducerClient, KafkaTopics
from rules import get_default_rules, AlertRule
from models.alerts import AlertMessage

logger = logging.getLogger(__name__)


class AlertManager:
    """Manager for evaluating CVEs and generating alerts."""

    def __init__(self, rules: List[AlertRule] = None):
        """Initialize alert manager.

        Args:
            rules: List of alert rules. If None, uses default rules.
        """
        self.rules = rules or get_default_rules()
        self.kafka_consumer = KafkaConsumerClient(
            topics=[KafkaTopics.CVE_ENRICHED],
            group_id="alert-manager-group",
        )
        self.kafka_producer = KafkaProducerClient()
        self.alert_count = 0
        logger.info(f"Alert Manager initialized with {len(self.rules)} rules")

    def evaluate_cve(self, cve_data: Dict[str, Any]) -> List[AlertMessage]:
        """Evaluate CVE against all rules.

        Args:
            cve_data: Enriched CVE data

        Returns:
            List of AlertMessage dataclasses generated
        """
        alerts = []

        for rule in self.rules:
            try:
                if rule.matches(cve_data):
                    alert = rule.create_alert(cve_data)
                    alerts.append(alert)
                    logger.info(
                        f"Rule '{rule.name}' matched for {cve_data.get('cve_id')} "
                        f"(priority: {rule.priority.value})"
                    )
            except Exception as e:
                logger.error(f"Error evaluating rule '{rule.name}': {e}")

        return alerts

    def process_cve(self, message: Dict[str, Any]) -> bool:
        """Process a single enriched CVE message.

        Args:
            message: Enriched CVE data from Kafka

        Returns:
            True if processed successfully
        """
        try:
            cve_id = message.get("cve_id")
            logger.debug(f"Evaluating CVE: {cve_id}")

            # Evaluate against all rules
            alerts = self.evaluate_cve(message)

            if not alerts:
                logger.debug(f"No alerts generated for {cve_id}")
                return True

            # Send each alert to Kafka
            for alert in alerts:
                success = self.kafka_producer.send_message(
                    topic=KafkaTopics.CVE_ALERTS,
                    message=alert.to_dict(),
                    key=cve_id,
                )

                if success:
                    self.alert_count += 1
                    logger.info(f"Alert sent: {alert}")
                else:
                    logger.warning(f"Failed to send alert for {cve_id}")

            return True

        except Exception as e:
            logger.error(f"Error processing CVE: {e}", exc_info=True)
            return False

    def handle_error(self, error: Exception, message: Dict[str, Any]):
        """Handle processing errors.

        Args:
            error: Exception that occurred
            message: Original message that failed
        """
        logger.error(f"Error processing message: {error}")

    def run(self):
        """Run alert manager - consume messages and evaluate them."""
        logger.info("Starting Alert Manager...")
        logger.info(f"Active rules: {[rule.name for rule in self.rules]}")

        try:
            self.kafka_consumer.consume(
                handler=self.process_cve,
                error_handler=self.handle_error,
            )
        except KeyboardInterrupt:
            logger.info(f"Alert Manager stopped. Total alerts sent: {self.alert_count}")
        except Exception as e:
            logger.error(f"Fatal error in alert manager: {e}", exc_info=True)
            raise
        finally:
            self.kafka_producer.close()
            logger.info("Alert Manager stopped")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    manager = AlertManager()
    manager.run()
