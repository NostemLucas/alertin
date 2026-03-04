"""
Base alert rule definition.
"""
from enum import Enum
from typing import Dict, Any
from abc import ABC, abstractmethod
from models.alerts import AlertMessage


class AlertPriority(str, Enum):
    """Alert priority levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlertRule(ABC):
    """Base class for alert rules."""

    def __init__(self, name: str, priority: AlertPriority, description: str):
        """Initialize rule.

        Args:
            name: Rule name
            priority: Alert priority if rule matches
            description: Rule description
        """
        self.name = name
        self.priority = priority
        self.description = description

    @abstractmethod
    def matches(self, cve_data: Dict[str, Any]) -> bool:
        """Check if CVE matches this rule.

        Args:
            cve_data: CVE data to evaluate

        Returns:
            True if rule matches
        """
        pass

    def create_alert(self, cve_data: Dict[str, Any]) -> AlertMessage:
        """Create alert message.

        Args:
            cve_data: CVE data

        Returns:
            AlertMessage dataclass
        """
        return AlertMessage(
            rule_name=self.name,
            priority=self.priority.value,
            cve_id=cve_data.get("cve_id", "UNKNOWN"),
            description=self.description,
            cve_data=cve_data,
        )
