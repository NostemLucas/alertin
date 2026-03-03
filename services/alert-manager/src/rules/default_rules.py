"""
Default alert rules for SOC operations.
"""
from typing import Dict, Any, List
from .base_rule import AlertRule, AlertPriority


class CISAKEVRule(AlertRule):
    """Alert on CVEs in CISA KEV catalog."""

    def __init__(self):
        super().__init__(
            name="CISA_KEV",
            priority=AlertPriority.CRITICAL,
            description="CVE is in CISA Known Exploited Vulnerabilities catalog"
        )

    def matches(self, cve_data: Dict[str, Any]) -> bool:
        return cve_data.get("is_in_cisa_kev", False)


class HighCVSSRule(AlertRule):
    """Alert on high CVSS scores (>= 9.0)."""

    def __init__(self):
        super().__init__(
            name="HIGH_CVSS",
            priority=AlertPriority.CRITICAL,
            description="CVE has CVSS score >= 9.0"
        )

    def matches(self, cve_data: Dict[str, Any]) -> bool:
        cvss_score = cve_data.get("cvss_score")
        return cvss_score is not None and cvss_score >= 9.0


class NetworkExploitableRule(AlertRule):
    """Alert on network-exploitable CVEs without authentication."""

    def __init__(self):
        super().__init__(
            name="NETWORK_NO_AUTH",
            priority=AlertPriority.HIGH,
            description="Network-exploitable without authentication"
        )

    def matches(self, cve_data: Dict[str, Any]) -> bool:
        is_network = cve_data.get("attack_vector") == "NETWORK"
        no_auth = not cve_data.get("requires_auth", True)
        return is_network and no_auth


class RemoteCodeExecutionRule(AlertRule):
    """Alert on RCE vulnerabilities."""

    def __init__(self):
        super().__init__(
            name="REMOTE_CODE_EXECUTION",
            priority=AlertPriority.CRITICAL,
            description="Remote Code Execution vulnerability"
        )

    def matches(self, cve_data: Dict[str, Any]) -> bool:
        description = cve_data.get("description", "").lower()
        rce_keywords = [
            "remote code execution",
            "rce",
            "arbitrary code execution",
            "execute arbitrary code",
        ]
        return any(keyword in description for keyword in rce_keywords)


class ZeroDayRule(AlertRule):
    """Alert on suspected zero-day vulnerabilities."""

    def __init__(self):
        super().__init__(
            name="ZERO_DAY",
            priority=AlertPriority.CRITICAL,
            description="Suspected zero-day vulnerability"
        )

    def matches(self, cve_data: Dict[str, Any]) -> bool:
        description = cve_data.get("description", "").lower()
        zeroday_keywords = ["zero-day", "zero day", "0day", "0-day"]

        # Check NLP enrichment if available
        nlp = cve_data.get("nlp_enrichment", {})
        if nlp:
            risk_indicators = nlp.get("risk_indicators", [])
            if "zero_day" in risk_indicators:
                return True

        return any(keyword in description for keyword in zeroday_keywords)


class HighRiskScoreRule(AlertRule):
    """Alert on high risk scores (>= 85)."""

    def __init__(self):
        super().__init__(
            name="HIGH_RISK_SCORE",
            priority=AlertPriority.HIGH,
            description="Risk score >= 85"
        )

    def matches(self, cve_data: Dict[str, Any]) -> bool:
        risk_score = cve_data.get("risk_score")
        return risk_score is not None and risk_score >= 85


class CriticalSeverityRule(AlertRule):
    """Alert on CRITICAL severity CVEs."""

    def __init__(self):
        super().__init__(
            name="CRITICAL_SEVERITY",
            priority=AlertPriority.CRITICAL,
            description="CVE has CRITICAL severity"
        )

    def matches(self, cve_data: Dict[str, Any]) -> bool:
        severity = cve_data.get("severity", "").upper()
        return severity == "CRITICAL"


def get_default_rules() -> List[AlertRule]:
    """Get list of default alert rules.

    Returns:
        List of alert rules
    """
    return [
        CISAKEVRule(),
        HighCVSSRule(),
        NetworkExploitableRule(),
        RemoteCodeExecutionRule(),
        ZeroDayRule(),
        HighRiskScoreRule(),
        CriticalSeverityRule(),
    ]
