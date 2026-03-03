"""
Technical keyword extraction for CVE descriptions.

Identifies security-relevant keywords, attack vectors, vulnerability types,
and technical concepts from CVE descriptions.
"""

import logging
import re
from typing import Optional
from collections import Counter

logger = logging.getLogger(__name__)


class CVEKeywordExtractor:
    """
    Extracts technical keywords and security concepts from CVE descriptions.

    Uses a combination of:
    1. Predefined security vocabulary
    2. Pattern matching for attack vectors
    3. Frequency analysis
    """

    # Predefined security keywords by category
    ATTACK_VECTORS = {
        "remote code execution", "rce", "arbitrary code execution",
        "sql injection", "sqli", "cross-site scripting", "xss",
        "cross-site request forgery", "csrf", "buffer overflow",
        "command injection", "path traversal", "directory traversal",
        "file inclusion", "lfi", "rfi", "deserialization",
        "xml external entity", "xxe", "server-side request forgery", "ssrf",
        "privilege escalation", "authentication bypass", "authorization bypass",
        "denial of service", "dos", "ddos", "memory corruption",
        "use after free", "heap overflow", "stack overflow",
        "integer overflow", "race condition", "time-of-check time-of-use",
        "information disclosure", "information leakage", "sensitive data exposure",
        "insecure deserialization", "ldap injection", "jndi injection",
        "template injection", "ssti", "code injection", "eval injection"
    }

    IMPACT_KEYWORDS = {
        "confidentiality", "integrity", "availability",
        "data breach", "data exfiltration", "privilege",
        "unauthorized access", "bypass", "disclosure",
        "corruption", "manipulation", "modification",
        "crash", "hang", "resource exhaustion"
    }

    TECHNICAL_PROTOCOLS = {
        "http", "https", "ftp", "smtp", "ssh", "telnet",
        "ldap", "jndi", "rmi", "dns", "dhcp", "snmp",
        "tcp", "udp", "icmp", "ssl", "tls", "jdbc",
        "odbc", "soap", "rest", "graphql", "websocket"
    }

    PROGRAMMING_CONCEPTS = {
        "authentication", "authorization", "session", "cookie",
        "token", "jwt", "oauth", "saml", "api", "endpoint",
        "parameter", "input validation", "sanitization", "encoding",
        "encryption", "decryption", "hashing", "signature",
        "certificate", "key", "password", "credential",
        "memory", "pointer", "buffer", "heap", "stack",
        "thread", "process", "kernel", "user space"
    }

    VULNERABILITY_TYPES = {
        "vulnerability", "flaw", "weakness", "bug", "issue",
        "exposure", "misconfiguration", "backdoor", "trojan",
        "malware", "exploit", "zero-day", "0day",
        "unpatched", "outdated", "legacy", "deprecated"
    }

    def __init__(self, min_keyword_length: int = 3):
        """
        Initialize keyword extractor.

        Args:
            min_keyword_length: Minimum character length for keywords
        """
        self.min_keyword_length = min_keyword_length

        # Combine all predefined keywords
        self.all_keywords = (
            self.ATTACK_VECTORS |
            self.IMPACT_KEYWORDS |
            self.TECHNICAL_PROTOCOLS |
            self.PROGRAMMING_CONCEPTS |
            self.VULNERABILITY_TYPES
        )

        logger.info(
            f"CVEKeywordExtractor initialized with {len(self.all_keywords)} "
            f"predefined keywords"
        )

    def extract_keywords(
        self,
        text: str,
        max_keywords: int = 20,
        include_scores: bool = True
    ) -> dict[str, any]:
        """
        Extract technical keywords from CVE description.

        Args:
            text: CVE description text
            max_keywords: Maximum number of keywords to return
            include_scores: Include relevance scores

        Returns:
            Dictionary with:
                - attack_vectors: List of identified attack types
                - impact_keywords: CIA-related keywords
                - technical_keywords: General technical terms
                - vulnerability_types: Vulnerability classifications
                - all_keywords: Combined list (optionally with scores)
                - keyword_count: Total count

        Example:
            >>> extractor = CVEKeywordExtractor()
            >>> result = extractor.extract_keywords(
            ...     "Remote code execution via JNDI injection in LDAP"
            ... )
            >>> print(result["attack_vectors"])
            ["remote code execution", "jndi injection"]
        """
        if not text or not text.strip():
            return self._empty_result()

        text_lower = text.lower()

        # Extract keywords by category
        attack_vectors = self._extract_by_category(text_lower, self.ATTACK_VECTORS)
        impact_keywords = self._extract_by_category(text_lower, self.IMPACT_KEYWORDS)
        protocols = self._extract_by_category(text_lower, self.TECHNICAL_PROTOCOLS)
        concepts = self._extract_by_category(text_lower, self.PROGRAMMING_CONCEPTS)
        vuln_types = self._extract_by_category(text_lower, self.VULNERABILITY_TYPES)

        # Combine all with frequency scoring
        all_keywords_counter = Counter()
        all_keywords_counter.update(attack_vectors)
        all_keywords_counter.update(impact_keywords)
        all_keywords_counter.update(protocols)
        all_keywords_counter.update(concepts)
        all_keywords_counter.update(vuln_types)

        # Get top keywords
        top_keywords = all_keywords_counter.most_common(max_keywords)

        if include_scores:
            all_keywords = [
                {"keyword": kw, "frequency": freq}
                for kw, freq in top_keywords
            ]
        else:
            all_keywords = [kw for kw, _ in top_keywords]

        result = {
            "attack_vectors": list(set(attack_vectors)),
            "impact_keywords": list(set(impact_keywords)),
            "technical_protocols": list(set(protocols)),
            "programming_concepts": list(set(concepts)),
            "vulnerability_types": list(set(vuln_types)),
            "all_keywords": all_keywords,
            "keyword_count": len(all_keywords)
        }

        logger.debug(f"Extracted {result['keyword_count']} keywords from text")

        return result

    def _extract_by_category(self, text: str, keyword_set: set[str]) -> list[str]:
        """
        Extract keywords from specific category.

        Args:
            text: Lowercase text
            keyword_set: Set of keywords to search for

        Returns:
            List of found keywords
        """
        found = []
        for keyword in keyword_set:
            # Use word boundaries for accurate matching
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, text):
                found.append(keyword)

        return found

    def identify_attack_type(self, text: str) -> dict[str, any]:
        """
        Identify primary attack type and characteristics.

        Args:
            text: CVE description

        Returns:
            Dictionary with:
                - primary_attack_type: Main attack category
                - secondary_types: Additional attack types
                - attack_complexity: Estimated complexity
                - requires_authentication: Boolean guess
                - network_accessible: Boolean guess

        Example:
            >>> extractor = CVEKeywordExtractor()
            >>> attack = extractor.identify_attack_type(
            ...     "Unauthenticated remote code execution via buffer overflow"
            ... )
            >>> print(attack["primary_attack_type"])
            "Remote Code Execution"
            >>> print(attack["requires_authentication"])
            False
        """
        text_lower = text.lower()

        # Identify attack types
        keywords = self.extract_keywords(text)
        attack_vectors = keywords["attack_vectors"]

        # Determine primary attack type
        primary_attack_type = "Unknown"
        if any(v in attack_vectors for v in ["remote code execution", "rce", "arbitrary code execution"]):
            primary_attack_type = "Remote Code Execution"
        elif any(v in attack_vectors for v in ["sql injection", "sqli"]):
            primary_attack_type = "SQL Injection"
        elif any(v in attack_vectors for v in ["cross-site scripting", "xss"]):
            primary_attack_type = "Cross-Site Scripting"
        elif any(v in attack_vectors for v in ["buffer overflow", "heap overflow", "stack overflow"]):
            primary_attack_type = "Buffer Overflow"
        elif any(v in attack_vectors for v in ["denial of service", "dos", "ddos"]):
            primary_attack_type = "Denial of Service"
        elif any(v in attack_vectors for v in ["privilege escalation"]):
            primary_attack_type = "Privilege Escalation"
        elif "bypass" in text_lower:
            primary_attack_type = "Authentication/Authorization Bypass"
        elif any(v in attack_vectors for v in ["information disclosure", "information leakage"]):
            primary_attack_type = "Information Disclosure"

        # Secondary types (all except primary)
        secondary_types = [v for v in attack_vectors if v not in primary_attack_type.lower()]

        # Guess complexity
        attack_complexity = "MEDIUM"
        if any(word in text_lower for word in ["easy", "simple", "trivial", "unauthenticated", "no authentication"]):
            attack_complexity = "LOW"
        elif any(word in text_lower for word in ["complex", "difficult", "race condition", "timing"]):
            attack_complexity = "HIGH"

        # Guess authentication requirement
        requires_authentication = True
        if any(word in text_lower for word in ["unauthenticated", "no authentication", "without authentication", "anonymous"]):
            requires_authentication = False
        elif any(word in text_lower for word in ["authenticated", "requires authentication", "logged in"]):
            requires_authentication = True
        else:
            requires_authentication = None  # Unknown

        # Guess network accessibility
        network_accessible = True
        if any(word in text_lower for word in ["remote", "network", "internet", "remotely"]):
            network_accessible = True
        elif any(word in text_lower for word in ["local", "physical access", "local access"]):
            network_accessible = False
        else:
            network_accessible = None  # Unknown

        return {
            "primary_attack_type": primary_attack_type,
            "secondary_types": secondary_types[:3],  # Limit to top 3
            "attack_complexity": attack_complexity,
            "requires_authentication": requires_authentication,
            "network_accessible": network_accessible,
            "confidence": 0.7  # Heuristic-based, moderate confidence
        }

    def extract_cia_impact(self, text: str) -> dict[str, str]:
        """
        Extract CIA triad impact (Confidentiality, Integrity, Availability).

        Args:
            text: CVE description

        Returns:
            Dictionary with impact levels for each CIA component

        Example:
            >>> extractor = CVEKeywordExtractor()
            >>> impact = extractor.extract_cia_impact(
            ...     "Allows unauthorized access to sensitive data and system modification"
            ... )
            >>> print(impact)
            {
                "confidentiality": "HIGH",
                "integrity": "HIGH",
                "availability": "NONE"
            }
        """
        text_lower = text.lower()

        # Confidentiality keywords
        confidentiality_high = [
            "disclosure", "exposure", "leak", "access", "read", "view",
            "sensitive data", "credentials", "password", "private",
            "confidential", "unauthorized access", "data breach"
        ]

        # Integrity keywords
        integrity_high = [
            "modification", "modify", "alter", "change", "write",
            "manipulate", "corrupt", "tamper", "inject", "bypass"
        ]

        # Availability keywords
        availability_high = [
            "denial of service", "dos", "ddos", "crash", "hang",
            "resource exhaustion", "unavailable", "outage", "downtime"
        ]

        # Assess impact
        c_impact = "NONE"
        i_impact = "NONE"
        a_impact = "NONE"

        if any(word in text_lower for word in confidentiality_high):
            c_impact = "HIGH"

        if any(word in text_lower for word in integrity_high):
            i_impact = "HIGH"

        if any(word in text_lower for word in availability_high):
            a_impact = "HIGH"

        # Special case: RCE affects all three
        if any(word in text_lower for word in ["remote code execution", "rce", "arbitrary code"]):
            c_impact = "HIGH"
            i_impact = "HIGH"
            a_impact = "HIGH"

        return {
            "confidentiality": c_impact,
            "integrity": i_impact,
            "availability": a_impact
        }

    def _empty_result(self) -> dict[str, any]:
        """Return empty result structure."""
        return {
            "attack_vectors": [],
            "impact_keywords": [],
            "technical_protocols": [],
            "programming_concepts": [],
            "vulnerability_types": [],
            "all_keywords": [],
            "keyword_count": 0
        }


# Singleton instance
_keyword_extractor_instance: Optional[CVEKeywordExtractor] = None


def get_keyword_extractor() -> CVEKeywordExtractor:
    """
    Get singleton keyword extractor instance.

    Returns:
        CVEKeywordExtractor instance
    """
    global _keyword_extractor_instance

    if _keyword_extractor_instance is None:
        _keyword_extractor_instance = CVEKeywordExtractor()

    return _keyword_extractor_instance
