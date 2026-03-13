"""Pattern detection on tool call responses."""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field

from ancilis.engine.patterns import PatternMatch, scan_for_patterns


@dataclass
class EncryptionFinding:
    finding_type: str  # "high_entropy" | "base64_block" | "jwt_token"
    detail: str


@dataclass
class ScanResult:
    tool_name: str
    patterns: list[PatternMatch] = field(default_factory=list)
    encryption_findings: list[EncryptionFinding] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


# Mapping from pattern type to recommended my_agent_handles type
PATTERN_TO_DATA_TYPE: dict[str, str] = {
    "ssn": "personal_info",
    "credit_card": "credit_cards",
    "email": "personal_info",
    "phone": "personal_info",
    "mrn": "health_records",
    "api_key": "trade_secrets",
}


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _detect_encryption(text: str) -> list[EncryptionFinding]:
    """Detect encrypted/tokenized data in text."""
    findings: list[EncryptionFinding] = []

    # Check for JWT tokens
    import re
    jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
    if jwt_pattern.search(text):
        findings.append(EncryptionFinding(
            "jwt_token",
            "JWT token detected — evidence of token-based authentication in use.",
        ))

    # Check for high-entropy strings (potential encrypted data)
    # Split on whitespace and common delimiters
    tokens = re.split(r'[\s,;:"\'\[\]\{\}]+', text)
    for token in tokens:
        if len(token) > 20:
            entropy = _shannon_entropy(token)
            if entropy > 4.5:
                findings.append(EncryptionFinding(
                    "high_entropy",
                    f"High-entropy string detected (entropy={entropy:.1f}) — possible encrypted or tokenized data.",
                ))
                break  # One finding is enough

    # Check for base64 blocks
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    if b64_pattern.search(text):
        if not jwt_pattern.search(text):  # Don't double-count JWTs
            findings.append(EncryptionFinding(
                "base64_block",
                "Base64-encoded block detected — possible encrypted payload.",
            ))

    return findings


def scan_response(tool_name: str, response_text: str) -> ScanResult:
    """Scan a tool response for sensitive data patterns and encryption indicators."""
    result = ScanResult(tool_name=tool_name)

    # Scan for sensitive data patterns (reuses Unit 2 patterns module)
    result.patterns = scan_for_patterns(response_text)

    # Generate recommendations from detected patterns
    for match in result.patterns:
        data_type = PATTERN_TO_DATA_TYPE.get(match.pattern_type)
        if data_type:
            result.recommendations.append(
                f"Detected {match.pattern_type} patterns ({match.count} found) in responses "
                f"from tool '{tool_name}'. Consider adding '{data_type}' to your "
                f"my_agent_handles configuration."
            )

    # Detect encryption/tokenization (positive finding)
    result.encryption_findings = _detect_encryption(response_text)

    return result
