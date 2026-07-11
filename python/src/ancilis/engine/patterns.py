"""Sensitive data pattern definitions for PR-04 Data Exposure Prevention."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class PatternMatch:
    pattern_type: str
    count: int
    redacted_sample: str


# --- Pattern Definitions ---

SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
US_PHONE_PATTERN = re.compile(
    r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)
CREDIT_CARD_PATTERN = re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,7}\b")
API_KEY_PATTERN = re.compile(
    r"\b(?:sk|pk|api|key|token|secret|bearer)[-_]?[A-Za-z0-9]{20,}\b", re.IGNORECASE
)
MRN_PATTERN = re.compile(r"\bMRN[-:\s]?\d{6,}\b", re.IGNORECASE)


def _luhn_check(number: str) -> bool:
    """Validate a number string using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _redact_ssn(match: str) -> str:
    return f"***-**-{match[-4:]}"


def _redact_email(match: str) -> str:
    parts = match.split("@")
    local = parts[0]
    domain = parts[1] if len(parts) > 1 else ""
    redacted_local = local[0] + "***" if local else "***"
    return f"{redacted_local}@{domain}"


def _redact_card(match: str) -> str:
    digits = "".join(c for c in match if c.isdigit())
    return f"****-****-****-{digits[-4:]}"


def _redact_phone(match: str) -> str:
    digits = "".join(c for c in match if c.isdigit())
    return f"***-***-{digits[-4:]}"


def _redact_api_key(match: str) -> str:
    return f"{match[:4]}***"


def _redact_mrn(match: str) -> str:
    digits = "".join(c for c in match if c.isdigit())
    return f"MRN-***{digits[-3:]}"


def scan_for_patterns(text: str) -> list[PatternMatch]:
    """Scan text for sensitive data patterns. Returns list of PatternMatch."""
    results: list[PatternMatch] = []

    ssn_matches = SSN_PATTERN.findall(text)
    if ssn_matches:
        results.append(PatternMatch("ssn", len(ssn_matches), _redact_ssn(ssn_matches[0])))

    card_matches = CREDIT_CARD_PATTERN.findall(text)
    luhn_valid = [m for m in card_matches if _luhn_check(m)]
    if luhn_valid:
        results.append(
            PatternMatch("credit_card", len(luhn_valid), _redact_card(luhn_valid[0]))
        )

    email_matches = EMAIL_PATTERN.findall(text)
    if email_matches:
        results.append(
            PatternMatch("email", len(email_matches), _redact_email(email_matches[0]))
        )

    phone_matches = US_PHONE_PATTERN.findall(text)
    if phone_matches:
        results.append(
            PatternMatch("phone", len(phone_matches), _redact_phone(phone_matches[0]))
        )

    api_key_matches = API_KEY_PATTERN.findall(text)
    if api_key_matches:
        results.append(
            PatternMatch("api_key", len(api_key_matches), _redact_api_key(api_key_matches[0]))
        )

    mrn_matches = MRN_PATTERN.findall(text)
    if mrn_matches:
        results.append(
            PatternMatch("mrn", len(mrn_matches), _redact_mrn(mrn_matches[0]))
        )

    return results


def scan_parameters(params: dict) -> list[PatternMatch]:  # type: ignore[type-arg]
    """Recursively scan a parameter dict for sensitive data patterns."""
    import json

    text = json.dumps(params, default=str)
    return scan_for_patterns(text)


_DESTINATION_KEYS = ("destination", "url", "endpoint", "host", "server")
_DESTINATION_MAX_DEPTH = 8


def extract_destinations(params: Any, _depth: int = 0) -> list[str]:
    """Collect every destination-like value in an action's raw parameters.

    Producers nest call arguments (e.g. ToolActionProducer stores
    {"args": [...], "kwargs": {...}}), so a top-level-only lookup misses
    the destination entirely and destination policy never fires. Returns
    ALL candidates rather than the first match: with both "url" and
    "destination" present, enforcing against only one lets the other slip
    a blocked value through. Callers must treat any blocked candidate as
    a violation (fail-safe). Order is deterministic (key priority, then
    traversal order); duplicates removed.
    """
    found: list[str] = []
    _collect_destinations(params, 0, found)
    seen: set[str] = set()
    unique: list[str] = []
    for value in found:
        if value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


def _collect_destinations(params: Any, depth: int, out: list[str]) -> None:
    if depth > _DESTINATION_MAX_DEPTH:
        return
    if isinstance(params, dict):
        for key in _DESTINATION_KEYS:
            value = params.get(key)
            if isinstance(value, str):
                out.append(value)
        for key, value in params.items():
            if key in _DESTINATION_KEYS and isinstance(value, str):
                continue
            _collect_destinations(value, depth + 1, out)
    elif isinstance(params, (list, tuple)):
        for item in params:
            _collect_destinations(item, depth + 1, out)


def extract_destination(params: Any) -> str | None:
    """First destination candidate, for callers that only report one."""
    candidates = extract_destinations(params)
    return candidates[0] if candidates else None
