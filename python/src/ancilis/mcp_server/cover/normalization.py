"""Deterministic business phrase normalization for Cover gap targets."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from pydantic import BaseModel, Field

from ancilis.activation.loader import (
    load_certification_profile,
    load_overlay_profiles,
    load_taxonomy,
)
from ancilis.mcp_server.cover.models import (
    GapReviewItem,
    GapTarget,
    NormalizationSignal,
)
from ancilis.overlays import normalize_overlay_ids


@dataclass(frozen=True)
class _PhraseRule:
    target_type: str
    mapped_to: str
    patterns: tuple[str, ...]
    confidence: str = "high"


class GapNormalizationResult(BaseModel):
    """Normalized target state plus deterministic signals and review notes."""

    target: GapTarget
    signals: list[NormalizationSignal] = Field(default_factory=list)
    review_items: list[GapReviewItem] = Field(default_factory=list)
    confidence: str = "low"


_DATA_TARGET = "my_agent_handles"
_OVERLAY_TARGET = "active_overlays"
_CERT_TARGET = "certification_targets"

_PHRASE_RULES: tuple[_PhraseRule, ...] = (
    _PhraseRule(
        _DATA_TARGET,
        "health_records",
        (
            r"\bpatients?\b",
            r"\bpatient records?\b",
            r"\bmedical records?\b",
            r"\bmedical\b",
            r"\bclinics?\b",
            r"\btherapy\b",
            r"\btherap(?:y|ist|ists)\b",
            r"\behrs?\b",
            r"\bmrn\b",
            r"\bphi\b",
            r"\bprotected health information\b",
        ),
    ),
    _PhraseRule(
        _OVERLAY_TARGET,
        "hipaa",
        (r"\bhipaa\b", r"\bhealth insurance portability\b"),
    ),
    _PhraseRule(
        _DATA_TARGET,
        "credit_cards",
        (
            r"\bcredit cards?\b",
            r"\bcards?\b",
            r"\bcardholders?\b",
            r"\bcheckout\b",
            r"\bstripe\b",
            r"\bpayments?\b",
            r"\bbilling\b",
        ),
    ),
    _PhraseRule(
        _OVERLAY_TARGET,
        "pci-dss-v4",
        (r"\bpci\b", r"\bpci[-\s]?dss\b", r"\bpayment card industry\b"),
    ),
    _PhraseRule(
        _DATA_TARGET,
        "personal_info",
        (
            r"\bcustomers?\b",
            r"\busers?\b",
            r"\bemails?\b",
            r"\baddresses?\b",
            r"\bprofiles?\b",
            r"\baccounts?\b",
        ),
        confidence="medium",
    ),
    _PhraseRule(
        _OVERLAY_TARGET,
        "gdpr",
        (r"\bgdpr\b", r"\beu\b", r"\beuropean union\b", r"\bdata subjects?\b"),
    ),
    _PhraseRule(
        _OVERLAY_TARGET,
        "soc2",
        (
            r"\bsoc\s*2\b",
            r"\bsoc2\b",
            r"\bservice organization control\b",
            r"\btrust services\b",
        ),
    ),
    _PhraseRule(
        _DATA_TARGET,
        "financial_records",
        (
            r"\bbanks?\b",
            r"\bkyc\b",
            r"\bloans?\b",
            r"\btrading\b",
            r"\bportfolios?\b",
            r"\binvoices?\b",
        ),
    ),
    _PhraseRule(
        _DATA_TARGET,
        "biometric_data",
        (r"\bbiometrics?\b", r"\bfaces?\b", r"\bfingerprints?\b", r"\bvoiceprints?\b"),
    ),
)

_UNKNOWN_COMPLIANCE_RE = re.compile(
    r"\b((?:[a-z][a-z0-9-]*|\d{1,5})(?:\s+(?:[a-z][a-z0-9-]*|\d{1,5})){0,5}\s+compliance)\b",
    re.IGNORECASE,
)
_COMPLIANCE_LEADERS = {"and", "for", "need", "needs", "require", "requires", "we"}
_GENERIC_COMPLIANCE_SUBJECTS = {"need", "needs", "require", "requires"}


def normalize_gap_target(
    *,
    business_context: str | None = None,
    target_data_types: Sequence[str] | None = None,
    target_overlays: Sequence[str] | None = None,
    target_certifications: Sequence[str] | None = None,
) -> GapNormalizationResult:
    """Map business phrases and explicit targets to Ancilis gap target terms."""
    valid_data_types = set(load_taxonomy().get("developer_type_mapping", {}))
    valid_overlays = set(load_overlay_profiles())

    handles: set[str] = set()
    overlays: set[str] = set()
    certifications: set[str] = set()
    signals: list[NormalizationSignal] = []
    review_items: list[GapReviewItem] = []

    context = business_context or ""
    for rule in _PHRASE_RULES:
        for phrase in _matching_phrases(context, rule.patterns):
            _add_target(rule.target_type, rule.mapped_to, handles, overlays, certifications)
            signals.append(
                NormalizationSignal(
                    source="business_context",
                    phrase=phrase,
                    mapped_to=rule.mapped_to,
                    target_type=rule.target_type,
                    confidence=rule.confidence,
                )
            )

    _add_explicit_targets(
        target_data_types,
        target_type=_DATA_TARGET,
        valid_values=valid_data_types,
        target_values=handles,
        signals=signals,
        review_items=review_items,
    )
    _add_explicit_targets(
        normalize_overlay_ids(list(target_overlays or [])),
        target_type=_OVERLAY_TARGET,
        valid_values=valid_overlays,
        target_values=overlays,
        signals=signals,
        review_items=review_items,
    )
    _add_explicit_certifications(
        target_certifications,
        certifications=certifications,
        signals=signals,
        review_items=review_items,
    )

    for phrase in _unknown_compliance_phrases(context):
        if _compliance_phrase_already_mapped(phrase, signals):
            continue
        review_items.append(
            GapReviewItem(
                source="business_context",
                value=phrase,
                reason="unmapped_compliance_phrase",
            )
        )

    return GapNormalizationResult(
        target=GapTarget(
            my_agent_handles=sorted(handles),
            active_overlays=sorted(overlays),
            certification_targets=sorted(certifications),
        ),
        signals=_dedupe_signals(signals),
        review_items=_dedupe_review_items(review_items),
        confidence=_overall_confidence(signals, review_items),
    )


def _matching_phrases(text: str, patterns: Iterable[str]) -> list[str]:
    matches: list[str] = []
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            phrase = match.group(0).strip()
            if phrase and phrase.lower() not in {item.lower() for item in matches}:
                matches.append(phrase)
    return matches


def _add_target(
    target_type: str,
    value: str,
    handles: set[str],
    overlays: set[str],
    certifications: set[str],
) -> None:
    if target_type == _DATA_TARGET:
        handles.add(value)
    elif target_type == _OVERLAY_TARGET:
        overlays.add(value)
    elif target_type == _CERT_TARGET:
        certifications.add(value)


def _add_explicit_targets(
    values: Sequence[str] | None,
    *,
    target_type: str,
    valid_values: set[str],
    target_values: set[str],
    signals: list[NormalizationSignal],
    review_items: list[GapReviewItem],
) -> None:
    for raw_value in values or []:
        value = raw_value.strip()
        if not value:
            continue
        if value not in valid_values:
            review_items.append(
                GapReviewItem(
                    source="explicit_input",
                    value=value,
                    reason=f"unknown_{target_type}",
                )
            )
            continue
        target_values.add(value)
        signals.append(
            NormalizationSignal(
                source="explicit_input",
                phrase=value,
                mapped_to=value,
                target_type=target_type,
                confidence="high",
            )
        )


def _add_explicit_certifications(
    values: Sequence[str] | None,
    *,
    certifications: set[str],
    signals: list[NormalizationSignal],
    review_items: list[GapReviewItem],
) -> None:
    for raw_value in values or []:
        value = raw_value.strip()
        if not value:
            continue
        if load_certification_profile(value) is None:
            review_items.append(
                GapReviewItem(
                    source="explicit_input",
                    value=value,
                    reason="unknown_certification_targets",
                )
            )
            continue
        certifications.add(value)
        signals.append(
            NormalizationSignal(
                source="explicit_input",
                phrase=value,
                mapped_to=value,
                target_type=_CERT_TARGET,
                confidence="high",
            )
        )


def _unknown_compliance_phrases(text: str) -> list[str]:
    phrases: list[str] = []
    for match in _UNKNOWN_COMPLIANCE_RE.finditer(text):
        for phrase in _candidate_compliance_phrases(match.group(1).strip().lower()):
            if phrase in {"hipaa compliance", "pci compliance", "gdpr compliance", "soc2 compliance"}:
                continue
            phrases.append(phrase)
    return phrases


def _candidate_compliance_phrases(phrase: str) -> list[str]:
    phrase = _trim_compliance_phrase(phrase)
    subject = phrase.removesuffix(" compliance").strip()
    if not subject or subject in _GENERIC_COMPLIANCE_SUBJECTS:
        return []
    if " and " not in subject:
        return [phrase]
    return [
        f"{part.strip()} compliance"
        for part in subject.split(" and ")
        if part.strip() and part.strip() not in _GENERIC_COMPLIANCE_SUBJECTS
    ]


def _trim_compliance_phrase(phrase: str) -> str:
    tokens = phrase.split()
    while len(tokens) > 2 and tokens[0] in _COMPLIANCE_LEADERS:
        tokens.pop(0)
    return " ".join(tokens)


def _compliance_phrase_already_mapped(
    phrase: str,
    signals: list[NormalizationSignal],
) -> bool:
    normalized_subject = _normalize_token(
        phrase.lower().removesuffix(" compliance").strip()
    )
    for signal in signals:
        if signal.target_type != _OVERLAY_TARGET:
            continue
        if normalized_subject in {
            _normalize_token(signal.phrase),
            _normalize_token(signal.mapped_to),
        }:
            return True
    return False


def _normalize_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _dedupe_signals(signals: list[NormalizationSignal]) -> list[NormalizationSignal]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[NormalizationSignal] = []
    for signal in signals:
        key = (signal.source, signal.phrase.lower(), signal.mapped_to, signal.target_type)
        if key in seen:
            continue
        seen.add(key)
        out.append(signal)
    return out


def _dedupe_review_items(review_items: list[GapReviewItem]) -> list[GapReviewItem]:
    seen: set[tuple[str, str, str]] = set()
    out: list[GapReviewItem] = []
    for item in review_items:
        key = (item.source, item.value.lower(), item.reason)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _overall_confidence(
    signals: list[NormalizationSignal],
    review_items: list[GapReviewItem],
) -> str:
    if review_items:
        return "low"
    if any(signal.confidence == "high" for signal in signals):
        return "high"
    if any(signal.confidence == "medium" for signal in signals):
        return "medium"
    return "low"
