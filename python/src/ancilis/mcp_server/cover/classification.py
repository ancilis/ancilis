"""Deterministic project classification for Ancilis Cover."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ancilis.config import load_config
from ancilis.mcp_server.cover.models import CoverSignal, ProjectClassification
from ancilis.mcp_server.cover.project import inspect_project


@dataclass(frozen=True)
class _DataRule:
    handle: str
    terms: tuple[str, ...]


_DATA_RULES: tuple[_DataRule, ...] = (
    _DataRule("credit_cards", ("stripe", "checkout", "card", "payment", "payments", "billing")),
    _DataRule("health_records", ("patient", "clinic", "medical", "mrn", "ehr", "therapist", "therapy")),
    _DataRule("financial_records", ("invoice", "bank", "portfolio", "trading", "kyc", "loan")),
    _DataRule("personal_info", ("email", "address", "profile", "user", "account", "customer")),
    _DataRule("biometric_data", ("biometric", "face", "voiceprint", "fingerprint")),
)


def classify_project(
    root: str | Path | None = None,
    *,
    description: str | None = None,
    signals: Sequence[CoverSignal | Mapping[str, object]] | None = None,
) -> ProjectClassification:
    """Classify likely data handled by a project using deterministic rules only."""
    collected_signals = _coerce_signals(signals)
    if root is not None:
        collected_signals.extend(inspect_project(root).signals)

    emitted: list[CoverSignal] = []
    review_items: list[CoverSignal] = []
    accepted_handles: list[str] = []

    for rule in _DATA_RULES:
        matches = _matches_for_rule(rule, description=description, signals=collected_signals)
        if not matches:
            continue

        confidence = _confidence_for_matches(matches)
        if confidence == "low":
            review_items.extend(matches)
            continue

        accepted_handles.append(rule.handle)
        emitted.extend(matches)

    overlays, classifications = _resolve_activation(accepted_handles)
    overall_confidence = _overall_confidence(emitted, review_items)
    return ProjectClassification(
        my_agent_handles=sorted(set(accepted_handles)),
        data_classifications=classifications,
        active_overlays=overlays,
        confidence=overall_confidence,
        signals=emitted,
        review_items=review_items,
    )


def _coerce_signals(signals: Sequence[CoverSignal | Mapping[str, object]] | None) -> list[CoverSignal]:
    if not signals:
        return []
    out: list[CoverSignal] = []
    for signal in signals:
        if isinstance(signal, CoverSignal):
            out.append(signal)
        else:
            out.append(CoverSignal.model_validate(dict(signal)))
    return out


def _matches_for_rule(
    rule: _DataRule,
    *,
    description: str | None,
    signals: list[CoverSignal],
) -> list[CoverSignal]:
    matches: list[CoverSignal] = []
    description_text = (description or "").lower()
    for term in rule.terms:
        if term in description_text:
            matches.append(
                CoverSignal(
                    source="description",
                    value=term,
                    rule_id=f"data.{rule.handle}.{term}",
                    confidence="medium",
                    recommendation=rule.handle,
                )
            )
        for signal in signals:
            if term not in signal.value.lower():
                continue
            matches.append(
                CoverSignal(
                    source=signal.source,
                    value=signal.value,
                    rule_id=f"data.{rule.handle}.{term}",
                    confidence="high" if signal.source == "dependency" else signal.confidence,
                    recommendation=rule.handle,
                    path=signal.path,
                )
            )
    return _dedupe_signals(matches)


def _dedupe_signals(signals: list[CoverSignal]) -> list[CoverSignal]:
    seen: set[tuple[str, str, str, str | None]] = set()
    out: list[CoverSignal] = []
    for signal in signals:
        key = (signal.source, signal.value, signal.rule_id, signal.path)
        if key in seen:
            continue
        seen.add(key)
        out.append(signal)
    return out


def _confidence_for_matches(matches: list[CoverSignal]) -> str:
    if any(match.confidence == "high" for match in matches) or len(matches) >= 2:
        return "high"
    return "low"


def _resolve_activation(handles: list[str]) -> tuple[list[str], list[str]]:
    if not handles:
        return [], []
    config = load_config(
        raw={
            "agent": {"name": "cover-preview"},
            "my_agent_handles": sorted(set(handles)),
        }
    )
    return sorted(config.active_overlays), sorted(config.data_classifications)


def _overall_confidence(
    signals: list[CoverSignal],
    review_items: list[CoverSignal],
) -> str:
    if signals:
        if len(signals) >= 2:
            return "high"
        return "high" if any(signal.confidence == "high" for signal in signals) else "medium"
    if review_items:
        return "low"
    return "low"
