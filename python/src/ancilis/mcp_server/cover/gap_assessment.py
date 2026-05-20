"""Deterministic setup gap assessment for Ancilis Cover."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ancilis.config import ResolvedConfig, load_config
from ancilis.mcp_server.cover.code_review import review_code
from ancilis.mcp_server.cover.models import (
    ConfigGap,
    EvidenceGap,
    GapAssessmentResult,
    GapReviewItem,
    InstrumentationGap,
)
from ancilis.mcp_server.cover.normalization import normalize_gap_target
from ancilis.mcp_server.cover.project import inspect_project


def assess_gap(
    root: str | Path | None = None,
    *,
    business_context: str | None = None,
    target_data_types: Sequence[str] | None = None,
    target_overlays: Sequence[str] | None = None,
    target_certifications: Sequence[str] | None = None,
    session_id: str | None = None,
    include_code_review: bool = False,
    paths: Sequence[str | Path] | None = None,
    runtime_context: Any | None = None,
) -> GapAssessmentResult:
    """Compare normalized business targets to local project setup state."""
    root_path = (Path.cwd() if root is None else Path(root)).resolve()
    inspection = inspect_project(root_path)
    normalization = normalize_gap_target(
        business_context=business_context,
        target_data_types=target_data_types,
        target_overlays=target_overlays,
        target_certifications=target_certifications,
    )

    warnings = list(inspection.warnings)
    config = _load_project_config(inspection.config_path, runtime_context, warnings)
    config_gap = _config_gap(normalization.target, config)
    instrumentation_gap = InstrumentationGap(
        recommended_producers=sorted(inspection.recommended_producers),
        present_producers=[],
        missing_producers=sorted(inspection.recommended_producers),
    )
    review_items = list(normalization.review_items)

    if include_code_review:
        code_review = review_code(root_path, paths=paths)
        review_items.extend(
            GapReviewItem(
                source="code_review",
                value=finding.category,
                reason=finding.message,
            )
            for finding in code_review.findings
        )

    evidence_gap = EvidenceGap(
        session_id=session_id,
        requested_overlays=list(normalization.target.active_overlays),
    )
    return GapAssessmentResult(
        mode="evidence_gap" if evidence_gap.session_id else "setup_gap",
        target=normalization.target,
        normalization_signals=normalization.signals,
        review_items=review_items,
        project={
            "ancilis_present": inspection.ancilis_present,
            "recommended_producers": list(inspection.recommended_producers),
            "languages": list(inspection.languages),
        },
        config_gap=config_gap,
        instrumentation_gap=instrumentation_gap,
        evidence_gap=evidence_gap,
        next_steps=_next_steps(
            config_gap=config_gap,
            config_present=inspection.ancilis_present,
            missing_producers=instrumentation_gap.missing_producers,
            evidence_gap=evidence_gap,
        ),
        confidence=normalization.confidence,
        warnings=warnings,
    )


def _load_project_config(
    config_path: str | None,
    runtime_context: Any | None,
    warnings: list[str],
) -> ResolvedConfig | None:
    if config_path is not None:
        try:
            config = load_config(path=config_path)
        except Exception as exc:
            warnings.append(f"config_load_error:{config_path}:{exc}")
        else:
            warnings.extend(config.warnings)
            return config

    if runtime_context is not None:
        config = getattr(runtime_context, "config", None)
        if config is not None:
            warnings.extend(getattr(config, "warnings", []) or [])
            return config

    if config_path is None:
        warnings.append("config_not_found:ancilis.yaml")
    return None


def _config_gap(target: Any, config: ResolvedConfig | None) -> ConfigGap:
    present_handles = set(getattr(config, "data_classifications", {}) or {})
    present_overlays = set(getattr(config, "active_overlays", {}) or {})
    present_certs = set(getattr(config, "active_certifications", []) or [])

    target_handles = set(target.my_agent_handles)
    target_overlays = set(target.active_overlays)
    target_certs = set(target.certification_targets)

    return ConfigGap(
        missing_my_agent_handles=sorted(target_handles - present_handles),
        present_my_agent_handles=sorted(target_handles & present_handles),
        missing_overlays=sorted(target_overlays - present_overlays),
        present_overlays=sorted(target_overlays & present_overlays),
        missing_certification_targets=sorted(target_certs - present_certs),
        present_certification_targets=sorted(target_certs & present_certs),
    )


def _next_steps(
    *,
    config_gap: ConfigGap,
    config_present: bool,
    missing_producers: Sequence[str],
    evidence_gap: EvidenceGap,
) -> list[str]:
    steps: list[str] = []
    if _has_config_gap(config_gap):
        if config_present:
            steps.append("Update ancilis.yaml with missing data, overlay, and certification targets.")
        else:
            steps.append("Create ancilis.yaml with the requested data, overlay, and certification targets.")
    if missing_producers:
        producers = ", ".join(sorted(missing_producers))
        steps.append(f"Wrap recommended producer surfaces with Ancilis instrumentation: {producers}.")
    if evidence_gap.session_id is None:
        steps.append("Run ancilis doctor and ancilis scan after setup to collect evidence.")
    return steps


def _has_config_gap(config_gap: ConfigGap) -> bool:
    return bool(
        config_gap.missing_my_agent_handles
        or config_gap.missing_overlays
        or config_gap.missing_certification_targets
    )
