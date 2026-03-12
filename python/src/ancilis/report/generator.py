"""Core report generation — queries evidence, assembles sections."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

from ancilis.activation.loader import (
    load_certification_profiles,
    load_control_definitions,
    load_overlay_profiles,
)
from ancilis.config import ResolvedConfig
from ancilis.evidence.store import EvidenceStore
from ancilis.report.baseline import build_baseline_section
from ancilis.report.compliance import build_compliance_sections
from ancilis.report.certification import build_certification_section
from ancilis.report.advisory import build_advisory_section


@dataclass
class ReportData:
    """Assembled report data ready for rendering."""

    agent_name: str = ""
    mode: str = "audit"
    period_start: str = ""
    period_end: str = ""
    generated_at: str = ""
    report_format: str = "terminal"

    # Baseline section (always present)
    baseline: dict[str, Any] = field(default_factory=dict)

    # Compliance sections (when overlays active)
    compliance_sections: list[dict[str, Any]] = field(default_factory=list)

    # Certification section (when certification targets active)
    certification: dict[str, Any] | None = None

    # Advisory section (when pattern detections found)
    advisory: dict[str, Any] | None = None

    # Evidence summary
    total_evaluations: int = 0
    chain_valid: bool = True
    chain_errors: list[str] = field(default_factory=list)


def _parse_period(period: str) -> timedelta:
    """Parse a period string like '30d' into a timedelta."""
    if period.endswith("d"):
        return timedelta(days=int(period[:-1]))
    if period.endswith("h"):
        return timedelta(hours=int(period[:-1]))
    return timedelta(days=30)


class ReportGenerator:
    """Generates posture reports from evidence store data."""

    def __init__(self, config: ResolvedConfig, store: EvidenceStore) -> None:
        self._config = config
        self._store = store
        self._control_defs = load_control_definitions()
        self._overlay_profiles = load_overlay_profiles()

    def generate(self, period: str = "30d", report_format: str = "terminal") -> ReportData:
        """Generate a complete report."""
        now = datetime.now(timezone.utc)
        delta = _parse_period(period)
        period_start = now - delta

        data = ReportData(
            agent_name=self._config.agent_name,
            mode=self._config.mode,
            period_start=period_start.isoformat(),
            period_end=now.isoformat(),
            generated_at=now.isoformat(),
            report_format=report_format,
        )

        # Get evidence summary (period-filtered)
        summary = self._store.get_summary(since=period_start.isoformat())
        data.total_evaluations = summary.get("total_evaluations", 0)
        data.chain_valid = summary.get("chain_valid", True)
        data.chain_errors = summary.get("chain_errors", [])

        # 1. Baseline section (always present)
        data.baseline = build_baseline_section(
            self._config, summary, self._control_defs
        )

        # 2. Compliance sections (when overlays active)
        if self._config.active_overlays:
            data.compliance_sections = build_compliance_sections(
                self._config, summary, self._control_defs, self._overlay_profiles
            )

        # 3. Certification section
        if self._config.active_certifications:
            if report_format == "aiuc1-readiness" or "aiuc-1" in self._config.active_certifications:
                cert_profiles = load_certification_profiles(self._config.active_certifications)
                data.certification = build_certification_section(
                    self._config, summary, cert_profiles
                )

        # 4. Advisory section
        data.advisory = build_advisory_section(self._config, summary)

        return data
