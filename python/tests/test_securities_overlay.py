"""Focused tests for the securities MNPI overlay."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from click.testing import CliRunner

from ancilis.activation.loader import load_overlay_profiles, load_taxonomy
from ancilis.activation.resolver import ALL_AKSI_CONTROLS, ActivationResolver
from ancilis.cli.main import cli
from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore
from ancilis.report.generator import ReportGenerator
from ancilis.report.renderer import render_terminal


def _write_config(tmp_path: Path, data: dict[str, Any]) -> Path:
    path = tmp_path / "ancilis.yaml"
    path.write_text(yaml.dump(data, default_flow_style=False))
    return path


def _minimal_securities_config() -> dict[str, Any]:
    return {"agent": {"name": "sec-agent"}, "my_agent_handles": ["mnpi"]}


class TestSecuritiesOverlayProfile:
    def test_securities_overlay_profile_loads(self) -> None:
        profiles = load_overlay_profiles()

        assert "securities-mnpi" in profiles

    def test_securities_overlay_metadata_matches_mnpi_activation(self) -> None:
        profile = load_overlay_profiles()["securities-mnpi"]

        assert profile["trigger_type"] == "data_classification"
        assert profile["triggered_by"] == ["DC-MNPI"]
        assert profile["applicable_data_types"] == ["material_nonpublic", "mnpi"]

    def test_mnpi_taxonomy_status_is_active(self) -> None:
        taxonomy = load_taxonomy()
        mnpi = next(entry for entry in taxonomy["classifications"] if entry["code"] == "DC-MNPI")

        assert mnpi["overlay_status"] == "active"
        assert "securities-mnpi" in mnpi["overlays"]

    def test_securities_framework_mapping_covers_all_aksi_controls(self) -> None:
        profile = load_overlay_profiles()["securities-mnpi"]

        assert set(profile["framework_mapping"]) == ALL_AKSI_CONTROLS

    def test_securities_active_controls_reference_reg_fd_and_sox(self) -> None:
        profile = load_overlay_profiles()["securities-mnpi"]
        controls = profile["controls"]

        for control_id in ("PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"):
            reference = controls[control_id]["framework_reference"]
            assert "SEC Reg FD" in reference
            assert "SOX" in reference

    def test_securities_sets_strict_thresholds_for_market_sensitive_controls(self) -> None:
        profile = load_overlay_profiles()["securities-mnpi"]
        adjustments = profile["control_adjustments"]

        for control_id in ("PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"):
            assert adjustments[control_id]["threshold_adjustment"] == "strict"

    def test_resolver_activates_securities_overlay_for_mnpi(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["mnpi"])

        assert "DC-MNPI" in spec.data_classifications
        assert "securities-mnpi" in spec.active_overlays
        assert spec.control_thresholds["PR-01"] == "strict"
        assert spec.control_thresholds["PR-05"] == "strict"
        assert spec.evidence_requirements["PR-01"]

    def test_resolver_activates_securities_overlay_for_material_nonpublic(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["material_nonpublic"])

        assert "DC-MNPI" in spec.data_classifications
        assert "securities-mnpi" in spec.active_overlays

    def test_config_resolution_applies_securities_retention_and_no_unavailable_overlay(self) -> None:
        resolved = load_config(raw=_minimal_securities_config())

        assert "securities-mnpi" in resolved.active_overlays
        assert resolved.evidence_retention_days == 2555
        assert all(item.overlay_id != "securities-mnpi" for item in resolved.unavailable_overlays)

    def test_config_validate_surfaces_securities_overlay(self, tmp_path: Path) -> None:
        cfg = _write_config(tmp_path, _minimal_securities_config())
        runner = CliRunner()

        result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])

        assert result.exit_code == 0
        assert "Securities Markets" in result.output

    def test_report_generator_includes_securities_overlay_section(self) -> None:
        resolved = load_config(raw=_minimal_securities_config())
        store = EvidenceStore(resolved, in_memory=True)
        try:
            report = ReportGenerator(resolved, store).generate()
        finally:
            store.close()

        assert any(section["overlay_id"] == "securities-mnpi" for section in report.compliance_sections)
        assert "Securities Markets" in render_terminal(report)
