"""Focused tests for the financial services overlay."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from click.testing import CliRunner

from ancilis.activation.loader import load_overlay_profiles, load_taxonomy
from ancilis.activation.resolver import COMMON_AKSI_CONTROLS, ActivationResolver
from ancilis.cli.main import cli
from ancilis.config import load_config


def _write_config(tmp_path: Path, data: dict[str, Any]) -> Path:
    path = tmp_path / "ancilis.yaml"
    path.write_text(yaml.dump(data, default_flow_style=False))
    return path


def _minimal_financial_config() -> dict[str, Any]:
    return {"agent": {"name": "fin-agent"}, "my_agent_handles": ["financial_data"]}


class TestFinancialOverlayProfile:
    def test_glba_overlay_profile_loads(self) -> None:
        profiles = load_overlay_profiles()

        assert "glba" in profiles

    def test_glba_overlay_metadata_matches_financial_activation(self) -> None:
        profile = load_overlay_profiles()["glba"]

        assert profile["trigger_type"] == "data_classification"
        assert profile["triggered_by"] == ["DC-FIN"]
        assert profile["applicable_data_types"] == ["financial_data", "financial_records"]

    def test_financial_taxonomy_status_is_active(self) -> None:
        taxonomy = load_taxonomy()
        fin = next(entry for entry in taxonomy["classifications"] if entry["code"] == "DC-FIN")

        assert fin["overlay_status"] == "active"
        assert "glba" in fin["overlays"]

    def test_glba_framework_mapping_covers_all_aksi_controls(self) -> None:
        profile = load_overlay_profiles()["glba"]

        assert set(profile["framework_mapping"]) == COMMON_AKSI_CONTROLS

    def test_glba_active_controls_reference_glba_sox_and_dora(self) -> None:
        profile = load_overlay_profiles()["glba"]
        controls = profile["controls"]

        for control_id in ("PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"):
            reference = controls[control_id]["framework_reference"]
            assert "314.4" in reference
            assert "SOX" in reference
            assert "DORA" in reference

    def test_glba_sets_strict_thresholds_for_financial_high_risk_controls(self) -> None:
        profile = load_overlay_profiles()["glba"]
        adjustments = profile["control_adjustments"]

        for control_id in ("PR-01", "PR-02", "PR-04", "PR-05", "DE-01"):
            assert adjustments[control_id]["threshold_adjustment"] == "strict"

    def test_resolver_activates_glba_for_financial_data(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["financial_data"])

        assert "DC-FIN" in spec.data_classifications
        assert "glba" in spec.active_overlays
        assert "soc2" in spec.active_overlays
        assert spec.control_thresholds["PR-01"] == "strict"
        assert spec.control_thresholds["PR-05"] == "strict"

    def test_resolver_activates_glba_for_financial_records(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["financial_records"])

        assert "DC-FIN" in spec.data_classifications
        assert "glba" in spec.active_overlays

    def test_config_resolution_applies_financial_retention_and_no_unavailable_overlay(self) -> None:
        resolved = load_config(raw=_minimal_financial_config())

        assert "glba" in resolved.active_overlays
        assert resolved.evidence_retention_days == 2555
        assert all(item.overlay_id != "glba" for item in resolved.unavailable_overlays)

    def test_config_validate_surfaces_financial_overlay(self, tmp_path: Path) -> None:
        cfg = _write_config(tmp_path, _minimal_financial_config())
        runner = CliRunner()

        result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])

        assert result.exit_code == 0
        assert "Financial Services" in result.output
