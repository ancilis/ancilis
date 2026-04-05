"""Focused tests for the government CUI overlay."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from click.testing import CliRunner

from ancilis.activation.loader import load_overlay_profiles, load_taxonomy
from ancilis.activation.resolver import ALL_AKSI_CONTROLS, ActivationResolver
from ancilis.cli.main import cli
from ancilis.config import load_config


def _write_config(tmp_path: Path, data: dict[str, Any]) -> Path:
    path = tmp_path / "ancilis.yaml"
    path.write_text(yaml.dump(data, default_flow_style=False))
    return path


def _minimal_government_config() -> dict[str, Any]:
    return {"agent": {"name": "gov-agent"}, "my_agent_handles": ["government_cui"]}


class TestGovernmentOverlayProfile:
    def test_cmmc_overlay_profile_loads(self) -> None:
        profiles = load_overlay_profiles()

        assert "cmmc-l2" in profiles

    def test_cmmc_overlay_metadata_matches_government_activation(self) -> None:
        profile = load_overlay_profiles()["cmmc-l2"]

        assert profile["trigger_type"] == "data_classification"
        assert set(profile["triggered_by"]) == {"DC-CUI", "DC-GOV"}
        assert "government_cui" in profile["applicable_data_types"]

    def test_government_taxonomy_status_is_active(self) -> None:
        taxonomy = load_taxonomy()
        gov = next(entry for entry in taxonomy["classifications"] if entry["code"] == "DC-GOV")
        cui = next(entry for entry in taxonomy["classifications"] if entry["code"] == "DC-CUI")

        assert gov["overlay_status"] == "active"
        assert "cmmc-l2" in gov["overlays"]
        assert cui["overlay_status"] == "active"
        assert "cmmc-l2" in cui["overlays"]

    def test_cmmc_framework_mapping_covers_all_aksi_controls(self) -> None:
        profile = load_overlay_profiles()["cmmc-l2"]

        assert set(profile["framework_mapping"]) == ALL_AKSI_CONTROLS

    def test_cmmc_active_controls_reference_cmmc_and_nist(self) -> None:
        profile = load_overlay_profiles()["cmmc-l2"]
        controls = profile["controls"]

        for control_id in ("PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"):
            reference = controls[control_id]["framework_reference"]
            assert "CMMC Level 2" in reference
            assert "NIST SP 800-171 Rev. 3" in reference
            assert "03." in reference

    def test_cmmc_sets_strict_thresholds_for_government_high_risk_controls(self) -> None:
        profile = load_overlay_profiles()["cmmc-l2"]
        adjustments = profile["control_adjustments"]

        for control_id in ("PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"):
            assert adjustments[control_id]["threshold_adjustment"] == "strict"

    def test_resolver_activates_cmmc_for_government_cui(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["government_cui"])

        assert "cmmc-l2" in spec.active_overlays
        assert "DC-CUI" in spec.data_classifications
        assert spec.control_thresholds["PR-01"] == "strict"
        assert spec.control_thresholds["PR-05"] == "strict"
        assert spec.evidence_requirements["PR-01"]

    def test_resolver_activates_cmmc_for_controlled_unclassified(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["controlled_unclassified"])

        assert "DC-CUI" in spec.data_classifications
        assert "cmmc-l2" in spec.active_overlays

    def test_config_resolution_applies_government_retention_and_no_unavailable_overlay(self) -> None:
        resolved = load_config(raw=_minimal_government_config())

        assert "cmmc-l2" in resolved.active_overlays
        assert resolved.evidence_retention_days >= 365
        assert all(item.overlay_id != "cmmc-l2" for item in resolved.unavailable_overlays)

    def test_config_validate_surfaces_government_overlay(self, tmp_path: Path) -> None:
        cfg = _write_config(tmp_path, _minimal_government_config())
        runner = CliRunner()

        result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])

        assert result.exit_code == 0
        assert "CMMC Level 2" in result.output
