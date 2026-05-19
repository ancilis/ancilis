"""Focused tests for the FedRAMP Rev 5 Moderate overlay."""

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


def _minimal_fedramp_config() -> dict[str, Any]:
    return {"agent": {"name": "fedramp-agent"}, "my_agent_handles": ["federal_contract"]}


class TestFedRAMPOverlayProfile:
    def test_fedramp_overlay_profile_loads(self) -> None:
        profiles = load_overlay_profiles()

        assert "fedramp" in profiles

    def test_fedramp_overlay_metadata_matches_federal_activation(self) -> None:
        profile = load_overlay_profiles()["fedramp"]

        assert profile["trigger_type"] == "data_classification"
        assert set(profile["triggered_by"]) == {"DC-FCI", "DC-GOV"}
        assert "federal_contract" in profile["applicable_data_types"]
        assert "fedramp_system" in profile["applicable_data_types"]

    def test_federal_taxonomy_status_is_active(self) -> None:
        taxonomy = load_taxonomy()
        fci = next(entry for entry in taxonomy["classifications"] if entry["code"] == "DC-FCI")
        gov = next(entry for entry in taxonomy["classifications"] if entry["code"] == "DC-GOV")

        assert fci["overlay_status"] == "active"
        assert "fedramp" in fci["overlays"]
        assert gov["overlay_status"] == "active"
        assert "fedramp" in gov["overlays"]

    def test_fedramp_framework_mapping_covers_all_aksi_controls(self) -> None:
        profile = load_overlay_profiles()["fedramp"]

        assert set(profile["framework_mapping"]) == COMMON_AKSI_CONTROLS

    def test_fedramp_active_controls_reference_nist_800_53_rev5(self) -> None:
        profile = load_overlay_profiles()["fedramp"]
        controls = profile["controls"]

        for control_id in ("PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"):
            reference = controls[control_id]["framework_reference"]
            assert "NIST SP 800-53 Rev 5" in reference
            assert "FedRAMP Moderate" in reference

    def test_fedramp_sets_strict_thresholds_for_all_active_controls(self) -> None:
        profile = load_overlay_profiles()["fedramp"]
        adjustments = profile["control_adjustments"]

        for control_id in ("PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"):
            assert adjustments[control_id]["threshold_adjustment"] == "strict"

    def test_fedramp_evidence_fields_do_not_overlap_with_cmmc_l2(self) -> None:
        profiles = load_overlay_profiles()
        fedramp_fields: set[str] = set()
        cmmc_fields: set[str] = set()

        for fields in profiles["fedramp"]["evidence_requirements"].values():
            fedramp_fields.update(fields)
        for fields in profiles["cmmc-l2"]["evidence_requirements"].values():
            cmmc_fields.update(fields)

        overlap = fedramp_fields & cmmc_fields
        assert not overlap, f"Evidence field overlap between fedramp and cmmc-l2: {overlap}"

    def test_resolver_activates_fedramp_for_federal_contract(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["federal_contract"])

        assert "fedramp" in spec.active_overlays
        assert "DC-FCI" in spec.data_classifications
        assert spec.control_thresholds["PR-01"] == "strict"
        assert spec.control_thresholds["PR-05"] == "strict"
        assert spec.evidence_requirements["PR-01"]

    def test_resolver_activates_fedramp_for_fedramp_system(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["fedramp_system"])

        assert "DC-FCI" in spec.data_classifications
        assert "fedramp" in spec.active_overlays

    def test_resolver_activates_fedramp_for_government_system(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["government_system"])

        assert "DC-GOV" in spec.data_classifications
        assert "fedramp" in spec.active_overlays

    def test_resolver_activates_both_fedramp_and_cmmc_for_gov_system(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["government_system"])

        assert "fedramp" in spec.active_overlays
        assert "cmmc-l2" in spec.active_overlays

    def test_fedramp_breach_notification_is_one_hour(self) -> None:
        profile = load_overlay_profiles()["fedramp"]

        assert profile["reporting_obligations"]["breach_notification_hours"] == 1

    def test_fedramp_retention_is_1095_days(self) -> None:
        profile = load_overlay_profiles()["fedramp"]

        assert profile["evidence_retention_minimum_days"] == 1095

    def test_config_resolution_applies_fedramp_overlay(self) -> None:
        resolved = load_config(raw=_minimal_fedramp_config())

        assert "fedramp" in resolved.active_overlays
        assert resolved.evidence_retention_days >= 365
        assert all(item.overlay_id != "fedramp" for item in resolved.unavailable_overlays)

    def test_config_validate_surfaces_fedramp_overlay(self, tmp_path: Path) -> None:
        cfg = _write_config(tmp_path, _minimal_fedramp_config())
        runner = CliRunner()

        result = runner.invoke(cli, ["config", "validate", "--config", str(cfg)])

        assert result.exit_code == 0
        assert "FedRAMP" in result.output
