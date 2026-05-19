"""Focused tests for the government CUI overlay."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from click.testing import CliRunner

from ancilis.activation.loader import (
    load_certification_profile,
    load_overlay_profiles,
    load_taxonomy,
)
from ancilis.activation.resolver import COMMON_AKSI_CONTROLS, ActivationResolver
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

        assert set(profile["framework_mapping"]) == COMMON_AKSI_CONTROLS

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

    # --- regulatory_mappings.cmmc coverage (ANC-550 acceptance criterion) ---

    def test_all_common_aksi_controls_have_regulatory_mappings_cmmc(self) -> None:
        profile = load_overlay_profiles()["cmmc-l2"]
        controls = profile["controls"]

        assert set(controls.keys()) == COMMON_AKSI_CONTROLS, (
            "CMMC-L2 must cover all 39 common AKSI controls"
        )
        for control_id, control in controls.items():
            assert "regulatory_mappings" in control, (
                f"{control_id} missing regulatory_mappings field"
            )
            assert "cmmc" in control["regulatory_mappings"], (
                f"{control_id} missing regulatory_mappings.cmmc field"
            )

    def test_enforced_controls_have_non_empty_cmmc_practice_refs(self) -> None:
        """The 6 enforced evaluator controls must all have explicit CMMC practice codes."""
        profile = load_overlay_profiles()["cmmc-l2"]
        controls = profile["controls"]

        enforced = ("PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01")
        for control_id in enforced:
            practices = controls[control_id]["regulatory_mappings"]["cmmc"]
            assert practices, f"{control_id} has empty CMMC practice list"
            for p in practices:
                assert ".L2-" in p, f"{control_id} practice '{p}' does not look like a CMMC L2 code"

    def test_gap_controls_have_cmmc_gap_note(self) -> None:
        """GOV-04, ID-04, RC-01 have no direct CMMC L2 practice — must document gap."""
        profile = load_overlay_profiles()["cmmc-l2"]
        controls = profile["controls"]

        gap_controls = ("GOV-04", "ID-04", "RC-01")
        for control_id in gap_controls:
            rm = controls[control_id]["regulatory_mappings"]
            assert rm["cmmc"] == [], f"{control_id} expected empty cmmc list (gap), got {rm['cmmc']}"
            assert "cmmc_gap" in rm, f"{control_id} missing cmmc_gap explanation"
            assert rm["cmmc_gap"], f"{control_id} cmmc_gap note is empty"

    def test_cmmc_notes_documents_gap_analysis(self) -> None:
        profile = load_overlay_profiles()["cmmc-l2"]

        assert "GAP ANALYSIS" in profile.get("notes", "").upper() or "gap" in profile.get("notes", "").lower()
        assert "GOV-04" in profile["notes"]
        assert "ID-04" in profile["notes"]
        assert "RC-01" in profile["notes"]


class TestGovernmentSystemHandle:
    """government_system handle should activate both CMMC L2 and FedRAMP."""

    def test_government_system_activates_cmmc_l2(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["government_system"])

        assert "DC-GOV" in spec.data_classifications
        assert "cmmc-l2" in spec.active_overlays

    def test_government_system_activates_fedramp(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["government_system"])

        assert "fedramp" in spec.active_overlays

    def test_government_system_activates_both_overlays(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["government_system"])

        assert "cmmc-l2" in spec.active_overlays
        assert "fedramp" in spec.active_overlays

    def test_government_system_sets_strict_thresholds(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["government_system"])

        # Both overlays set strict — both define strict for these controls
        assert spec.control_thresholds["PR-01"] == "strict"
        assert spec.control_thresholds["PR-04"] == "strict"
        assert spec.control_thresholds["DE-01"] == "strict"

    def test_government_system_dc_gov_in_classifications(self) -> None:
        taxonomy = load_taxonomy()
        gov = next(e for e in taxonomy["classifications"] if e["code"] == "DC-GOV")

        assert "cmmc-l2" in gov["overlays"]
        assert "fedramp" in gov["overlays"]

    def test_government_system_fedramp_triggered_by_dc_gov(self) -> None:
        profile = load_overlay_profiles()["fedramp"]

        assert "DC-GOV" in profile["triggered_by"]


class TestFederalContractHandle:
    """federal_contract handle should activate FedRAMP only."""

    def test_federal_contract_activates_fedramp(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["federal_contract"])

        assert "DC-FCI" in spec.data_classifications
        assert "fedramp" in spec.active_overlays

    def test_federal_contract_does_not_activate_cmmc(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["federal_contract"])

        # federal_contract → DC-FCI → fedramp only (not cmmc-l2)
        assert "cmmc-l2" not in spec.active_overlays

    def test_federal_contract_dc_fci_in_taxonomy(self) -> None:
        taxonomy = load_taxonomy()
        fci = next(e for e in taxonomy["classifications"] if e["code"] == "DC-FCI")

        assert "fedramp" in fci["overlays"]
        assert fci["overlay_status"] == "active"

    def test_fedramp_triggered_by_dc_fci(self) -> None:
        profile = load_overlay_profiles()["fedramp"]

        assert "DC-FCI" in profile["triggered_by"]


class TestGovContractorCertTarget:
    """gov-contractor certification target profile tests."""

    def test_gov_contractor_profile_loads(self) -> None:
        profile = load_certification_profile("gov-contractor")

        assert profile is not None
        assert profile["id"] == "gov-contractor"

    def test_gov_contractor_requires_both_overlays(self) -> None:
        profile = load_certification_profile("gov-contractor")

        assert "cmmc-l2" in profile["required_overlays"]
        assert "fedramp" in profile["required_overlays"]

    def test_gov_contractor_requires_all_common_aksi_controls(self) -> None:
        profile = load_certification_profile("gov-contractor")
        required = set(profile["required_aksi_controls"])

        assert required == COMMON_AKSI_CONTROLS

    def test_gov_contractor_strict_threshold_controls(self) -> None:
        profile = load_certification_profile("gov-contractor")
        strict = set(profile["strict_threshold_controls"])

        assert "PR-01" in strict
        assert "PR-04" in strict
        assert "DE-01" in strict

    def test_gov_contractor_retention_is_1095_days(self) -> None:
        profile = load_certification_profile("gov-contractor")

        assert profile["evidence_packaging"]["retention_days"] == 1095

    def test_gov_contractor_activates_via_resolver_with_data_handles(self) -> None:
        """Cert target + data handle together activate both overlays and all controls."""
        resolver = ActivationResolver()
        spec = resolver.resolve(
            my_agent_handles=["government_system"],
            certification_targets=["gov-contractor"],
        )

        assert "gov-contractor" in spec.active_certifications
        assert "cmmc-l2" in spec.active_overlays
        assert "fedramp" in spec.active_overlays
        assert set(spec.active_controls) == COMMON_AKSI_CONTROLS

    def test_gov_contractor_cert_stacks_strict_thresholds(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(
            my_agent_handles=["government_system"],
            certification_targets=["gov-contractor"],
        )

        assert spec.control_thresholds["PR-01"] == "strict"
        assert spec.control_thresholds["PR-04"] == "strict"
        assert spec.control_thresholds["DE-01"] == "strict"

    def test_gov_contractor_evidence_retention_is_maximum(self) -> None:
        resolver = ActivationResolver()
        spec = resolver.resolve(
            my_agent_handles=["government_system"],
            certification_targets=["gov-contractor"],
        )

        # gov-contractor sets 1095 days — should be the max
        assert spec.evidence_retention_days == 1095
