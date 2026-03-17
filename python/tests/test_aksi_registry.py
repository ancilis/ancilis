"""Tests for AKSI control registry, data classifications, overlay profiles, and activation paths."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ancilis.activation.loader import (
    load_control_definitions,
    load_overlay_profiles,
    load_taxonomy,
)
from ancilis.activation.resolver import (
    ALL_AKSI_CONTROLS,
    ActivationResolver,
)
from ancilis.config import load_config


# --- Constants ---

ALL_26_CONTROL_IDS = {
    "GOV-01", "GOV-02", "GOV-03", "GOV-04",
    "ID-01", "ID-02", "ID-03", "ID-04", "ID-05",
    "PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "PR-06", "PR-07", "PR-08",
    "DE-01", "DE-02", "DE-03", "DE-04",
    "RS-01", "RS-02", "RS-03",
    "RC-01", "RC-02",
}

ALL_16_DC_CODES = {
    "DC-CHD", "DC-PII", "DC-FIN", "DC-PHI", "DC-CUI", "DC-MNPI",
    "DC-FCI", "DC-GEN", "DC-GOV", "DC-AI", "DC-ITAR", "DC-CRIT",
    "DC-MINOR", "DC-BIO", "DC-LEGAL", "DC-IP",
}

FIVE_OVERLAY_IDS = {"pci-dss-v4", "soc2", "eu-ai-act", "iso-42001", "nist-csf"}


# --- Part 1: AKSI Control Registry ---


class TestAKSIControlRegistry:
    def test_all_26_controls_present(self):
        controls = load_control_definitions()
        assert set(controls.keys()) == ALL_26_CONTROL_IDS

    def test_all_controls_have_required_fields(self):
        controls = load_control_definitions()
        required_fields = {
            "id", "name", "function", "csf_mapping", "description",
            "security_outcome", "evidence_fields", "default_enabled", "baseline",
        }
        for cid, cdef in controls.items():
            for field in required_fields:
                assert field in cdef, f"{cid} missing required field '{field}'"

    def test_all_controls_have_display_fields(self):
        controls = load_control_definitions()
        for cid, cdef in controls.items():
            assert "display_name" in cdef, f"{cid} missing display_name"
            assert "display_detail" in cdef, f"{cid} missing display_detail"
            assert "remediation_hint_template" in cdef, f"{cid} missing remediation_hint_template"

    def test_all_controls_have_regulatory_mappings(self):
        controls = load_control_definitions()
        for cid, cdef in controls.items():
            assert "regulatory_mappings" in cdef, f"{cid} missing regulatory_mappings"
            mappings = cdef["regulatory_mappings"]
            assert "nist_csf" in mappings, f"{cid} missing nist_csf in regulatory_mappings"
            assert "soc2" in mappings, f"{cid} missing soc2 in regulatory_mappings"

    def test_all_controls_baseline_true(self):
        controls = load_control_definitions()
        for cid, cdef in controls.items():
            assert cdef["baseline"] is True, f"{cid} should have baseline=true"

    def test_control_functions_valid(self):
        controls = load_control_definitions()
        valid_functions = {"GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"}
        for cid, cdef in controls.items():
            assert cdef["function"] in valid_functions, \
                f"{cid} has invalid function '{cdef['function']}'"

    def test_govern_controls_count(self):
        controls = load_control_definitions()
        gov = [c for c in controls.values() if c["function"] == "GOVERN"]
        assert len(gov) == 4

    def test_identify_controls_count(self):
        controls = load_control_definitions()
        identify = [c for c in controls.values() if c["function"] == "IDENTIFY"]
        assert len(identify) == 5

    def test_protect_controls_count(self):
        controls = load_control_definitions()
        protect = [c for c in controls.values() if c["function"] == "PROTECT"]
        assert len(protect) == 8

    def test_detect_controls_count(self):
        controls = load_control_definitions()
        detect = [c for c in controls.values() if c["function"] == "DETECT"]
        assert len(detect) == 4

    def test_respond_controls_count(self):
        controls = load_control_definitions()
        respond = [c for c in controls.values() if c["function"] == "RESPOND"]
        assert len(respond) == 3

    def test_recover_controls_count(self):
        controls = load_control_definitions()
        recover = [c for c in controls.values() if c["function"] == "RECOVER"]
        assert len(recover) == 2

    def test_descriptions_substantive(self):
        """Descriptions should not be placeholder text."""
        controls = load_control_definitions()
        for cid, cdef in controls.items():
            assert len(cdef["description"]) > 50, \
                f"{cid} description too short — should be substantive"

    def test_security_outcomes_have_pass_and_fail(self):
        controls = load_control_definitions()
        for cid, cdef in controls.items():
            outcome = cdef["security_outcome"]
            assert "pass" in outcome, f"{cid} missing 'pass' in security_outcome"
            assert "fail" in outcome, f"{cid} missing 'fail' in security_outcome"


# --- Part 2: Data Classification Registry ---


class TestDataClassificationRegistry:
    def test_all_16_dc_codes_present(self):
        taxonomy = load_taxonomy()
        codes = {c["code"] for c in taxonomy["classifications"]}
        assert codes == ALL_16_DC_CODES

    def test_all_classifications_have_required_fields(self):
        taxonomy = load_taxonomy()
        for entry in taxonomy["classifications"]:
            assert "code" in entry
            assert "name" in entry
            assert "description" in entry
            assert "overlays" in entry
            assert isinstance(entry["overlays"], list)

    def test_pattern_detection_metadata(self):
        taxonomy = load_taxonomy()
        for entry in taxonomy["classifications"]:
            assert "pattern_detection" in entry, \
                f"{entry['code']} missing pattern_detection metadata"
            pd = entry["pattern_detection"]
            assert "enabled" in pd

    def test_chd_has_patterns(self):
        taxonomy = load_taxonomy()
        chd = next(c for c in taxonomy["classifications"] if c["code"] == "DC-CHD")
        assert chd["pattern_detection"]["enabled"] is True
        patterns = chd["pattern_detection"]["patterns"]
        types = {p["type"] for p in patterns}
        assert "luhn_checksum" in types
        assert "card_number_visa" in types

    def test_pii_has_patterns(self):
        taxonomy = load_taxonomy()
        pii = next(c for c in taxonomy["classifications"] if c["code"] == "DC-PII")
        assert pii["pattern_detection"]["enabled"] is True
        patterns = pii["pattern_detection"]["patterns"]
        types = {p["type"] for p in patterns}
        assert "ssn" in types
        assert "email" in types

    def test_phi_has_patterns(self):
        taxonomy = load_taxonomy()
        phi = next(c for c in taxonomy["classifications"] if c["code"] == "DC-PHI")
        assert phi["pattern_detection"]["enabled"] is True
        patterns = phi["pattern_detection"]["patterns"]
        types = {p["type"] for p in patterns}
        assert "icd10" in types
        assert "npi" in types

    def test_fin_has_patterns(self):
        taxonomy = load_taxonomy()
        fin = next(c for c in taxonomy["classifications"] if c["code"] == "DC-FIN")
        assert fin["pattern_detection"]["enabled"] is True
        patterns = fin["pattern_detection"]["patterns"]
        types = {p["type"] for p in patterns}
        assert "routing_number" in types
        assert "swift_bic" in types

    def test_declared_classification_types_have_no_patterns(self):
        """DC codes requiring declared classification should have pattern detection disabled."""
        taxonomy = load_taxonomy()
        no_pattern_codes = {"DC-CUI", "DC-MNPI", "DC-FCI", "DC-GOV", "DC-ITAR",
                           "DC-CRIT", "DC-MINOR", "DC-BIO", "DC-LEGAL", "DC-IP", "DC-GEN"}
        for entry in taxonomy["classifications"]:
            if entry["code"] in no_pattern_codes:
                assert entry["pattern_detection"]["enabled"] is False, \
                    f"{entry['code']} should not have pattern detection enabled"

    def test_plain_language_keys_mapped(self):
        taxonomy = load_taxonomy()
        mapping = taxonomy["developer_type_mapping"]
        # Check task-specified canonical keys
        assert "credit_cards" in mapping
        assert "personal_info" in mapping
        assert "financial_data" in mapping
        assert "health_records" in mapping
        assert "controlled_unclassified" in mapping
        assert "material_nonpublic" in mapping
        assert "federal_contract" in mapping
        assert "general" in mapping
        assert "government_system" in mapping
        assert "ai_training_data" in mapping
        assert "export_controlled" in mapping
        assert "critical_infrastructure" in mapping
        assert "childrens_data" in mapping
        assert "biometric_data" in mapping
        assert "legal_privileged" in mapping
        assert "trade_secrets" in mapping

    def test_credit_cards_maps_to_chd(self):
        taxonomy = load_taxonomy()
        assert "DC-CHD" in taxonomy["developer_type_mapping"]["credit_cards"]

    def test_personal_info_maps_to_pii(self):
        taxonomy = load_taxonomy()
        assert taxonomy["developer_type_mapping"]["personal_info"] == ["DC-PII"]

    def test_ai_training_data_maps_to_ai(self):
        taxonomy = load_taxonomy()
        assert taxonomy["developer_type_mapping"]["ai_training_data"] == ["DC-AI"]

    def test_overlay_status_field(self):
        taxonomy = load_taxonomy()
        for entry in taxonomy["classifications"]:
            assert "overlay_status" in entry, \
                f"{entry['code']} missing overlay_status field"
            assert entry["overlay_status"] in ("active", "roadmap"), \
                f"{entry['code']} invalid overlay_status"


# --- Part 3: Overlay Profile Validation ---


class TestOverlayProfiles:
    def test_five_overlays_present(self):
        profiles = load_overlay_profiles()
        for oid in FIVE_OVERLAY_IDS:
            assert oid in profiles, f"Overlay '{oid}' not found"

    def test_overlay_schema_complete(self):
        """All overlays should have required schema fields."""
        profiles = load_overlay_profiles()
        required_fields = {"id", "name", "version", "framework_mapping",
                          "evidence_retention_minimum_days", "human_oversight_required"}
        for oid in FIVE_OVERLAY_IDS:
            profile = profiles[oid]
            for field in required_fields:
                assert field in profile, f"{oid} missing required field '{field}'"

    def test_all_overlays_map_26_controls_in_framework_mapping(self):
        """Each overlay should map all 26 AKSI controls in framework_mapping."""
        profiles = load_overlay_profiles()
        for oid in FIVE_OVERLAY_IDS:
            profile = profiles[oid]
            fm = profile.get("framework_mapping", {})
            for cid in ALL_26_CONTROL_IDS:
                assert cid in fm, f"{oid} missing {cid} in framework_mapping"

    def test_no_orphan_control_ids_in_overlays(self):
        """Overlay profiles should not reference non-existent control IDs."""
        profiles = load_overlay_profiles()
        for oid in FIVE_OVERLAY_IDS:
            profile = profiles[oid]
            # Check framework_mapping
            for cid in profile.get("framework_mapping", {}):
                assert cid in ALL_26_CONTROL_IDS, \
                    f"{oid} references unknown control '{cid}' in framework_mapping"
            # Check controls section
            for cid in profile.get("controls", {}):
                assert cid in ALL_26_CONTROL_IDS, \
                    f"{oid} references unknown control '{cid}' in controls"
            # Check control_adjustments
            for cid in profile.get("control_adjustments", {}):
                assert cid in ALL_26_CONTROL_IDS, \
                    f"{oid} references unknown control '{cid}' in control_adjustments"

    def test_pci_dss_v4_triggered_by_chd(self):
        profiles = load_overlay_profiles()
        pci = profiles["pci-dss-v4"]
        assert "DC-CHD" in pci["triggered_by"]
        assert pci["trigger_type"] == "data_classification"

    def test_pci_dss_v4_strict_thresholds(self):
        profiles = load_overlay_profiles()
        pci = profiles["pci-dss-v4"]
        adj = pci.get("control_adjustments", {})
        assert adj["PR-02"]["threshold_adjustment"] == "strict"
        assert adj["PR-04"]["threshold_adjustment"] == "strict"
        assert adj["PR-05"]["threshold_adjustment"] == "strict"
        assert adj["PR-07"]["threshold_adjustment"] == "strict"

    def test_pci_dss_v4_retention_365(self):
        profiles = load_overlay_profiles()
        assert profiles["pci-dss-v4"]["evidence_retention_minimum_days"] == 365

    def test_soc2_triggered_by_gen(self):
        profiles = load_overlay_profiles()
        soc2 = profiles["soc2"]
        assert "DC-GEN" in soc2["triggered_by"]

    def test_soc2_standard_thresholds(self):
        """SOC 2 should set standard thresholds — it focuses on demonstrating controls, not strict criteria."""
        profiles = load_overlay_profiles()
        soc2 = profiles["soc2"]
        adj = soc2.get("control_adjustments", {})
        for cid, a in adj.items():
            assert a["threshold_adjustment"] == "standard", \
                f"SOC 2 {cid} should be standard threshold"

    def test_eu_ai_act_triggered_by_ai(self):
        profiles = load_overlay_profiles()
        eu = profiles["eu-ai-act"]
        assert "DC-AI" in eu["triggered_by"]
        assert eu["human_oversight_required"] is True

    def test_eu_ai_act_strict_thresholds(self):
        profiles = load_overlay_profiles()
        eu = profiles["eu-ai-act"]
        adj = eu.get("control_adjustments", {})
        assert adj["PR-05"]["threshold_adjustment"] == "strict"
        assert adj["DE-01"]["threshold_adjustment"] == "strict"
        assert adj["GOV-04"]["threshold_adjustment"] == "strict"

    def test_eu_ai_act_retention_10_years(self):
        profiles = load_overlay_profiles()
        assert profiles["eu-ai-act"]["evidence_retention_minimum_days"] == 3650

    def test_iso_42001_triggered_by_ai(self):
        profiles = load_overlay_profiles()
        iso = profiles["iso-42001"]
        assert "DC-AI" in iso["triggered_by"]
        assert iso["trigger_type"] == "data_classification"

    def test_iso_42001_no_strict_thresholds(self):
        """ISO 42001 is process-oriented, not prescriptive — no strict thresholds."""
        profiles = load_overlay_profiles()
        iso = profiles["iso-42001"]
        adj = iso.get("control_adjustments", {})
        assert len(adj) == 0

    def test_nist_csf_baseline_trigger(self):
        profiles = load_overlay_profiles()
        nist = profiles["nist-csf"]
        assert nist["trigger_type"] == "baseline"
        assert nist["triggered_by"] == ["*"]

    def test_nist_csf_no_strict_thresholds(self):
        """NIST CSF is about alignment, not pass/fail — no strict thresholds."""
        profiles = load_overlay_profiles()
        nist = profiles["nist-csf"]
        adj = nist.get("control_adjustments", {})
        assert len(adj) == 0

    def test_nist_csf_no_human_oversight_mandate(self):
        profiles = load_overlay_profiles()
        nist = profiles["nist-csf"]
        assert nist["human_oversight_required"] is False

    def test_overlay_has_controls_section(self):
        """New overlays should have the detailed controls section with evidence requirements."""
        profiles = load_overlay_profiles()
        for oid in FIVE_OVERLAY_IDS:
            profile = profiles[oid]
            assert "controls" in profile, f"{oid} missing controls section"
            controls = profile["controls"]
            # Each control should have applicable and evidence_requirements
            for cid, ctrl in controls.items():
                assert "applicable" in ctrl, f"{oid}.{cid} missing applicable"
                assert "evidence_requirements" in ctrl, f"{oid}.{cid} missing evidence_requirements"
                assert "framework_reference" in ctrl, f"{oid}.{cid} missing framework_reference"

    def test_reporting_obligations(self):
        """Overlays should document reporting obligations."""
        profiles = load_overlay_profiles()
        for oid in FIVE_OVERLAY_IDS:
            profile = profiles[oid]
            assert "reporting_obligations" in profile, f"{oid} missing reporting_obligations"

    def test_human_oversight_mandates(self):
        """Overlays should document human oversight mandates."""
        profiles = load_overlay_profiles()
        for oid in FIVE_OVERLAY_IDS:
            profile = profiles[oid]
            assert "human_oversight_mandates" in profile, f"{oid} missing human_oversight_mandates"


# --- Part 4: Activation Path Tests ---


class TestActivationPaths:
    def test_credit_cards_activates_pci(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["credit_cards"])
        assert "pci-dss-v4" in spec.active_overlays
        assert "DC-CHD" in spec.data_classifications

    def test_personal_info_activates_gdpr_and_soc2(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["personal_info"])
        assert "DC-PII" in spec.data_classifications
        # DC-PII triggers gdpr and soc2
        assert "gdpr" in spec.active_overlays
        assert "soc2" in spec.active_overlays

    def test_ai_training_data_activates_eu_ai_act_and_iso_42001(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["ai_training_data"])
        assert "DC-AI" in spec.data_classifications
        assert "eu-ai-act" in spec.active_overlays
        assert "iso-42001" in spec.active_overlays

    def test_classification_stacking(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["credit_cards", "personal_info"])
        assert "pci-dss-v4" in spec.active_overlays
        assert "gdpr" in spec.active_overlays
        assert "soc2" in spec.active_overlays
        assert "DC-CHD" in spec.data_classifications
        assert "DC-PII" in spec.data_classifications

    def test_certification_still_works(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(certification_targets=["aiuc-1"])
        assert "aiuc-1" in spec.active_certifications
        assert len(spec.active_controls) == 26

    def test_combined_certification_and_data(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(
            certification_targets=["aiuc-1"],
            my_agent_handles=["credit_cards"],
        )
        assert "aiuc-1" in spec.active_certifications
        assert "pci-dss-v4" in spec.active_overlays
        assert "nist-csf" in spec.active_overlays

    def test_nist_csf_always_active(self):
        """NIST CSF should be active even with no my_agent_handles."""
        resolver = ActivationResolver()
        spec = resolver.resolve()
        assert "nist-csf" in spec.active_overlays

    def test_nist_csf_active_with_data_handles(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["credit_cards"])
        assert "nist-csf" in spec.active_overlays

    def test_all_26_controls_baseline(self):
        """All 26 controls should be active even with no config."""
        resolver = ActivationResolver()
        spec = resolver.resolve()
        assert len(spec.active_controls) == 26
        assert set(spec.active_controls) == ALL_26_CONTROL_IDS

    def test_roadmap_overlay_graceful_degradation(self):
        """DC code with no overlay profile should not error."""
        resolver = ActivationResolver()
        # DC-CUI maps to cmmc-l2 which is roadmap — should not crash
        spec = resolver.resolve(my_agent_handles=["controlled_unclassified"])
        assert "DC-CUI" in spec.data_classifications
        # cmmc-l2 should NOT be in active overlays (it doesn't exist)
        assert "cmmc-l2" not in spec.active_overlays
        # But NIST CSF baseline should still be active
        assert "nist-csf" in spec.active_overlays
        # All 26 controls should still be active
        assert len(spec.active_controls) == 26

    def test_financial_data_roadmap(self):
        """Financial data overlay (glba) is roadmap — should degrade gracefully."""
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["financial_data"])
        assert "DC-FIN" in spec.data_classifications
        # glba is roadmap, but soc2 should activate via DC-FIN
        assert "soc2" in spec.active_overlays

    def test_general_data_activates_soc2(self):
        """General business data should activate SOC 2."""
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["general"])
        assert "DC-GEN" in spec.data_classifications
        assert "soc2" in spec.active_overlays

    def test_pci_strict_thresholds_applied(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["credit_cards"])
        assert spec.control_thresholds.get("PR-02") == "strict"
        assert spec.control_thresholds.get("PR-04") == "strict"
        assert spec.control_thresholds.get("PR-07") == "strict"

    def test_eu_ai_act_human_oversight_activated(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["ai_training_data"])
        assert spec.human_oversight_required is True

    def test_eu_ai_act_retention_10_years(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["ai_training_data"])
        assert spec.evidence_retention_days >= 3650


# --- Part 5: Config Integration ---


class TestConfigIntegration:
    def test_credit_cards_end_to_end(self):
        resolved = load_config(
            raw={"agent": {"name": "x"}, "my_agent_handles": ["credit_cards"]}
        )
        assert "pci-dss-v4" in resolved.active_overlays
        assert "DC-CHD" in resolved.data_classifications["credit_cards"]
        assert resolved.controls["PR-02"].threshold == "strict"

    def test_ai_training_data_end_to_end(self):
        resolved = load_config(
            raw={"agent": {"name": "x"}, "my_agent_handles": ["ai_training_data"]}
        )
        assert "eu-ai-act" in resolved.active_overlays
        assert "iso-42001" in resolved.active_overlays
        assert resolved.human_oversight_required is True
        assert resolved.evidence_retention_days >= 3650

    def test_minimal_config_26_controls(self):
        resolved = load_config(raw={"agent": {"name": "x"}})
        assert len(resolved.controls) == 26
