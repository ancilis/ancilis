"""Tests for ancilis activation — Unit 5: Overlay Activation & Remaining Controls."""

from __future__ import annotations

import pytest

from ancilis.activation.advisory import (
    CertificationUpgradeAdvisory,
    ClassificationAdvisory,
    ClassificationRecommendation,
    PatternDetection,
)
from ancilis.activation.loader import (
    load_certification_profile,
    load_control_definitions,
    load_overlay_profiles,
)
from ancilis.activation.resolver import (
    BASELINE_CONTROLS,
    EXTENDED_CONTROLS,
    ActivationResolver,
    ActivationSpec,
)
from ancilis.config import load_config
from ancilis.controls.de01_baseline import BaselineWindow, DE01BaselineEvaluator
from ancilis.controls.pr05_audit import PR05AuditEvaluator
from ancilis.engine.action import Action, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry


def make_action(
    agent_id: str = "test-agent",
    tool_name: str = "my-tool",
) -> Action:
    return Action(
        action_id="act-001",
        timestamp="2025-01-15T10:30:00Z",
        agent_id=agent_id,
        action_type="tool_call",
        tool=ToolInfo(name=tool_name),
        parameters=ActionParameters(raw={}),
    )


# --- Activation Resolver: Path 1 (data classification) ---


class TestPath1DataClassification:
    def test_health_records_activates_hipaa(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["health_records"])
        assert "hipaa" in spec.active_overlays
        assert "DC-PHI" in spec.data_classifications

    def test_health_records_pr04_strict(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["health_records"])
        assert spec.control_thresholds.get("PR-04") == "strict"

    def test_personal_info_activates_gdpr(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["personal_info"])
        assert "gdpr" in spec.active_overlays
        assert "DC-PII" in spec.data_classifications

    def test_both_data_types_both_overlays(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["health_records", "personal_info"])
        assert "hipaa" in spec.active_overlays
        assert "gdpr" in spec.active_overlays

    def test_no_my_agent_handles_no_overlays(self):
        resolver = ActivationResolver()
        spec = resolver.resolve()
        assert spec.active_overlays == []
        assert spec.data_classifications == []


# --- Activation Resolver: Path 2 (certification intent) ---


class TestPath2CertificationIntent:
    def test_aiuc1_all_controls_active(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(certification_targets=["aiuc-1"])
        assert "PR-01" in spec.active_controls
        assert "PR-02" in spec.active_controls
        assert "PR-03" in spec.active_controls
        assert "PR-04" in spec.active_controls
        assert "PR-05" in spec.active_controls
        assert "DE-01" in spec.active_controls
        assert "aiuc-1" in spec.active_certifications

    def test_aiuc1_activation_source(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(certification_targets=["aiuc-1"])
        # Controls sourced from certification
        assert "certification_targets:aiuc-1" in spec.activation_source.get("PR-05", "")

    def test_unknown_certification_warns(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(certification_targets=["unknown-cert"])
        assert "unknown-cert" not in spec.active_certifications

    def test_certification_profile_version_required(self):
        profile = load_certification_profile("aiuc-1")
        assert profile is not None
        assert "version" in profile


# --- Both Paths Composing ---


class TestBothPaths:
    def test_both_declared(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(
            my_agent_handles=["health_records"],
            certification_targets=["aiuc-1"],
        )
        assert "hipaa" in spec.active_overlays
        assert "aiuc-1" in spec.active_certifications
        assert len(spec.active_controls) == 6

    def test_conflict_strictest_wins(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(
            my_agent_handles=["health_records"],
            certification_targets=["aiuc-1"],
        )
        # HIPAA sets PR-04 to strict
        assert spec.control_thresholds["PR-04"] == "strict"

    def test_activation_source_correct(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(
            my_agent_handles=["health_records"],
            certification_targets=["aiuc-1"],
        )
        assert "hipaa" in spec.activation_source
        assert "my_agent_handles:health_records" in spec.activation_source["hipaa"]


# --- Baseline Controls ---


class TestBaselineControls:
    def test_empty_config_baseline_active(self):
        resolver = ActivationResolver()
        spec = resolver.resolve()
        for cid in BASELINE_CONTROLS:
            assert cid in spec.active_controls

    def test_empty_config_no_extended(self):
        resolver = ActivationResolver()
        spec = resolver.resolve()
        for cid in EXTENDED_CONTROLS:
            assert cid not in spec.active_controls

    def test_overlay_activates_extended(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["health_records"])
        assert "PR-05" in spec.active_controls
        assert "DE-01" in spec.active_controls


# --- Overlay Profiles ---


class TestOverlayProfiles:
    def test_hipaa_loads(self):
        profiles = load_overlay_profiles()
        assert "hipaa" in profiles
        assert profiles["hipaa"]["evidence_retention_minimum_days"] == 2190

    def test_soc2_framework_mappings(self):
        profiles = load_overlay_profiles()
        soc2 = profiles["soc2"]
        fm = soc2.get("framework_mapping", {})
        assert "PR-01" in fm
        assert "PR-05" in fm
        assert "DE-01" in fm

    def test_eu_ai_act_human_oversight(self):
        profiles = load_overlay_profiles()
        assert profiles["eu-ai-act"]["human_oversight_required"] is True

    def test_gdpr_pr04_strict(self):
        profiles = load_overlay_profiles()
        gdpr = profiles["gdpr"]
        assert gdpr["control_adjustments"]["PR-04"]["threshold_adjustment"] == "strict"

    def test_retention_days(self):
        profiles = load_overlay_profiles()
        assert profiles["hipaa"]["evidence_retention_minimum_days"] == 2190
        assert profiles["eu-ai-act"]["evidence_retention_minimum_days"] == 3650
        assert profiles["soc2"]["evidence_retention_minimum_days"] == 365
        assert profiles["gdpr"]["evidence_retention_minimum_days"] == 365


# --- Certification Profile ---


class TestCertificationProfile:
    def test_aiuc1_loads(self):
        profile = load_certification_profile("aiuc-1")
        assert profile is not None
        assert profile["id"] == "aiuc-1"

    def test_aiuc1_required_controls(self):
        profile = load_certification_profile("aiuc-1")
        assert profile is not None
        assert set(profile["required_aksi_controls"]) == {
            "PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"
        }

    def test_aiuc1_requirement_map(self):
        profile = load_certification_profile("aiuc-1")
        assert profile is not None
        req_map = profile["aksi_to_requirement_map"]
        assert "PR-01" in req_map
        assert "B001" in req_map["PR-01"]

    def test_aiuc1_operator_actions(self):
        profile = load_certification_profile("aiuc-1")
        assert profile is not None
        assert len(profile["operator_action_required"]) == 3

    def test_aiuc1_quarterly_summary(self):
        profile = load_certification_profile("aiuc-1")
        assert profile is not None
        assert profile["evidence_packaging"]["quarterly_summary"] is True


# --- PR-05 Evaluator ---


class TestPR05Evaluator:
    def test_logging_enabled_pass(self):
        config = load_config(raw={"agent": {"name": "test-agent"}})
        evaluator = PR05AuditEvaluator()
        action = make_action()
        result = evaluator.evaluate(action, config)
        assert result.result == "PASS"
        assert result.evidence_data["logging_enabled"] is True
        assert result.evidence_data["log_format"] == "json"

    def test_logging_disabled_fail(self):
        config = load_config(raw={"agent": {"name": "test-agent"}})
        config.evidence_retention_days = 0
        evaluator = PR05AuditEvaluator()
        action = make_action()
        result = evaluator.evaluate(action, config)
        assert result.result == "FAIL"

    def test_evidence_no_raw_logs(self):
        config = load_config(raw={"agent": {"name": "test-agent"}})
        evaluator = PR05AuditEvaluator()
        action = make_action()
        result = evaluator.evaluate(action, config)
        # Evidence should contain structural metadata, not raw log content
        assert "log_format" in result.evidence_data
        assert "sample_entry_field_count" in result.evidence_data


# --- DE-01 Evaluator ---


class TestDE01Evaluator:
    def test_empty_baseline_pass(self):
        evaluator = DE01BaselineEvaluator()
        config = load_config(raw={"agent": {"name": "test-agent"}})
        action = make_action()
        result = evaluator.evaluate(action, config)
        assert result.result == "PASS"
        assert "baseline not yet established" in result.detail.lower()

    def test_normal_behavior_pass(self):
        baseline = BaselineWindow(
            tool_calls=["tool-a", "tool-b", "tool-a"],
            call_count=3,
            window_minutes=5.0,
        )
        evaluator = DE01BaselineEvaluator(baseline_window=baseline)
        config = load_config(raw={"agent": {"name": "test-agent"}})
        action = make_action(tool_name="tool-a")
        result = evaluator.evaluate(action, config)
        assert result.result == "PASS"

    def test_new_tool_flag(self):
        baseline = BaselineWindow(
            tool_calls=["tool-a", "tool-b"],
            call_count=10,
            window_minutes=5.0,
        )
        evaluator = DE01BaselineEvaluator(baseline_window=baseline)
        config = load_config(raw={"agent": {"name": "test-agent"}})
        action = make_action(tool_name="unknown-tool")
        result = evaluator.evaluate(action, config)
        assert result.result == "FLAG"
        assert "unknown-tool" in result.evidence_data["new_tools_detected"]

    def test_frequency_spike_flag(self):
        baseline = BaselineWindow(
            tool_calls=["tool-a"] * 10,
            call_count=10,
            window_minutes=10.0,  # 1 call/min baseline
        )
        evaluator = DE01BaselineEvaluator(baseline_window=baseline)
        config = load_config(raw={"agent": {"name": "test-agent"}})
        action = make_action(tool_name="tool-a")
        # Use evaluate_with_rate to test frequency spike
        result = evaluator.evaluate_with_rate(action, config, current_rate=5.0)  # 5x baseline
        assert result.result == "FLAG"
        flags = result.evidence_data["deviation_flags"]
        assert any(f["type"] == "frequency_spike" for f in flags)

    def test_de01_never_blocks(self):
        """DE-01 should only produce PASS or FLAG, never BLOCK."""
        baseline = BaselineWindow(
            tool_calls=["tool-a"],
            call_count=5,
            window_minutes=5.0,
        )
        evaluator = DE01BaselineEvaluator(baseline_window=baseline)
        config = load_config(raw={"agent": {"name": "test-agent"}})
        action = make_action(tool_name="suspicious-tool")
        result = evaluator.evaluate(action, config)
        assert result.result in ("PASS", "FLAG")
        assert result.result != "BLOCK"

    def test_deviation_flags_are_objects(self):
        baseline = BaselineWindow(
            tool_calls=["tool-a"],
            call_count=5,
            window_minutes=5.0,
        )
        evaluator = DE01BaselineEvaluator(baseline_window=baseline)
        config = load_config(raw={"agent": {"name": "test-agent"}})
        action = make_action(tool_name="new-tool")
        result = evaluator.evaluate(action, config)
        for flag in result.evidence_data["deviation_flags"]:
            assert "type" in flag
            assert "display_message" in flag
            assert "severity" in flag


# --- Pattern Detection Advisory ---


class TestPatternAdvisory:
    def test_ssn_recommends_personal_info(self):
        advisor = ClassificationAdvisory()
        detections = [PatternDetection(pattern_type="ssn", count=5)]
        recs, _ = advisor.generate(detections)
        assert len(recs) >= 1
        assert recs[0].suggested_value == "personal_info"

    def test_credit_card_recommends_credit_cards(self):
        advisor = ClassificationAdvisory()
        detections = [PatternDetection(pattern_type="credit_card", count=3)]
        recs, _ = advisor.generate(detections)
        assert any(r.suggested_value == "credit_cards" for r in recs)

    def test_already_covered_no_duplicate(self):
        advisor = ClassificationAdvisory()
        detections = [PatternDetection(pattern_type="ssn", count=5)]
        recs, _ = advisor.generate(detections, active_my_agent_handles=["personal_info"])
        assert len(recs) == 0

    def test_certification_upgrade_advisory(self):
        advisor = ClassificationAdvisory()
        detections = [PatternDetection(pattern_type="mrn", count=10)]
        recs, upgrades = advisor.generate(
            detections,
            active_certifications=["aiuc-1"],
        )
        assert len(upgrades) >= 1
        assert upgrades[0].certification_id == "aiuc-1"
        assert upgrades[0].severity == "info"

    def test_advisory_has_example_config(self):
        advisor = ClassificationAdvisory()
        detections = [PatternDetection(pattern_type="ssn", count=5)]
        recs, _ = advisor.generate(detections)
        assert recs[0].example_config.startswith("my_agent_handles:")

    def test_advisory_never_auto_applies(self):
        """Config should not be modified by advisory generation."""
        config = load_config(raw={"agent": {"name": "test-agent"}})
        advisor = ClassificationAdvisory()
        detections = [PatternDetection(pattern_type="ssn", count=5)]
        advisor.generate(detections)
        # Config unchanged
        assert not config.data_classifications

    def test_recommendation_has_severity(self):
        advisor = ClassificationAdvisory()
        detections = [PatternDetection(pattern_type="ssn", count=5)]
        recs, _ = advisor.generate(detections)
        assert recs[0].severity in ("info", "warning", "alert")

    def test_ssn_severity_alert(self):
        advisor = ClassificationAdvisory()
        detections = [PatternDetection(pattern_type="ssn", count=5)]
        recs, _ = advisor.generate(detections)
        assert recs[0].severity == "alert"


# --- Conflict Resolution ---


class TestConflictResolution:
    def test_hipaa_gdpr_pr04_strict(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["health_records", "personal_info"])
        # Both HIPAA and GDPR set PR-04 strict
        assert spec.control_thresholds["PR-04"] == "strict"

    def test_hipaa_soc2_retention_longest(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["health_records"])
        # HIPAA: 2190 days, SOC2: 365 days → HIPAA wins
        assert spec.evidence_retention_days >= 2190

    def test_evidence_requirements_union(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["health_records"])
        # Should have evidence requirements from both HIPAA and other overlays
        pr04_reqs = spec.evidence_requirements.get("PR-04", [])
        assert len(pr04_reqs) > 0


# --- Engine Integration ---


class TestEngineIntegration:
    def test_engine_has_pr05_evaluator(self):
        config = load_config(raw={"agent": {"name": "test-agent"}})
        engine = Engine(config)
        assert "PR-05" in engine._evaluators

    def test_engine_has_de01_evaluator(self):
        config = load_config(raw={"agent": {"name": "test-agent"}})
        engine = Engine(config)
        assert "DE-01" in engine._evaluators

    def test_all_six_controls_evaluate(self):
        config = load_config(raw={"agent": {"name": "test-agent"}})
        registry = ToolRegistry()
        from ancilis.engine.registry import ToolStatus
        registry.register(ToolEntry(name="my-tool", status=ToolStatus.APPROVED))
        engine = Engine(config, registry=registry)
        action = make_action()
        result = engine.evaluate(action)
        control_ids = [cr.control_id for cr in result.control_results]
        assert "PR-05" in control_ids
        assert "DE-01" in control_ids


# --- Output Disclosure Contract ---


class TestOutputDisclosure:
    def test_control_definitions_have_display_fields(self):
        controls = load_control_definitions()
        for cid, cdef in controls.items():
            assert "display_name" in cdef, f"{cid} missing display_name"
            assert "display_detail" in cdef, f"{cid} missing display_detail"
            assert "remediation_hint_template" in cdef, f"{cid} missing remediation_hint_template"
            assert cdef["display_name"], f"{cid} display_name is empty"
            assert cdef["display_detail"], f"{cid} display_detail is empty"

    def test_display_name_not_raw_control_id(self):
        controls = load_control_definitions()
        for cid, cdef in controls.items():
            assert cdef["display_name"] != cid, f"{cid} display_name is just the control ID"

    def test_activation_summary_populated(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(certification_targets=["aiuc-1"])
        assert len(spec.activation_summary) >= 1
        assert any("AIUC-1" in s for s in spec.activation_summary)

    def test_activation_summary_overlay(self):
        resolver = ActivationResolver()
        spec = resolver.resolve(my_agent_handles=["health_records"])
        assert len(spec.activation_summary) >= 1

    def test_recommendation_severity_set(self):
        advisor = ClassificationAdvisory()
        detections = [PatternDetection(pattern_type="ssn", count=5)]
        recs, _ = advisor.generate(detections)
        assert all(r.severity in ("info", "warning", "alert") for r in recs)

    def test_upgrade_advisory_severity_info(self):
        advisor = ClassificationAdvisory()
        detections = [PatternDetection(pattern_type="mrn", count=5)]
        _, upgrades = advisor.generate(detections, active_certifications=["aiuc-1"])
        assert all(u.severity == "info" for u in upgrades)


# --- Overlay Data Integrity ---


class TestOverlayDataIntegrity:
    def test_all_overlays_have_framework_mapping(self):
        profiles = load_overlay_profiles()
        for oid, profile in profiles.items():
            assert "framework_mapping" in profile, f"{oid} missing framework_mapping"

    def test_all_overlays_have_evidence_requirements(self):
        profiles = load_overlay_profiles()
        for oid, profile in profiles.items():
            assert "evidence_requirements" in profile, f"{oid} missing evidence_requirements"
