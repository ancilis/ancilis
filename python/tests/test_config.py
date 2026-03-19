"""Tests for ancilis.config — Unit 1: Policy Schema & Configuration."""

import pytest

from ancilis.config import SHARED_DIR, load_config, validate_config


class TestMinimalConfig:
    def test_packaged_shared_assets_available(self):
        assert SHARED_DIR.joinpath("controls", "pr-01.json").exists()
        assert SHARED_DIR.joinpath("classifications", "taxonomy.json").exists()

    def test_minimal_config_loads(self):
        resolved = load_config(raw={"agent": {"name": "my-agent"}})
        assert resolved.agent_name == "my-agent"
        assert resolved.mode == "audit"

    def test_minimal_config_all_controls_active(self):
        resolved = load_config(raw={"agent": {"name": "my-agent"}})
        assert len(resolved.controls) == 26
        for cs in resolved.controls.values():
            assert cs.enabled is True

    def test_minimal_config_no_overlays(self):
        resolved = load_config(raw={"agent": {"name": "my-agent"}})
        assert len(resolved.active_overlays) == 0
        assert len(resolved.data_classifications) == 0


class TestFullConfig:
    def test_full_config_loads(self):
        raw = {
            "agent": {"name": "claims-processor", "description": "Test agent", "owner": "team"},
            "security": {
                "mode": "enforce",
                "controls": {"PR-01": {"enabled": True}, "DE-01": {"enabled": False}},
                "tools": {"allowed": ["tool-a"], "blocked": ["tool-b"]},
                "scope": {
                    "max_actions_per_minute": 100,
                    "allowed_destinations": ["api.example.com"],
                    "blocked_destinations": ["evil.com"],
                },
            },
            "my_agent_handles": ["credit_cards", "personal_info"],
            "compliance": {
                "overlays": ["hipaa", "gdpr"],
                "evidence": {"storage": "local", "retention_days": 730},
            },
        }
        resolved = load_config(raw=raw)
        assert resolved.agent_name == "claims-processor"
        assert resolved.mode == "enforce"
        assert resolved.controls["DE-01"].enabled is False
        assert "hipaa" in resolved.active_overlays
        assert "gdpr" in resolved.active_overlays


class TestValidation:
    def test_missing_agent_name_raises(self):
        with pytest.raises(Exception):
            load_config(raw={})

    def test_empty_agent_name_raises(self):
        with pytest.raises(Exception):
            load_config(raw={"agent": {"name": ""}})

    def test_invalid_mode_raises(self):
        with pytest.raises(Exception):
            load_config(raw={"agent": {"name": "x"}, "security": {"mode": "invalid"}})

    def test_unknown_data_type_raises(self):
        with pytest.raises(ValueError, match="Unknown data type"):
            load_config(raw={"agent": {"name": "x"}, "my_agent_handles": ["not_a_type"]})

    def test_unknown_control_id_raises(self):
        with pytest.raises(ValueError, match="Unknown control ID"):
            load_config(
                raw={
                    "agent": {"name": "x"},
                    "security": {"controls": {"XX-99": {"enabled": True}}},
                }
            )


class TestDataTypeTranslation:
    def test_health_records_maps_to_phi_pii(self):
        resolved = load_config(
            raw={"agent": {"name": "x"}, "my_agent_handles": ["health_records"]}
        )
        assert "DC-PHI" in resolved.data_classifications["health_records"]
        assert "DC-PII" in resolved.data_classifications["health_records"]

    def test_personal_info_maps_to_pii(self):
        resolved = load_config(
            raw={"agent": {"name": "x"}, "my_agent_handles": ["personal_info"]}
        )
        assert resolved.data_classifications["personal_info"] == ["DC-PII"]


class TestOverlayActivation:
    def test_health_records_activates_hipaa_and_gdpr(self):
        resolved = load_config(
            raw={"agent": {"name": "x"}, "my_agent_handles": ["health_records"]}
        )
        assert "hipaa" in resolved.active_overlays
        assert "gdpr" in resolved.active_overlays

    def test_overlay_stacking(self):
        resolved = load_config(
            raw={
                "agent": {"name": "x"},
                "my_agent_handles": ["health_records", "credit_cards"],
            }
        )
        assert "hipaa" in resolved.active_overlays
        assert "gdpr" in resolved.active_overlays
        assert "pci-dss-v4" in resolved.active_overlays

    def test_unavailable_overlay_warning(self):
        resolved = load_config(
            raw={"agent": {"name": "x"}, "my_agent_handles": ["government_documents"]}
        )
        unavailable_ids = [uo.overlay_id for uo in resolved.unavailable_overlays]
        # DC-CUI maps to cmmc-l2 (roadmap overlay)
        assert "cmmc-l2" in unavailable_ids or len(unavailable_ids) > 0

    def test_ai_training_data_activates_eu_ai_act(self):
        resolved = load_config(
            raw={"agent": {"name": "x"}, "my_agent_handles": ["ai_training_data"]}
        )
        assert "eu-ai-act" in resolved.active_overlays

    def test_hipaa_sets_strict_thresholds(self):
        resolved = load_config(
            raw={"agent": {"name": "x"}, "my_agent_handles": ["health_records"]}
        )
        assert resolved.controls["PR-01"].threshold == "strict"
        assert resolved.controls["PR-04"].threshold == "strict"

    def test_hipaa_sets_retention_2190(self):
        resolved = load_config(
            raw={"agent": {"name": "x"}, "my_agent_handles": ["health_records"]}
        )
        assert resolved.evidence_retention_days == 2190

    def test_eu_ai_act_requires_human_oversight(self):
        resolved = load_config(
            raw={"agent": {"name": "x"}, "my_agent_handles": ["ai_training_data"]}
        )
        assert resolved.human_oversight_required is True


class TestControlOverride:
    def test_disable_control(self):
        resolved = load_config(
            raw={
                "agent": {"name": "x"},
                "security": {"controls": {"PR-01": {"enabled": False}}},
            }
        )
        assert resolved.controls["PR-01"].enabled is False
        assert resolved.controls["PR-02"].enabled is True

    def test_disabled_control_not_adjusted_by_overlay(self):
        resolved = load_config(
            raw={
                "agent": {"name": "x"},
                "security": {"controls": {"PR-01": {"enabled": False}}},
                "my_agent_handles": ["health_records"],
            }
        )
        assert resolved.controls["PR-01"].enabled is False
        # Threshold should stay default since control is disabled
        assert resolved.controls["PR-01"].threshold == "standard"
