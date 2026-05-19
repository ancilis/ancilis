"""Tests for ancilis.config — Unit 1: Policy Schema & Configuration."""

import pytest
from pydantic import ValidationError

from ancilis.config import SHARED_DIR, load_config, load_overlay_definitions, validate_config
from ancilis.errors import ConfigError


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
        assert len(resolved.controls) == 41
        enabled = {cid for cid, cs in resolved.controls.items() if cs.enabled}
        assert len(enabled) == 39
        assert "PAY-01" not in enabled
        assert "PAY-02" not in enabled

    def test_minimal_config_no_overlays(self):
        resolved = load_config(raw={"agent": {"name": "my-agent"}})
        assert len(resolved.active_overlays) == 0
        assert len(resolved.data_classifications) == 0

    def test_minimal_config_marks_default_control_activation_source(self):
        resolved = load_config(raw={"agent": {"name": "my-agent"}})
        assert resolved.control_activation_sources["DE-04"] == {"default"}
        assert not resolved.control_has_activation_source(
            "DE-04", "explicit:security.controls", "certification_targets:"
        )


class TestFullConfig:
    def test_full_config_loads(self):
        raw = {
            "agent": {"name": "claims-processor", "description": "Test agent", "owner": "team"},
            "platform": {"url": "https://app.ancilis.ai", "api_key_env": "ANCILIS_TOKEN"},
            "sync": {
                "offline_mode": "always_online",
                "interval_seconds": 60,
                "max_retries": 3,
                "backoff_base_seconds": 5,
                "max_queue_size": 500,
                "batch_size": 25,
            },
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
        assert resolved.platform_url == "https://app.ancilis.ai"
        assert resolved.platform_api_key_env == "ANCILIS_TOKEN"
        assert resolved.sync_offline_mode == "always_online"
        assert resolved.sync_interval_seconds == 60
        assert resolved.sync_max_retries == 3
        assert resolved.sync_backoff_base_seconds == 5
        assert resolved.sync_max_queue_size == 500
        assert resolved.sync_batch_size == 25


class TestSyncConfig:
    def test_default_platform_and_sync_config(self):
        resolved = load_config(raw={"agent": {"name": "my-agent"}})

        assert resolved.platform_url is None
        assert resolved.platform_api_key_env == "ANCILIS_API_KEY"
        assert resolved.sync_offline_mode == "auto"
        assert resolved.sync_interval_seconds == 300
        assert resolved.sync_max_retries == 8
        assert resolved.sync_backoff_base_seconds == 2
        assert resolved.sync_max_queue_size == 10000
        assert resolved.sync_batch_size == 100

    def test_invalid_sync_offline_mode_raises(self):
        with pytest.raises(ValidationError):
            load_config(
                raw={
                    "agent": {"name": "x"},
                    "sync": {"offline_mode": "sometimes_online"},
                }
            )

    @pytest.mark.parametrize(
        "field,value",
        [
            ("interval_seconds", 0),
            ("max_retries", -1),
            ("backoff_base_seconds", -1),
            ("max_queue_size", 0),
            ("batch_size", 0),
            ("batch_size", 101),
        ],
    )
    def test_invalid_sync_numeric_values_raise(self, field, value):
        with pytest.raises(ValidationError):
            load_config(
                raw={
                    "agent": {"name": "x"},
                    "sync": {field: value},
                }
            )


class TestValidation:
    def test_missing_agent_name_raises(self):
        with pytest.raises(ValidationError):
            load_config(raw={})

    def test_empty_agent_name_raises(self):
        with pytest.raises(ValidationError):
            load_config(raw={"agent": {"name": ""}})

    def test_invalid_mode_raises(self):
        with pytest.raises(ValidationError):
            load_config(raw={"agent": {"name": "x"}, "security": {"mode": "invalid"}})

    def test_unknown_data_type_raises(self):
        with pytest.raises(ConfigError, match="Unknown data type"):
            load_config(raw={"agent": {"name": "x"}, "my_agent_handles": ["not_a_type"]})

    def test_unknown_control_id_raises(self):
        with pytest.raises(ConfigError, match="Unknown control ID"):
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

    def test_government_cui_alias_activates_cmmc_overlay(self):
        resolved = load_config(
            raw={"agent": {"name": "x"}, "my_agent_handles": ["government_cui"]}
        )
        assert "cmmc-l2" in resolved.active_overlays
        assert all(item.overlay_id != "cmmc-l2" for item in resolved.unavailable_overlays)

    def test_ai_training_data_activates_eu_ai_act(self):
        resolved = load_config(
            raw={"agent": {"name": "x"}, "my_agent_handles": ["ai_training_data"]}
        )
        assert "eu-ai-act" in resolved.active_overlays

    def test_nist_csf_2_alias_resolves_to_canonical_overlay(self):
        resolved = load_config(
            raw={
                "agent": {"name": "x"},
                "compliance": {"overlays": ["nist-csf-2"]},
            }
        )

        assert list(resolved.active_overlays) == ["nist-csf"]
        assert resolved.active_overlays["nist-csf"].overlay_id == "nist-csf"
        assert resolved.active_overlays["nist-csf"].name == "NIST Cybersecurity Framework 2.0"
        assert all(item.overlay_id != "nist-csf-2" for item in resolved.unavailable_overlays)
        assert "nist-csf" in resolved.overlay_requirements["GOV-01"]
        assert "nist-csf-2" not in resolved.overlay_requirements["GOV-01"]

    def test_nist_csf_2_alias_deduplicates_with_canonical_overlay(self):
        resolved = load_config(
            raw={
                "agent": {"name": "x"},
                "compliance": {"overlays": ["nist-csf", "nist-csf-2"]},
            }
        )

        assert list(resolved.active_overlays) == ["nist-csf"]

    def test_nist_csf_overlay_version_matches_framework_version(self):
        assert load_overlay_definitions()["nist-csf"]["version"] == "2.0"

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

    def test_enabled_control_override_marks_explicit_activation_source(self):
        resolved = load_config(
            raw={
                "agent": {"name": "x"},
                "security": {"controls": {"DE-04": {"enabled": True}}},
            }
        )
        assert "explicit:security.controls" in resolved.control_activation_sources["DE-04"]
        assert resolved.control_has_activation_source("DE-04", "explicit:security.controls")

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


class TestCertificationTargets:
    def test_certification_target_marks_control_activation_source(self):
        resolved = load_config(
            raw={
                "agent": {"name": "x"},
                "certification_targets": ["gov-contractor"],
            }
        )
        assert "certification_targets:gov-contractor" in resolved.control_activation_sources["DE-04"]
        assert resolved.control_has_activation_source("DE-04", "certification_targets:")
