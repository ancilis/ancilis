from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import pytest

from ancilis.activation.resolver import ActivationResolver
from ancilis.config import load_config
from ancilis.plugins import PluginContext, PluginMetadata, PluginRecord, PluginRegistry


def _overlay_profile(
    overlay_id: str = "plugin:acme-risk",
    *,
    trigger_type: str = "data_classification",
    triggered_by: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": overlay_id,
        "name": "Acme Risk Overlay",
        "version": "1.0.0",
        "trigger_type": trigger_type,
        "triggered_by": triggered_by or ["DC-FIN"],
        "description": "Fake plugin overlay for runtime activation tests.",
        "control_adjustments": {
            "PR-01": {
                "threshold_adjustment": "strict",
                "regulatory_citation": "ACME-RISK-1",
            }
        },
        "evidence_requirements": {
            "PR-01": ["acme-risk-review"],
        },
        "controls": {
            "PR-01": {
                "applicable": True,
                "evidence_requirements": ["acme-risk-review"],
                "framework_reference": "ACME-RISK-1",
            }
        },
        "evidence_retention_minimum_days": 730,
        "human_oversight_required": True,
    }


@dataclass
class FakeOverlayPlugin:
    name: str = "acme-risk"
    profile: dict[str, Any] | None = None

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name=self.name,
            plugin_type="overlay",
            package_name=f"{self.name}-package",
            package_version="1.0.0",
            min_sdk_version="0.1.0",
        )

    def load_overlay_profile(self, context: PluginContext) -> dict[str, Any]:
        assert context.config.get("tenant") == "acme"
        return self.profile or _overlay_profile(f"plugin:{self.name}")


def _plugin_registry(*plugins: FakeOverlayPlugin) -> PluginRegistry:
    return PluginRegistry(
        records=[
            PluginRecord(
                name=plugin.metadata.name,
                plugin_type="overlay",
                entry_point_group="ancilis.overlays",
                entry_point_name=plugin.metadata.name,
                package_name=plugin.metadata.package_name,
                package_version=plugin.metadata.package_version,
                metadata=plugin.metadata,
                plugin=plugin,
                compatible=True,
            )
            for plugin in plugins
        ],
        sdk_version="0.1.0",
    )


def test_activation_resolver_activates_plugin_overlay_from_data_classification() -> None:
    registry = _plugin_registry(FakeOverlayPlugin(profile=_overlay_profile(triggered_by=["DC-LEGAL"])))

    spec = ActivationResolver(
        plugin_registry=registry,
        plugin_configs={"acme-risk": {"tenant": "acme"}},
    ).resolve(my_agent_handles=["legal_data"])

    assert "plugin:acme-risk" in spec.active_overlays
    assert spec.activation_source["plugin:acme-risk"] == "my_agent_handles:legal_data"
    assert spec.control_thresholds["PR-01"] == "strict"
    assert "acme-risk-review" in spec.evidence_requirements["PR-01"]
    assert spec.evidence_retention_days == 730
    assert spec.human_oversight_required is True


def test_activation_resolver_activates_plugin_overlay_from_certification_target() -> None:
    registry = _plugin_registry(
        FakeOverlayPlugin(
            profile=_overlay_profile(
                trigger_type="certification_target",
                triggered_by=["aiuc-1"],
            )
        )
    )

    spec = ActivationResolver(
        plugin_registry=registry,
        plugin_configs={"acme-risk": {"tenant": "acme"}},
    ).resolve(certification_targets=["aiuc-1"])

    assert "plugin:acme-risk" in spec.active_overlays
    assert spec.activation_source["plugin:acme-risk"] == "certification_targets:aiuc-1"
    assert spec.control_thresholds["PR-01"] == "strict"
    assert spec.evidence_requirements["PR-01"] == ["acme-risk-review"]


def test_load_config_can_activate_plugin_overlay_from_explicit_compliance_config() -> None:
    registry = _plugin_registry(FakeOverlayPlugin(profile=_overlay_profile(triggered_by=["DC-LEGAL"])))

    config = load_config(
        raw={
            "agent": {"name": "plugin-overlay-agent"},
            "compliance": {"overlays": ["plugin:acme-risk"]},
        },
        plugin_registry=registry,
        plugin_configs={"acme-risk": {"tenant": "acme"}},
    )

    assert set(config.active_overlays) == {"plugin:acme-risk"}
    assert config.active_overlays["plugin:acme-risk"].name == "Acme Risk Overlay"
    assert config.controls["PR-01"].threshold == "strict"
    assert config.overlay_requirements["PR-01"]["plugin:acme-risk"] == {
        "evidence_requirements": ["acme-risk-review"],
        "framework_reference": "ACME-RISK-1",
    }


def test_load_config_activates_plugin_overlay_from_certification_target() -> None:
    registry = _plugin_registry(
        FakeOverlayPlugin(
            profile=_overlay_profile(
                trigger_type="certification_target",
                triggered_by=["aiuc-1"],
            )
        )
    )

    config = load_config(
        raw={
            "agent": {"name": "plugin-overlay-agent"},
            "certification_targets": ["aiuc-1"],
        },
        plugin_registry=registry,
        plugin_configs={"acme-risk": {"tenant": "acme"}},
    )

    assert "plugin:acme-risk" in config.active_overlays
    assert config.active_overlays["plugin:acme-risk"].triggered_by == ["certification_targets:aiuc-1"]
    assert config.controls["PR-01"].threshold == "strict"
    assert config.overlay_requirements["PR-01"]["plugin:acme-risk"] == {
        "evidence_requirements": ["acme-risk-review"],
        "framework_reference": "ACME-RISK-1",
    }


def test_malformed_plugin_overlay_warns_and_skips_without_crashing_config_resolution(
    caplog: Any,
) -> None:
    caplog.set_level(logging.WARNING)
    registry = _plugin_registry(FakeOverlayPlugin(profile={"id": "acme-risk"}))

    config = load_config(
        raw={
            "agent": {"name": "plugin-overlay-agent"},
            "compliance": {"overlays": ["acme-risk"]},
        },
        plugin_registry=registry,
        plugin_configs={"acme-risk": {"tenant": "acme"}},
    )

    assert config.active_overlays == {}
    assert config.unavailable_overlays == []
    assert "Skipping Ancilis plugin overlay acme-risk" in caplog.text
    assert any("Skipping Ancilis plugin overlay acme-risk" in warning for warning in config.warnings)


@pytest.mark.parametrize(
    ("field_name", "field_value", "warning_fragment"),
    [
        (
            "control_adjustments",
            {"PR-01": "strict"},
            "control_adjustments.PR-01' must be a mapping",
        ),
        (
            "evidence_requirements",
            {"PR-01": "acme-risk-review"},
            "evidence_requirements.PR-01' must be a list of strings",
        ),
        (
            "controls",
            {"PR-01": "applicable"},
            "controls.PR-01' must be a mapping",
        ),
        (
            "evidence_retention_minimum_days",
            "730",
            "evidence_retention_minimum_days' must be an integer",
        ),
        (
            "human_oversight_required",
            "yes",
            "human_oversight_required' must be a boolean",
        ),
    ],
)
def test_malformed_plugin_overlay_nested_fields_warn_and_skip_without_crashing(
    caplog: Any,
    field_name: str,
    field_value: Any,
    warning_fragment: str,
) -> None:
    caplog.set_level(logging.WARNING)
    profile = _overlay_profile()
    profile[field_name] = field_value
    registry = _plugin_registry(FakeOverlayPlugin(profile=profile))

    config = load_config(
        raw={
            "agent": {"name": "plugin-overlay-agent"},
            "compliance": {"overlays": ["plugin:acme-risk"]},
        },
        plugin_registry=registry,
        plugin_configs={"acme-risk": {"tenant": "acme"}},
    )

    assert config.active_overlays == {}
    assert warning_fragment in caplog.text
    assert any(warning_fragment in warning for warning in config.warnings)
