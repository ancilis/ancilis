from __future__ import annotations

from ancilis.activation.loader import load_overlay_profiles
from ancilis.config import load_config


def _activate_all_overlays() -> tuple[int, int, int]:
    profiles = load_overlay_profiles()
    resolved = load_config(
        raw={
            "agent": {"name": "benchmark-agent"},
            "compliance": {"overlays": sorted(profiles)},
        }
    )
    enabled_controls = sum(1 for control in resolved.controls.values() if control.enabled)
    overlay_requirements = sum(len(requirements) for requirements in resolved.overlay_requirements.values())
    return len(resolved.active_overlays), enabled_controls, overlay_requirements


def test_overlay_loading_and_control_mapping(benchmark) -> None:
    profile_count = len(load_overlay_profiles())
    active_overlays, enabled_controls, overlay_requirements = benchmark.pedantic(
        _activate_all_overlays,
        rounds=5,
        iterations=1,
    )
    assert active_overlays == profile_count
    assert enabled_controls > 0
    assert overlay_requirements >= 0
