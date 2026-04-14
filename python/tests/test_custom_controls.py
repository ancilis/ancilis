"""Runtime tests for SDK custom control definitions."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

import ancilis
from ancilis.config import SHARED_DIR, load_config, load_control_definitions
from ancilis.engine import (
    Action,
    ActionContext,
    ActionParameters,
    Engine,
    ToolEntry,
    ToolInfo,
    ToolRegistry,
)
from ancilis.engine.registry import ToolStatus


FIXTURE_DIR = SHARED_DIR / "fixtures" / "custom-controls"


@pytest.fixture(autouse=True)
def clear_custom_control_registry() -> None:
    from ancilis.controls.custom import clear_custom_controls

    clear_custom_controls()
    yield
    clear_custom_controls()


def _fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURE_DIR / name).read_text())


def _config() -> Any:
    return load_config(raw={"agent": {"name": "test-agent"}})


def _engine(config: Any) -> Engine:
    registry = ToolRegistry()
    registry.register(
        ToolEntry(name="test-tool", description_hash="hash123", status=ToolStatus.APPROVED)
    )
    return Engine(config, registry=registry)


def _action(params: dict[str, Any]) -> Action:
    return Action(
        action_id="custom-control-action",
        timestamp="2026-04-14T00:00:00Z",
        agent_id="test-agent",
        action_type="tool_call",
        tool=ToolInfo(name="test-tool", description_hash="hash123"),
        parameters=ActionParameters(raw=params, parameter_hash="hash123"),
        context=ActionContext(),
    )


def _control_result(result: Any, control_id: str) -> Any:
    return next(r for r in result.control_results if r.control_id == control_id)


def test_register_control_adds_schema_valid_definition_without_mutating_builtins() -> None:
    definition = _fixture("acme-siem-latency.json")

    registered = ancilis.register_control(definition)
    config = _config()

    assert registered.id == "custom:siem-latency"
    assert "custom:siem-latency" in config.controls
    assert "custom:siem-latency" not in load_control_definitions()
    assert "PR-01" in config.controls


def test_register_control_rejects_duplicate_custom_control_id() -> None:
    definition = _fixture("acme-siem-latency.json")

    ancilis.register_control(definition)

    with pytest.raises(ValueError, match="already registered"):
        ancilis.register_control(definition)


def test_load_config_registers_json_controls_next_to_config(tmp_path: Path) -> None:
    config_path = tmp_path / "ancilis.yaml"
    controls_dir = tmp_path / ".ancilis" / "controls"
    controls_dir.mkdir(parents=True)
    config_path.write_text("agent:\n  name: test-agent\n")
    (controls_dir / "vendor-review.json").write_text(
        json.dumps(_fixture("manual-vendor-review.json"))
    )

    config = load_config(path=config_path)

    assert "custom:vendor-review" in config.controls
    assert config.controls["custom:vendor-review"].enabled is True


def test_regex_custom_control_passes_and_fails_against_metadata() -> None:
    ancilis.register_control(_fixture("acme-siem-latency.json"))
    engine = _engine(_config())

    passing = engine.evaluate(_action({"metadata": {"siem_latency_ms": 250}}))
    failing = engine.evaluate(_action({"metadata": {"siem_latency_ms": 900}}))

    passed = _control_result(passing, "custom:siem-latency")
    failed = _control_result(failing, "custom:siem-latency")
    assert passed.result == "PASS"
    assert failed.result == "FAIL"
    assert failed.evidence_data["evaluator_type"] == "regex"


def test_manual_custom_control_skips_until_attestation_is_supplied() -> None:
    ancilis.register_control(_fixture("manual-vendor-review.json"))
    engine = _engine(_config())

    missing = engine.evaluate(_action({}))
    supplied = engine.evaluate(
        _action({"manual_attestations": {"custom:vendor-review": True}})
    )

    skipped = _control_result(missing, "custom:vendor-review")
    passed = _control_result(supplied, "custom:vendor-review")
    assert skipped.result == "SKIP"
    assert "attestation" in skipped.detail.lower()
    assert passed.result == "PASS"


@pytest.mark.parametrize("reserved_type", ["script", "webhook"])
def test_reserved_evaluator_types_are_rejected_before_runtime(reserved_type: str) -> None:
    definition = copy.deepcopy(_fixture("acme-siem-latency.json"))
    definition["evaluator_type"] = reserved_type

    with pytest.raises(ValueError, match=f"unsupported evaluator_type '{reserved_type}'"):
        ancilis.register_control(definition)
