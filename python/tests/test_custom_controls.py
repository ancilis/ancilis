"""Runtime tests for SDK custom control definitions."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Generator
from pathlib import Path
from typing import Any, cast

import pytest

import ancilis
from ancilis.config import SHARED_DIR, ResolvedConfig, load_config, load_control_definitions
from ancilis.controls.custom import CustomControlDefinition
from ancilis.engine import (
    Action,
    ActionContext,
    ActionParameters,
    ControlResult,
    Engine,
    EvaluationResult,
    ToolEntry,
    ToolInfo,
    ToolRegistry,
)
from ancilis.engine.registry import ToolStatus
from ancilis.errors import ConfigError


FIXTURE_DIR = SHARED_DIR / "fixtures" / "custom-controls"
RegisterControl = Callable[[dict[str, Any] | CustomControlDefinition], CustomControlDefinition]


@pytest.fixture(autouse=True)
def clear_custom_control_registry() -> Generator[None]:
    from ancilis.controls.custom import clear_custom_controls

    clear_custom_controls()
    yield
    clear_custom_controls()


def _fixture(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((FIXTURE_DIR / name).read_text()))


def _register_control() -> RegisterControl:
    return cast(RegisterControl, ancilis.__getattr__("register_control"))


def _config() -> ResolvedConfig:
    return load_config(raw={"agent": {"name": "test-agent"}})


def _engine(config: ResolvedConfig) -> Engine:
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


def _control_result(result: EvaluationResult, control_id: str) -> ControlResult:
    return next(r for r in result.control_results if r.control_id == control_id)


def test_register_control_adds_schema_valid_definition_without_mutating_builtins() -> None:
    definition = _fixture("acme-siem-latency.json")

    registered = _register_control()(definition)
    config = _config()

    assert registered.id == "custom:siem-latency"
    assert "custom:siem-latency" in config.controls
    assert "custom:siem-latency" not in load_control_definitions()
    assert "PR-01" in config.controls


def test_register_control_rejects_duplicate_custom_control_id() -> None:
    definition = _fixture("acme-siem-latency.json")

    _register_control()(definition)

    with pytest.raises(ValueError, match="already registered"):
        _register_control()(definition)


def test_register_control_validates_definition_objects() -> None:
    definition = CustomControlDefinition(
        id="bad-prefix:siem-latency",
        title="SIEM Event Latency",
        description="Invalid custom control object with a non-canonical id.",
        category="detect",
        severity="medium",
        evaluator_type="regex",
        evaluator={"pattern": "latency"},
    )

    with pytest.raises(ValueError, match="invalid custom control bad-prefix:siem-latency"):
        _register_control()(definition)


def test_config_rejects_unknown_custom_control_override() -> None:
    with pytest.raises(ConfigError, match="Unknown custom control ID"):
        load_config(
            raw={
                "agent": {"name": "test-agent"},
                "security": {"controls": {"custom:missing-definition": {"enabled": True}}},
            }
        )


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
    _register_control()(_fixture("acme-siem-latency.json"))
    engine = _engine(_config())

    passing = engine.evaluate(_action({"metadata": {"siem_latency_ms": 250}}))
    failing = engine.evaluate(_action({"metadata": {"siem_latency_ms": 900}}))

    passed = _control_result(passing, "custom:siem-latency")
    failed = _control_result(failing, "custom:siem-latency")
    assert passed.result == "PASS"
    assert failed.result == "FAIL"
    assert failed.evidence_data["evaluator_type"] == "regex"


def test_manual_custom_control_skips_until_attestation_is_supplied() -> None:
    _register_control()(_fixture("manual-vendor-review.json"))
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
        _register_control()(definition)
