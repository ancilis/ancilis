"""AKSI integration tests — programmatic engine invocation without CLI subprocess.

ANC-191: Validates that the Ancilis SDK engine can be driven entirely through
direct Python imports with no subprocess or CLI layer involved.
"""

from __future__ import annotations

import importlib
import uuid
from pathlib import Path

import pytest

from ancilis.config import load_config
from ancilis.engine import (
    Action,
    ActionContext,
    ActionParameters,
    Engine,
    ToolInfo,
)

# Path to demo config shipped with the repo
DEMO_CONFIG_PATH = Path(__file__).parent.parent.parent / "examples" / "demo" / "ancilis.yaml"

# Implemented evaluator control IDs that must appear in every evaluation
EVALUATOR_CONTROL_IDS = {
    "PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "PR-06", "PR-07", "PR-08",
    "DE-01", "DE-02", "DE-04", "GOV-02",
}

VALID_RESULTS = {"PASS", "FAIL", "FLAG", "SKIP", "ERROR"}


def _make_action(
    tool_name: str = "check_balance",
    agent_id: str = "test-agent",
    params: dict | None = None,
) -> Action:
    return Action(
        action_id=str(uuid.uuid4()),
        timestamp="2026-04-07T00:00:00Z",
        agent_id=agent_id,
        action_type="tool_call",
        tool=ToolInfo(name=tool_name),
        parameters=ActionParameters(raw=params or {}, parameter_hash="abc123"),
        context=ActionContext(),
    )


class TestProgrammaticEngineInvocation:
    """Integration: full config → engine → evaluate flow with no subprocess."""

    def test_load_config_from_yaml_path(self) -> None:
        """Config loads from demo YAML path without subprocess."""
        config = load_config(path=DEMO_CONFIG_PATH)
        assert config.agent_name == "finance-demo-agent"
        assert config.mode == "enforce"

    def test_engine_instantiation_from_yaml_config(self) -> None:
        """Engine instantiates from a programmatically loaded config."""
        config = load_config(path=DEMO_CONFIG_PATH)
        engine = Engine(config)
        assert engine is not None
        assert engine.config is config

    def test_evaluate_returns_evaluation_result(self) -> None:
        """engine.evaluate() returns an EvaluationResult with required fields."""
        config = load_config(path=DEMO_CONFIG_PATH)
        engine = Engine(config)
        action = _make_action()

        result = engine.evaluate(action)

        assert result.evaluation_id is not None
        assert result.action_id == action.action_id
        assert result.decision in ("ALLOW", "BLOCK")
        assert isinstance(result.control_results, list)
        assert len(result.control_results) > 0

    def test_all_implemented_evaluators_produce_results(self) -> None:
        """All implemented evaluator controls appear in results."""
        config = load_config(path=DEMO_CONFIG_PATH)
        engine = Engine(config)
        action = _make_action()

        result = engine.evaluate(action)

        result_ids = {cr.control_id for cr in result.control_results}
        assert EVALUATOR_CONTROL_IDS.issubset(result_ids), (
            f"Missing evaluators: {EVALUATOR_CONTROL_IDS - result_ids}"
        )

    def test_de02_evaluator_exported_from_evaluators_package(self) -> None:
        """DE-02 evaluator is importable from the evaluators package."""
        evaluators = importlib.import_module("ancilis.engine.evaluators")
        assert hasattr(evaluators, "DE02ClassificationDriftEvaluator")

    def test_de04_evaluator_exported_from_evaluators_package(self) -> None:
        """DE-04 evaluator is importable from the evaluators package."""
        evaluators = importlib.import_module("ancilis.engine.evaluators")
        assert hasattr(evaluators, "DE04IntegrityEvaluator")

    def test_gov02_evaluator_exported_from_evaluators_package(self) -> None:
        """GOV-02 evaluator is importable from the evaluators package."""
        evaluators = importlib.import_module("ancilis.engine.evaluators")
        assert hasattr(evaluators, "GOV02OwnershipEvaluator")

    def test_each_control_result_has_valid_outcome(self) -> None:
        """Every ControlResult has a valid result value."""
        config = load_config(path=DEMO_CONFIG_PATH)
        engine = Engine(config)
        action = _make_action()

        result = engine.evaluate(action)

        for cr in result.control_results:
            assert cr.control_id is not None
            assert cr.result in VALID_RESULTS, (
                f"Control {cr.control_id} returned unexpected result: {cr.result!r}"
            )

    def test_pr01_control_present_in_results(self) -> None:
        """PR-01 identity control is in results — mirrors the spec usage pattern."""
        config = load_config(path=DEMO_CONFIG_PATH)
        engine = Engine(config)
        action = _make_action(agent_id="test-agent")

        result = engine.evaluate(action)

        pr01 = next((cr for cr in result.control_results if cr.control_id == "PR-01"), None)
        assert pr01 is not None
        assert pr01.result in VALID_RESULTS

    def test_full_programmatic_flow_no_subprocess(self) -> None:
        """End-to-end programmatic flow: YAML path → config → engine → evaluate → assert."""
        # Step 1: Load config from YAML path (no subprocess)
        config = load_config(path=DEMO_CONFIG_PATH)

        # Step 2: Create engine instance
        engine = Engine(config)

        # Step 3: Feed a test action
        action = _make_action(tool_name="check_balance", params={"account_id": "123"})

        # Step 4: Receive evaluation result
        result = engine.evaluate(action)

        # Step 5: Assert results contain expected control evaluations
        assert result.control_results[0].control_id is not None
        assert result.control_results[0].result in VALID_RESULTS
        assert result.agent_id == "test-agent"
        assert result.source_type == "agent"
        assert result.total_duration_ms >= 0


class TestEngineConstructorValidatesConfig:
    """Unit: engine constructor rejects invalid input, accepts minimal config."""

    def test_engine_requires_resolved_config(self) -> None:
        """Engine must receive a ResolvedConfig — raw dict fails at evaluate time."""
        bad_engine = Engine({"agent": {"name": "test"}})  # type: ignore[arg-type]
        with pytest.raises((TypeError, AttributeError)):
            bad_engine.evaluate(_make_action())

    def test_engine_built_from_minimal_programmatic_config(self) -> None:
        """Engine initialises with a minimal config dict (no YAML file needed)."""
        config = load_config(raw={"agent": {"name": "minimal-agent"}})
        engine = Engine(config)
        action = _make_action()
        result = engine.evaluate(action)
        assert result.decision in ("ALLOW", "BLOCK")
        assert len(result.control_results) > 0


class TestEvaluatorRootImportability:
    """Verify all 9 new evaluators are importable from the root evaluators package."""

    def test_de03_config_drift_importable(self) -> None:
        from ancilis.engine.evaluators import DE03ConfigDriftEvaluator  # noqa: F401
        assert DE03ConfigDriftEvaluator is not None

    def test_pr07_transport_importable(self) -> None:
        from ancilis.engine.evaluators import PR07TransportEvaluator  # noqa: F401
        assert PR07TransportEvaluator is not None

    def test_pr08_input_importable(self) -> None:
        from ancilis.engine.evaluators import PR08InputEvaluator  # noqa: F401
        assert PR08InputEvaluator is not None

    def test_gov01_identity_auth_importable(self) -> None:
        from ancilis.engine.evaluators import GOV01IdentityAuthEvaluator  # noqa: F401
        assert GOV01IdentityAuthEvaluator is not None

    def test_gov02_ownership_importable(self) -> None:
        from ancilis.engine.evaluators import GOV02OwnershipEvaluator  # noqa: F401
        assert GOV02OwnershipEvaluator is not None

    def test_gov03_risk_tolerance_importable(self) -> None:
        from ancilis.engine.evaluators import GOV03RiskToleranceEvaluator  # noqa: F401
        assert GOV03RiskToleranceEvaluator is not None

    def test_de02_classification_drift_importable(self) -> None:
        from ancilis.engine.evaluators import DE02ClassificationDriftEvaluator  # noqa: F401
        assert DE02ClassificationDriftEvaluator is not None

    def test_de04_integrity_importable(self) -> None:
        from ancilis.engine.evaluators import DE04IntegrityEvaluator  # noqa: F401
        assert DE04IntegrityEvaluator is not None

    def test_id01_inventory_importable(self) -> None:
        from ancilis.engine.evaluators import ID01InventoryEvaluator  # noqa: F401
        assert ID01InventoryEvaluator is not None

    def test_all_new_evaluators_in_dunder_all(self) -> None:
        """__all__ in evaluators package lists all 9 new evaluators."""
        import ancilis.engine.evaluators as evs
        new_evaluators = [
            "PR01ActionAuthorizationEvaluator",
            "PR05IsolationEvaluator",
            "PR06AuditTrailEvaluator",
            "PR07TransportEvaluator",
            "PR08InputEvaluator",
            "GOV01IdentityAuthEvaluator",
            "GOV02OwnershipEvaluator",
            "GOV03RiskToleranceEvaluator",
            "DE02ClassificationDriftEvaluator",
            "DE03ConfigDriftEvaluator",
            "DE04IntegrityEvaluator",
            "ID01InventoryEvaluator",
        ]
        for name in new_evaluators:
            assert name in evs.__all__, f"{name} missing from evaluators.__all__"
