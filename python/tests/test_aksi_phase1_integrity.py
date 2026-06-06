from __future__ import annotations

from datetime import datetime, timezone
import uuid

from ancilis.config import load_config
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.evidence.store import EvidenceStore


def _registry(tool_name: str = "probe-tool", description_hash: str = "hash-v1") -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolEntry(
            name=tool_name,
            description_hash=description_hash,
            status=ToolStatus.APPROVED,
            approved_by="test",
        )
    )
    return registry


def _action(
    *,
    agent_id: str = "probe-agent",
    agent_owner: str = "security-team",
    tool_name: str = "probe-tool",
    action_type: str = "tool_call",
    params: dict | None = None,
    description_hash: str = "hash-v1",
    session_id: str = "phase1-session",
) -> Action:
    return Action(
        action_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_id=agent_id,
        agent_owner=agent_owner,
        action_type=action_type,
        tool=ToolInfo(name=tool_name, description_hash=description_hash),
        parameters=ActionParameters(raw=params or {}, parameter_hash="params"),
        context=ActionContext(session_id=session_id),
        source_type="test",
    )


def _config(**overrides):
    raw = {
        "agent": {
            "name": "runtime-probe-agent",
            "agent_id": "probe-agent",
            "owner": "security-team",
        },
        "security": {
            "mode": "audit",
            "tools": {"allowed": ["probe-tool"]},
            "scope": {
                "allowed_destinations": ["api.allowed.example"],
                "blocked_destinations": ["blocked.example"],
            },
            "controls": {
                "GOV-01": {"enabled": True},
                "GOV-02": {"enabled": True},
                "GOV-03": {"enabled": True},
                "ID-01": {"enabled": True},
                "DE-04": {"enabled": True},
            },
        },
        "my_agent_handles": ["personal_info", "credit_cards"],
    }
    raw.update(overrides)
    return load_config(raw=raw)


def _result(evaluation, control_id: str):
    return next(r for r in evaluation.control_results if r.control_id == control_id)


def test_phase1_engine_registers_correct_v06_evaluators() -> None:
    config = _config()
    store = EvidenceStore(config, in_memory=True)
    engine = Engine(config, registry=_registry(), evidence_store=store)

    assert "GOV-01" in engine._evaluators
    assert "PR-01" in engine._evaluators
    assert "PR-05" in engine._evaluators
    assert "PR-06" in engine._evaluators
    assert "DE-02" in engine._evaluators
    assert "DE-03" in engine._evaluators

    assert engine._evaluators["GOV-01"].control_name == "Agent Identity Declaration and Match"
    assert engine._evaluators["PR-01"].control_name == "Action Authorization"
    assert engine._evaluators["PR-05"].control_name == "Context and Tenant Isolation"
    assert engine._evaluators["PR-06"].control_name == "Audit Trail Completeness"
    assert engine._evaluators["DE-02"].control_name == "Classification Drift and Boundary Validation"
    assert engine._evaluators["DE-03"].control_name == "Configuration/Dependency Drift Monitoring"


def test_phase1_probe_clean_control_semantics_pass() -> None:
    config = _config()
    store = EvidenceStore(config, in_memory=True)
    engine = Engine(config, registry=_registry(), evidence_store=store)

    evaluation = engine.evaluate(
        _action(params={"operation": "summarize", "destination": "api.allowed.example"})
    )

    assert _result(evaluation, "GOV-01").result == "PASS"
    assert _result(evaluation, "PR-01").result == "PASS"
    assert _result(evaluation, "PR-05").result == "PASS"
    assert _result(evaluation, "PR-06").result == "PASS"
    assert _result(evaluation, "DE-02").result == "PASS"
    assert _result(evaluation, "DE-03").result == "PASS"


def test_de02_fails_when_observed_classification_is_not_declared() -> None:
    config = _config(my_agent_handles=["personal_info"])
    store = EvidenceStore(config, in_memory=True)
    engine = Engine(config, registry=_registry(), evidence_store=store)

    evaluation = engine.evaluate(
        _action(params={"card": "4111-1111-1111-1111", "destination": "api.allowed.example"})
    )

    de02 = _result(evaluation, "DE-02")
    assert de02.result == "FAIL"
    assert de02.evidence_data["undeclared_data_classes"] == ["DC-CHD"]


def test_de02_flags_compatible_phi_to_pii_boundary() -> None:
    config = _config(my_agent_handles=["health_records"])
    config.data_classifications["health_records"] = ["DC-PHI"]
    store = EvidenceStore(config, in_memory=True)
    engine = Engine(config, registry=_registry(), evidence_store=store)

    evaluation = engine.evaluate(
        _action(params={"ssn": "123-45-6789", "destination": "api.allowed.example"})
    )

    de02 = _result(evaluation, "DE-02")
    assert de02.result == "FLAG"
    assert de02.evidence_data["compatible_data_classes"] == ["DC-PII"]


def test_pr05_detects_cross_tenant_reference() -> None:
    config = _config()
    store = EvidenceStore(config, in_memory=True)
    engine = Engine(config, registry=_registry(), evidence_store=store)
    action = _action(params={"tenant_id": "tenant-b", "destination": "api.allowed.example"})
    action.context.tenant_id = "tenant-a"  # type: ignore[attr-defined]

    evaluation = engine.evaluate(action)

    pr05 = _result(evaluation, "PR-05")
    assert pr05.result == "FAIL"
    assert "tenant" in pr05.detail.lower()
