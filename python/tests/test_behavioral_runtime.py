from __future__ import annotations

import uuid

from ancilis.config import load_config
from ancilis.controls.de01_baseline import DE01BaselineEvaluator
from ancilis.engine.action import Action, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.tool import ToolActionProducer


def _config():
    return load_config(raw={"agent": {"name": "runtime-agent", "owner": "sdk-team"}})


def _make_action(tool_name: str, parameter_hash: str) -> Action:
    return Action(
        action_id=str(uuid.uuid4()),
        timestamp="2026-05-16T10:00:00Z",
        agent_id="runtime-agent",
        action_type="tool_call",
        tool=ToolInfo(name=tool_name),
        parameters=ActionParameters(raw={}, parameter_hash=parameter_hash),
    )


def _de01_record(record):
    return next(item for item in record.control_results if item["control_id"] == "DE-01")


def test_de01_warms_for_first_25_tool_calls() -> None:
    evaluator = DE01BaselineEvaluator()
    config = _config()

    for index in range(25):
        result = evaluator.evaluate(
            _make_action("tool:payments.lookup", f"warm-hash-{index}"),
            config,
        )

        assert result.result == "PASS"
        assert result.evidence_data["behavior_schema_version"] == 1
        assert result.evidence_data["observation_type"] == "tool_call"
        assert result.evidence_data["observed_tool_name"] == "tool:payments.lookup"
        assert result.evidence_data["observed_parameter_hash"] == f"warm-hash-{index}"
        assert result.evidence_data["baseline_established"] is False
        assert result.evidence_data["baseline_min_events"] == 25
        assert result.evidence_data["window_event_count"] == index
        assert result.evidence_data["new_tools_detected"] == []
        assert result.evidence_data["deviation_flags"] == []


def test_de01_flags_first_unseen_tool_after_warmup_then_converges() -> None:
    evaluator = DE01BaselineEvaluator()
    config = _config()

    for index in range(25):
        evaluator.evaluate(_make_action("tool:payments.lookup", f"warm-{index}"), config)

    anomalous = evaluator.evaluate(_make_action("tool:payments.export", "new-hash"), config)
    repeated = evaluator.evaluate(_make_action("tool:payments.export", "repeat-hash"), config)

    assert anomalous.result == "FLAG"
    assert anomalous.evidence_data["baseline_established"] is True
    assert anomalous.evidence_data["window_event_count"] == 25
    assert anomalous.evidence_data["window_unique_tools"] == ["tool:payments.lookup"]
    assert anomalous.evidence_data["new_tools_detected"] == ["tool:payments.export"]
    assert anomalous.evidence_data["deviation_flags"][0]["type"] == "new_tool"

    assert repeated.result == "PASS"
    assert repeated.evidence_data["baseline_established"] is True
    assert repeated.evidence_data["new_tools_detected"] == []
    assert repeated.evidence_data["deviation_flags"] == []


def test_tool_action_producer_persists_behavior_evidence_and_chain_verifies() -> None:
    config = _config()
    store = EvidenceStore(config, in_memory=True)
    producer = ToolActionProducer(config=config, engine=Engine(config), evidence_store=store)

    def lookup(value: str) -> str:
        return value

    def export(value: str) -> str:
        return value

    for index in range(25):
        producer.execute(
            lookup,
            agent_name="runtime-agent",
            tool_name="tool:payments.lookup",
            args=(f"pay-{index}",),
        )

    producer.execute(
        export,
        agent_name="runtime-agent",
        tool_name="tool:payments.export",
        args=("pay-final",),
    )

    records = store.get_records(limit=30)
    warm_record = _de01_record(records[24])
    anomaly_record = _de01_record(records[25])

    assert warm_record["result"] == "PASS"
    assert warm_record["evidence_data"]["baseline_established"] is False
    assert warm_record["evidence_data"]["window_event_count"] == 24

    assert anomaly_record["result"] == "FLAG"
    assert anomaly_record["evidence_data"]["behavior_schema_version"] == 1
    assert anomaly_record["evidence_data"]["observed_tool_name"] == "tool:payments.export"
    assert anomaly_record["evidence_data"]["observed_parameter_hash"]
    assert anomaly_record["evidence_data"]["baseline_established"] is True
    assert anomaly_record["evidence_data"]["new_tools_detected"] == ["tool:payments.export"]

    valid, errors = store.verify_chain()
    assert valid, errors

    store.close()
