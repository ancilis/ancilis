"""Tests for ancilis evidence — Unit 4: Evidence Generation & Storage."""

from __future__ import annotations

import json

import pytest

from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.chain import GENESIS_SEED, canonical_payload, compute_hash
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.store import EvidenceStore


def make_config(**overrides) -> ResolvedConfig:
    raw = {"agent": {"name": "test-agent"}, **overrides}
    return load_config(raw=raw)


def make_evaluation(
    evaluation_id: str = "eval-001",
    agent_id: str = "test-agent",
    decision: str = "ALLOW",
    mode: str = "audit",
    control_results: list[ControlResult] | None = None,
) -> EvaluationResult:
    if control_results is None:
        control_results = [
            ControlResult(
                control_id="PR-01",
                control_name="Agent Identity",
                result="PASS",
                detail="Agent identity verified",
                evidence_data={"agent_id": agent_id},
                duration_ms=1.5,
            ),
        ]
    return EvaluationResult(
        evaluation_id=evaluation_id,
        action_id="action-001",
        timestamp="2025-01-15T10:30:00Z",
        agent_id=agent_id,
        mode=mode,
        control_results=control_results,
        decision=decision,
        decision_reason="All controls passed",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=5.0,
    )


# --- Hash Chain ---


class TestHashChain:
    def test_genesis_seed_is_deterministic(self):
        assert GENESIS_SEED == GENESIS_SEED
        assert len(GENESIS_SEED) == 64  # SHA-256 hex

    def test_canonical_payload_deterministic(self):
        args = dict(
            evaluation_id="e1",
            timestamp="2025-01-01T00:00:00Z",
            agent_id="agent",
            source_type="agent",
            tool_name="tool",
            decision="ALLOW",
            mode="audit",
            control_results=[],
            active_overlays=[],
            data_classifications=[],
            active_certifications=[],
            total_duration_ms=1.0,
            previous_hash=GENESIS_SEED,
        )
        p1 = canonical_payload(**args)
        p2 = canonical_payload(**args)
        assert p1 == p2

    def test_canonical_payload_sorted_keys(self):
        payload = canonical_payload(
            evaluation_id="e1",
            timestamp="t1",
            agent_id="a1",
            source_type="agent",
            tool_name="tool",
            decision="ALLOW",
            mode="audit",
            control_results=[],
            active_overlays=[],
            data_classifications=[],
            active_certifications=[],
            total_duration_ms=0.0,
            previous_hash="prev",
        )
        parsed = json.loads(payload)
        keys = list(parsed.keys())
        assert keys == sorted(keys)

    def test_compute_hash_produces_sha256(self):
        h = compute_hash("test data")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_different_input_different_hash(self):
        h1 = compute_hash("input1")
        h2 = compute_hash("input2")
        assert h1 != h2


# --- Evidence Record ---


class TestEvidenceRecord:
    def test_record_dataclass(self):
        record = EvidenceRecord(
            record_id="r1",
            evaluation_id="e1",
            timestamp="2025-01-01T00:00:00Z",
            agent_id="agent",
            source_type="agent",
            tool_name="my-tool",
            decision="ALLOW",
            mode="audit",
            control_results=[],
            active_overlays=[],
            data_classifications=[],
            active_certifications=[],
            record_hash="abc",
            previous_hash=GENESIS_SEED,
        )
        assert record.record_id == "r1"
        assert record.tool_name == "my-tool"
        assert record.active_certifications == []


# --- Evidence Store ---


class TestEvidenceStore:
    def test_store_creates_record(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)
        ev = make_evaluation()

        record = store.store(ev, tool_name="my-tool")
        assert record.evaluation_id == "eval-001"
        assert record.tool_name == "my-tool"
        assert record.decision == "ALLOW"
        assert len(record.record_hash) == 64
        store.close()

    def test_first_record_uses_genesis_seed(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)
        ev = make_evaluation()

        record = store.store(ev, tool_name="tool-a")
        assert record.previous_hash == GENESIS_SEED
        store.close()

    def test_hash_chain_links(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        ev1 = make_evaluation(evaluation_id="e1")
        ev2 = make_evaluation(evaluation_id="e2")

        r1 = store.store(ev1, tool_name="tool-a")
        r2 = store.store(ev2, tool_name="tool-b")

        assert r1.previous_hash == GENESIS_SEED
        assert r2.previous_hash == r1.record_hash
        assert r2.record_hash != r1.record_hash
        store.close()

    def test_count(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        assert store.count() == 0
        store.store(make_evaluation(evaluation_id="e1"), tool_name="t1")
        assert store.count() == 1
        store.store(make_evaluation(evaluation_id="e2"), tool_name="t2")
        assert store.count() == 2
        store.close()

    def test_get_records_all(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        store.store(make_evaluation(evaluation_id="e1"), tool_name="t1")
        store.store(make_evaluation(evaluation_id="e2"), tool_name="t2")

        records = store.get_records()
        assert len(records) == 2
        store.close()

    def test_get_records_filter_tool(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        store.store(make_evaluation(evaluation_id="e1"), tool_name="tool-a")
        store.store(make_evaluation(evaluation_id="e2"), tool_name="tool-b")

        records = store.get_records(tool_name="tool-a")
        assert len(records) == 1
        assert records[0].tool_name == "tool-a"
        store.close()

    def test_get_records_filter_decision(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        store.store(make_evaluation(evaluation_id="e1", decision="ALLOW"), tool_name="t1")
        store.store(make_evaluation(evaluation_id="e2", decision="BLOCK"), tool_name="t2")

        records = store.get_records(decision="BLOCK")
        assert len(records) == 1
        assert records[0].decision == "BLOCK"
        store.close()

    def test_get_records_filter_session_id(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        ev1 = make_evaluation(evaluation_id="e1")
        ev1.session_id = "sess-1"
        ev2 = make_evaluation(evaluation_id="e2")
        ev2.session_id = "sess-2"

        store.store(ev1, tool_name="tool-a")
        store.store(ev2, tool_name="tool-b")

        records = store.get_records(session_id="sess-2")
        assert len(records) == 1
        assert records[0].evaluation_id == "e2"
        assert records[0].session_id == "sess-2"
        store.close()

    def test_verify_chain_valid(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        store.store(make_evaluation(evaluation_id="e1"), tool_name="t1")
        store.store(make_evaluation(evaluation_id="e2"), tool_name="t2")
        store.store(make_evaluation(evaluation_id="e3"), tool_name="t3")

        valid, errors = store.verify_chain()
        assert valid is True
        assert errors == []
        store.close()

    def test_verify_chain_detects_output_summary_tampering(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        record = store.store(
            make_evaluation(evaluation_id="e1"),
            tool_name="t1",
            output_summary="safe summary",
        )
        store._connection.execute(
            "UPDATE evidence_records SET output_summary = ? WHERE record_id = ?",
            ["tampered summary", record.record_id],
        )

        valid, errors = store.verify_chain()
        assert valid is False
        assert any("hash mismatch" in error for error in errors)
        store.close()

    def test_verify_chain_empty(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        valid, errors = store.verify_chain()
        assert valid is True
        assert errors == []
        store.close()

    def test_active_certifications_stored(self):
        config = make_config()
        config.active_certifications = ["SOC2", "HIPAA"]
        store = EvidenceStore(config, in_memory=True)

        record = store.store(make_evaluation(), tool_name="t1")
        assert record.active_certifications == ["SOC2", "HIPAA"]
        store.close()

    def test_active_certifications_default_empty(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        record = store.store(make_evaluation(), tool_name="t1")
        assert record.active_certifications == []
        store.close()

    def test_blocked_evaluation_stored(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        ev = make_evaluation(decision="BLOCK")
        record = store.store(ev, tool_name="blocked-tool")
        assert record.decision == "BLOCK"
        assert store.count() == 1
        store.close()

    def test_config_agent_id_overrides_evaluation_agent_id(self):
        config = make_config(agent={"name": "test-agent", "agent_id": "00000000-0000-0000-0000-000000000001"})
        store = EvidenceStore(config, in_memory=True)

        ev = make_evaluation(agent_id="eval-agent")
        record = store.store(ev, tool_name="t1")
        assert record.agent_id == "00000000-0000-0000-0000-000000000001"
        store.close()

    def test_config_agent_id_null_uses_evaluation_agent_id(self):
        config = make_config()
        assert config.agent_id is None
        store = EvidenceStore(config, in_memory=True)

        ev = make_evaluation(agent_id="eval-agent")
        record = store.store(ev, tool_name="t1")
        assert record.agent_id == "eval-agent"
        store.close()

    def test_config_agent_id_persisted_and_queryable(self):
        config = make_config(agent={"name": "test-agent", "agent_id": "00000000-0000-0000-0000-000000000002"})
        store = EvidenceStore(config, in_memory=True)

        store.store(make_evaluation(evaluation_id="e1"), tool_name="t1")
        store.store(make_evaluation(evaluation_id="e2"), tool_name="t2")

        records = store.get_records(agent_id="00000000-0000-0000-0000-000000000002")
        assert len(records) == 2
        assert all(r.agent_id == "00000000-0000-0000-0000-000000000002" for r in records)
        store.close()

    def test_config_agent_id_in_hash_chain(self):
        """Hash chain includes config agent_id — tampering is detectable."""
        config = make_config(agent={"name": "test-agent", "agent_id": "00000000-0000-0000-0000-000000000003"})
        store = EvidenceStore(config, in_memory=True)

        store.store(make_evaluation(evaluation_id="e1"), tool_name="t1")
        valid, errors = store.verify_chain()
        assert valid is True
        assert errors == []
        store.close()


# --- Summary ---


class TestSummary:
    def test_get_summary_empty(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        summary = store.get_summary()
        assert summary["total_evaluations"] == 0
        assert summary["chain_valid"] is True
        store.close()

    def test_get_summary_with_records(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        store.store(make_evaluation(evaluation_id="e1", decision="ALLOW"), tool_name="tool-a")
        store.store(make_evaluation(evaluation_id="e2", decision="ALLOW"), tool_name="tool-b")
        store.store(make_evaluation(evaluation_id="e3", decision="BLOCK"), tool_name="tool-a")

        summary = store.get_summary()
        assert summary["total_evaluations"] == 3
        assert summary["decisions"]["ALLOW"] == 2
        assert summary["decisions"]["BLOCK"] == 1
        assert set(summary["tools_evaluated"]) == {"tool-a", "tool-b"}
        assert summary["chain_valid"] is True
        store.close()

    def test_get_summary_control_pass_rates(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        store.store(make_evaluation(evaluation_id="e1"), tool_name="t1")
        store.store(
            make_evaluation(
                evaluation_id="e2",
                control_results=[
                    ControlResult("PR-01", "Agent Identity", "FAIL", "Failed", {}, 1.0),
                ],
            ),
            tool_name="t2",
        )

        summary = store.get_summary()
        assert "control_pass_rates" in summary
        assert summary["control_pass_rates"]["PR-01"]["PASS"] == 1
        assert summary["control_pass_rates"]["PR-01"]["FAIL"] == 1
        store.close()

    def test_get_summary_aggregates_pattern_detections(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        store.store(
            make_evaluation(
                evaluation_id="e1",
                control_results=[
                    ControlResult(
                        "PR-04",
                        "Data Exposure Prevention",
                        "PASS",
                        "Patterns detected",
                        {
                            "scan_result": "patterns_found",
                            "patterns_detected": [
                                {"type": "credit_card", "count": 2, "redacted_sample": "****1111"},
                                {"type": "ssn", "count": 1, "redacted_sample": "***-**-6789"},
                            ],
                        },
                        1.0,
                    ),
                ],
            ),
            tool_name="t1",
        )

        summary = store.get_summary()
        assert summary["pattern_detections"] == {"credit_card": 2, "ssn": 1}
        store.close()

    def test_get_summary_filters_by_session_id(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        ev1 = make_evaluation(evaluation_id="e1", decision="ALLOW")
        ev1.session_id = "sess-1"
        ev2 = make_evaluation(evaluation_id="e2", decision="BLOCK")
        ev2.session_id = "sess-2"

        store.store(ev1, tool_name="tool-a")
        store.store(ev2, tool_name="tool-a")

        summary = store.get_summary(session_id="sess-2")
        assert summary["total_evaluations"] == 1
        assert summary["decisions"] == {"BLOCK": 1}
        assert summary["tools_evaluated"] == ["tool-a"]
        store.close()


# --- Purge ---


class TestPurge:
    def test_purge_before(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        ev1 = make_evaluation(evaluation_id="e1")
        ev1.timestamp = "2024-01-01T00:00:00Z"
        ev2 = make_evaluation(evaluation_id="e2")
        ev2.timestamp = "2025-06-01T00:00:00Z"

        store.store(ev1, tool_name="t1")
        store.store(ev2, tool_name="t2")
        assert store.count() == 2

        removed = store.purge_before("2025-01-01T00:00:00Z")
        assert removed == 1
        assert store.count() == 1
        store.close()

    def test_purge_none_removed(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        ev = make_evaluation()
        ev.timestamp = "2025-06-01T00:00:00Z"
        store.store(ev, tool_name="t1")

        removed = store.purge_before("2024-01-01T00:00:00Z")
        assert removed == 0
        assert store.count() == 1
        store.close()


# --- File-based Persistence ---


class TestFilePersistence:
    def test_file_db(self, tmp_path):
        db_file = tmp_path / "test_evidence.duckdb"
        config = make_config()

        store = EvidenceStore(config, db_path=db_file)
        store.store(make_evaluation(evaluation_id="e1"), tool_name="t1")
        store.close()

        # Reopen
        store2 = EvidenceStore(config, db_path=db_file)
        assert store2.count() == 1
        valid, errors = store2.verify_chain()
        assert valid is True
        store2.close()
