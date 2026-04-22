"""Tests for DuckDB evidence sync metadata state."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore
from ancilis.evidence.sync_state import (
    SYNC_STATUS_FAILED,
    SYNC_STATUS_PENDING,
    SYNC_STATUS_SYNCED,
)


def make_config(**overrides: Any) -> ResolvedConfig:
    raw = {"agent": {"name": "test-agent"}, **overrides}
    return load_config(raw=raw)


def make_evaluation(evaluation_id: str, timestamp: str) -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=evaluation_id,
        action_id=f"action-{evaluation_id}",
        timestamp=timestamp,
        agent_id="test-agent",
        mode="audit",
        control_results=[
            ControlResult(
                control_id="PR-01",
                control_name="Agent Identity",
                result="PASS",
                detail="Agent identity verified",
                evidence_data={"agent_id": "test-agent"},
                duration_ms=1.0,
            ),
        ],
        decision="ALLOW",
        decision_reason="All controls passed",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=2.0,
    )


def sync_table_names(store: EvidenceStore) -> set[str]:
    rows = store._connection.execute("SHOW TABLES").fetchall()
    return {row[0] for row in rows}


class TestEvidenceSyncMetadata:
    def test_constructor_does_not_create_db_file(self, tmp_path: Path) -> None:
        db_file = tmp_path / "evidence.duckdb"
        store = EvidenceStore(make_config(), db_path=db_file)

        assert not db_file.exists()

        store.close()

    def test_store_creates_pending_sync_row_separate_from_evidence_record(self) -> None:
        store = EvidenceStore(make_config(), in_memory=True)

        record = store.store(make_evaluation("e1", "2025-01-01T00:00:00Z"), tool_name="t1")

        assert {"evidence_sync_state", "evidence_sync_meta"} <= sync_table_names(store)
        evidence_columns = {
            row[1] for row in store._connection.execute("PRAGMA table_info('evidence_records')").fetchall()
        }
        assert "sync_status" not in evidence_columns
        assert "last_synced_at" not in evidence_columns
        state = store.get_sync_state(record.record_id)
        assert state is not None
        assert state.status == SYNC_STATUS_PENDING
        assert state.attempt_count == 0
        store.close()

    def test_opening_existing_db_backfills_missing_pending_sync_rows(
        self, tmp_path: Path
    ) -> None:
        db_file = tmp_path / "evidence.duckdb"
        config = make_config()
        store = EvidenceStore(config, db_path=db_file)
        record = store.store(make_evaluation("e1", "2025-01-01T00:00:00Z"), tool_name="t1")
        store._connection.execute("DROP TABLE evidence_sync_state")
        store._connection.execute("DROP TABLE evidence_sync_meta")
        store.close()

        upgraded_store = EvidenceStore(config, db_path=db_file)

        state = upgraded_store.get_sync_state(record.record_id)
        pending = upgraded_store.get_pending_sync_records()
        valid, errors = upgraded_store.verify_chain()
        assert state is not None
        assert state.status == SYNC_STATUS_PENDING
        assert state.attempt_count == 0
        assert [pending_record.record_id for pending_record in pending] == [record.record_id]
        assert valid is True
        assert errors == []
        upgraded_store.close()

    def test_pending_records_return_in_sequence_order(self) -> None:
        store = EvidenceStore(make_config(), in_memory=True)
        first = store.store(make_evaluation("e1", "2025-01-01T00:00:00Z"), tool_name="t1")
        second = store.store(make_evaluation("e2", "2025-01-01T00:00:01Z"), tool_name="t2")
        third = store.store(make_evaluation("e3", "2025-01-01T00:00:02Z"), tool_name="t3")

        assert [record.record_id for record in store.get_pending_sync_records()] == [
            first.record_id,
            second.record_id,
            third.record_id,
        ]
        store.close()

    def test_pending_records_respect_next_retry_at(self) -> None:
        store = EvidenceStore(make_config(), in_memory=True)
        due = store.store(make_evaluation("e1", "2025-01-01T00:00:00Z"), tool_name="t1")
        not_due = store.store(make_evaluation("e2", "2025-01-01T00:00:01Z"), tool_name="t2")

        store.mark_sync_failed(
            not_due.record_id,
            error="platform unavailable",
            attempted_at="2025-01-01T00:00:10Z",
            next_retry_at="2025-01-01T00:10:00Z",
        )

        pending = store.get_pending_sync_records(now="2025-01-01T00:05:00Z")
        assert [record.record_id for record in pending] == [due.record_id]
        store.close()

    def test_mark_synced_updates_state_and_removes_from_pending(self) -> None:
        store = EvidenceStore(make_config(), in_memory=True)
        record = store.store(make_evaluation("e1", "2025-01-01T00:00:00Z"), tool_name="t1")

        store.mark_sync_synced(
            record.record_id,
            synced_at="2025-01-01T00:01:00Z",
            remote_status_code=201,
            remote_evidence_id="remote-1",
        )

        assert store.get_pending_sync_records() == []
        state = store.get_sync_state(record.record_id)
        assert state is not None
        assert state.status == SYNC_STATUS_SYNCED
        assert state.last_synced_at == "2025-01-01T00:01:00Z"
        assert state.remote_status_code == 201
        assert state.remote_evidence_id == "remote-1"
        store.close()

    def test_mark_failed_records_error_attempt_and_retry(self) -> None:
        store = EvidenceStore(make_config(), in_memory=True)
        record = store.store(make_evaluation("e1", "2025-01-01T00:00:00Z"), tool_name="t1")

        store.mark_sync_failed(
            record.record_id,
            error="timeout",
            attempted_at="2025-01-01T00:01:00Z",
            next_retry_at="2025-01-01T00:05:00Z",
            remote_status_code=503,
        )

        state = store.get_sync_state(record.record_id)
        assert state is not None
        assert state.status == SYNC_STATUS_FAILED
        assert state.attempt_count == 1
        assert state.last_error == "timeout"
        assert state.last_attempt_at == "2025-01-01T00:01:00Z"
        assert state.next_retry_at == "2025-01-01T00:05:00Z"
        assert state.remote_status_code == 503
        store.close()

    def test_mark_synced_rejects_unknown_record_id(self) -> None:
        store = EvidenceStore(make_config(), in_memory=True)

        with pytest.raises(KeyError, match="unknown evidence record_id"):
            store.mark_sync_synced("missing-record")

        store.close()

    def test_mark_failed_rejects_unknown_record_id(self) -> None:
        store = EvidenceStore(make_config(), in_memory=True)

        with pytest.raises(KeyError, match="unknown evidence record_id"):
            store.mark_sync_failed("missing-record", error="timeout")

        store.close()

    def test_sync_summary_counts_and_last_error(self) -> None:
        store = EvidenceStore(make_config(), in_memory=True)
        pending = store.store(make_evaluation("e1", "2025-01-01T00:00:00Z"), tool_name="t1")
        failed = store.store(make_evaluation("e2", "2025-01-01T00:00:01Z"), tool_name="t2")
        synced = store.store(make_evaluation("e3", "2025-01-01T00:00:02Z"), tool_name="t3")

        store.mark_sync_failed(
            failed.record_id,
            error="rate limited",
            attempted_at="2025-01-01T00:01:00Z",
            next_retry_at="2025-01-01T00:05:00Z",
        )
        store.mark_sync_synced(synced.record_id, synced_at="2025-01-01T00:02:00Z")

        summary = store.get_sync_summary()
        assert summary.pending_count == 1
        assert summary.failed_count == 1
        assert summary.last_sync_at == "2025-01-01T00:02:00Z"
        assert summary.last_error == "rate limited"
        assert summary.next_retry_at == "2025-01-01T00:05:00Z"
        assert [
            record.record_id
            for record in store.get_pending_sync_records(now="2025-01-01T00:03:00Z")
        ] == [pending.record_id]
        store.close()

    def test_pending_records_respect_config_max_queue_size(self) -> None:
        store = EvidenceStore(make_config(sync={"max_queue_size": 2}), in_memory=True)
        records = [
            store.store(make_evaluation(f"e{i}", f"2025-01-01T00:00:0{i}Z"), tool_name=f"t{i}")
            for i in range(4)
        ]

        pending = store.get_pending_sync_records()

        assert [record.record_id for record in pending] == [
            records[0].record_id,
            records[1].record_id,
        ]
        assert store.count() == 4
        store.close()

    def test_sync_state_transitions_do_not_change_hash_chain(self) -> None:
        store = EvidenceStore(make_config(), in_memory=True)
        first = store.store(make_evaluation("e1", "2025-01-01T00:00:00Z"), tool_name="t1")
        second = store.store(make_evaluation("e2", "2025-01-01T00:00:01Z"), tool_name="t2")
        hashes_before = [record.record_hash for record in store.get_records(limit=None)]

        store.mark_sync_failed(
            first.record_id,
            error="temporary",
            attempted_at="2025-01-01T00:01:00Z",
            next_retry_at="2025-01-01T00:05:00Z",
        )
        store.mark_sync_synced(second.record_id, synced_at="2025-01-01T00:02:00Z")

        assert [record.record_hash for record in store.get_records(limit=None)] == hashes_before
        valid, errors = store.verify_chain()
        assert valid is True
        assert errors == []
        store.close()
