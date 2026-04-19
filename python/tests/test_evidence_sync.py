"""Tests for manual evidence sync engine behavior."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

import pytest

from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore
from ancilis.evidence.sync import SyncEngine
from ancilis.evidence.sync_state import SYNC_STATUS_FAILED, SYNC_STATUS_SYNCED
from ancilis.platform.client import (
    EVIDENCE_BATCH_ENDPOINT,
    PlatformBatchItem,
    PlatformBatchResponse,
    PlatformClient,
    PlatformConnectionError,
)


def make_config(**overrides: Any) -> ResolvedConfig:
    raw: dict[str, Any] = {
        "agent": {
            "name": "test-agent",
            "agent_id": "agent-123",
            "llm_provider": "openai",
        },
        "platform": {
            "url": "https://platform.example",
            "api_key_env": "ANCILIS_TEST_TOKEN",
        },
        "sync": {
            "offline_mode": "auto",
            "batch_size": 2,
            "backoff_base_seconds": 5,
            "max_retries": 3,
        },
    }
    raw.update(overrides)
    return load_config(raw=raw)


def make_evaluation(evaluation_id: str, timestamp: str) -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=evaluation_id,
        action_id=f"action-{evaluation_id}",
        timestamp=timestamp,
        agent_id="runtime-agent",
        source_type="tool",
        mode="audit",
        control_results=[
            ControlResult(
                control_id="PR-01",
                control_name="Agent Identity",
                result="PASS",
                detail="Agent identity verified",
                evidence_data={"agent_id": "runtime-agent"},
                duration_ms=1.0,
            ),
        ],
        decision="ALLOW",
        decision_reason="All controls passed",
        active_overlays=["financial"],
        data_classifications=["personal_info"],
        detected_data_types=["email"],
        total_duration_ms=2.0,
        session_id="session-1",
    )


def store_records(store: EvidenceStore, count: int) -> list[str]:
    records = []
    for index in range(count):
        record = store.store(
            make_evaluation(
                f"eval-{index}",
                f"2025-01-01T00:00:0{index}Z",
            ),
            tool_name=f"tool-{index}",
            output_summary=f"summary-{index}",
        )
        records.append(record.record_id)
    return records


class RecordingClient:
    def __init__(self, responses: list[PlatformBatchResponse] | None = None) -> None:
        self.responses = responses or []
        self.batches: list[list[dict[str, Any]]] = []

    def post_evidence_batch(self, records: list[dict[str, Any]]) -> PlatformBatchResponse:
        self.batches.append(records)
        if self.responses:
            return self.responses.pop(0)
        return PlatformBatchResponse(
            results=[
                PlatformBatchItem(record_id=record["record_id"], status_code=201)
                for record in records
            ]
        )


def fixed_now() -> datetime:
    return datetime(2025, 1, 1, 0, 1, tzinfo=timezone.utc)


def test_platform_client_posts_centralized_batch_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[urllib.request.Request] = []

    class FakeResponse:
        status = 201

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {
                    "results": [
                        {
                            "record_id": "rec-1",
                            "status_code": 201,
                            "remote_evidence_id": "remote-1",
                        }
                    ]
                }
            ).encode()

    def fake_urlopen(request: urllib.request.Request, timeout: int) -> FakeResponse:
        assert timeout == 10
        requests.append(request)
        return FakeResponse()

    monkeypatch.setattr("ancilis.platform.client.urllib.request.urlopen", fake_urlopen)
    client = PlatformClient("https://platform.example/", "secret-token", timeout=10)

    response = client.post_evidence_batch([{"record_id": "rec-1", "decision": "ALLOW"}])

    assert response.results[0].remote_evidence_id == "remote-1"
    assert len(requests) == 1
    request = requests[0]
    assert request.full_url == f"https://platform.example{EVIDENCE_BATCH_ENDPOINT}"
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer secret-token"
    assert request.get_header("Content-type") == "application/json"
    assert isinstance(request.data, bytes)
    assert json.loads(request.data.decode()) == {
        "records": [{"record_id": "rec-1", "decision": "ALLOW"}]
    }


def test_sync_success_batches_and_marks_records_synced() -> None:
    store = EvidenceStore(make_config(), in_memory=True)
    record_ids = store_records(store, 3)
    client = RecordingClient()

    result = SyncEngine(make_config(), store, client=client, now=fixed_now).sync_once()

    assert result.status == "synced"
    assert result.attempted == 3
    assert result.synced == 3
    assert [len(batch) for batch in client.batches] == [2, 1]
    assert client.batches[0][0]["record_id"] == record_ids[0]
    assert client.batches[0][0]["agent_id"] == "agent-123"
    assert client.batches[0][0]["source_type"] == "tool"
    assert client.batches[0][0]["controls"][0]["control_id"] == "PR-01"
    assert client.batches[0][0]["overlays"] == ["financial"]
    assert client.batches[0][0]["classifications"] == ["personal_info"]
    assert client.batches[0][0]["certifications"] == []
    assert client.batches[0][0]["session"] == "session-1"
    assert client.batches[0][0]["classification_context"] == {"llm_provider": "openai"}
    assert store.get_pending_sync_records() == []
    assert all(
        store.get_sync_state(record_id).status == SYNC_STATUS_SYNCED  # type: ignore[union-attr]
        for record_id in record_ids
    )
    store.close()


def test_sync_treats_duplicate_item_response_as_synced() -> None:
    store = EvidenceStore(make_config(), in_memory=True)
    record_id = store_records(store, 1)[0]
    client = RecordingClient(
        [
            PlatformBatchResponse(
                results=[
                    PlatformBatchItem(
                        record_id=record_id,
                        status_code=409,
                        remote_evidence_id="already-stored",
                    )
                ]
            )
        ]
    )

    result = SyncEngine(make_config(), store, client=client, now=fixed_now).sync_once()

    state = store.get_sync_state(record_id)
    assert result.synced == 1
    assert state is not None
    assert state.status == SYNC_STATUS_SYNCED
    assert state.remote_status_code == 409
    assert state.remote_evidence_id == "already-stored"
    store.close()


def test_sync_transient_network_error_records_retry_metadata() -> None:
    store = EvidenceStore(make_config(), in_memory=True)
    record_id = store_records(store, 1)[0]

    class FailingClient:
        def post_evidence_batch(self, records: list[dict[str, Any]]) -> PlatformBatchResponse:
            raise PlatformConnectionError("timeout")

    result = SyncEngine(make_config(), store, client=FailingClient(), now=fixed_now).sync_once()

    state = store.get_sync_state(record_id)
    assert result.status == "pending"
    assert result.failed == 1
    assert state is not None
    assert state.status == SYNC_STATUS_FAILED
    assert state.attempt_count == 1
    assert state.last_error == "timeout"
    assert state.next_retry_at == "2025-01-01T00:01:05Z"
    assert store.get_pending_sync_records(now="2025-01-01T00:01:04Z") == []
    assert [record.record_id for record in store.get_pending_sync_records(now="2025-01-01T00:01:05Z")] == [
        record_id
    ]
    store.close()


def test_sync_permanent_validation_error_does_not_hot_loop() -> None:
    store = EvidenceStore(make_config(), in_memory=True)
    record_id = store_records(store, 1)[0]
    client = RecordingClient(
        [
            PlatformBatchResponse(
                results=[
                    PlatformBatchItem(
                        record_id=record_id,
                        status_code=422,
                        error="schema validation failed",
                    )
                ]
            )
        ]
    )

    result = SyncEngine(make_config(), store, client=client, now=fixed_now).sync_once()

    state = store.get_sync_state(record_id)
    assert result.status == "failed"
    assert state is not None
    assert state.status == SYNC_STATUS_FAILED
    assert state.last_error == "schema validation failed"
    assert state.remote_status_code == 422
    assert state.next_retry_at is None
    assert store.get_pending_sync_records(now="2025-01-01T00:02:00Z") == []
    store.close()


def test_sync_dry_run_reports_without_mutating_sync_state() -> None:
    store = EvidenceStore(make_config(), in_memory=True)
    record_id = store_records(store, 1)[0]
    client = RecordingClient()

    result = SyncEngine(make_config(), store, client=client, now=fixed_now).sync_once(
        dry_run=True
    )

    state = store.get_sync_state(record_id)
    assert result.status == "dry_run"
    assert result.pending == 1
    assert result.attempted == 0
    assert client.batches == []
    assert state is not None
    assert state.status != SYNC_STATUS_SYNCED
    store.close()


def test_sync_always_offline_returns_noop_without_client_call() -> None:
    config = make_config(sync={"offline_mode": "always_offline"})
    store = EvidenceStore(config, in_memory=True)
    store_records(store, 1)
    client = RecordingClient()

    result = SyncEngine(config, store, client=client, now=fixed_now).sync_once()

    assert result.status == "noop"
    assert result.pending == 1
    assert result.message == "sync skipped because sync.offline_mode is always_offline"
    assert client.batches == []
    assert len(store.get_pending_sync_records()) == 1
    store.close()


def test_platform_client_network_errors_are_transient(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(_request: urllib.request.Request, timeout: int) -> object:
        raise urllib.error.URLError("refused")

    monkeypatch.setattr("ancilis.platform.client.urllib.request.urlopen", fake_urlopen)
    client = PlatformClient("https://platform.example", "secret-token")

    with pytest.raises(PlatformConnectionError, match="refused"):
        client.post_evidence_batch([{"record_id": "rec-1"}])
