"""Attestation lookup must not materialize unrelated runtime evidence."""

import uuid

from ancilis.config import load_config
from ancilis.engine.evaluators.attestation import latest_attestation_event
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore


def evaluation(
    source="attestation", agent="agent-a", timestamp="2026-09-10T10:00:00Z", revoked=False
):
    return EvaluationResult(
        evaluation_id=str(uuid.uuid4()),
        action_id="action",
        timestamp=timestamp,
        agent_id=agent,
        source_type=source,
        mode="audit",
        decision="ALLOW",
        decision_reason="fixture",
        control_results=[
            ControlResult(
                control_id="GOV-04",
                control_name="Oversight",
                result="PASS",
                detail="synthetic",
                evidence_data={"attestation": {"revoked": revoked, "fields": {}}},
                duration_ms=0,
            )
        ],
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=0,
    )


def test_lookup_deserializes_only_attestation_records(monkeypatch):
    store = EvidenceStore(load_config(raw={"agent": {"name": "fixture"}}), in_memory=True)
    try:
        for _ in range(30):
            store.store(evaluation(source="agent"), "runtime")
        target = store.store(evaluation(), "attest")
        original = store._row_to_record
        materialized = []

        def convert(row):
            result = original(row)
            materialized.append(result.record_id)
            return result

        monkeypatch.setattr(store, "_row_to_record", convert)
        event = latest_attestation_event(store, "GOV-04")
        assert event.record.record_id == target.record_id
        assert materialized == [target.record_id]
    finally:
        store.close()


def test_filter_preserves_tenant_agent_late_time_ties_and_revocation(tmp_path):
    config = load_config(raw={"agent": {"name": "fixture"}})
    a = EvidenceStore(config, db_path=tmp_path / "evidence.duckdb", tenant_id="a")
    b = EvidenceStore(config, db_path=tmp_path / "evidence.duckdb", tenant_id="b")
    try:
        first = a.store(evaluation(), "attest")
        a.store(evaluation(timestamp="2026-09-09T10:00:00Z"), "late-older")
        a.store(evaluation(revoked=True), "same-time-later-insert")
        b.store(evaluation(timestamp="2026-09-12T10:00:00Z"), "other-tenant")
        a.store(evaluation(agent="agent-b", timestamp="2026-09-11T10:00:00Z"), "other-agent")
        assert (
            latest_attestation_event(
                a, "GOV-04", agent_id="agent-a", per_agent=True
            ).record.record_id
            == first.record_id
        )
        revoke = a.store(evaluation(timestamp="2026-09-13T10:00:00Z", revoked=True), "revoke")
        event = latest_attestation_event(a, "GOV-04", agent_id="agent-a", per_agent=True)
        assert event.record.record_id == revoke.record_id and event.data["revoked"] is True
    finally:
        a.close()
        b.close()


def test_source_type_filter_is_parameterized_and_composes_with_existing_filters():
    store = EvidenceStore(load_config(raw={"agent": {"name": "fixture"}}), in_memory=True)
    try:
        target = store.store(evaluation(), "attest")
        store.store(evaluation(source="agent"), "runtime")
        assert [
            r.record_id
            for r in store.get_records(source_type="attestation", agent_id="agent-a", limit=None)
        ] == [target.record_id]
        assert store.get_records(source_type="attestation' OR 1=1 --", limit=None) == []
        assert len(store.get_records(limit=None)) == 2
    finally:
        store.close()


def test_structural_store_without_new_keyword_keeps_existing_call_contract():
    calls = []

    class Store:
        def get_records(self, *, limit):
            calls.append(limit)
            return []

    assert latest_attestation_event(Store(), "GOV-04") is None
    assert calls == [None]


def test_subclass_get_records_override_is_not_bypassed():
    calls = []

    class FilteredStore(EvidenceStore):
        def get_records(self, *, limit):
            calls.append(limit)
            return []

    store = FilteredStore(load_config(raw={"agent": {"name": "fixture"}}), in_memory=True)
    try:
        store.store(evaluation(), "attest")
        assert latest_attestation_event(store, "GOV-04") is None
        assert calls == [None]
    finally:
        store.close()
