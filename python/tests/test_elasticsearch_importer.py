"""Tests for the Elasticsearch X-Pack security audit-log evidence importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers.elasticsearch import ElasticsearchImporter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(**overrides) -> dict:
    base: dict = {
        "@timestamp": "2026-04-15T12:00:00Z",
        "event.action": "authentication_success",
        "event.category": ["authentication"],
        "event.type": ["start"],
        "user.name": "agent_svc",
        "user.realm": "native",
        "authentication.type": "REALM",
        "indices.0.name": "rag-corpus-prod",
        "indices.0.privilege": "read",
        "indices.count": 1,
        "request.method": "GET",
        "request.body_length": 256,
        "url.path": "/_search",
        "url.query_count": 3,
        "client.ip": "10.0.0.1",
        "client.address.port": 50000,
        "trace.id": "trace-abc-123",
        "transport.profile": "default",
        "elasticsearch.cluster.name": "prod-search",
        "elasticsearch.cluster.uuid": "cluster-uuid-1",
        "elasticsearch.node.name": "es-prod-01",
        "request.id": "req-id-12345678abcdef",
        "kibana.session_id": None,
        "wildcard_expansion": False,
        "tls.client.certificate.serial_number": None,
        "tls.cipher": "TLS_AES_256_GCM_SHA384",
        "tls.version": "TLSv1.3",
    }
    base.update(overrides)
    return base


def _doc(*events) -> str:
    return json.dumps({"events": list(events)})


# ---------------------------------------------------------------------------
# Per-event signal coverage
# ---------------------------------------------------------------------------


def test_authentication_success_passes() -> None:
    doc = _doc(_event(**{"event.action": "authentication_success"}))
    results = ElasticsearchImporter().parse_string(doc)
    assert len(results) == 1
    er = results[0]
    assert er.source_type == "elasticsearch_import"
    assert er.decision == "ALLOW"
    signals = {cr.evidence_data.get("signal") for cr in er.control_results}
    assert "authentication_success" in signals
    auth_cr = next(
        cr for cr in er.control_results if cr.evidence_data.get("signal") == "authentication_success"
    )
    assert auth_cr.control_id == "PR-01"
    assert auth_cr.result == "PASS"


def test_authentication_failed_flags() -> None:
    doc = _doc(_event(**{"event.action": "authentication_failed", "user.name": "intruder"}))
    results = ElasticsearchImporter().parse_string(doc)
    er = results[0]
    cr = next(
        c for c in er.control_results if c.evidence_data.get("signal") == "authentication_failed"
    )
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"
    assert er.decision == "FLAG"


def test_security_index_read_fails() -> None:
    doc = _doc(
        _event(
            **{
                "event.action": "access_granted",
                "indices.0.name": ".security",
                "indices.0.privilege": "read",
            }
        )
    )
    results = ElasticsearchImporter().parse_string(doc)
    er = results[0]
    cr = next(
        c for c in er.control_results if c.evidence_data.get("signal") == "security_index_read"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert er.decision == "BLOCK"


def test_security_index_write_fails() -> None:
    doc = _doc(
        _event(
            **{
                "event.action": "access_granted",
                "indices.0.name": ".security",
                "indices.0.privilege": "manage",
                "request.method": "POST",
                "url.path": "/_security/api_key",
            }
        )
    )
    results = ElasticsearchImporter().parse_string(doc)
    er = results[0]
    sigs = {c.evidence_data.get("signal") for c in er.control_results}
    assert "security_index_write" in sigs
    cr = next(
        c for c in er.control_results if c.evidence_data.get("signal") == "security_index_write"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert er.decision == "BLOCK"


def test_manage_privilege_on_prod_flags() -> None:
    doc = _doc(
        _event(
            **{
                "event.action": "access_granted",
                "indices.0.name": "rag-corpus-prod",
                "indices.0.privilege": "manage",
            }
        )
    )
    results = ElasticsearchImporter().parse_string(doc)
    er = results[0]
    cr = next(
        c for c in er.control_results
        if c.evidence_data.get("signal") == "manage_privilege_on_prod"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert er.decision == "FLAG"


def test_access_denied_audit_pass() -> None:
    doc = _doc(
        _event(
            **{
                "event.action": "access_denied",
                "indices.0.name": "rag-corpus-prod",
                "indices.0.privilege": "write",
            }
        )
    )
    results = ElasticsearchImporter().parse_string(doc)
    er = results[0]
    cr = next(c for c in er.control_results if c.evidence_data.get("signal") == "access_denied")
    assert cr.control_id == "PR-02"
    assert cr.result == "PASS"
    assert er.decision == "ALLOW"


def test_tampered_request_fails() -> None:
    doc = _doc(_event(**{"event.action": "tampered_request"}))
    results = ElasticsearchImporter().parse_string(doc)
    er = results[0]
    cr = next(
        c for c in er.control_results if c.evidence_data.get("signal") == "tampered_request"
    )
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert er.decision == "BLOCK"


def test_run_as_flags() -> None:
    doc = _doc(
        _event(
            **{
                "event.action": "run_as_granted",
                "user.name": "ops_svc",
                "user.run_as.name": "alice",
            }
        )
    )
    results = ElasticsearchImporter().parse_string(doc)
    er = results[0]
    cr = next(
        c for c in er.control_results if c.evidence_data.get("signal") == "run_as_granted"
    )
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"
    assert cr.evidence_data["user_run_as_name"] == "alice"


def test_wildcard_search_many_indices_flags() -> None:
    doc = _doc(
        _event(
            **{
                "event.action": "access_granted",
                "url.path": "/_search",
                "wildcard_expansion": True,
                "indices.count": 12,
                "indices.0.name": "rag-corpus-prod",
                "indices.0.privilege": "read",
            }
        )
    )
    results = ElasticsearchImporter().parse_string(doc)
    er = results[0]
    cr = next(
        c for c in er.control_results if c.evidence_data.get("signal") == "wildcard_search_many"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert er.decision == "FLAG"


def test_cluster_settings_modification_fails() -> None:
    doc = _doc(
        _event(
            **{
                "event.action": "access_granted",
                "url.path": "/_cluster/settings",
                "request.method": "PUT",
                "indices.0.name": None,
                "indices.0.privilege": None,
                "indices.count": 0,
            }
        )
    )
    results = ElasticsearchImporter().parse_string(doc)
    er = results[0]
    cr = next(
        c for c in er.control_results if c.evidence_data.get("signal") == "cluster_settings_modify"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert er.decision == "BLOCK"


def test_security_role_grant_fails() -> None:
    doc = _doc(
        _event(
            **{
                "event.action": "access_granted",
                "url.path": "/_security/role/data_reader",
                "request.method": "PUT",
                "indices.0.name": None,
                "indices.0.privilege": None,
                "indices.count": 0,
            }
        )
    )
    results = ElasticsearchImporter().parse_string(doc)
    er = results[0]
    cr = next(
        c for c in er.control_results if c.evidence_data.get("signal") == "security_role_grant"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert er.decision == "BLOCK"


def test_legacy_tls_fails() -> None:
    doc = _doc(_event(**{"tls.version": "TLSv1.0"}))
    results = ElasticsearchImporter().parse_string(doc)
    er = results[0]
    cr = next(c for c in er.control_results if c.evidence_data.get("signal") == "legacy_tls")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert er.decision == "BLOCK"


def test_failed_auth_burst_synthetic() -> None:
    # 11 failures from same client.ip (> default threshold 10)
    events = [
        _event(
            **{
                "event.action": "authentication_failed",
                "user.name": f"victim-{i}",
                "client.ip": "203.0.113.5",
            }
        )
        for i in range(11)
    ]
    doc = json.dumps({"events": events})
    results = ElasticsearchImporter().parse_string(doc)
    synthetic = [r for r in results if r.source_type == "elasticsearch_import_synthetic"]
    assert any(
        cr.evidence_data.get("signal") == "failed_auth_burst" and cr.result == "FAIL"
        for r in synthetic
        for cr in r.control_results
    )
    burst = next(
        r for r in synthetic
        if any(cr.evidence_data.get("signal") == "failed_auth_burst" for cr in r.control_results)
    )
    assert burst.decision == "BLOCK"


def test_cross_index_synthetic() -> None:
    # 11 distinct indices touched by same user (> default threshold 10)
    events = [
        _event(
            **{
                "event.action": "access_granted",
                "user.name": "promiscuous_agent",
                "indices.0.name": f"index-{i}",
                "indices.0.privilege": "read",
            }
        )
        for i in range(11)
    ]
    doc = json.dumps({"events": events})
    results = ElasticsearchImporter().parse_string(doc)
    synthetic = [r for r in results if r.source_type == "elasticsearch_import_synthetic"]
    found = [
        r for r in synthetic
        if any(cr.evidence_data.get("signal") == "cross_index_pattern" for cr in r.control_results)
    ]
    assert len(found) == 1
    cr = found[0].control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert found[0].decision == "FLAG"


def test_request_body_never_stored() -> None:
    """Raw request bodies must NEVER appear in evidence_data."""
    secret_body = "SECRET-USER-QUERY-DO-NOT-LEAK"
    event = _event(
        **{
            "event.action": "access_granted",
            "indices.0.name": "rag-corpus-prod",
            "indices.0.privilege": "read",
            "request.body": secret_body,  # would be a leak if stored
            "request.body_length": len(secret_body),
        }
    )
    doc = json.dumps({"events": [event]})
    results = ElasticsearchImporter().parse_string(doc)
    er = results[0]
    blob = json.dumps([cr.evidence_data for cr in er.control_results])
    assert secret_body not in blob
    # body_length (length only) is fine.
    assert any(cr.evidence_data.get("request_body_length") == len(secret_body) for cr in er.control_results)


def test_client_ip_redacted() -> None:
    """client.ip must be masked to /16 — full IP must not appear in evidence."""
    full_ip = "192.168.42.99"
    doc = _doc(
        _event(
            **{
                "event.action": "authentication_success",
                "client.ip": full_ip,
            }
        )
    )
    results = ElasticsearchImporter().parse_string(doc)
    er = results[0]
    blob = json.dumps([cr.evidence_data for cr in er.control_results])
    assert full_ip not in blob
    masked = next(
        cr.evidence_data["client_ip_masked"]
        for cr in er.control_results
        if "client_ip_masked" in cr.evidence_data
    )
    assert masked == "192.168.0.0/16"


# ---------------------------------------------------------------------------
# Shape parsing & provenance
# ---------------------------------------------------------------------------


def test_parses_events_data_jsonl_and_single() -> None:
    imp = ElasticsearchImporter()
    # events envelope
    assert len(imp.parse_string(_doc(_event(), _event()))) == 2
    # data envelope
    assert len(imp.parse_string(json.dumps({"data": [_event()]}))) == 1
    # JSON array
    assert len(imp.parse_string(json.dumps([_event(), _event(), _event()]))) == 3
    # Single event object
    assert len(imp.parse_string(json.dumps(_event()))) == 1
    # JSONL
    jsonl = "\n".join(json.dumps(_event()) for _ in range(4))
    assert len(imp.parse_string(jsonl)) == 4


def test_file_hash_in_provenance(tmp_path: Path) -> None:
    payload = _doc(_event())
    p = tmp_path / "es.json"
    p.write_text(payload)
    expected = hashlib.sha256(payload.encode()).hexdigest()
    results = ElasticsearchImporter().parse(p)
    er = results[0]
    cr = er.control_results[0]
    assert cr.evidence_data["source_provenance"]["original_file_sha256"] == expected
    assert cr.evidence_data["source_provenance"]["source_format"] == "elasticsearch"
