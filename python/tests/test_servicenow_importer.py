"""Tests for the ServiceNow sys_audit importer."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ancilis.importers.servicenow import ServiceNowImporter


# ---------------------------------------------------------------------------
# Fixtures — inline ServiceNow sys_audit records
# ---------------------------------------------------------------------------


def _audit(
    *,
    sys_id: str = "abcdef0123456789abcdef0123456789",
    sys_created_on: str = "2026-04-01T12:00:00Z",
    tablename: str = "incident",
    record_id: str = "INC0012345",
    field: str = "state",
    old_value: str | None = None,
    new_value: str | None = None,
    old_value_length: int = 0,
    new_value_length: int = 0,
    user: str = "agent.svc",
    user_id: str = "u-0123456789abcdef",
    reason: str = "web",
    is_now_assist: bool = False,
    now_assist_capability: str | None = None,
    client_ip: str | None = "203.0.113.42",
    internal_type: str = "string",
    action: str = "UPDATED",
    auth_method: str = "oauth",
    domain: str = "company",
    is_sensitive_field: bool = False,
    approval_state: str | None = None,
) -> dict:
    return {
        "sys_id": sys_id,
        "sys_created_on": sys_created_on,
        "tablename": tablename,
        "record_id": record_id,
        "field": field,
        "old_value": old_value,
        "new_value": new_value,
        "old_value_length": old_value_length,
        "new_value_length": new_value_length,
        "user": user,
        "user_id": user_id,
        "reason": reason,
        "is_now_assist": is_now_assist,
        "now_assist_capability": now_assist_capability,
        "client_ip": client_ip,
        "internal_type": internal_type,
        "action": action,
        "auth_method": auth_method,
        "domain": domain,
        "is_sensitive_field": is_sensitive_field,
        "approval_state": approval_state,
    }


def _signals(result) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in result.control_results]


def _by_signal(result, signal: str):
    return next(
        cr for cr in result.control_results if cr.evidence_data.get("signal") == signal
    )


# ---------------------------------------------------------------------------
# Now Assist — incident creation (PR-01 FLAG)
# ---------------------------------------------------------------------------


def test_now_assist_creates_incident_flags() -> None:
    """tablename=incident action=INSERTED reason=now_assist → PR-01 FLAG."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    sys_id="na-create-1",
                    tablename="incident",
                    action="INSERTED",
                    field="number",
                    record_id="INC0099999",
                    reason="now_assist",
                    is_now_assist=True,
                    now_assist_capability="qualify",
                    new_value="INC0099999",
                    new_value_length=10,
                )
            ]
        }
    )
    [result] = ServiceNowImporter().parse_string(doc)
    assert result.decision == "FLAG"
    assert result.source_type == "servicenow_import"
    cr = _by_signal(result, "now_assist_creates_incident")
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"
    assert cr.evidence_data["is_now_assist"] is True
    assert cr.evidence_data["now_assist_capability"] == "qualify"


# ---------------------------------------------------------------------------
# Now Assist — autonomous incident resolution (PR-02 FAIL)
# ---------------------------------------------------------------------------


def test_now_assist_resolves_incident_fails() -> None:
    """tablename=incident action=UPDATED field=state new_value=Resolved
    reason=now_assist → PR-02 FAIL."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    sys_id="na-resolve-1",
                    tablename="incident",
                    action="UPDATED",
                    field="state",
                    record_id="INC0012345",
                    reason="now_assist",
                    is_now_assist=True,
                    now_assist_capability="auto_resolve",
                    old_value="In Progress",
                    new_value="Resolved",
                    old_value_length=11,
                    new_value_length=8,
                )
            ]
        }
    )
    [result] = ServiceNowImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = _by_signal(result, "now_assist_resolves_incident")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# change_request — autonomous Implementation without approval (PR-02 FAIL)
# ---------------------------------------------------------------------------


def test_change_request_implementation_no_approval_fails() -> None:
    """tablename=change_request action=UPDATED field=state new_value=Implemented
    reason=now_assist + approval_state≠approved → PR-02 FAIL."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    sys_id="cr-impl-1",
                    tablename="change_request",
                    action="UPDATED",
                    field="state",
                    record_id="CHG0098765",
                    reason="now_assist",
                    is_now_assist=True,
                    now_assist_capability="auto_implement",
                    new_value="Implemented",
                    new_value_length=11,
                    approval_state="not_requested",
                )
            ]
        }
    )
    [result] = ServiceNowImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = _by_signal(result, "now_assist_implements_change_unapproved")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["approval_state"] == "not_requested"


# ---------------------------------------------------------------------------
# kb_knowledge — Now Assist publishing (PR-04 FAIL)
# ---------------------------------------------------------------------------


def test_kb_publishing_now_assist_fails() -> None:
    """tablename=kb_knowledge action=UPDATED field=published_state
    new_value=published reason=now_assist → PR-04 FAIL."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    sys_id="kb-pub-1",
                    tablename="kb_knowledge",
                    action="UPDATED",
                    field="published_state",
                    record_id="KB0001234",
                    reason="now_assist",
                    is_now_assist=True,
                    now_assist_capability="draft_resolution",
                    new_value="published",
                    new_value_length=9,
                )
            ]
        }
    )
    [result] = ServiceNowImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = _by_signal(result, "kb_published_by_now_assist")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# sys_user_role admin grant (PR-02 FAIL)
# ---------------------------------------------------------------------------


def test_admin_role_insert_fails() -> None:
    """tablename=sys_user_role action=INSERTED with role pattern admin* → PR-02 FAIL."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    sys_id="role-admin-1",
                    tablename="sys_user_role",
                    action="INSERTED",
                    field="role",
                    record_id="role-row-1",
                    reason="api",
                    is_now_assist=False,
                    new_value="security_admin",
                    new_value_length=14,
                )
            ]
        }
    )
    [result] = ServiceNowImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = _by_signal(result, "admin_role_grant")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# sys_security_acl modification (PR-02 FAIL)
# ---------------------------------------------------------------------------


def test_acl_modification_fails() -> None:
    """tablename=sys_security_acl action=UPDATED → PR-02 FAIL."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    sys_id="acl-1",
                    tablename="sys_security_acl",
                    action="UPDATED",
                    field="operation",
                    record_id="acl-row-1",
                    reason="web",
                    is_now_assist=False,
                    new_value="write",
                    new_value_length=5,
                )
            ]
        }
    )
    [result] = ServiceNowImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = _by_signal(result, "acl_modification")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Sensitive field by Now Assist (PR-04 FLAG)
# ---------------------------------------------------------------------------


def test_sensitive_field_now_assist_flags() -> None:
    """is_sensitive_field=true field changed by now_assist → PR-04 FLAG."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    sys_id="sens-1",
                    tablename="sys_user",
                    action="UPDATED",
                    field="tax_id",
                    record_id="USR0001234",
                    reason="now_assist",
                    is_now_assist=True,
                    is_sensitive_field=True,
                    new_value_length=11,
                    old_value_length=11,
                )
            ]
        }
    )
    [result] = ServiceNowImporter().parse_string(doc)
    cr = _by_signal(result, "sensitive_field_now_assist")
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    # Field name is captured.
    assert cr.evidence_data["field"] == "tax_id"


# ---------------------------------------------------------------------------
# Basic auth (PR-04 FAIL)
# ---------------------------------------------------------------------------


def test_basic_auth_fails() -> None:
    """auth_method=basic → PR-04 FAIL."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    sys_id="ba-1",
                    tablename="incident",
                    action="UPDATED",
                    field="description",
                    record_id="INC0012345",
                    reason="api",
                    auth_method="basic",
                    new_value_length=10,
                )
            ]
        }
    )
    [result] = ServiceNowImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = _by_signal(result, "basic_auth")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Workflow audit trail = PASS
# ---------------------------------------------------------------------------


def test_workflow_passes() -> None:
    """reason=workflow → PR-05 PASS."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    sys_id="wf-1",
                    tablename="task",
                    action="UPDATED",
                    field="state",
                    record_id="TASK0001",
                    reason="workflow",
                    is_now_assist=False,
                    new_value="Closed Complete",
                    new_value_length=15,
                )
            ]
        }
    )
    [result] = ServiceNowImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    cr = _by_signal(result, "workflow_audit")
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"


# ---------------------------------------------------------------------------
# Now-Assist velocity synthetic (PR-04 FLAG)
# ---------------------------------------------------------------------------


def test_now_assist_velocity_synthetic() -> None:
    """now_assist actor exceeding threshold → synthetic PR-04 FLAG."""
    importer = ServiceNowImporter(now_assist_velocity_threshold=3)
    base = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
    audits = [
        _audit(
            sys_id=f"vel-{i:08d}",
            sys_created_on=(base + timedelta(seconds=i * 10)).isoformat(),
            tablename="incident",
            action="UPDATED",
            field="comments",
            record_id=f"INC000{i:04d}",
            reason="now_assist",
            is_now_assist=True,
            user="now.assist.svc",
            new_value_length=20,
        )
        for i in range(6)
    ]
    doc = json.dumps({"audits": audits})
    results = importer.parse_string(doc)
    synthetic = [
        r for r in results
        if r.action_id == "servicenow-now-assist-velocity-now.assist.svc"
    ]
    assert len(synthetic) == 1
    cr = synthetic[0].control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["synthetic"] is True
    assert cr.evidence_data["now_assist_velocity_count"] == 6
    assert cr.evidence_data["now_assist_velocity_threshold"] == 3


# ---------------------------------------------------------------------------
# Sensitive-field burst synthetic (PR-04 FAIL)
# ---------------------------------------------------------------------------


def test_sensitive_burst_synthetic() -> None:
    """Same actor changing > N is_sensitive_field=true fields in 1h → PR-04 FAIL."""
    importer = ServiceNowImporter(sensitive_field_burst_threshold=2)
    base = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
    audits = [
        _audit(
            sys_id=f"sb-{i:08d}",
            sys_created_on=(base + timedelta(seconds=i * 60)).isoformat(),
            tablename="sys_user",
            action="UPDATED",
            field=f"sensitive_field_{i}",
            record_id=f"USR000{i:04d}",
            reason="now_assist",
            is_now_assist=True,
            is_sensitive_field=True,
            user="bursty.actor",
            new_value_length=12,
        )
        for i in range(5)
    ]
    doc = json.dumps({"audits": audits})
    results = importer.parse_string(doc)
    synthetic = [
        r for r in results
        if r.action_id == "servicenow-sensitive-burst-bursty.actor"
    ]
    assert len(synthetic) == 1
    cr = synthetic[0].control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert cr.evidence_data["sensitive_field_burst_count"] == 5
    assert synthetic[0].decision == "BLOCK"


# ---------------------------------------------------------------------------
# Field values (old_value/new_value text) are NOT stored
# ---------------------------------------------------------------------------


def test_field_values_not_stored() -> None:
    """Raw old_value/new_value strings are never persisted to evidence_data."""
    secret_old = "OLD-CUSTOMER-PII-SHOULD-NEVER-PERSIST-XYZ"
    secret_new = "NEW-CUSTOMER-PII-ALSO-MUST-NEVER-PERSIST-ABC"
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    sys_id="redact-1",
                    tablename="incident",
                    action="UPDATED",
                    field="description",
                    record_id="INC0011111",
                    reason="now_assist",
                    is_now_assist=True,
                    is_sensitive_field=True,
                    old_value=secret_old,
                    new_value=secret_new,
                    old_value_length=len(secret_old),
                    new_value_length=len(secret_new),
                )
            ]
        }
    )
    [result] = ServiceNowImporter().parse_string(doc)
    for cr in result.control_results:
        serialized = json.dumps(cr.evidence_data, default=str)
        assert secret_old not in serialized
        assert secret_new not in serialized
        # Lengths are kept.
        assert cr.evidence_data["old_value_length"] == len(secret_old)
        assert cr.evidence_data["new_value_length"] == len(secret_new)


# ---------------------------------------------------------------------------
# IP redaction (/16)
# ---------------------------------------------------------------------------


def test_ip_redacted() -> None:
    """client_ip is masked to /16 for public IPv4."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    sys_id="ip-1",
                    tablename="incident",
                    action="UPDATED",
                    field="comments",
                    record_id="INC0011112",
                    reason="api",
                    is_now_assist=False,
                    client_ip="52.94.236.248",
                    new_value_length=5,
                )
            ]
        }
    )
    [result] = ServiceNowImporter().parse_string(doc)
    cr = result.control_results[0]
    # Original IP must not appear.
    assert cr.evidence_data["client_ip_redacted"] == "52.94.0.0/16"
    serialized = json.dumps(cr.evidence_data, default=str)
    assert "52.94.236.248" not in serialized


# ---------------------------------------------------------------------------
# JSONL shape support
# ---------------------------------------------------------------------------


def test_jsonl_shape() -> None:
    """JSONL — one record per line — is accepted."""
    lines = "\n".join(
        json.dumps(
            _audit(
                sys_id=f"jl-{i:08d}",
                tablename="incident",
                action="UPDATED",
                field="comments",
                record_id=f"INC00{i:05d}",
                reason="api",
                new_value_length=3,
            )
        )
        for i in range(3)
    )
    results = ServiceNowImporter().parse_string(lines)
    assert len(results) == 3
    assert all(r.source_type == "servicenow_import" for r in results)


# ---------------------------------------------------------------------------
# Identifier truncation: sys_id, record_id, user_id stored as last-8 only
# ---------------------------------------------------------------------------


def test_identifiers_truncated_to_last_8() -> None:
    """sys_id, record_id, and user_id are reduced to last-8 in evidence."""
    full_sys = "abcdef0123456789abcdef0123456789"
    full_rec = "RECORDID_LONG_FULL_VALUE_999"
    full_uid = "u-0123456789abcdef0123456789"
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    sys_id=full_sys,
                    record_id=full_rec,
                    user_id=full_uid,
                    tablename="incident",
                    action="UPDATED",
                    field="comments",
                    reason="api",
                    new_value_length=2,
                )
            ]
        }
    )
    [result] = ServiceNowImporter().parse_string(doc)
    cr = result.control_results[0]
    assert cr.evidence_data["sys_id_last8"] == full_sys[-8:]
    assert cr.evidence_data["record_id_last8"] == full_rec[-8:]
    assert cr.evidence_data["user_id_last8"] == full_uid[-8:]


# ---------------------------------------------------------------------------
# File parsing & provenance
# ---------------------------------------------------------------------------


def test_parse_file_records_sha256(tmp_path: Path) -> None:
    """parse() hashes the original file and surfaces it in source_provenance."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    sys_id="prov-1",
                    tablename="incident",
                    action="UPDATED",
                    field="comments",
                    record_id="INC0099999",
                    reason="api",
                    new_value_length=2,
                )
            ]
        }
    )
    p = tmp_path / "servicenow-audits.json"
    p.write_bytes(doc.encode("utf-8"))
    expected = hashlib.sha256(doc.encode("utf-8")).hexdigest()
    [result] = ServiceNowImporter().parse(p)
    cr = result.control_results[0]
    assert cr.evidence_data["source_provenance"]["original_file_sha256"] == expected


# ---------------------------------------------------------------------------
# data envelope support
# ---------------------------------------------------------------------------


def test_data_envelope_supported() -> None:
    """{'data': [...]} envelope is accepted."""
    doc = json.dumps(
        {
            "data": [
                _audit(
                    sys_id="d-1",
                    tablename="incident",
                    action="UPDATED",
                    field="comments",
                    record_id="INC0009999",
                    reason="api",
                    new_value_length=1,
                )
            ]
        }
    )
    results = ServiceNowImporter().parse_string(doc)
    assert len(results) == 1
    assert "now_assist_creates_incident" not in _signals(results[0])


# ---------------------------------------------------------------------------
# Approval rejected = governance functioning (PR-05 PASS)
# ---------------------------------------------------------------------------


def test_approval_rejected_passes() -> None:
    """approval_state=rejected on action=UPDATED → PR-05 PASS."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    sys_id="rej-1",
                    tablename="change_request",
                    action="UPDATED",
                    field="approval",
                    record_id="CHG0001234",
                    reason="web",
                    approval_state="rejected",
                    new_value_length=8,
                )
            ]
        }
    )
    [result] = ServiceNowImporter().parse_string(doc)
    cr = _by_signal(result, "approval_rejected")
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
