"""Tests for the Workday System Audit Log importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers.workday import WorkdayImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Workday audit-log records
# ---------------------------------------------------------------------------


def _event(
    *,
    event_id: str = "evt-1",
    event_type: str = "View_Worker",
    timestamp: str = "2026-04-01T12:00:00Z",
    actor_worker_id: str = "emp-actor-001ABCDE",
    actor_worker_name: str = "Alice Anderson",
    actor_username: str = "alice.anderson@example.com",
    user_type: str = "Regular",
    actor_region: str | None = "US",
    target_worker_id: str | None = "emp-target-002WXYZ",
    target_name: str | None = "Bob Baker",
    target_position: str | None = "Senior Engineer",
    target_cost_center: str | None = "CC-ENG-12345678",
    target_region: str | None = "US",
    objects: list[str] | None = None,
    records_affected: int = 1,
    is_bulk: bool = False,
    is_self_service: bool = False,
    approval_required: bool = False,
    approver_id: str | None = None,
    client_ip: str = "203.0.113.42",
    integration_system_id: str | None = None,
    tenant_id: str = "company-prod",
    environment: str = "Production",
    tls_version: str = "TLSv1.3",
    status: str = "Success",
    error_code: str | None = None,
    sensitivity_level: str = "Confidential",
    is_compliance_relevant: bool = False,
) -> dict:
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "actor": {
            "worker_id": actor_worker_id,
            "worker_name_length": len(actor_worker_name),
            "username": actor_username,
            "user_type": user_type,
            "region": actor_region,
        },
        "target_worker": (
            {
                "worker_id": target_worker_id,
                "name_length": len(target_name) if target_name else None,
                "position": target_position,
                "cost_center": target_cost_center,
                "region": target_region,
            }
            if target_worker_id is not None
            else {}
        ),
        "action": {
            "objects": objects if objects is not None else ["Personal_Data"],
            "records_affected": records_affected,
            "is_bulk": is_bulk,
            "is_self_service": is_self_service,
            "approval_required": approval_required,
            "approver_id": approver_id,
        },
        "system_info": {
            "client_ip": client_ip,
            "integration_system_id": integration_system_id,
            "tenant_id": tenant_id,
            "environment": environment,
            "tls_version": tls_version,
        },
        "result": {
            "status": status,
            "error_code": error_code,
            "sensitivity_level": sensitivity_level,
        },
        "is_compliance_relevant": is_compliance_relevant,
    }


def _signals(result) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in result.control_results]


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


def test_login_passes() -> None:
    """event_type=Login + result=Success → PR-01 PASS."""
    doc = json.dumps(
        {"events": [_event(event_id="login-ok", event_type="Login", status="Success")]}
    )
    [result] = WorkdayImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "workday_audit_log_import"
    assert "login_success" in _signals(result)
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "login_success")
    assert cr.control_id == "PR-01"
    assert cr.result == "PASS"


def test_view_self_passes() -> None:
    """View_Worker by Regular user on self → PR-04 PASS (self-service)."""
    same_id = "emp-self-001SELF"
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="self-view",
                    event_type="View_Worker",
                    actor_worker_id=same_id,
                    target_worker_id=same_id,
                    user_type="Regular",
                )
            ]
        }
    )
    [result] = WorkdayImporter().parse_string(doc)
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "view_self_service")
    assert cr.control_id == "PR-04"
    assert cr.result == "PASS"
    assert result.decision == "ALLOW"


# ---------------------------------------------------------------------------
# Compensation — service-account access is the worst pattern
# ---------------------------------------------------------------------------


def test_service_account_view_compensation_fails_and_blocks() -> None:
    """View_Compensation by Service Account → PR-04 FAIL → BLOCK."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="svc-comp",
                    event_type="View_Compensation",
                    user_type="Service Account",
                    actor_username="agent.svc",
                    objects=["Compensation"],
                )
            ]
        }
    )
    [result] = WorkdayImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "service_account_view_compensation"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert "compensation" in cr.detail.lower()


# ---------------------------------------------------------------------------
# Mass PII view
# ---------------------------------------------------------------------------


def test_mass_pii_view_fails() -> None:
    """View_PII records_affected > threshold → PR-04 FAIL."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="mass-pii",
                    event_type="View_PII",
                    records_affected=200,
                    objects=["Personal_Data"],
                )
            ]
        }
    )
    [result] = WorkdayImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "mass_pii_view")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert cr.evidence_data["records_affected"] == 200


# ---------------------------------------------------------------------------
# Edit_Compensation — high-impact financial action
# ---------------------------------------------------------------------------


def test_edit_compensation_fails() -> None:
    """Edit_Compensation → PR-02 FAIL."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="edit-comp",
                    event_type="Edit_Compensation",
                    objects=["Compensation"],
                )
            ]
        }
    )
    [result] = WorkdayImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "edit_compensation")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Lifecycle events — Terminate_Worker captured for audit
# ---------------------------------------------------------------------------


def test_terminate_worker_audit_pass() -> None:
    """Terminate_Worker → PR-05 PASS (audit trail)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="term-1",
                    event_type="Terminate_Worker",
                    objects=["Personal_Data"],
                )
            ]
        }
    )
    [result] = WorkdayImporter().parse_string(doc)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "terminate_worker_audit"
    )
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert result.decision == "ALLOW"


# ---------------------------------------------------------------------------
# Security configuration changes
# ---------------------------------------------------------------------------


def test_security_config_fails() -> None:
    """Configure_Security → PR-02 FAIL."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="sec-cfg",
                    event_type="Configure_Security",
                    objects=["Personal_Data"],
                )
            ]
        }
    )
    [result] = WorkdayImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "security_configuration_change"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Bulk_Edit
# ---------------------------------------------------------------------------


def test_bulk_edit_fails() -> None:
    """Bulk_Edit records_affected > 100 → PR-02 FAIL."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="bulk-edit",
                    event_type="Bulk_Edit",
                    records_affected=500,
                    is_bulk=True,
                    objects=["Personal_Data"],
                )
            ]
        }
    )
    [result] = WorkdayImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "bulk_edit")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["records_affected"] == 500


# ---------------------------------------------------------------------------
# Export_Data
# ---------------------------------------------------------------------------


def test_export_data_fails() -> None:
    """Export_Data records_affected > threshold → PR-04 FAIL."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="export-1",
                    event_type="Export_Data",
                    records_affected=2500,
                    objects=["Personal_Data", "Compensation"],
                )
            ]
        }
    )
    [result] = WorkdayImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "bulk_export_data")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Missing required approval
# ---------------------------------------------------------------------------


def test_missing_approval_fails() -> None:
    """approval_required=true + approver_id=null → PR-02 FAIL."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="missing-app",
                    event_type="Add_Worker",
                    approval_required=True,
                    approver_id=None,
                )
            ]
        }
    )
    [result] = WorkdayImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "missing_required_approval"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Legacy TLS
# ---------------------------------------------------------------------------


def test_legacy_tls_fails() -> None:
    """tls_version=TLSv1.0 → PR-04 FAIL."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="tls-bad",
                    event_type="Login",
                    status="Success",
                    tls_version="TLSv1.0",
                )
            ]
        }
    )
    [result] = WorkdayImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "legacy_tls")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Synthetic — cross-worker pattern (mass-PII access)
# ---------------------------------------------------------------------------


def test_cross_worker_synthetic() -> None:
    """Same actor accessing > N target_workers in 1h → synthetic PR-04 FAIL → BLOCK."""
    importer = WorkdayImporter(cross_worker_threshold=3)
    actor = "emp-actor-MASS9999"
    events = [
        _event(
            event_id=f"crossw-{i}",
            event_type="View_Worker",
            timestamp=f"2026-04-01T12:00:{i:02d}Z",
            actor_worker_id=actor,
            target_worker_id=f"emp-target-{i:08d}",
            user_type="Regular",
        )
        for i in range(6)
    ]
    doc = json.dumps({"events": events})
    results = importer.parse_string(doc)
    actor_last8 = actor[-8:]
    synthetic = [r for r in results if r.action_id == f"workday-cross-worker-{actor_last8}"]
    assert len(synthetic) == 1
    cr = synthetic[0].control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert synthetic[0].decision == "BLOCK"
    assert cr.evidence_data["synthetic"] is True
    assert cr.evidence_data["cross_worker_unique_count"] == 6
    assert cr.evidence_data["cross_worker_threshold"] == 3


# ---------------------------------------------------------------------------
# Synthetic — out-of-region (GDPR/PIPEDA cross-jurisdiction)
# ---------------------------------------------------------------------------


def test_out_of_region_synthetic() -> None:
    """Actor accessing > N targets in different region → synthetic PR-04 FLAG."""
    importer = WorkdayImporter(cross_region_threshold=2)
    actor = "emp-actor-USACTOR1"
    events = [
        _event(
            event_id=f"region-{i}",
            event_type="View_Worker",
            timestamp=f"2026-04-01T12:{i:02d}:00Z",
            actor_worker_id=actor,
            actor_region="US",
            target_worker_id=f"emp-eu-{i:08d}",
            target_region="EU",
            user_type="Regular",
        )
        for i in range(5)
    ]
    doc = json.dumps({"events": events})
    results = importer.parse_string(doc)
    actor_last8 = actor[-8:]
    synthetic = [r for r in results if r.action_id == f"workday-out-of-region-{actor_last8}"]
    assert len(synthetic) == 1
    cr = synthetic[0].control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["cross_region_target_count"] == 5
    assert cr.evidence_data["cross_region_threshold"] == 2
    # GDPR/PIPEDA wording in the detail.
    assert (
        "GDPR" in cr.detail
        or "PIPEDA" in cr.detail
        or "cross-jurisdiction" in cr.detail.lower()
    )


# ---------------------------------------------------------------------------
# Sanitization — worker_id last-8 only, name length only, IP redacted
# ---------------------------------------------------------------------------


def test_worker_id_truncated_to_last_8() -> None:
    """actor.worker_id and target_worker.worker_id are stored as last-8 only."""
    actor = "emp-actor-VERYLONGABCD1234"
    target = "emp-target-OTHERLONGWXYZ5678"
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="trunc-1",
                    event_type="View_Worker",
                    actor_worker_id=actor,
                    target_worker_id=target,
                    user_type="Service Account",
                )
            ]
        }
    )
    [result] = WorkdayImporter().parse_string(doc)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "service_account_view_worker"
    )
    assert cr.evidence_data["actor_worker_id_last8"] == actor[-8:]
    assert cr.evidence_data["target_worker_id_last8"] == target[-8:]
    serialized = json.dumps(cr.evidence_data, default=str)
    # Full IDs must NOT appear anywhere in evidence_data.
    assert actor not in serialized
    assert target not in serialized


def test_worker_name_not_stored() -> None:
    """actor.worker_name and target_worker.name are stored as length only — never the value."""
    name = "Alice Wonderland Confidential"
    target_name = "Bob Sensitive Smith"
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="name-1",
                    event_type="View_Worker",
                    actor_worker_name=name,
                    target_name=target_name,
                    user_type="Service Account",
                )
            ]
        }
    )
    [result] = WorkdayImporter().parse_string(doc)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "service_account_view_worker"
    )
    assert cr.evidence_data["actor_worker_name_length"] == len(name)
    assert cr.evidence_data["target_worker_name_length"] == len(target_name)
    serialized = json.dumps(cr.evidence_data, default=str)
    assert name not in serialized
    assert target_name not in serialized
    assert "Wonderland" not in serialized
    assert "Sensitive" not in serialized


def test_client_ip_redacted_to_slash16() -> None:
    """Public IPv4 client_ip reduced to A.B.0.0/16."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="ip-1",
                    event_type="Login",
                    status="Success",
                    client_ip="93.184.216.34",
                )
            ]
        }
    )
    [result] = WorkdayImporter().parse_string(doc)
    cr = result.control_results[0]
    assert cr.evidence_data["client_ip_redacted"] == "93.184.0.0/16"
    serialized = json.dumps(cr.evidence_data, default=str)
    assert "93.184.216.34" not in serialized


# ---------------------------------------------------------------------------
# Provenance & shape
# ---------------------------------------------------------------------------


def test_parse_file_records_sha256(tmp_path: Path) -> None:
    """parse() hashes the original file and surfaces it in source_provenance."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="prov-1",
                    event_type="Login",
                    status="Success",
                )
            ]
        }
    )
    p = tmp_path / "workday-events.json"
    p.write_bytes(doc.encode("utf-8"))
    expected_sha = hashlib.sha256(doc.encode("utf-8")).hexdigest()
    [result] = WorkdayImporter().parse(p)
    cr = result.control_results[0]
    assert cr.evidence_data["source_provenance"]["original_file_sha256"] == expected_sha


def test_jsonl_supported() -> None:
    """JSONL — one event per line — is accepted."""
    lines = "\n".join(
        json.dumps(_event(event_id=f"jl-{i}", event_type="Login", status="Success"))
        for i in range(3)
    )
    results = WorkdayImporter().parse_string(lines)
    assert len(results) == 3
    assert all(r.source_type == "workday_audit_log_import" for r in results)
    assert all(r.decision == "ALLOW" for r in results)
