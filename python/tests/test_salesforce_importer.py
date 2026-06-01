"""Tests for the Salesforce Event Monitoring importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers.salesforce import SalesforceImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Salesforce Event Monitoring records
# ---------------------------------------------------------------------------


def _event(
    *,
    event_id: str = "evt-1",
    event_type: str = "ApiTotalUsage",
    timestamp_derived: str = "2026-04-01T12:00:00Z",
    user_id: str | None = "005XX000001abcdAAA",
    username: str | None = "agent-svc@example.com",
    user_type: str | None = "Standard",
    client_ip: str | None = "203.0.113.42",
    uri: str | None = "/services/data/v60.0/sobjects/Account",
    uri_id_derived: str | None = None,
    object_type: str | None = "Account",
    request_method: str | None = "GET",
    run_time: int = 230,
    rows_returned: int = 100,
    rows_processed: int = 1,
    event_log_file_api_version: str = "60.0",
    api_type: str = "REST",
    session_key: str | None = "ABCDEFGHIJKLMNOP",
    organization_id: str = "00DXX0000004CCEMA2",
    event_date: str = "2026-04-01",
    file_type: str | None = None,
    file_size_bytes: int = 0,
    report_id_derived: str | None = None,
    dashboard_id_derived: str | None = None,
    exception_type: str | None = None,
    einstein_model_id: str | None = None,
    prediction_confidence: float | None = None,
    query_length: int = 0,
    is_agentforce: bool = False,
    agent_name: str | None = None,
    blocked_reason: str | None = None,
    tls_version: str = "TLSv1.3",
    api_response_time_ms: int = 230,
) -> dict:
    return {
        "event_id": event_id,
        "EVENT_TYPE": event_type,
        "TIMESTAMP_DERIVED": timestamp_derived,
        "USER_ID": user_id,
        "USERNAME": username,
        "USER_TYPE": user_type,
        "CLIENT_IP": client_ip,
        "URI": uri,
        "URI_ID_DERIVED": uri_id_derived,
        "OBJECT_TYPE": object_type,
        "REQUEST_METHOD": request_method,
        "RUN_TIME": run_time,
        "ROWS_RETURNED": rows_returned,
        "ROWS_PROCESSED": rows_processed,
        "EVENT_LOG_FILE_API_VERSION": event_log_file_api_version,
        "API_TYPE": api_type,
        "SESSION_KEY": session_key,
        "ORGANIZATION_ID": organization_id,
        "EVENT_DATE": event_date,
        "FILE_TYPE": file_type,
        "FILE_SIZE_BYTES": file_size_bytes,
        "REPORT_ID_DERIVED": report_id_derived,
        "DASHBOARD_ID_DERIVED": dashboard_id_derived,
        "EXCEPTION_TYPE": exception_type,
        "EINSTEIN_MODEL_ID": einstein_model_id,
        "PREDICTION_CONFIDENCE": prediction_confidence,
        "QUERY_LENGTH": query_length,
        "IS_AGENTFORCE": is_agentforce,
        "AGENT_NAME": agent_name,
        "BLOCKED_REASON": blocked_reason,
        "TLS_VERSION": tls_version,
        "API_RESPONSE_TIME_MS": api_response_time_ms,
    }


def _findings(results: list, event_id: str) -> list:
    return [r for r in results if r.action_id == f"salesforce-{event_id}"]


def _signals(result) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in result.control_results]


# ---------------------------------------------------------------------------
# Login / LoginAs
# ---------------------------------------------------------------------------


def test_login_passes() -> None:
    """EVENT_TYPE=Login + blocked_reason=null → PR-01 PASS, ALLOW."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="login-1",
                    event_type="Login",
                    blocked_reason=None,
                    object_type=None,
                    request_method="POST",
                )
            ]
        }
    )
    [result] = SalesforceImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "salesforce_event_monitoring_import"
    assert "login_pass" in _signals(result)
    cr = result.control_results[0]
    assert cr.control_id == "PR-01"
    assert cr.result == "PASS"


def test_login_blocked_flags() -> None:
    """EVENT_TYPE=Login + blocked_reason=Permissions → PR-01 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="login-2",
                    event_type="Login",
                    blocked_reason="Permissions",
                    object_type=None,
                )
            ]
        }
    )
    [result] = SalesforceImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "login_blocked")
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"
    assert cr.evidence_data["blocked_reason"] == "Permissions"


def test_login_as_fails_admin_impersonation() -> None:
    """EVENT_TYPE=LoginAs → PR-01 FAIL (admin impersonating user)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="loginas-1",
                    event_type="LoginAs",
                    object_type=None,
                )
            ]
        }
    )
    [result] = SalesforceImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "login_as_admin_impersonation"
    )
    assert cr.control_id == "PR-01"
    assert cr.result == "FAIL"
    assert "impersonating" in cr.detail.lower() or "impersonat" in cr.detail.lower()


# ---------------------------------------------------------------------------
# DataExport
# ---------------------------------------------------------------------------


def test_data_export_large_fails() -> None:
    """EVENT_TYPE=DataExport + FILE_SIZE_BYTES > 100MB → PR-04 FAIL."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="export-big",
                    event_type="DataExport",
                    file_type="PDF",
                    file_size_bytes=200 * 1024 * 1024,
                    object_type="Account",
                )
            ]
        }
    )
    [result] = SalesforceImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "data_export_large"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


def test_report_export_by_agentforce_flags() -> None:
    """EVENT_TYPE=ReportExport + is_agentforce=true → PR-04 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="report-1",
                    event_type="ReportExport",
                    is_agentforce=True,
                    agent_name="ServiceAgent",
                    report_id_derived="00OXX0000001abc",
                    object_type=None,
                )
            ]
        }
    )
    [result] = SalesforceImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "report_export_agentforce"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["report_id_derived"] == "00OXX0000001abc"


# ---------------------------------------------------------------------------
# BulkApi V2 — bulk delete is the most dangerous mass-action
# ---------------------------------------------------------------------------


def test_bulk_delete_fails() -> None:
    """EVENT_TYPE=BulkApiV2Request + request_method=DELETE → PR-02 FAIL."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="bulk-del",
                    event_type="BulkApiV2Request",
                    request_method="DELETE",
                    rows_processed=50000,
                    object_type="Contact",
                    api_type="Bulk",
                )
            ]
        }
    )
    [result] = SalesforceImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "bulk_delete")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["rows_processed"] == 50000


# ---------------------------------------------------------------------------
# WaveDownload — analytics export = bulk exfiltration surface
# ---------------------------------------------------------------------------


def test_wave_download_flags() -> None:
    """EVENT_TYPE=WaveDownload → PR-04 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="wave-1",
                    event_type="WaveDownload",
                    is_agentforce=False,
                    object_type=None,
                    file_size_bytes=12345,
                )
            ]
        }
    )
    [result] = SalesforceImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "wave_download")
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"


# ---------------------------------------------------------------------------
# Apex
# ---------------------------------------------------------------------------


def test_apex_unexpected_exception_fails() -> None:
    """EVENT_TYPE=ApexUnexpectedException → DE-01 FAIL."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="apex-err",
                    event_type="ApexUnexpectedException",
                    exception_type="System.NullPointerException",
                    object_type=None,
                )
            ]
        }
    )
    [result] = SalesforceImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "apex_unexpected_exception"
    )
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert cr.evidence_data["exception_type"] == "System.NullPointerException"


# ---------------------------------------------------------------------------
# Einstein
# ---------------------------------------------------------------------------


def test_low_confidence_einstein_flags() -> None:
    """EVENT_TYPE=EinsteinPrediction + PREDICTION_CONFIDENCE < 0.5 → PR-03 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="einstein-1",
                    event_type="EinsteinPrediction",
                    einstein_model_id="model-abc",
                    prediction_confidence=0.32,
                    object_type="Lead",
                )
            ]
        }
    )
    [result] = SalesforceImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "low_confidence_einstein"
    )
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert cr.evidence_data["prediction_confidence"] == 0.32


# ---------------------------------------------------------------------------
# Integration user
# ---------------------------------------------------------------------------


def test_integration_user_on_customer_data_flags() -> None:
    """USER_TYPE=PlatformIntegrationUser AND OBJECT_TYPE in {Contact,Account,Case} → PR-02 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="intuser-1",
                    event_type="ApiTotalUsage",
                    user_type="PlatformIntegrationUser",
                    object_type="Contact",
                    rows_returned=10,
                )
            ]
        }
    )
    [result] = SalesforceImporter().parse_string(doc)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "integration_user_customer_data"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert result.decision == "FLAG"


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------


def test_legacy_tls_fails() -> None:
    """TLS_VERSION=TLSv1.0 → PR-04 FAIL."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="tls-1",
                    event_type="ApiTotalUsage",
                    tls_version="TLSv1.0",
                    object_type="Account",
                    rows_returned=5,
                )
            ]
        }
    )
    [result] = SalesforceImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "legacy_tls")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# FLS governance — correctly-blocked Agentforce access = audit trail PASS
# ---------------------------------------------------------------------------


def test_blocked_by_fls_passes_governance_audit() -> None:
    """BLOCKED_REASON=Field-level security on Agentforce attempt → PR-02 PASS."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="fls-1",
                    event_type="ApiTotalUsage",
                    is_agentforce=True,
                    agent_name="ServiceAgent",
                    blocked_reason="Field-level security",
                    object_type="Account",
                    rows_returned=0,
                )
            ]
        }
    )
    [result] = SalesforceImporter().parse_string(doc)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "blocked_by_fls_governance"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "PASS"
    # Decision: only PASS controls → ALLOW.
    assert result.decision == "ALLOW"


# ---------------------------------------------------------------------------
# Synthetic findings: cross-object & high-volume agent
# ---------------------------------------------------------------------------


def test_cross_object_pattern_synthetic() -> None:
    """Same Agentforce USER_ID touching > 8 OBJECT_TYPEs → synthetic PR-04 FLAG."""
    user_id = "005XX000001agentAAA"
    object_types = [
        "Contact",
        "Account",
        "Lead",
        "Opportunity",
        "Case",
        "User",
        "Asset",
        "Campaign",
        "Product2",
    ]
    events = [
        _event(
            event_id=f"cross-{i}",
            event_type="ApiTotalUsage",
            user_id=user_id,
            object_type=ot,
            is_agentforce=True,
            agent_name="BroadAgent",
            rows_returned=10,
        )
        for i, ot in enumerate(object_types)
    ]
    doc = json.dumps({"events": events})
    results = SalesforceImporter().parse_string(doc)
    synthetic = [
        r for r in results
        if r.action_id == f"salesforce-cross-object-{user_id}"
    ]
    assert len(synthetic) == 1
    cr = synthetic[0].control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["synthetic"] is True
    assert cr.evidence_data["cross_object_object_count"] == len(object_types)
    assert set(cr.evidence_data["cross_object_object_types"]) == set(object_types)
    # Per-event marker also fired on the contributing events.
    per_event_markers = [
        cr2
        for r in results
        if r.action_id.startswith("salesforce-cross-")
        for cr2 in r.control_results
        if cr2.evidence_data.get("signal") == "cross_object_pattern"
    ]
    assert len(per_event_markers) >= 1


def test_high_volume_agent_synthetic() -> None:
    """Same AGENT_NAME with > threshold API calls → synthetic PR-04 FLAG."""
    importer = SalesforceImporter(high_volume_agent_threshold=3)
    events = [
        _event(
            event_id=f"vol-{i}",
            event_type="ApiTotalUsage",
            agent_name="HotAgent",
            is_agentforce=True,
            rows_returned=1,
            object_type="Account",
        )
        for i in range(5)
    ]
    doc = json.dumps({"events": events})
    results = importer.parse_string(doc)
    synthetic = [
        r for r in results
        if r.action_id == "salesforce-high-volume-HotAgent"
    ]
    assert len(synthetic) == 1
    cr = synthetic[0].control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["api_call_count"] == 5
    assert cr.evidence_data["high_volume_agent_threshold"] == 3


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def test_username_only_domain_stored() -> None:
    """USERNAME is reduced to email domain only — no local part stored."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="san-1",
                    event_type="Login",
                    username="agent-svc-secret-handle@acme.example.com",
                    blocked_reason=None,
                    object_type=None,
                )
            ]
        }
    )
    [result] = SalesforceImporter().parse_string(doc)
    cr = result.control_results[0]
    # Domain only — local part must NOT appear anywhere in evidence_data.
    assert cr.evidence_data["username_domain"] == "acme.example.com"
    serialized = json.dumps(cr.evidence_data, default=str)
    assert "agent-svc-secret-handle" not in serialized
    assert "@" not in cr.evidence_data["username_domain"]


def test_uri_query_strings_stripped() -> None:
    """URI query strings dropped, long path segments truncated to last-8 with id: prefix."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="san-2",
                    event_type="ApiTotalUsage",
                    uri=(
                        "/services/data/v60.0/sobjects/Account/001XX000003DGb2YAH"
                        "?q=SELECT+Id+FROM+Account+WHERE+Name='Acme'"
                    ),
                    uri_id_derived="001XX000003DGb2YAH",
                    session_key="ABCDEFGHIJKLMNOPQRSTUVWX",
                    object_type="Account",
                    rows_returned=1,
                )
            ]
        }
    )
    [result] = SalesforceImporter().parse_string(doc)
    cr = result.control_results[0]
    uri_norm = cr.evidence_data["uri_normalized"]
    # No query string.
    assert "?" not in uri_norm
    assert "SELECT" not in uri_norm
    # Long row-ID segment truncated.
    assert "001XX000003DGb2YAH" not in uri_norm
    assert "id:" in uri_norm
    # URI_ID_DERIVED reduced to last-8.
    assert cr.evidence_data["uri_id_last8"] == "DGb2YAH"[-8:] or len(
        cr.evidence_data["uri_id_last8"]
    ) == 8
    # SESSION_KEY reduced to last-8.
    assert len(cr.evidence_data["session_key_last8"]) == 8
    assert cr.evidence_data["session_key_last8"] == "QRSTUVWX"


# ---------------------------------------------------------------------------
# File parsing & provenance
# ---------------------------------------------------------------------------


def test_parse_file_records_sha256(tmp_path: Path) -> None:
    """parse() hashes the original file and surfaces it in source_provenance."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="prov-1",
                    event_type="Login",
                    blocked_reason=None,
                    object_type=None,
                )
            ]
        }
    )
    p = tmp_path / "salesforce-events.json"
    p.write_bytes(doc.encode("utf-8"))
    expected_sha = hashlib.sha256(doc.encode("utf-8")).hexdigest()
    [result] = SalesforceImporter().parse(p)
    cr = result.control_results[0]
    assert (
        cr.evidence_data["source_provenance"]["original_file_sha256"] == expected_sha
    )


def test_jsonl_supported() -> None:
    """JSONL — one event per line — is accepted."""
    lines = "\n".join(
        json.dumps(
            _event(
                event_id=f"jl-{i}",
                event_type="Login",
                blocked_reason=None,
                object_type=None,
            )
        )
        for i in range(3)
    )
    results = SalesforceImporter().parse_string(lines)
    assert len(results) == 3
    assert all(
        r.source_type == "salesforce_event_monitoring_import" for r in results
    )


def test_data_envelope_supported() -> None:
    """{'data':[...]} envelope is accepted."""
    doc = json.dumps(
        {
            "data": [
                _event(
                    event_id="d-1",
                    event_type="Login",
                    blocked_reason=None,
                    object_type=None,
                )
            ]
        }
    )
    results = SalesforceImporter().parse_string(doc)
    assert len(results) == 1
