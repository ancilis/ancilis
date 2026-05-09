"""Tests for the SentinelOne Singularity EDR importer."""

from __future__ import annotations

import json
from typing import Any

from ancilis.importers import SentinelOneImporter


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _threat(
    *,
    threat_id: str = "thr-001",
    created_at: str = "2026-05-09T12:00:00Z",
    updated_at: str = "2026-05-09T12:00:00Z",
    severity: str = "E_HIGH",
    analyst_verdict: str = "undefined",
    confidence_level: str = "high",
    incident_status: str = "detected",
    classification: str | None = "Malware",
    threat_name: str = "agent.exe",
    mitigation_status: str = "not_mitigated",
    engines: list[str] | None = None,
    behavioral_indicators: list[str] | None = None,
    agent_computer_name: str = "agent-svc-prod-1",
    agent_domain: str = "corp.example.com",
    agent_os_type: str = "linux",
    agent_machine_type: str = "server",
    agent_version: str = "23.4.1",
    agent_infected: bool = False,
    agent_is_active: bool = True,
    actions_taken: list[str] | None = None,
    approval_required: bool = False,
    approved_by: str | None = None,
    is_authenticated_response: bool = True,
    binary_signature_status: str | None = "signed",
    binary_path_normalized: str | None = "system/agent.exe",
    kill_chain_position: str | None = None,
    hostname_origin_country: str = "US",
    external_ticket_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if engines is None:
        engines = ["AI", "Behavioral AI"]
    if behavioral_indicators is None:
        behavioral_indicators = []
    if actions_taken is None:
        actions_taken = []
    obj: dict[str, Any] = {
        "id": threat_id,
        "createdAt": created_at,
        "updatedAt": updated_at,
        "threatInfo": {
            "identifier": threat_id,
            "threatName": threat_name,
            "severity": severity,
            "analystVerdict": analyst_verdict,
            "confidenceLevel": confidence_level,
            "incidentStatus": incident_status,
            "classification": classification,
            "mitigationStatus": mitigation_status,
            "engines": list(engines),
        },
        "agentRealtimeInfo": {
            "agentComputerName": agent_computer_name,
            "agentDomain": agent_domain,
            "agentInfected": agent_infected,
            "agentIsActive": agent_is_active,
            "agentMachineType": agent_machine_type,
            "agentOsType": agent_os_type,
            "agentVersion": agent_version,
        },
        "behavioralIndicators": list(behavioral_indicators),
        "automatedResponses": {
            "actionsTaken": list(actions_taken),
            "approvalRequired": approval_required,
            "approvedBy": approved_by,
        },
        "is_authenticated_response": is_authenticated_response,
        "hostname_origin_country": hostname_origin_country,
        "binary_signature_status": binary_signature_status,
        "binary_path_normalized": binary_path_normalized,
        "kill_chain_position": kill_chain_position,
        "externalTicketId": external_ticket_id,
        "ranges": {"detectionEngines": list(engines)},
        "mitigationStatusDescription": "no action",
    }
    if extra:
        obj.update(extra)
    return obj


def _audit(
    *,
    timestamp: str = "2026-05-09T12:00:00Z",
    action: str = "deep_visibility_query",
    username: str = "alice-12345",
    email: str = "alice@corp.example.com",
    is_admin: bool = True,
    target_id: str = "tgt-abcdef0123456789",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "action": action,
        "actor": {
            "username": username,
            "email": email,
            "is_admin": is_admin,
        },
        "target_id": target_id,
        "details": details or {},
    }


def _wrap_threats(threats: list[dict[str, Any]]) -> str:
    return json.dumps({"threats": threats})


def _wrap_audits(audits: list[dict[str, Any]]) -> str:
    return json.dumps({"audit_logs": audits})


def _find_signal(results: list, signal: str):
    for r in results:
        for cr in r.control_results:
            if cr.evidence_data.get("signal") == signal:
                return cr
    return None


def _find_eval_with_signal(results: list, signal: str):
    for r in results:
        for cr in r.control_results:
            if cr.evidence_data.get("signal") == signal:
                return r
    return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_critical_threat_open_fails():
    importer = SentinelOneImporter()
    payload = _wrap_threats(
        [_threat(severity="E_CRITICAL", incident_status="unresolved")]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "critical_open")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


def test_ransomware_classification_fails_and_blocks():
    importer = SentinelOneImporter(mode="enforce")
    payload = _wrap_threats(
        [
            _threat(
                severity="E_CRITICAL",
                classification="Ransomware",
                incident_status="unresolved",
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "ransomware_classification")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    eval_result = _find_eval_with_signal(results, "ransomware_classification")
    assert eval_result is not None
    assert eval_result.decision == "BLOCK"


def test_supply_chain_classification_fails():
    importer = SentinelOneImporter()
    payload = _wrap_threats(
        [
            _threat(
                severity="E_HIGH",
                classification="Supply Chain",
                incident_status="detected",
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "supply_chain_classification")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


def test_ai_threat_classification_fails():
    importer = SentinelOneImporter()
    payload = _wrap_threats(
        [
            _threat(
                severity="E_HIGH",
                classification="AI Threat",
                incident_status="detected",
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "ai_threat_classification")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


def test_data_exfiltration_indicator_fails():
    importer = SentinelOneImporter()
    payload = _wrap_threats(
        [
            _threat(
                severity="E_HIGH",
                classification="Malware",
                incident_status="detected",
                behavioral_indicators=["DataExfiltration"],
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "indicator_data_exfiltration")
    assert cr is not None
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


def test_credential_dumping_indicator_fails():
    importer = SentinelOneImporter()
    payload = _wrap_threats(
        [
            _threat(
                severity="E_HIGH",
                classification="Malware",
                incident_status="detected",
                behavioral_indicators=["CredentialDumping"],
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "indicator_credential_dumping")
    assert cr is not None
    assert cr.control_id == "PR-01"
    assert cr.result == "FAIL"


def test_lateral_movement_indicator_fails():
    importer = SentinelOneImporter()
    payload = _wrap_threats(
        [
            _threat(
                severity="E_HIGH",
                classification="Malware",
                incident_status="detected",
                behavioral_indicators=["LateralMovement"],
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "indicator_lateral_movement")
    assert cr is not None
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


def test_command_and_control_indicator_fails():
    importer = SentinelOneImporter()
    payload = _wrap_threats(
        [
            _threat(
                severity="E_HIGH",
                classification="Malware",
                incident_status="detected",
                behavioral_indicators=["CommandAndControl"],
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "indicator_command_and_control")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


def test_invalid_binary_signature_fails():
    importer = SentinelOneImporter()
    payload = _wrap_threats(
        [
            _threat(
                severity="E_HIGH",
                classification="Malware",
                incident_status="detected",
                binary_signature_status="invalid",
                binary_path_normalized="system/svchost.exe",
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "binary_signature_invalid")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


def test_autonomous_quarantine_no_approval_fails():
    importer = SentinelOneImporter()
    payload = _wrap_threats(
        [
            _threat(
                severity="E_HIGH",
                classification="Malware",
                incident_status="detected",
                actions_taken=["quarantine"],
                approval_required=True,
                approved_by=None,
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "autonomous_high_impact_no_approval")
    assert cr is not None
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


def test_agent_uninstalled_non_admin_fails():
    importer = SentinelOneImporter()
    payload = _wrap_audits(
        [
            _audit(
                action="agent_uninstalled",
                is_admin=False,
                username="rogue-9876543210",
                email="rogue@external.example.org",
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "agent_uninstalled_non_admin")
    assert cr is not None
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


def test_marked_benign_on_malware_fails():
    importer = SentinelOneImporter()
    payload = _wrap_threats(
        [
            _threat(
                severity="E_HIGH",
                classification="AI Threat",
                incident_status="resolved",
                mitigation_status="marked_as_benign",
                analyst_verdict="undefined",
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "marked_benign_critical_classification")
    assert cr is not None
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


def test_recurring_true_positive_synthetic_emitted():
    importer = SentinelOneImporter(recurring_tp_threshold=2)
    threats = [
        _threat(
            threat_id=f"thr-tp-{i}",
            severity="E_HIGH",
            analyst_verdict="true_positive",
            incident_status="resolved",
            threat_name="recurring-bad.exe",
            agent_computer_name=f"agent-svc-prod-{i}",
            created_at="2026-05-09T08:00:00Z",
        )
        for i in range(5)
    ]
    payload = _wrap_threats(threats)
    results = importer.parse_string(payload)
    cr = _find_signal(results, "recurring_tp_synthetic")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert cr.evidence_data.get("synthetic") is True
    redacted = cr.evidence_data.get("threat_name_redacted") or {}
    assert "sha256" in redacted
    serialized = json.dumps(cr.evidence_data, default=str)
    assert "recurring-bad.exe" not in serialized


def test_cross_host_attack_synthetic_emitted():
    importer = SentinelOneImporter(cross_host_threshold=2)
    threats = [
        _threat(
            threat_id=f"thr-spread-{i}",
            severity="E_CRITICAL",
            classification="AI Threat",
            incident_status="unresolved",
            agent_computer_name=f"agent-svc-prod-{i}",
            created_at="2026-05-09T08:00:00Z",
            threat_name=f"name-{i}",
        )
        for i in range(5)
    ]
    payload = _wrap_threats(threats)
    results = importer.parse_string(payload)
    cr = _find_signal(results, "cross_host_attack_synthetic")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert cr.evidence_data.get("synthetic") is True
    assert cr.evidence_data.get("classification") == "ai threat"


def test_hostname_redacted_never_plaintext():
    importer = SentinelOneImporter()
    sensitive_host = "secret-tenant-internal-svc-1"
    payload = _wrap_threats(
        [
            _threat(
                severity="E_HIGH",
                classification="Malware",
                incident_status="detected",
                agent_computer_name=sensitive_host,
                agent_domain="secret-tenant-internal.example.org",
                threat_name="confidential-payload.exe",
            )
        ]
    )
    results = importer.parse_string(payload)
    serialized = json.dumps(
        [
            {"detail": cr.detail, "evidence_data": cr.evidence_data}
            for r in results
            for cr in r.control_results
        ],
        default=str,
    )
    assert sensitive_host not in serialized
    assert "secret-tenant-internal.example.org" not in serialized
    assert "confidential-payload.exe" not in serialized
    found_redaction = False
    for r in results:
        for cr in r.control_results:
            ev = cr.evidence_data.get("agent_computer_name_redacted")
            if isinstance(ev, dict) and ev.get("sha256"):
                found_redaction = True
                break
    assert found_redaction


def test_email_domain_only_in_audit_evidence():
    importer = SentinelOneImporter()
    payload = _wrap_audits(
        [
            _audit(
                action="api_token_created",
                is_admin=True,
                username="user-987654321",
                email="kevin.special.user@kevin-private.example.com",
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "api_token_created")
    assert cr is not None
    assert (
        cr.evidence_data.get("actor_email_domain")
        == "kevin-private.example.com"
    )
    serialized = json.dumps(cr.evidence_data, default=str)
    assert "kevin.special.user" not in serialized


def test_jsonl_input_supported():
    importer = SentinelOneImporter()
    threat_obj = _threat(
        severity="E_CRITICAL",
        classification="Ransomware",
        incident_status="unresolved",
    )
    audit_obj = _audit(action="api_token_created", is_admin=True)
    jsonl = json.dumps(threat_obj) + "\n" + json.dumps(audit_obj) + "\n"
    results = importer.parse_string(jsonl)
    assert _find_signal(results, "ransomware_classification") is not None
    assert _find_signal(results, "api_token_created") is not None
