"""Tests for the SentinelOne Singularity EDR importer."""

from __future__ import annotations

import json
from typing import Any

from ancilis.importers import SentinelOneImporter


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _indicator(
    *,
    category: str = "Execution",
    tactic: str = "Execution",
    technique: str = "T1059",
    ids: list[str] | None = None,
    description_length: int = 80,
) -> dict[str, Any]:
    return {
        "category": category,
        "tactic": tactic,
        "technique": technique,
        "ids": list(ids) if ids is not None else ["ind-1"],
        "description_length": description_length,
    }


def _mitigation(
    *,
    action: str = "kill",
    status: str = "success",
    mitigation_status: str = "completed",
    user_id: str | None = "user-abcdefgh12345",
    initiated_by_policy: bool = True,
) -> dict[str, Any]:
    return {
        "action": action,
        "status": status,
        "mitigationStatus": mitigation_status,
        "userId": user_id,
        "initiatedByPolicy": initiated_by_policy,
    }


def _threat(
    *,
    threat_id: str = "threat-001",
    created_at: str = "2026-05-09T12:00:00Z",
    agent_id_field: str = "agent-001",
    ai_confidence_level: str = "malicious",
    analyst_verdict: str = "undefined",
    classification: str = "Malware",
    classification_source: str = "Engine",
    file_verification_type: str = "SignedVerified",
    incident_status: str = "unresolved",
    mitigation_status_top: str = "not_mitigated",
    threat_name: str = "Ransom.Cryptolocker",
    file_hash_sha256: str = "a" * 64,
    file_path_length: int = 80,
    originator_process_length: int = 40,
    storyline: str = "story-12345",
    agent_computer_name: str = "agent-prod-1.corp.example.com",
    agent_domain: str = "corp.example.com",
    agent_os_name: str = "Linux",
    agent_version: str = "22.2.1.1",
    network_interfaces: list[dict[str, Any]] | None = None,
    agent_is_active: bool = True,
    group_name: str = "production-servers",
    indicators: list[dict[str, Any]] | None = None,
    mitigations: list[dict[str, Any]] | None = None,
    network: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if network_interfaces is None:
        network_interfaces = [{"ip_v4": ["10.0.0.1"]}]
    if indicators is None:
        indicators = [_indicator()]
    if mitigations is None:
        mitigations = []
    if network is None:
        network = {
            "externalIp": "203.0.113.5",
            "sourceIp": "10.0.0.1",
            "destinationIp": "203.0.113.10",
            "destinationDomain_length": 30,
            "destinationPort": 443,
        }
    return {
        "id": threat_id,
        "createdAt": created_at,
        "threatInfo": {
            "agentId": agent_id_field,
            "aiConfidenceLevel": ai_confidence_level,
            "analystVerdict": analyst_verdict,
            "classification": classification,
            "classificationSource": classification_source,
            "fileVerificationType": file_verification_type,
            "incidentStatus": incident_status,
            "mitigationStatus": mitigation_status_top,
            "threatName": threat_name,
            "fileHashSha256": file_hash_sha256,
            "filePath_length": file_path_length,
            "originatorProcess_length": originator_process_length,
            "storyline": storyline,
        },
        "agentRealtimeInfo": {
            "agentComputerName": agent_computer_name,
            "agentDomain": agent_domain,
            "agentOsName": agent_os_name,
            "agentVersion": agent_version,
            "networkInterfaces": network_interfaces,
            "agentIsActive": agent_is_active,
            "groupName": group_name,
        },
        "mitigationStatus": list(mitigations),
        "indicators": list(indicators),
        "network": dict(network),
    }


def _wrap(threats: list[dict[str, Any]]) -> str:
    return json.dumps({"threats": threats})


def _signals(result) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in result.control_results]


def _control_ids(result) -> list[str]:
    return [cr.control_id for cr in result.control_results]


def _results_for_signal(results, signal):
    return [
        cr
        for r in results
        for cr in r.control_results
        if cr.evidence_data.get("signal") == signal
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_malicious_unresolved_fails() -> None:
    importer = SentinelOneImporter()
    threat = _threat(
        ai_confidence_level="malicious",
        incident_status="unresolved",
        classification="Generic.Suspicious",
        indicators=[],
    )
    [result] = importer.parse_string(_wrap([threat]))
    sigs = _signals(result)
    assert "malicious_open" in sigs
    [cr] = [c for c in result.control_results if c.evidence_data.get("signal") == "malicious_open"]
    assert cr.result == "FAIL"
    assert cr.control_id == "DE-01"
    assert result.decision == "FLAG"


def test_ransomware_fails_block() -> None:
    importer = SentinelOneImporter(mode="enforce")
    threat = _threat(classification="Ransomware", indicators=[])
    [result] = importer.parse_string(_wrap([threat]))
    sigs = _signals(result)
    assert "ransomware_classification" in sigs
    [cr] = [
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "ransomware_classification"
    ]
    assert cr.result == "FAIL"
    assert cr.control_id == "DE-01"
    assert result.decision == "BLOCK"


def test_credential_theft_fails() -> None:
    importer = SentinelOneImporter()
    threat = _threat(
        classification="Credential Theft",
        indicators=[],
        ai_confidence_level="suspicious",
        incident_status="resolved",
    )
    [result] = importer.parse_string(_wrap([threat]))
    sigs = _signals(result)
    assert "classification_credential_theft" in sigs
    [cr] = [
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "classification_credential_theft"
    ]
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-01"


def test_data_exfiltration_indicator_fails() -> None:
    importer = SentinelOneImporter()
    threat = _threat(
        classification="Data Exfiltration",
        indicators=[_indicator(category="Exfiltration", technique="T1041")],
        ai_confidence_level="malicious",
        incident_status="resolved",
        analyst_verdict="undefined",
    )
    [result] = importer.parse_string(_wrap([threat]))
    sigs = _signals(result)
    assert "indicator_exfiltration" in sigs
    assert "classification_data_exfiltration" in sigs
    [cr] = [
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "indicator_exfiltration"
    ]
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"


def test_technique_t1041_fails() -> None:
    importer = SentinelOneImporter()
    threat = _threat(
        classification="Generic.Suspicious",
        ai_confidence_level="suspicious",
        incident_status="resolved",
        indicators=[_indicator(category="Discovery", technique="T1041")],
    )
    [result] = importer.parse_string(_wrap([threat]))
    sigs = _signals(result)
    assert "mitre_technique_pr04" in sigs
    [cr] = [
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "mitre_technique_pr04"
    ]
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"
    assert "T1041" in cr.evidence_data.get("mitre_techniques", [])


def test_manual_mitigation_no_user_flags() -> None:
    importer = SentinelOneImporter()
    threat = _threat(
        ai_confidence_level="suspicious",
        incident_status="resolved",
        classification="Generic.Suspicious",
        indicators=[],
        mitigations=[
            _mitigation(
                action="network_quarantine",
                user_id=None,
                initiated_by_policy=False,
            )
        ],
    )
    [result] = importer.parse_string(_wrap([threat]))
    sigs = _signals(result)
    assert "manual_mitigation_no_user" in sigs
    [cr] = [
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "manual_mitigation_no_user"
    ]
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-02"


def test_rollback_flags() -> None:
    importer = SentinelOneImporter()
    threat = _threat(
        ai_confidence_level="suspicious",
        incident_status="resolved",
        classification="Generic.Suspicious",
        indicators=[],
        mitigations=[_mitigation(action="rollback", initiated_by_policy=True)],
    )
    [result] = importer.parse_string(_wrap([threat]))
    sigs = _signals(result)
    assert "rollback_mitigation" in sigs
    [cr] = [
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "rollback_mitigation"
    ]
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-05"


def test_signed_revoked_fails() -> None:
    importer = SentinelOneImporter()
    threat = _threat(
        ai_confidence_level="suspicious",
        incident_status="resolved",
        classification="Generic.Suspicious",
        file_verification_type="SignedRevoked",
        indicators=[],
    )
    [result] = importer.parse_string(_wrap([threat]))
    sigs = _signals(result)
    assert "signed_revoked_binary" in sigs
    [cr] = [
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "signed_revoked_binary"
    ]
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"


def test_inactive_prod_agent_flags() -> None:
    importer = SentinelOneImporter()
    threat = _threat(
        ai_confidence_level="suspicious",
        incident_status="resolved",
        classification="Generic.Suspicious",
        indicators=[],
        group_name="prod-frontend",
        agent_is_active=False,
    )
    [result] = importer.parse_string(_wrap([threat]))
    sigs = _signals(result)
    assert "inactive_production_agent" in sigs
    [cr] = [
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "inactive_production_agent"
    ]
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-01"


def test_out_of_date_agent_flags() -> None:
    importer = SentinelOneImporter(min_agent_version="22.0.0")
    threat = _threat(
        ai_confidence_level="suspicious",
        incident_status="resolved",
        classification="Generic.Suspicious",
        indicators=[],
        agent_version="21.5.3.7",
    )
    [result] = importer.parse_string(_wrap([threat]))
    sigs = _signals(result)
    assert "out_of_date_agent" in sigs
    [cr] = [
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "out_of_date_agent"
    ]
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-05"


def test_cross_host_synthetic() -> None:
    importer = SentinelOneImporter(cross_host_threshold=2)
    threats = [
        _threat(
            threat_id=f"threat-{i:03d}",
            created_at="2026-05-09T12:00:00Z",
            classification="Malware",
            ai_confidence_level="malicious",
            incident_status="unresolved",
            storyline="shared-story-deadbeef",
            agent_computer_name=f"host-{i}.corp.example.com",
            indicators=[],
        )
        for i in range(4)
    ]
    results = importer.parse_string(_wrap(threats))
    cross_host = _results_for_signal(results, "cross_host_attack_synthetic")
    assert len(cross_host) == 1
    cr = cross_host[0]
    assert cr.result == "FAIL"
    assert cr.control_id == "DE-01"
    assert cr.evidence_data.get("distinct_host_count") == 4


def test_repeated_fp_synthetic() -> None:
    importer = SentinelOneImporter(repeated_fp_threshold=2)
    threats = [
        _threat(
            threat_id=f"threat-fp-{i:03d}",
            created_at="2026-05-09T12:00:00Z",
            classification="Generic.Suspicious",
            ai_confidence_level="malicious",
            analyst_verdict="false_positive",
            incident_status="resolved",
            threat_name="repeating-noisy-rule",
            indicators=[],
        )
        for i in range(4)
    ]
    results = importer.parse_string(_wrap(threats))
    fp_synth = _results_for_signal(results, "repeated_fp_synthetic")
    assert len(fp_synth) == 1
    cr = fp_synth[0]
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-03"
    assert cr.evidence_data.get("false_positive_count") == 4


def test_rollback_frequency_synthetic() -> None:
    importer = SentinelOneImporter(
        rollback_frequency_threshold=2,
        rollback_frequency_window_seconds=3600,
    )
    base = "2026-05-09T12:00"
    threats = [
        _threat(
            threat_id=f"threat-rb-{i:03d}",
            created_at=f"{base}:0{i % 6}Z",
            classification="Generic.Suspicious",
            ai_confidence_level="suspicious",
            incident_status="resolved",
            indicators=[],
            mitigations=[_mitigation(action="rollback", initiated_by_policy=True)],
        )
        for i in range(5)
    ]
    results = importer.parse_string(_wrap(threats))
    rb_synth = _results_for_signal(results, "rollback_frequency_synthetic")
    assert len(rb_synth) == 1
    cr = rb_synth[0]
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-05"
    assert cr.evidence_data.get("rollback_count") == 5


def test_threat_name_not_stored() -> None:
    importer = SentinelOneImporter()
    secret_name = "Ransom.SuperSensitiveTargetCustomerNameProject2026"
    threat = _threat(threat_name=secret_name, indicators=[])
    [result] = importer.parse_string(_wrap([threat]))
    payload = json.dumps([cr.evidence_data for cr in result.control_results])
    assert secret_name not in payload
    # length + sha256 should be present
    redacted = result.control_results[0].evidence_data.get("threat_name_redacted")
    assert isinstance(redacted, dict)
    assert redacted.get("length") == len(secret_name)
    assert redacted.get("present") is True
    assert "sha256" in redacted


def test_file_path_not_stored() -> None:
    importer = SentinelOneImporter()
    secret_path = "/Users/sensitive-user/Documents/customer-secret.docx"
    threat = _threat(indicators=[])
    threat["threatInfo"]["filePath"] = secret_path
    threat["threatInfo"]["originatorProcess"] = "C:\\Users\\sensitive-user\\evil.exe"
    threat["threatInfo"]["filePath_length"] = len(secret_path)
    [result] = importer.parse_string(_wrap([threat]))
    payload = json.dumps([cr.evidence_data for cr in result.control_results])
    assert secret_path not in payload
    assert "sensitive-user" not in payload
    # length retained
    assert result.control_results[0].evidence_data.get("file_path_length") == len(
        secret_path
    )


def test_ip_redacted() -> None:
    importer = SentinelOneImporter()
    threat = _threat(
        indicators=[],
        network_interfaces=[{"ip_v4": ["10.1.2.3", "192.168.1.55"]}],
        network={
            "externalIp": "203.0.113.5",
            "sourceIp": "10.0.0.1",
            "destinationIp": "198.51.100.42",
            "destinationDomain_length": 12,
            "destinationPort": 443,
        },
    )
    [result] = importer.parse_string(_wrap([threat]))
    ev = result.control_results[0].evidence_data
    payload = json.dumps(ev)
    # Raw IPs must not appear
    assert "10.1.2.3" not in payload
    assert "192.168.1.55" not in payload
    assert "203.0.113.5" not in payload
    assert "10.0.0.1" not in payload
    assert "198.51.100.42" not in payload
    # Masked equivalents present
    assert ev.get("external_ip_masked") == "203.0.113.0"
    assert ev.get("source_ip_masked") == "10.0.0.0"
    assert ev.get("destination_ip_masked") == "198.51.100.0"
    assert ev.get("network_interfaces") == [
        {"ip_v4_masked": ["10.1.2.0", "192.168.1.0"]}
    ]


def test_jsonl_and_data_envelope_supported() -> None:
    importer = SentinelOneImporter()
    t1 = _threat(threat_id="t1", indicators=[])
    t2 = _threat(threat_id="t2", indicators=[])
    # JSONL
    jsonl = "\n".join(json.dumps(x) for x in (t1, t2))
    results_jsonl = importer.parse_string(jsonl)
    assert any(r.session_id == "t1" for r in results_jsonl)
    assert any(r.session_id == "t2" for r in results_jsonl)
    # data envelope
    results_data = importer.parse_string(json.dumps({"data": [t1]}))
    assert any(r.session_id == "t1" for r in results_data)
