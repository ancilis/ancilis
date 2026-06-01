"""Tests for the Splunk notable-event importer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ancilis.importers import SplunkImporter
from ancilis.importers.splunk import (
    _is_service_account,
    _mask_ip,
    _normalize_source_path,
    _redact_user,
    _truncate_search_id,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _event(
    *,
    severity: str = "low",
    status: str = "new",
    disposition: str | None = None,
    category: str | None = None,
    rule_name: str | None = "Test Rule",
    search_name: str | None = "Notable - Test",
    sourcetype: str = "agent_log:json",
    index: str = "main",
    host: str = "agent-svc-prod-1",
    user: str = "agent-svc",
    src_ip: str = "10.0.0.1",
    dest_ip: str = "10.0.1.1",
    dest_port: int | None = 443,
    ai_agent_id: str | None = None,
    ai_confidence_score: float | None = None,
    ai_runbook_executed: bool | None = None,
    ai_action_taken: str | None = None,
    user_decision: str | None = None,
    rule_action: list[str] | None = None,
    count_distinct_users: int | None = 1,
    count_distinct_src_ips: int | None = 1,
    raw_length: int = 1234,
    source: str = "/var/log/agent/agent.log",
    search_id: str = "scheduler__admin_search_id_RMD12345abcdef",
    owner: str | None = "soc-team",
    timestamp: str = "2026-05-09T12:00:00Z",
    indexed_at: str = "2026-05-09T12:00:01Z",
) -> dict[str, Any]:
    if rule_action is None:
        rule_action = ["alert"]
    return {
        "_time": timestamp,
        "host": host,
        "source": source,
        "sourcetype": sourcetype,
        "index": index,
        "_raw_length": raw_length,
        "search_name": search_name,
        "search_id": search_id,
        "severity": severity,
        "rule_name": rule_name,
        "category": category,
        "owner": owner,
        "status": status,
        "disposition": disposition,
        "rule_action": rule_action,
        "user": user,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "ai_agent_id": ai_agent_id,
        "ai_confidence_score": ai_confidence_score,
        "ai_runbook_executed": ai_runbook_executed,
        "ai_action_taken": ai_action_taken,
        "user_decision": user_decision,
        "_count_distinct_users": count_distinct_users,
        "_count_distinct_src_ips": count_distinct_src_ips,
        "indexed_at": indexed_at,
    }


def _envelope(events: list[dict[str, Any]]) -> str:
    return json.dumps({"events": events})


def _has_signal(result: Any, signal: str) -> bool:
    return any(
        cr.evidence_data.get("signal") == signal for cr in result.control_results
    )


def _signal_results(result: Any, signal: str) -> list[Any]:
    return [
        cr for cr in result.control_results if cr.evidence_data.get("signal") == signal
    ]


# ---------------------------------------------------------------------------
# Severity / status / disposition tests
# ---------------------------------------------------------------------------

def test_critical_open_fails() -> None:
    importer = SplunkImporter()
    results = importer.parse_string(
        _envelope(
            [
                _event(
                    severity="critical",
                    status="new",
                    rule_name="Suspicious AI Tool Call",
                )
            ]
        )
    )
    # 1 per-event result. No synthetics for a single event.
    per_event = [r for r in results if r.action_id != ""]
    assert len(per_event) >= 1
    target = per_event[0]
    assert _has_signal(target, "critical_open")
    crs = _signal_results(target, "critical_open")
    assert crs[0].control_id == "DE-01"
    assert crs[0].result == "FAIL"
    # Decision should be FLAG (audit mode) not BLOCK.
    assert target.decision == "FLAG"


def test_critical_resolved_true_positive_audit_fail() -> None:
    importer = SplunkImporter()
    results = importer.parse_string(
        _envelope(
            [
                _event(
                    severity="critical",
                    status="resolved",
                    disposition="true_positive",
                )
            ]
        )
    )
    target = results[0]
    assert _has_signal(target, "critical_resolved_true_positive")
    cr = _signal_results(target, "critical_resolved_true_positive")[0]
    assert cr.control_id == "PR-05"
    assert cr.result == "FAIL"


def test_critical_false_positive_passes() -> None:
    importer = SplunkImporter()
    results = importer.parse_string(
        _envelope(
            [
                _event(
                    severity="critical",
                    status="resolved",
                    disposition="false_positive",
                )
            ]
        )
    )
    target = results[0]
    assert _has_signal(target, "critical_false_positive")
    cr = _signal_results(target, "critical_false_positive")[0]
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert target.decision == "ALLOW"


# ---------------------------------------------------------------------------
# AI/ML category
# ---------------------------------------------------------------------------

def test_ai_ml_high_severity_fails() -> None:
    importer = SplunkImporter()
    results = importer.parse_string(
        _envelope(
            [
                _event(
                    severity="high",
                    status="new",
                    category="AI/ML",
                    ai_agent_id="agent-007",
                    rule_name="AI - Hallucination Detected",
                )
            ]
        )
    )
    target = results[0]
    assert _has_signal(target, "ai_ml_high_severity")
    cr = _signal_results(target, "ai_ml_high_severity")[0]
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert cr.evidence_data.get("ai_agent_id") == "agent-007"


# ---------------------------------------------------------------------------
# AI Assistant for SecOps autonomy governance
# ---------------------------------------------------------------------------

def test_autonomous_runbook_no_review_flags() -> None:
    importer = SplunkImporter()
    results = importer.parse_string(
        _envelope(
            [
                _event(
                    severity="medium",
                    status="in_progress",
                    ai_runbook_executed=True,
                    ai_action_taken="open_ticket",
                    ai_confidence_score=0.95,
                    user_decision=None,
                )
            ]
        )
    )
    target = results[0]
    assert _has_signal(target, "autonomous_runbook_no_review")
    cr = _signal_results(target, "autonomous_runbook_no_review")[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"


def test_runbook_user_rejected_fails() -> None:
    importer = SplunkImporter()
    results = importer.parse_string(
        _envelope(
            [
                _event(
                    severity="medium",
                    status="resolved",
                    ai_runbook_executed=True,
                    ai_action_taken="block_user",
                    ai_confidence_score=0.9,
                    user_decision="rejected",
                )
            ]
        )
    )
    target = results[0]
    assert _has_signal(target, "runbook_user_rejected")
    cr = _signal_results(target, "runbook_user_rejected")[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


def test_high_impact_action_no_decision_fails() -> None:
    importer = SplunkImporter()
    results = importer.parse_string(
        _envelope(
            [
                _event(
                    severity="high",
                    status="in_progress",
                    ai_runbook_executed=True,
                    ai_action_taken="isolate_host",
                    ai_confidence_score=0.9,
                    user_decision=None,
                )
            ]
        )
    )
    target = results[0]
    assert _has_signal(target, "high_impact_action_no_decision")
    cr = _signal_results(target, "high_impact_action_no_decision")[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


def test_low_confidence_autonomous_flags() -> None:
    importer = SplunkImporter()
    results = importer.parse_string(
        _envelope(
            [
                _event(
                    severity="low",
                    status="resolved",
                    ai_runbook_executed=True,
                    ai_action_taken="open_ticket",
                    ai_confidence_score=0.42,
                    user_decision="approved",
                )
            ]
        )
    )
    target = results[0]
    assert _has_signal(target, "low_confidence_autonomous")
    cr = _signal_results(target, "low_confidence_autonomous")[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"


def test_quarantine_no_decision_fails() -> None:
    importer = SplunkImporter()
    # No ai_action_taken — only rule_action contains 'quarantine'.
    results = importer.parse_string(
        _envelope(
            [
                _event(
                    severity="medium",
                    status="in_progress",
                    rule_action=["alert", "quarantine"],
                    ai_runbook_executed=None,
                    ai_action_taken=None,
                    user_decision=None,
                )
            ]
        )
    )
    target = results[0]
    assert _has_signal(target, "quarantine_no_decision")
    cr = _signal_results(target, "quarantine_no_decision")[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Broad-impact + synthetics
# ---------------------------------------------------------------------------

def test_broad_impact_user_count_flags() -> None:
    importer = SplunkImporter(broad_impact_user_count=50)
    results = importer.parse_string(
        _envelope(
            [_event(severity="low", count_distinct_users=120)]
        )
    )
    target = results[0]
    assert _has_signal(target, "broad_impact_user_count")
    cr = _signal_results(target, "broad_impact_user_count")[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"


def test_high_volume_ai_synthetic() -> None:
    importer = SplunkImporter(ai_volume_per_day=5)
    events = []
    for i in range(8):
        events.append(
            _event(
                severity="low",
                ai_agent_id="agent-X",
                rule_name=f"rule-{i}",
                timestamp="2026-05-09T08:00:00Z",
            )
        )
    results = importer.parse_string(_envelope(events))
    synthetics = [
        r
        for r in results
        if any(
            cr.evidence_data.get("signal") == "high_volume_ai_synthetic"
            for cr in r.control_results
        )
    ]
    assert len(synthetics) == 1
    cr = synthetics[0].control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["notable_count"] == 8
    assert cr.evidence_data["ai_agent_id"] == "agent-X"
    assert cr.evidence_data["synthetic"] is True


def test_repeated_false_positive_synthetic() -> None:
    importer = SplunkImporter(false_positive_pattern_threshold=3)
    events = []
    for _i in range(5):
        events.append(
            _event(
                severity="medium",
                status="resolved",
                disposition="false_positive",
                rule_name="Noisy Rule A",
                timestamp="2026-05-05T08:00:00Z",
            )
        )
    # Add some events from a different rule that shouldn't trigger.
    for _i in range(2):
        events.append(
            _event(
                severity="medium",
                status="resolved",
                disposition="false_positive",
                rule_name="Quiet Rule B",
                timestamp="2026-05-05T08:00:00Z",
            )
        )
    results = importer.parse_string(_envelope(events))
    synthetics = [
        r
        for r in results
        if any(
            cr.evidence_data.get("signal") == "repeated_false_positive_synthetic"
            for cr in r.control_results
        )
    ]
    assert len(synthetics) == 1
    cr = synthetics[0].control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert cr.evidence_data["rule_name"] == "Noisy Rule A"
    assert cr.evidence_data["false_positive_count"] == 5


# ---------------------------------------------------------------------------
# Sanitization tests
# ---------------------------------------------------------------------------

def test_raw_text_never_stored(tmp_path: Path) -> None:
    """Even if _raw text is included in input, it is NEVER stored — only length."""
    secret_raw = "auth_token=secret_DO_NOT_LEAK_value_xyz"
    event = _event(severity="low")
    # Inject raw text + remove length so the importer must compute length itself.
    event.pop("_raw_length", None)
    event["_raw"] = secret_raw

    payload = json.dumps({"events": [event]})
    file_path = tmp_path / "splunk.json"
    file_path.write_text(payload)

    importer = SplunkImporter()
    results = importer.parse(file_path)

    serialized = json.dumps(
        [
            {
                "control_results": [
                    {
                        "evidence_data": cr.evidence_data,
                        "detail": cr.detail,
                    }
                    for cr in r.control_results
                ],
                "decision_reason": r.decision_reason,
            }
            for r in results
        ],
        default=str,
    )
    assert secret_raw not in serialized
    assert "secret_DO_NOT_LEAK" not in serialized

    # Length must still be captured.
    target = results[0]
    raw_length_seen = False
    for cr in target.control_results:
        if cr.evidence_data.get("_raw_length") == len(secret_raw):
            raw_length_seen = True
    assert raw_length_seen, "Expected _raw_length to be captured on at least one ControlResult"


def test_source_path_normalized() -> None:
    """Full source paths must be reduced to <parent>/<basename>."""
    full_path = "/very/long/sensitive/path/with/secrets/agent.log"
    importer = SplunkImporter()
    results = importer.parse_string(
        _envelope([_event(severity="low", source=full_path)])
    )
    target = results[0]
    serialized = json.dumps(
        [cr.evidence_data for cr in target.control_results], default=str
    )
    assert "/very/long/sensitive/path/with" not in serialized
    # Helper assertion.
    assert _normalize_source_path(full_path) == "secrets/agent.log"
    seen_normalized = False
    for cr in target.control_results:
        if cr.evidence_data.get("source_normalized") == "secrets/agent.log":
            seen_normalized = True
    assert seen_normalized


def test_ip_redacted() -> None:
    """src_ip / dest_ip must be masked to /16 (IPv4) — never the full address."""
    importer = SplunkImporter()
    results = importer.parse_string(
        _envelope(
            [
                _event(
                    severity="low",
                    src_ip="10.4.5.6",
                    dest_ip="192.168.99.42",
                )
            ]
        )
    )
    target = results[0]
    serialized = json.dumps(
        [cr.evidence_data for cr in target.control_results], default=str
    )
    # Full host bits must not appear.
    assert "10.4.5.6" not in serialized
    assert "192.168.99.42" not in serialized
    # /16 forms should appear.
    assert "10.4.0.0/16" in serialized
    assert "192.168.0.0/16" in serialized
    # Helper-level assertions.
    assert _mask_ip("10.4.5.6") == "10.4.0.0/16"
    assert _mask_ip("192.168.99.42") == "192.168.0.0/16"
    assert _mask_ip("not-an-ip") is None


# ---------------------------------------------------------------------------
# Helper-level sanity checks
# ---------------------------------------------------------------------------

def test_service_account_user_kept_human_user_redacted() -> None:
    assert _is_service_account("agent-svc")
    assert _is_service_account("svc-prod")
    assert not _is_service_account("alice.smith")
    svc = _redact_user("agent-svc")
    assert svc["kind"] == "service_account"
    assert svc["value"] == "agent-svc"
    human = _redact_user("alice.smith")
    assert human["kind"] == "user"
    assert "sha256" in human
    assert human.get("preview") == "alice.smith"


def test_search_id_truncated_to_last_8() -> None:
    long_sid = "scheduler__admin_search_id_RMD12345abcdef"
    assert _truncate_search_id(long_sid) == long_sid[-8:]
    assert _truncate_search_id(None) is None
    assert _truncate_search_id("") is None


def test_envelope_variants_accepted() -> None:
    """Importer accepts {events:[]}, {results:[]}, {data:[]}, JSONL, single event."""
    importer = SplunkImporter()
    e = _event(severity="low", count_distinct_users=1)

    # results envelope.
    r1 = importer.parse_string(json.dumps({"results": [e]}))
    assert len(r1) >= 1

    # data envelope.
    r2 = importer.parse_string(json.dumps({"data": [e]}))
    assert len(r2) >= 1

    # JSONL.
    jsonl_text = json.dumps(e) + "\n" + json.dumps(e)
    r3 = importer.parse_string(jsonl_text)
    assert len(r3) >= 2

    # Single bare event.
    r4 = importer.parse_string(json.dumps(e))
    assert len(r4) >= 1


def test_empty_input_returns_pass_audit_trail() -> None:
    importer = SplunkImporter()
    results = importer.parse_string("")
    assert len(results) == 1
    cr = results[0].control_results[0]
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
