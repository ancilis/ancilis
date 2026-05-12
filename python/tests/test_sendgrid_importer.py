"""Tests for the SendGrid email-activity importer."""

from __future__ import annotations

import json

from ancilis.importers.sendgrid import SendGridImporter


# ---------------------------------------------------------------------------
# Fixtures — inline SendGrid records (no sendgrid package required)
# ---------------------------------------------------------------------------


def _msg(
    *,
    msg_id: str = "msg-0001",
    from_email: str = "agent@example.com",
    to_email: str = "recipient@example.com",
    subject_length: int = 45,
    status: str = "delivered",
    opens_count: int = 0,
    clicks_count: int = 0,
    last_event_time: str = "2026-04-01T12:00:00Z",
    api_key_id: str = "abcd1234EFGH5678ZYXW",
    categories: list[str] | None = None,
    asm_group_id: int | None = 12345,
    events: list[dict] | None = None,
    bounce_classification: str | None = None,
    is_marketing: bool = False,
    consent_basis: str | None = "transactional",
    from_country: str = "US",
    to_country_resolved: str = "US",
) -> dict:
    return {
        "msg_id": msg_id,
        "from_email": from_email,
        "to_email": to_email,
        "subject_length": subject_length,
        "status": status,
        "opens_count": opens_count,
        "clicks_count": clicks_count,
        "last_event_time": last_event_time,
        "api_key_id": api_key_id,
        "categories": categories if categories is not None else ["transactional"],
        "asm_group_id": asm_group_id,
        "events": events
        if events is not None
        else [
            {
                "event": "delivered",
                "timestamp": last_event_time,
                "ip": "167.89.10.20",
                "sg_event_id": "evt-1",
            }
        ],
        "bounce_classification": bounce_classification,
        "is_marketing": is_marketing,
        "consent_basis": consent_basis,
        "from_country": from_country,
        "to_country_resolved": to_country_resolved,
    }


def _findings_for_action(results, action_id: str):
    return [r for r in results if r.action_id == action_id]


def _signals(result):
    return {
        cr.evidence_data.get("signal")
        for cr in result.control_results
    }


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


def test_parse_transactional_delivered() -> None:
    """transactional + delivered → PR-05 PASS audit trail."""
    importer = SendGridImporter()
    rec = _msg(
        msg_id="t-001",
        categories=["transactional"],
        is_marketing=False,
        consent_basis="transactional",
        status="delivered",
    )
    results = importer.parse_string(json.dumps({"messages": [rec]}))
    findings = _findings_for_action(results, "sendgrid-t-001")
    assert len(findings) == 1
    r = findings[0]
    assert r.decision == "ALLOW"
    primary = next(
        cr for cr in r.control_results
        if cr.evidence_data.get("signal") == "transactional_delivered"
    )
    assert primary.control_id == "PR-05"
    assert primary.result == "PASS"


def test_marketing_with_opt_in_passes() -> None:
    """marketing + delivered + consent=marketing_opt_in → PR-04 PASS."""
    importer = SendGridImporter()
    rec = _msg(
        msg_id="m-002",
        categories=["marketing"],
        is_marketing=True,
        consent_basis="marketing_opt_in",
        asm_group_id=42,
        status="delivered",
    )
    results = importer.parse_string(json.dumps({"messages": [rec]}))
    findings = _findings_for_action(results, "sendgrid-m-002")
    assert len(findings) == 1
    primary = next(
        cr for cr in findings[0].control_results
        if cr.evidence_data.get("signal") == "marketing_with_consent"
    )
    assert primary.control_id == "PR-04"
    assert primary.result == "PASS"
    # No CAN-SPAM / no-consent FAILs.
    assert findings[0].decision == "ALLOW"


def test_marketing_no_consent_fails_canspam() -> None:
    """marketing + delivered + consent_basis=null → DE-01 FAIL (CAN-SPAM)."""
    importer = SendGridImporter()
    rec = _msg(
        msg_id="m-003",
        categories=["marketing"],
        is_marketing=True,
        consent_basis=None,
        asm_group_id=42,  # has unsub group → isolate the CAN-SPAM consent FAIL
        status="delivered",
    )
    results = importer.parse_string(json.dumps({"messages": [rec]}))
    findings = _findings_for_action(results, "sendgrid-m-003")
    assert len(findings) == 1
    fr = findings[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "marketing_no_consent_canspam"
    )
    assert primary.control_id == "DE-01"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_marketing_legitimate_interest_flags() -> None:
    """marketing + delivered + consent=marketing_legitimate_interest → PR-04 FLAG."""
    importer = SendGridImporter()
    rec = _msg(
        msg_id="m-004",
        categories=["marketing"],
        is_marketing=True,
        consent_basis="marketing_legitimate_interest",
        asm_group_id=42,
        status="delivered",
    )
    results = importer.parse_string(json.dumps({"messages": [rec]}))
    findings = _findings_for_action(results, "sendgrid-m-004")
    assert len(findings) == 1
    fr = findings[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "marketing_legitimate_interest"
    )
    assert primary.control_id == "PR-04"
    assert primary.result == "FLAG"
    assert fr.decision == "FLAG"


def test_hard_bounce_flags() -> None:
    """status=bounce + classification=Hard Bounce → PR-03 FLAG."""
    importer = SendGridImporter()
    rec = _msg(
        msg_id="b-005",
        status="bounce",
        bounce_classification="Hard Bounce",
        is_marketing=False,
    )
    results = importer.parse_string(json.dumps({"messages": [rec]}))
    findings = _findings_for_action(results, "sendgrid-b-005")
    assert len(findings) == 1
    fr = findings[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "hard_bounce"
    )
    assert primary.control_id == "PR-03"
    assert primary.result == "FLAG"
    assert fr.decision == "FLAG"


def test_reputation_bounce_fails() -> None:
    """status=bounce + classification=Reputation → PR-04 FAIL."""
    importer = SendGridImporter()
    rec = _msg(
        msg_id="b-006",
        status="bounce",
        bounce_classification="Reputation",
        is_marketing=False,
    )
    results = importer.parse_string(json.dumps({"messages": [rec]}))
    findings = _findings_for_action(results, "sendgrid-b-006")
    assert len(findings) == 1
    fr = findings[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "reputation_bounce"
    )
    assert primary.control_id == "PR-04"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_blocked_fails() -> None:
    """status=block → PR-04 FAIL."""
    importer = SendGridImporter()
    rec = _msg(msg_id="bk-007", status="block", is_marketing=False)
    results = importer.parse_string(json.dumps({"messages": [rec]}))
    findings = _findings_for_action(results, "sendgrid-bk-007")
    assert len(findings) == 1
    fr = findings[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "blocked"
    )
    assert primary.control_id == "PR-04"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_spam_report_fails_top_priority() -> None:
    """status=spam_report → DE-01 FAIL (top-priority sender-reputation event)."""
    importer = SendGridImporter()
    rec = _msg(msg_id="sr-008", status="spam_report", is_marketing=False)
    results = importer.parse_string(json.dumps({"messages": [rec]}))
    findings = _findings_for_action(results, "sendgrid-sr-008")
    assert len(findings) == 1
    fr = findings[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "spam_report"
    )
    assert primary.control_id == "DE-01"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_dropped_flags_validation() -> None:
    """status=dropped → PR-02 FLAG (pre-flight drop)."""
    importer = SendGridImporter()
    rec = _msg(msg_id="d-009", status="dropped", is_marketing=False)
    results = importer.parse_string(json.dumps({"messages": [rec]}))
    findings = _findings_for_action(results, "sendgrid-d-009")
    assert len(findings) == 1
    fr = findings[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "dropped"
    )
    assert primary.control_id == "PR-02"
    assert primary.result == "FLAG"
    assert fr.decision == "FLAG"


def test_unsubscribe_audit() -> None:
    """status=unsubscribe → PR-05 PASS audit trail."""
    importer = SendGridImporter()
    rec = _msg(
        msg_id="u-010",
        status="unsubscribe",
        is_marketing=True,
        categories=["marketing"],
        asm_group_id=42,
        consent_basis="marketing_opt_in",
    )
    results = importer.parse_string(json.dumps({"messages": [rec]}))
    findings = _findings_for_action(results, "sendgrid-u-010")
    assert len(findings) == 1
    fr = findings[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "unsubscribe_audit"
    )
    assert primary.control_id == "PR-05"
    assert primary.result == "PASS"


def test_marketing_no_unsubscribe_group_fails_canspam() -> None:
    """marketing + asm_group_id is null → PR-05 FAIL (no opt-out)."""
    importer = SendGridImporter()
    rec = _msg(
        msg_id="m-011",
        categories=["marketing"],
        is_marketing=True,
        consent_basis="marketing_opt_in",
        asm_group_id=None,
        status="delivered",
    )
    results = importer.parse_string(json.dumps({"messages": [rec]}))
    findings = _findings_for_action(results, "sendgrid-m-011")
    assert len(findings) == 1
    fr = findings[0]
    canspam = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "marketing_no_unsubscribe_group"
    )
    assert canspam.control_id == "PR-05"
    assert canspam.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_cross_border_marketing_no_consent_flags() -> None:
    """is_marketing + cross-country + consent=null → PR-04 FLAG (GDPR)."""
    importer = SendGridImporter()
    rec = _msg(
        msg_id="m-012",
        categories=["marketing"],
        is_marketing=True,
        consent_basis=None,
        asm_group_id=42,
        from_country="US",
        to_country_resolved="DE",
        status="delivered",
    )
    results = importer.parse_string(json.dumps({"messages": [rec]}))
    findings = _findings_for_action(results, "sendgrid-m-012")
    assert len(findings) == 1
    fr = findings[0]
    signals = _signals(fr)
    # Both the CAN-SPAM consent FAIL *and* the cross-border FLAG should fire.
    assert "marketing_no_consent_canspam" in signals
    assert "cross_border_marketing_no_consent" in signals
    cb = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "cross_border_marketing_no_consent"
    )
    assert cb.control_id == "PR-04"
    assert cb.result == "FLAG"


def test_volume_velocity_synthetic() -> None:
    """>N records to same to_email → synthetic PR-04 FLAG."""
    importer = SendGridImporter(volume_velocity=2)
    msgs = [
        _msg(msg_id=f"v-{i:03d}", to_email="bulk@example.com")
        for i in range(4)
    ]
    results = importer.parse_string(json.dumps({"messages": msgs}))
    synthetic = [
        r for r in results
        if r.action_id.startswith("sendgrid-velocity-")
    ]
    assert len(synthetic) == 1
    fr = synthetic[0]
    cr = fr.control_results[0]
    assert cr.evidence_data.get("signal") == "volume_velocity"
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert fr.decision == "FLAG"
    assert cr.evidence_data["velocity_count"] == 4
    assert cr.evidence_data["velocity_threshold"] == 2


def test_high_bounce_rate_synthetic() -> None:
    """>threshold bounce-rate per api_key → synthetic PR-04 FLAG."""
    # Threshold 0.10; 2 of 4 = 0.50 > 0.10 → fire.
    importer = SendGridImporter(bounce_rate_threshold=0.10)
    api_key = "AKEYZ1234567890XYZ12"
    msgs = [
        _msg(msg_id="hb-1", api_key_id=api_key, status="delivered"),
        _msg(msg_id="hb-2", api_key_id=api_key, status="delivered"),
        _msg(
            msg_id="hb-3",
            api_key_id=api_key,
            status="bounce",
            bounce_classification="Hard Bounce",
        ),
        _msg(
            msg_id="hb-4",
            api_key_id=api_key,
            status="bounce",
            bounce_classification="Hard Bounce",
        ),
    ]
    results = importer.parse_string(json.dumps({"messages": msgs}))
    synthetic = [
        r for r in results
        if r.action_id.startswith("sendgrid-bounce-rate-")
    ]
    assert len(synthetic) == 1
    fr = synthetic[0]
    cr = fr.control_results[0]
    assert cr.evidence_data.get("signal") == "high_bounce_rate"
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["bounces"] == 2
    assert cr.evidence_data["messages"] == 4
    assert abs(cr.evidence_data["bounce_rate"] - 0.5) < 1e-9


def test_email_addresses_only_domain_stored() -> None:
    """from_email / to_email full local-parts must NEVER appear in any evidence."""
    importer = SendGridImporter()
    rec = _msg(
        msg_id="san-013",
        from_email="alice@corp.example.com",
        to_email="bob@partner.example.com",
    )
    results = importer.parse_string(json.dumps({"messages": [rec]}))
    serialized = json.dumps(
        [
            {
                "decision_reason": r.decision_reason,
                "control_results": [cr.evidence_data for cr in r.control_results],
            }
            for r in results
        ]
    )
    # Local-parts must not appear anywhere.
    assert "alice@" not in serialized
    assert "bob@" not in serialized
    assert "alice" not in serialized
    assert "bob" not in serialized
    # Domain-only forms should appear.
    assert "@corp.example.com" in serialized
    assert "@partner.example.com" in serialized
    # Per-record evidence has from_domain / to_domain set correctly.
    fr = _findings_for_action(results, "sendgrid-san-013")[0]
    primary_evidence = fr.control_results[0].evidence_data
    assert primary_evidence["from_domain"] == "@corp.example.com"
    assert primary_evidence["to_domain"] == "@partner.example.com"


def test_subject_text_never_stored() -> None:
    """subject text must NEVER survive — only subject_length is captured."""
    importer = SendGridImporter()
    leaked_subject = "VERY-SECRET-OTP-CODE-9921-DO-NOT-LOG"
    rec = _msg(msg_id="san-014")
    # SendGrid /v3/messages doesn't ship subject text, but a malformed export
    # with a stray "subject" field must still not leak.
    rec["subject"] = leaked_subject
    rec["subject_length"] = len(leaked_subject)
    results = importer.parse_string(json.dumps({"messages": [rec]}))
    serialized = json.dumps(
        [
            {
                "decision_reason": r.decision_reason,
                "control_results": [cr.evidence_data for cr in r.control_results],
            }
            for r in results
        ]
    )
    assert leaked_subject not in serialized
    assert "VERY-SECRET" not in serialized
    fr = _findings_for_action(results, "sendgrid-san-014")[0]
    primary_evidence = fr.control_results[0].evidence_data
    assert primary_evidence["subject_length"] == len(leaked_subject)
    assert "subject" not in primary_evidence  # no raw subject key in evidence
