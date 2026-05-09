"""Tests for the Twilio call/SMS audit-log importer."""

from __future__ import annotations

import json

from ancilis.importers.twilio import TwilioImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Twilio records (no twilio package required)
# ---------------------------------------------------------------------------


def _call(
    *,
    sid: str = "CA1234567890abcdef1234567890ABCD",
    account_sid: str = "AC0000000000000000000000000000ABCD",
    direction: str = "outbound-api",
    status: str = "completed",
    duration: int | str = 60,
    to: str = "+15551234567",
    from_: str = "+15559876543",
    country_code_to: str = "US",
    country_code_from: str = "US",
    answered_by: str | None = None,
    start_time: str = "2026-04-01T12:00:00Z",
    end_time: str = "2026-04-01T12:01:00Z",
    price: str = "-0.0085",
    caller_name: str | None = "John Smith",
) -> dict:
    return {
        "sid": sid,
        "account_sid": account_sid,
        "direction": direction,
        "status": status,
        "duration": str(duration),
        "to": to,
        "from": from_,
        "country_code_to": country_code_to,
        "country_code_from": country_code_from,
        "answered_by": answered_by,
        "start_time": start_time,
        "end_time": end_time,
        "price": price,
        "price_unit": "USD",
        "caller_name": caller_name,
    }


def _msg(
    *,
    sid: str = "SMabcdef1234567890abcdef1234567XYZ4",
    account_sid: str = "AC0000000000000000000000000000ABCD",
    direction: str = "outbound-api",
    status: str = "delivered",
    to: str = "+15551234567",
    from_: str = "+15559876543",
    country_code_to: str = "US",
    country_code_from: str = "US",
    num_segments: str = "1",
    num_media: str = "0",
    body_length: int = 80,
    is_marketing: bool = False,
    error_code: int | None = None,
    date_sent: str = "2026-04-01T12:00:00Z",
    price: str = "-0.0079",
) -> dict:
    return {
        "sid": sid,
        "account_sid": account_sid,
        "direction": direction,
        "status": status,
        "to": to,
        "from": from_,
        "country_code_to": country_code_to,
        "country_code_from": country_code_from,
        "num_segments": num_segments,
        "num_media": num_media,
        "body_length": body_length,
        "is_marketing": is_marketing,
        "error_code": error_code,
        "date_sent": date_sent,
        "price": price,
        "price_unit": "USD",
        "messaging_service_sid": "MGdeadbeefdeadbeefdeadbeefdeadbeef",
    }


def _findings_for_action(results, action_id: str):
    return [r for r in results if r.action_id == action_id]


# ---------------------------------------------------------------------------
# Calls
# ---------------------------------------------------------------------------


def test_parse_outbound_call() -> None:
    """outbound-api + completed → PR-04 FLAG (TCPA-relevant)."""
    doc = json.dumps({"calls": [_call()]})
    results = TwilioImporter().parse_string(doc)
    assert len(results) == 1
    res = results[0]
    assert res.decision == "FLAG"
    signals = {cr.evidence_data.get("signal") for cr in res.control_results}
    assert "outbound_call_tcpa" in signals
    cr = next(c for c in res.control_results if c.evidence_data.get("signal") == "outbound_call_tcpa")
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"


def test_inbound_call_audit() -> None:
    """direction=inbound + completed → PR-05 PASS, ALLOW decision."""
    doc = json.dumps({"calls": [_call(direction="inbound", status="completed")]})
    results = TwilioImporter().parse_string(doc)
    assert len(results) == 1
    res = results[0]
    assert res.decision == "ALLOW"
    cr = next(c for c in res.control_results if c.evidence_data.get("signal") == "inbound_call_audit")
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"


def test_call_failed_marks_fail() -> None:
    """status=failed → DE-01 FAIL, BLOCK decision."""
    doc = json.dumps({"calls": [_call(status="failed", duration=0)]})
    results = TwilioImporter().parse_string(doc)
    assert len(results) == 1
    res = results[0]
    assert res.decision == "BLOCK"
    cr = next(c for c in res.control_results if c.evidence_data.get("signal") == "call_failed")
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


def test_machine_answered_captured() -> None:
    """answered_by=machine_* → captured (TCPA differential treatment)."""
    doc = json.dumps({"calls": [_call(answered_by="machine_end_beep")]})
    results = TwilioImporter().parse_string(doc)
    res = results[0]
    machine_findings = [
        cr for cr in res.control_results
        if cr.evidence_data.get("signal") == "machine_answered"
    ]
    assert len(machine_findings) == 1
    assert machine_findings[0].result == "PASS"
    assert machine_findings[0].evidence_data["answered_by"] == "machine_end_beep"


def test_long_call_flags_recording_consent() -> None:
    """duration > long_call_threshold (1800s default) → PR-04 FLAG."""
    doc = json.dumps({"calls": [_call(duration=2400)]})  # 40 min
    results = TwilioImporter().parse_string(doc)
    res = results[0]
    long_findings = [
        cr for cr in res.control_results
        if cr.evidence_data.get("signal") == "long_call"
    ]
    assert len(long_findings) == 1
    cr = long_findings[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["duration_s"] == 2400
    assert cr.evidence_data["long_call_threshold_s"] == 1800


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


def test_outbound_marketing_sms_fails_tcpa() -> None:
    """is_marketing=true + delivered + outbound-api → PR-04 FAIL (TCPA violation)."""
    doc = json.dumps({"messages": [_msg(is_marketing=True)]})
    results = TwilioImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "BLOCK"
    cr = next(
        c for c in res.control_results
        if c.evidence_data.get("signal") == "marketing_sms_no_consent"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


def test_carrier_filtering_30007_fails() -> None:
    """status=undelivered + error_code=30007 → PR-04 FAIL (carrier spam-filter)."""
    doc = json.dumps({
        "messages": [_msg(status="undelivered", error_code=30007)]
    })
    results = TwilioImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "BLOCK"
    cr = next(
        c for c in res.control_results
        if c.evidence_data.get("signal") == "carrier_filtering_spam"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert cr.evidence_data["error_code"] == 30007


def test_invalid_number_30003_flags_validation() -> None:
    """status=undelivered + error_code=30003 → PR-03 FLAG (input validation)."""
    doc = json.dumps({
        "messages": [_msg(status="undelivered", error_code=30003)]
    })
    results = TwilioImporter().parse_string(doc)
    res = results[0]
    cr = next(
        c for c in res.control_results
        if c.evidence_data.get("signal") == "invalid_number"
    )
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert res.decision == "FLAG"


def test_mms_with_media_flags() -> None:
    """num_media > 0 → PR-04 FLAG (content surface)."""
    doc = json.dumps({"messages": [_msg(num_media="2")]})
    results = TwilioImporter().parse_string(doc)
    res = results[0]
    mms_findings = [
        cr for cr in res.control_results
        if cr.evidence_data.get("signal") == "mms_with_media"
    ]
    assert len(mms_findings) == 1
    assert mms_findings[0].control_id == "PR-04"
    assert mms_findings[0].result == "FLAG"
    assert mms_findings[0].evidence_data["num_media"] == 2


def test_sms_pumping_country_flags() -> None:
    """country_code_to in pumping list → PR-02 FLAG."""
    doc = json.dumps({
        "messages": [_msg(country_code_to="BR", to="+5511987654321")]
    })
    results = TwilioImporter().parse_string(doc)
    res = results[0]
    pumping_findings = [
        cr for cr in res.control_results
        if cr.evidence_data.get("signal") == "sms_pumping_country"
    ]
    assert len(pumping_findings) == 1
    cr = pumping_findings[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert "BR" in cr.evidence_data["sms_pumping_countries"]


# ---------------------------------------------------------------------------
# Synthetic patterns
# ---------------------------------------------------------------------------


def test_velocity_pattern_synthetic() -> None:
    """> N records to same destination → synthetic PR-02 FLAG."""
    # Threshold default is 5; emit 7 records to the same destination.
    same_dest = "+15551234567"
    msgs = [
        _msg(
            sid=f"SM{i:032x}",
            to=same_dest,
            country_code_to="US",
        )
        for i in range(7)
    ]
    doc = json.dumps({"messages": msgs})
    results = TwilioImporter().parse_string(doc)
    # Expect 7 per-message results + 1 synthetic velocity.
    synthetic = [
        r for r in results
        if r.action_id.startswith("twilio-velocity-")
    ]
    assert len(synthetic) == 1
    sr = synthetic[0]
    assert sr.decision == "FLAG"
    cr = sr.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.evidence_data["velocity_count"] == 7
    assert cr.evidence_data["velocity_threshold"] == 5
    # The masked destination should NOT contain the raw E.164 number.
    assert same_dest not in cr.evidence_data["to_masked"]
    assert cr.evidence_data["to_masked"].startswith("+US")


def test_cross_country_pattern_synthetic() -> None:
    """One account_sid spanning > N country codes → synthetic PR-04 FLAG."""
    countries = ["US", "GB", "DE", "FR", "IT", "ES", "JP", "AU", "CA", "MX", "NZ"]
    # 11 distinct countries > default threshold of 10.
    msgs = [
        _msg(
            sid=f"SM{i:032x}",
            to=f"+{i}5551234567",
            country_code_to=cc,
            country_code_from="US",
        )
        for i, cc in enumerate(countries)
    ]
    doc = json.dumps({"messages": msgs})
    results = TwilioImporter().parse_string(doc)
    synthetic = [
        r for r in results
        if r.action_id.startswith("twilio-cross-country-")
    ]
    assert len(synthetic) == 1
    sr = synthetic[0]
    cr = sr.control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.evidence_data["cross_country_count"] == 11
    assert cr.evidence_data["cross_country_threshold"] == 10
    assert sorted(cr.evidence_data["cross_country_codes"]) == sorted(countries)


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def test_phone_numbers_redacted_to_country_plus_last2() -> None:
    """Raw E.164 phone numbers must NEVER appear in evidence; only +<cc>•••••XX."""
    raw_to = "+15551234599"
    raw_from = "+447700900123"
    doc = json.dumps({
        "calls": [
            _call(to=raw_to, from_=raw_from, country_code_to="US", country_code_from="GB")
        ]
    })
    importer = TwilioImporter()
    results = importer.parse_string(doc)
    # Walk the entire result graph and assert raw numbers do not appear anywhere.
    serialized = json.dumps(
        [
            {
                "decision_reason": r.decision_reason,
                "control_results": [
                    {"detail": cr.detail, "evidence_data": cr.evidence_data}
                    for cr in r.control_results
                ],
            }
            for r in results
        ],
        default=str,
    )
    assert raw_to not in serialized
    assert raw_from not in serialized
    # Masked form should be present.
    cr = results[0].control_results[0]
    assert cr.evidence_data["to_masked"] == "+US•••••99"
    assert cr.evidence_data["from_masked"] == "+GB•••••23"
    assert cr.evidence_data["country_code_to"] == "US"
    assert cr.evidence_data["country_code_from"] == "GB"


def test_caller_name_never_stored() -> None:
    """caller_name (CNAM lookup) must be dropped — even partial CNAM is PII."""
    cnam = "JOHN SMITH JR"
    doc = json.dumps({"calls": [_call(caller_name=cnam)]})
    results = TwilioImporter().parse_string(doc)
    serialized = json.dumps(
        [
            {
                "decision_reason": r.decision_reason,
                "control_results": [
                    {"detail": cr.detail, "evidence_data": cr.evidence_data}
                    for cr in r.control_results
                ],
            }
            for r in results
        ],
        default=str,
    )
    assert cnam not in serialized
    assert "caller_name" not in serialized
    # Sanity: lower-case CNAM components should also be absent.
    assert "JOHN" not in serialized
    assert "Smith" not in serialized.lower().replace("smithy", "")


# ---------------------------------------------------------------------------
# Mixed dispatch
# ---------------------------------------------------------------------------


def test_mixed_calls_messages_dispatch_by_sid_prefix() -> None:
    """A single {"data": [...]} envelope mixing CA*/SM*/MM*/AU* records dispatches by SID prefix."""
    records = [
        _call(sid="CA" + "1" * 32),
        _msg(sid="SM" + "2" * 32),
        # MMS record (MM prefix, num_media>0)
        {**_msg(sid="MM" + "3" * 32, num_media="1"), "sid": "MM" + "3" * 32},
        # Audit-log record
        {
            "sid": "AU" + "4" * 32,
            "account_sid": "AC" + "0" * 32,
            "event_type": "user.created",
            "actor_sid": "US" + "9" * 32,
            "event_date": "2026-04-01T12:00:00Z",
        },
    ]
    doc = json.dumps({"data": records})
    results = TwilioImporter().parse_string(doc)
    # 4 records, no synthetic findings (all distinct destinations, single country).
    assert len(results) == 4
    kinds = sorted(
        cr.evidence_data.get("twilio_record_kind")
        for r in results
        for cr in r.control_results
        if cr.evidence_data.get("twilio_record_kind")
        in {"call", "message", "audit"}
    )
    # Each result has at least one cr with a kind tag — message records may
    # produce multiple control_results (status + mms_with_media), but kinds should cover all 3.
    distinct = set(kinds)
    assert "call" in distinct
    assert "message" in distinct
    assert "audit" in distinct
    # Audit record produces a single PR-05 PASS.
    audit_results = [
        r for r in results
        if any(cr.evidence_data.get("twilio_record_kind") == "audit" for cr in r.control_results)
    ]
    assert len(audit_results) == 1
    audit_cr = audit_results[0].control_results[0]
    assert audit_cr.control_id == "PR-05"
    assert audit_cr.result == "PASS"
    assert audit_results[0].decision == "ALLOW"


# ---------------------------------------------------------------------------
# Provenance + format support
# ---------------------------------------------------------------------------


def test_jsonl_format_supported() -> None:
    """JSONL input (one record per line) parses correctly."""
    lines = [
        json.dumps(_call(sid="CA" + "a" * 32)),
        json.dumps(_msg(sid="SM" + "b" * 32)),
    ]
    results = TwilioImporter().parse_string("\n".join(lines))
    assert len(results) == 2
