"""Tests for the Mixpanel analytics importer."""

from __future__ import annotations

import json

from ancilis.importers.mixpanel import MixpanelImporter


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _event(
    *,
    event: str = "agent_response_sent",
    time: int = 1730000000,
    distinct_id: str = "user-distinct-1234567890abcdef",
    insert_id: str = "ins-abc",
    properties: dict | None = None,
) -> dict:
    base_props = {
        "$user_id": "user-stable-1234567890abcdef",
        "$device_id": "dev-9999999999",
        "mp_lib": "python",
        "mp_processing_time_ms": 12,
        "event_property_count": 5,
        "property_keys": ["$user_id", "amount", "currency", "$device_id", "agent_id"],
        "contains_sensitive_pattern": False,
        "sensitive_patterns_matched": [],
        "agent_id": "agent-1",
        "is_imported": False,
        "server_geo": "US",
        "tracking_consent_recorded": True,
        "data_residency_region": "US",
    }
    if properties:
        base_props.update(properties)
    return {
        "event": event,
        "time": time,
        "distinct_id": distinct_id,
        "insert_id": insert_id,
        "properties": base_props,
    }


def _audit(
    *,
    action: str,
    timestamp: str = "2026-04-01T12:00:00Z",
    actor: dict | None = None,
    details: dict | None = None,
) -> dict:
    return {
        "action": action,
        "timestamp": timestamp,
        "actor": actor or {
            "user_id": "user-actor-1",
            "email": "agent@example.com",
            "is_service_account": True,
        },
        "details": details or {},
    }


def _findings_for_signal(results: list, signal: str) -> list:
    """Return ControlResults across all EvaluationResults whose signal matches."""
    out = []
    for r in results:
        for cr in r.control_results:
            if cr.evidence_data.get("signal") == signal:
                out.append((r, cr))
    return out


# ---------------------------------------------------------------------------
# Sensitive-pattern matches
# ---------------------------------------------------------------------------


def test_ssn_pattern_fails_block() -> None:
    """ssn_like_pattern in sensitive_patterns_matched → PR-04 FAIL → BLOCK."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="agent_response_sent",
                    insert_id="ssn-event-1",
                    properties={
                        "contains_sensitive_pattern": True,
                        "sensitive_patterns_matched": ["ssn_like_pattern"],
                    },
                )
            ]
        }
    )
    [result] = MixpanelImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    ssn = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "sensitive_pattern_ssn"
    ]
    assert len(ssn) == 1
    assert ssn[0].control_id == "PR-04"
    assert ssn[0].result == "FAIL"


def test_credit_card_pattern_fails_block() -> None:
    """credit_card_like_pattern → PR-04 FAIL → BLOCK."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="purchase_completed",
                    insert_id="cc-event-1",
                    properties={
                        "contains_sensitive_pattern": True,
                        "sensitive_patterns_matched": ["credit_card_like_pattern"],
                    },
                )
            ]
        }
    )
    [result] = MixpanelImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cc = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "sensitive_pattern_credit_card"
    ]
    assert len(cc) == 1
    assert cc[0].control_id == "PR-04"
    assert cc[0].result == "FAIL"


def test_email_pattern_flags() -> None:
    """email kind → PR-04 FLAG (not BLOCK)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="agent_response_sent",
                    insert_id="em-event-1",
                    properties={
                        "contains_sensitive_pattern": True,
                        "sensitive_patterns_matched": ["email"],
                    },
                )
            ]
        }
    )
    [result] = MixpanelImporter().parse_string(doc)
    assert result.decision == "FLAG"
    em = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "sensitive_pattern_email"
    ]
    assert len(em) == 1
    assert em[0].control_id == "PR-04"
    assert em[0].result == "FLAG"


# ---------------------------------------------------------------------------
# Identity / people / over-tracking / cross-region
# ---------------------------------------------------------------------------


def test_identify_flags_cross_session() -> None:
    """$identify with stable id → PR-04 FLAG (cross-session linking)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$identify",
                    insert_id="id-1",
                    properties={"$user_id": "u-stable-abc-12345678"},
                )
            ]
        }
    )
    [result] = MixpanelImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "identity_linking"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FLAG"
    assert result.decision == "FLAG"


def test_people_set_sensitive_fails() -> None:
    """$people_set with sensitive property keys → PR-04 FAIL."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$people_set",
                    insert_id="ps-1",
                    properties={
                        "property_keys": [
                            "$user_id",
                            "ssn",
                            "credit_card",
                            "first_name",
                        ],
                        "event_property_count": 4,
                    },
                )
            ]
        }
    )
    [result] = MixpanelImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "people_set_sensitive_property"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FAIL"
    assert "ssn" in findings[0].evidence_data["sensitive_property_keys"]
    assert "credit_card" in findings[0].evidence_data["sensitive_property_keys"]
    assert result.decision == "BLOCK"


def test_over_tracking_flags() -> None:
    """event_property_count > threshold → PR-04 FLAG over_tracking."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="page_viewed",
                    insert_id="ot-1",
                    properties={
                        "event_property_count": 50,
                        "property_keys": [f"k{i}" for i in range(50)],
                    },
                )
            ]
        }
    )
    [result] = MixpanelImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "over_tracking"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FLAG"


def test_cross_region_tracking_flags() -> None:
    """data_residency_region != server_geo → PR-04 FLAG cross_region_tracking."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="page_viewed",
                    insert_id="cr-1",
                    properties={
                        "server_geo": "US",
                        "data_residency_region": "EU",
                        "tracking_consent_recorded": True,
                    },
                )
            ]
        }
    )
    [result] = MixpanelImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "cross_region_tracking"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FLAG"


def test_eu_no_consent_fails() -> None:
    """EU residency + tracking_consent_recorded=false → PR-04 FAIL → BLOCK."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="page_viewed",
                    insert_id="eu-1",
                    properties={
                        "server_geo": "EU",
                        "data_residency_region": "DE",
                        "tracking_consent_recorded": False,
                    },
                )
            ]
        }
    )
    [result] = MixpanelImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "eu_no_consent"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FAIL"
    assert result.decision == "BLOCK"


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def test_data_residency_changed_fails() -> None:
    """Audit data_residency_changed → PR-04 FAIL → BLOCK."""
    doc = json.dumps(
        {
            "audit_log": [
                _audit(
                    action="data_residency_changed",
                    details={
                        "previous_value": "US",
                        "new_value": "EU",
                        "target_project_id": "proj-1",
                    },
                )
            ]
        }
    )
    [result] = MixpanelImporter().parse_string(doc)
    assert result.source_type == "mixpanel_import"
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "audit_data_residency_changed"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FAIL"
    assert result.decision == "BLOCK"


def test_gdpr_deletion_passes() -> None:
    """Audit gdpr_deletion_request → PR-05 PASS."""
    doc = json.dumps(
        {
            "audit_log": [
                _audit(
                    action="gdpr_deletion_request",
                    details={"target_project_id": "proj-1"},
                )
            ]
        }
    )
    [result] = MixpanelImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "audit_gdpr_deletion_request"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-05"
    assert findings[0].result == "PASS"
    assert result.decision == "ALLOW"


def test_webhook_external_flags() -> None:
    """webhook_url_added with non-allowlisted host → PR-04 FLAG."""
    doc = json.dumps(
        {
            "audit_log": [
                _audit(
                    action="webhook_url_added",
                    details={"webhook_url": "https://exfil.attacker.example.com/hook"},
                )
            ]
        }
    )
    [result] = MixpanelImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "audit_webhook_url_added"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FLAG"
    # Webhook URL host stored, not full URL.
    assert findings[0].evidence_data["webhook_url_host"] == (
        "https://exfil.attacker.example.com"
    )


# ---------------------------------------------------------------------------
# Synthetic findings
# ---------------------------------------------------------------------------


def test_high_volume_sensitive_synthetic() -> None:
    """> N sensitive events for same agent in 1h window → synthetic PR-04 FAIL."""
    events = []
    base_time = 1730000000
    # Use a low threshold via importer arg so the test stays fast.
    for i in range(5):
        events.append(
            _event(
                event="agent_response_sent",
                insert_id=f"hv-{i}",
                time=base_time + i * 60,
                properties={
                    "contains_sensitive_pattern": True,
                    "sensitive_patterns_matched": ["email"],
                },
            )
        )
    doc = json.dumps({"events": events})
    results = MixpanelImporter(high_volume_threshold=3).parse_string(doc)
    synthetic = [
        r
        for r in results
        if r.action_id.startswith("mixpanel-high-volume-")
    ]
    assert len(synthetic) == 1
    assert synthetic[0].decision == "BLOCK"
    cr = synthetic[0].control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert cr.evidence_data["burst_count"] == 5
    assert cr.evidence_data["high_volume_threshold"] == 3


def test_pii_concentration_synthetic() -> None:
    """ratio of sensitive/total > threshold → synthetic PR-04 FAIL."""
    events = []
    base_time = 1730000000
    # 4 sensitive out of 10 total = 40% concentration.
    for i in range(4):
        events.append(
            _event(
                event="agent_response_sent",
                insert_id=f"sens-{i}",
                time=base_time + i * 1000,
                properties={
                    "contains_sensitive_pattern": True,
                    "sensitive_patterns_matched": ["email"],
                },
            )
        )
    for i in range(6):
        events.append(
            _event(
                event="page_viewed",
                insert_id=f"pv-{i}",
                time=base_time + (4 + i) * 1000,
                properties={"contains_sensitive_pattern": False},
            )
        )
    doc = json.dumps({"events": events})
    # high_volume_threshold high so it doesn't trigger; we want pii_concentration only.
    results = MixpanelImporter(
        high_volume_threshold=1000,
        pii_concentration_threshold=0.10,
    ).parse_string(doc)
    synthetic = [
        r
        for r in results
        if r.action_id.startswith("mixpanel-pii-concentration-")
    ]
    assert len(synthetic) == 1
    cr = synthetic[0].control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert cr.evidence_data["sensitive_count"] == 4
    assert cr.evidence_data["total_count"] == 10
    assert cr.evidence_data["ratio"] == 0.4


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def test_property_values_not_stored() -> None:
    """Raw values for distinct_id, $user_id, $device_id, $ip, email, ssn never stored."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="agent_response_sent",
                    distinct_id="user-distinct-VERY-SECRET-VALUE",
                    insert_id="san-1",
                    properties={
                        "$user_id": "user-stable-PRIVATE-1234567",
                        "$device_id": "device-PRIVATE-9876543",
                        "$ip": "203.0.113.42",
                        "email": "alice@example.com",
                        "ssn": "123-45-6789",
                        "credit_card": "4111-1111-1111-1111",
                        "first_name": "Alice",
                        "property_keys": [
                            "$user_id",
                            "$device_id",
                            "$ip",
                            "email",
                            "ssn",
                            "credit_card",
                            "first_name",
                        ],
                        "event_property_count": 7,
                        "contains_sensitive_pattern": True,
                        "sensitive_patterns_matched": [
                            "ssn_like_pattern",
                            "credit_card_like_pattern",
                            "email",
                        ],
                    },
                )
            ]
        }
    )
    [result] = MixpanelImporter().parse_string(doc)
    # Walk every control result's evidence and ensure no raw secrets leak.
    forbidden = [
        "VERY-SECRET-VALUE",
        "PRIVATE-1234567",
        "PRIVATE-9876543",
        "203.0.113.42",
        "alice@example.com",
        "123-45-6789",
        "4111-1111-1111-1111",
        "Alice",
    ]
    for cr in result.control_results:
        encoded = json.dumps(cr.evidence_data, default=str)
        for token in forbidden:
            assert token not in encoded, (
                f"Forbidden token {token!r} leaked into evidence_data: {encoded}"
            )
        # Ensure suffix-only identifiers are stored (last 8 chars).
        assert cr.evidence_data["distinct_id_suffix"] == "ET-VALUE"
        assert cr.evidence_data["user_id_suffix"] == "-1234567"
        assert cr.evidence_data["device_id_suffix"] == "-9876543"
        # IP masked to /16.
        assert cr.evidence_data["ip_masked"] == "203.0.0.0/16"
        # property_keys retained but values are not.
        assert "ssn" in cr.evidence_data["property_keys"]
        assert "email" in cr.evidence_data["property_keys"]


# ---------------------------------------------------------------------------
# Mixed events + audit dispatch
# ---------------------------------------------------------------------------


def test_mixed_events_and_audit_dispatch() -> None:
    """`{"data": [...]}` with mixed event/audit records dispatches correctly."""
    doc = json.dumps(
        {
            "data": [
                _event(event="page_viewed", insert_id="m-evt-1"),
                _audit(
                    action="api_key_created",
                    actor={
                        "user_id": "u-human-1",
                        "email": "human@example.com",
                        "is_service_account": False,
                    },
                ),
                _event(
                    event="agent_response_sent",
                    insert_id="m-evt-2",
                    properties={
                        "contains_sensitive_pattern": True,
                        "sensitive_patterns_matched": ["ssn_like_pattern"],
                    },
                ),
                _audit(
                    action="gdpr_deletion_request",
                    timestamp="2026-04-01T13:00:00Z",
                ),
            ]
        }
    )
    results = MixpanelImporter().parse_string(doc)
    # Expect at least 4 base results — mapped events get one EvaluationResult each.
    event_results = [
        r for r in results if r.action_id.startswith("mixpanel-event-")
    ]
    audit_results = [
        r for r in results if r.action_id.startswith("mixpanel-audit-")
    ]
    assert len(event_results) == 2
    assert len(audit_results) == 2

    # Verify dispatch correctness: SSN event blocks, GDPR audit passes.
    ssn_event = next(
        r for r in event_results if r.action_id == "mixpanel-event-m-evt-2"
    )
    assert ssn_event.decision == "BLOCK"

    gdpr_audit = next(
        r
        for r in audit_results
        if any(
            cr.evidence_data.get("signal") == "audit_gdpr_deletion_request"
            for cr in r.control_results
        )
    )
    assert gdpr_audit.decision == "ALLOW"

    # api_key_created by a human → PR-01 FLAG.
    api_key_audit = next(
        r
        for r in audit_results
        if any(
            cr.evidence_data.get("signal") == "audit_api_key_created_human"
            for cr in r.control_results
        )
    )
    assert api_key_audit.decision == "FLAG"
    api_cr = next(
        cr
        for cr in api_key_audit.control_results
        if cr.evidence_data.get("signal") == "audit_api_key_created_human"
    )
    assert api_cr.control_id == "PR-01"
    # email domain captured but raw email not.
    assert api_cr.evidence_data["actor_email_domain"] == "example.com"
    encoded = json.dumps(api_cr.evidence_data, default=str)
    assert "human@example.com" not in encoded
