"""Tests for the PostHog analytics importer."""

from __future__ import annotations

import json

from ancilis.importers.posthog import PostHogImporter


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _event(
    *,
    event: str = "agent_action",
    timestamp: str = "2026-04-01T12:00:00Z",
    distinct_id: str = "user-distinct-1234567890abcdef",
    event_id: str = "evt-abc",
    properties: dict | None = None,
) -> dict:
    base_props = {
        "$lib": "posthog-python",
        "$lib_version": "3.5.0",
        "$ip": "10.0.0.1",
        "$current_url_host": "app.example.com",
        "$session_id": "sess-9999999999",
        "$user_id": "user-stable-1234567890abcdef",
        "ai_provider": None,
        "ai_model": None,
        "$ai_input_tokens": 0,
        "$ai_output_tokens": 0,
        "$ai_total_cost_usd": 0.0,
        "$exception_message_length": 0,
        "$exception_type": None,
        "event_property_keys": ["$user_id", "$session_id", "amount", "currency"],
        "contains_sensitive_pattern": False,
        "sensitive_patterns_matched": [],
        "agent_id": "agent-1",
        "tracking_consent_recorded": True,
        "data_residency_region": "US",
        "is_sample_event": False,
    }
    if properties:
        base_props.update(properties)
    return {
        "id": event_id,
        "timestamp": timestamp,
        "event": event,
        "distinct_id": distinct_id,
        "properties": base_props,
    }


def _audit(
    *,
    activity: str,
    scope: str,
    created_at: str = "2026-04-01T12:00:00Z",
    actor_id: str = "actor-1",
    actor_email: str = "agent@example.com",
    is_system_actor: bool = False,
    detail: dict | None = None,
) -> dict:
    return {
        "id": f"audit-{activity}-{scope}",
        "created_at": created_at,
        "activity": activity,
        "scope": scope,
        "actor_id": actor_id,
        "actor_email": actor_email,
        "is_system_actor": is_system_actor,
        "detail": detail or {},
    }


# ---------------------------------------------------------------------------
# Sensitive-pattern matches
# ---------------------------------------------------------------------------


def test_ssn_pattern_fails_block() -> None:
    """sensitive_patterns_matched contains ssn_like → PR-04 FAIL → BLOCK."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="agent_action",
                    event_id="ssn-event-1",
                    properties={
                        "contains_sensitive_pattern": True,
                        "sensitive_patterns_matched": ["ssn_like"],
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
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
    """sensitive_patterns_matched contains credit_card_like → PR-04 FAIL → BLOCK."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="purchase_completed",
                    event_id="cc-event-1",
                    properties={
                        "contains_sensitive_pattern": True,
                        "sensitive_patterns_matched": ["credit_card_like"],
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
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
                    event="agent_action",
                    event_id="em-event-1",
                    properties={
                        "contains_sensitive_pattern": True,
                        "sensitive_patterns_matched": ["email"],
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
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
# Identity / exception / AI / feature flag / over-tracking / consent / sample
# ---------------------------------------------------------------------------


def test_identify_flags_cross_session() -> None:
    """$identify with non-anonymous distinct_id → PR-04 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$identify",
                    event_id="id-1",
                    distinct_id="user-stable-abc-12345678",
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "identity_linking"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FLAG"
    assert result.decision == "FLAG"


def test_identify_anonymous_distinct_id_does_not_flag() -> None:
    """Anonymous distinct_id should NOT trigger identity linking flag."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$identify",
                    event_id="id-anon",
                    distinct_id="anonymous-abc-12345678",
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "identity_linking"
    ]
    assert len(findings) == 0


def test_exception_flags() -> None:
    """$exception with $exception_type set → DE-01 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$exception",
                    event_id="exc-1",
                    properties={
                        "$exception_type": "ValueError",
                        "$exception_message_length": 42,
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "exception_event"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "DE-01"
    assert findings[0].result == "FLAG"
    assert findings[0].evidence_data["exception_type"] == "ValueError"
    assert findings[0].evidence_data["exception_message_length"] == 42
    assert result.decision == "FLAG"


def test_ai_generation_cost_flags() -> None:
    """$ai_generation captures posture; $ai_total_cost_usd > $1 → PR-04 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$ai_generation",
                    event_id="ai-1",
                    properties={
                        "ai_provider": "openai",
                        "ai_model": "gpt-4o",
                        "$ai_input_tokens": 1000,
                        "$ai_output_tokens": 500,
                        "$ai_total_cost_usd": 2.50,
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    ai_gen = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "ai_generation"
    ]
    assert len(ai_gen) == 1
    assert ai_gen[0].result == "PASS"
    assert ai_gen[0].evidence_data["ai_provider"] == "openai"
    assert ai_gen[0].evidence_data["ai_model"] == "gpt-4o"
    assert ai_gen[0].evidence_data["ai_input_tokens"] == 1000
    assert ai_gen[0].evidence_data["ai_output_tokens"] == 500
    assert ai_gen[0].evidence_data["ai_total_cost_usd"] == 2.5

    cost = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "ai_cost_high"
    ]
    assert len(cost) == 1
    assert cost[0].control_id == "PR-04"
    assert cost[0].result == "FLAG"
    assert result.decision == "FLAG"


def test_eu_no_consent_fails() -> None:
    """EU residency + tracking_consent_recorded=false → PR-04 FAIL → BLOCK."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$pageview",
                    event_id="eu-1",
                    properties={
                        "data_residency_region": "DE",
                        "tracking_consent_recorded": False,
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "eu_no_consent"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FAIL"
    assert result.decision == "BLOCK"


def test_over_tracking_flags() -> None:
    """event_property_keys count > threshold → PR-04 FLAG over_tracking."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$autocapture",
                    event_id="ot-1",
                    properties={
                        "event_property_keys": [f"k{i}" for i in range(50)],
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "over_tracking"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FLAG"


def test_feature_flag_agent_captured() -> None:
    """$feature_flag_called with agent-* prefix → captured PR-05 PASS."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$feature_flag_called",
                    event_id="ff-1",
                    properties={
                        "$feature_flag": "agent-v2-enabled",
                        "$feature_flag_response": True,
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "feature_flag_agent"
    ]
    assert len(findings) == 1
    assert findings[0].result == "PASS"
    assert findings[0].evidence_data["feature_flag"] == "agent-v2-enabled"
    assert findings[0].evidence_data["feature_flag_response"] is True


def test_is_sample_event_passes() -> None:
    """is_sample_event=true → PR-05 PASS."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="agent_action",
                    event_id="samp-1",
                    properties={"is_sample_event": True},
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "is_sample_event"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-05"
    assert findings[0].result == "PASS"


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def test_dashboard_deleted_flags() -> None:
    """activity=deleted scope=Dashboard → PR-02 FLAG."""
    doc = json.dumps(
        {
            "audit_log": [
                _audit(activity="deleted", scope="Dashboard"),
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "audit_asset_deleted"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-02"
    assert findings[0].result == "FLAG"
    assert result.decision == "FLAG"


def test_feature_flag_deleted_flags() -> None:
    """activity=deleted scope=FeatureFlag → PR-02 FLAG."""
    doc = json.dumps(
        {
            "audit_log": [
                _audit(activity="deleted", scope="FeatureFlag"),
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "audit_feature_flag_deleted"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-02"
    assert findings[0].result == "FLAG"


def test_data_export_flags() -> None:
    """activity=exported → PR-04 FLAG."""
    doc = json.dumps(
        {
            "audit_log": [
                _audit(activity="exported", scope="Insight"),
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "audit_data_export"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FLAG"


def test_plugin_untrusted_host_fails() -> None:
    """activity=created scope=Plugin + plugin_url_host not in allowlist → PR-04 FAIL."""
    doc = json.dumps(
        {
            "audit_log": [
                _audit(
                    activity="created",
                    scope="Plugin",
                    detail={
                        "plugin_name": "rogue-plugin",
                        "plugin_url_host": "https://github.com/attacker/rogue-plugin",
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "audit_plugin_untrusted"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FAIL"
    assert result.decision == "BLOCK"
    # plugin URL host stored, no path leaked.
    assert findings[0].evidence_data["plugin_url_host"] == "https://github.com"


def test_api_key_flags() -> None:
    """activity=created scope=PersonalApiKey + is_system_actor=false → PR-01 FLAG."""
    doc = json.dumps(
        {
            "audit_log": [
                _audit(
                    activity="created",
                    scope="PersonalApiKey",
                    is_system_actor=False,
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "audit_personal_api_key_created"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-01"
    assert findings[0].result == "FLAG"
    # Email captured as DOMAIN ONLY.
    assert findings[0].evidence_data["actor_email_domain"] == "example.com"


def test_org_config_flags() -> None:
    """activity=updated scope=Organization → PR-02 FLAG."""
    doc = json.dumps(
        {
            "audit_log": [
                _audit(
                    activity="updated",
                    scope="Organization",
                    detail={
                        "name_length": 30,
                        "changes": [
                            {"field": "available_features", "action": "changed"},
                            {"field": "plugins_access_level", "action": "changed"},
                        ],
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "audit_org_config_changed"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-02"
    assert findings[0].result == "FLAG"
    assert "available_features" in findings[0].evidence_data["change_fields"]


def test_team_permissions_flags() -> None:
    """activity=updated scope=Team → PR-02 FLAG."""
    doc = json.dumps(
        {
            "audit_log": [
                _audit(
                    activity="updated",
                    scope="Team",
                    detail={
                        "changes": [
                            {"field": "access_control", "action": "changed"},
                        ],
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "audit_team_permissions_changed"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-02"
    assert findings[0].result == "FLAG"


# ---------------------------------------------------------------------------
# Synthetic findings
# ---------------------------------------------------------------------------


def test_high_volume_synthetic() -> None:
    """> N sensitive events for same agent in 1h window → synthetic PR-04 FAIL."""
    events = []
    base_time = 1730000000
    for i in range(5):
        events.append(
            _event(
                event="agent_action",
                event_id=f"hv-{i}",
                timestamp=f"2026-04-01T12:{i:02d}:00Z",
                properties={
                    "contains_sensitive_pattern": True,
                    "sensitive_patterns_matched": ["email"],
                },
            )
        )
        # Provide both timestamp and time fallback to be robust.
        events[-1]["properties"]["time"] = base_time + i * 60
    doc = json.dumps({"events": events})
    results = PostHogImporter(high_volume_threshold=3).parse_string(doc)
    synthetic = [
        r for r in results if r.action_id.startswith("posthog-high-volume-")
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
    for i in range(4):
        events.append(
            _event(
                event="agent_action",
                event_id=f"sens-{i}",
                timestamp=f"2026-04-01T12:{i:02d}:00Z",
                properties={
                    "contains_sensitive_pattern": True,
                    "sensitive_patterns_matched": ["email"],
                },
            )
        )
    for i in range(6):
        events.append(
            _event(
                event="$pageview",
                event_id=f"pv-{i}",
                timestamp=f"2026-04-01T13:{i:02d}:00Z",
                properties={"contains_sensitive_pattern": False},
            )
        )
    doc = json.dumps({"events": events})
    results = PostHogImporter(
        high_volume_threshold=1000,
        pii_concentration_threshold=0.10,
    ).parse_string(doc)
    synthetic = [
        r for r in results if r.action_id.startswith("posthog-pii-concentration-")
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
    """Raw values for distinct_id, $user_id, $session_id, $ip, email, ssn never stored."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="agent_action",
                    distinct_id="user-distinct-VERY-SECRET-VALUE",
                    event_id="san-1",
                    properties={
                        "$user_id": "user-stable-PRIVATE-1234567",
                        "$session_id": "sess-PRIVATE-9876543",
                        "$ip": "203.0.113.42",
                        "email": "alice@example.com",
                        "ssn": "123-45-6789",
                        "credit_card": "4111-1111-1111-1111",
                        "first_name": "Alice",
                        "event_property_keys": [
                            "$user_id",
                            "$session_id",
                            "$ip",
                            "email",
                            "ssn",
                            "credit_card",
                            "first_name",
                        ],
                        "contains_sensitive_pattern": True,
                        "sensitive_patterns_matched": [
                            "ssn_like",
                            "credit_card_like",
                            "email",
                        ],
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
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
        assert cr.evidence_data["distinct_id_suffix"] == "ET-VALUE"
        assert cr.evidence_data["user_id_suffix"] == "-1234567"
        assert cr.evidence_data["session_id_suffix"] == "-9876543"
        assert cr.evidence_data["ip_masked"] == "203.0.0.0/16"
        assert "ssn" in cr.evidence_data["property_keys"]
        assert "email" in cr.evidence_data["property_keys"]


def test_actor_email_domain_only() -> None:
    """Audit actor_email captured as DOMAIN ONLY — full email never stored."""
    doc = json.dumps(
        {
            "audit_log": [
                _audit(
                    activity="created",
                    scope="PersonalApiKey",
                    actor_email="human.actor.full.name@corp.example.org",
                    is_system_actor=False,
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    for cr in result.control_results:
        encoded = json.dumps(cr.evidence_data, default=str)
        assert "human.actor.full.name" not in encoded
        assert cr.evidence_data["actor_email_domain"] == "corp.example.org"


# ---------------------------------------------------------------------------
# Mixed events + audit dispatch
# ---------------------------------------------------------------------------


def test_mixed_events_audit_dispatch() -> None:
    """`{"data": [...]}` mixed event/audit auto-dispatches by `event` vs `activity`."""
    doc = json.dumps(
        {
            "data": [
                _event(event="$pageview", event_id="m-evt-1"),
                _audit(
                    activity="created",
                    scope="PersonalApiKey",
                    is_system_actor=False,
                ),
                _event(
                    event="agent_action",
                    event_id="m-evt-2",
                    properties={
                        "contains_sensitive_pattern": True,
                        "sensitive_patterns_matched": ["ssn_like"],
                    },
                ),
                _audit(
                    activity="exported",
                    scope="Insight",
                    created_at="2026-04-01T13:00:00Z",
                ),
            ]
        }
    )
    results = PostHogImporter().parse_string(doc)
    event_results = [
        r for r in results if r.action_id.startswith("posthog-event-")
    ]
    audit_results = [
        r for r in results if r.action_id.startswith("posthog-audit-")
    ]
    assert len(event_results) == 2
    assert len(audit_results) == 2

    # SSN event → BLOCK.
    ssn_event = next(
        r for r in event_results if r.action_id == "posthog-event-m-evt-2"
    )
    assert ssn_event.decision == "BLOCK"

    # PersonalApiKey audit → PR-01 FLAG.
    api_audit = next(
        r
        for r in audit_results
        if any(
            cr.evidence_data.get("signal") == "audit_personal_api_key_created"
            for cr in r.control_results
        )
    )
    assert api_audit.decision == "FLAG"

    # exported audit → PR-04 FLAG.
    export_audit = next(
        r
        for r in audit_results
        if any(
            cr.evidence_data.get("signal") == "audit_data_export"
            for cr in r.control_results
        )
    )
    assert export_audit.decision == "FLAG"


def test_jsonl_events() -> None:
    """JSONL: one event per line is parsed."""
    lines = [
        json.dumps(_event(event="$pageview", event_id="jl-1")),
        json.dumps(
            _event(
                event="agent_action",
                event_id="jl-2",
                properties={
                    "contains_sensitive_pattern": True,
                    "sensitive_patterns_matched": ["ssn_like"],
                },
            )
        ),
        json.dumps(_audit(activity="exported", scope="Dashboard")),
    ]
    content = "\n".join(lines)
    results = PostHogImporter().parse_string(content)
    event_results = [r for r in results if r.action_id.startswith("posthog-event-")]
    audit_results = [r for r in results if r.action_id.startswith("posthog-audit-")]
    assert len(event_results) == 2
    assert len(audit_results) == 1
    ssn = next(
        r for r in event_results if r.action_id == "posthog-event-jl-2"
    )
    assert ssn.decision == "BLOCK"


def test_empty_export() -> None:
    """Empty events array yields a single ALLOW PASS provenance result."""
    doc = json.dumps({"events": []})
    [result] = PostHogImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "posthog_import"
    assert result.control_results[0].control_id == "PR-05"
