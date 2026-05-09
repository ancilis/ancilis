"""Tests for the PostHog analytics + LLM-observability importer."""

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
    base_props: dict = {
        "$lib": "posthog-python",
        "$ip": "10.0.0.1",
        "$geoip_country_code": "US",
        "agent_id": "agent-1",
        "org_id": "org-1",
        "project_id": "proj-1",
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
    scope: str = "organization",
    timestamp: str = "2026-04-01T12:00:00Z",
    actor_id: str = "actor-1234567890",
    actor_email: str = "agent@example.com",
    is_service_account: bool = False,
    item_id: str = "item-1234567890",
    detail: dict | None = None,
) -> dict:
    return {
        "timestamp": timestamp,
        "activity": activity,
        "scope": scope,
        "actor": {
            "id": actor_id,
            "email": actor_email,
            "is_service_account": is_service_account,
        },
        "item_id": item_id,
        "detail": detail or {},
    }


# ---------------------------------------------------------------------------
# AI generation events
# ---------------------------------------------------------------------------


def test_ai_generation_passes() -> None:
    """$ai_generation with $ai_is_error=false → PR-01 PASS."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$ai_generation",
                    event_id="aig-1",
                    properties={
                        "$ai_provider": "openai",
                        "$ai_model": "gpt-4o",
                        "$ai_input_tokens": 100,
                        "$ai_output_tokens": 50,
                        "$ai_total_cost_usd": 0.001,
                        "$ai_latency": 1.2,
                        "$ai_is_error": False,
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    pass_results = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "ai_generation_pass"
    ]
    assert len(pass_results) == 1
    assert pass_results[0].control_id == "PR-01"
    assert pass_results[0].result == "PASS"
    assert result.decision == "ALLOW"


def test_ai_generation_error_fails() -> None:
    """$ai_generation with $ai_is_error=true → DE-01 FAIL → BLOCK."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$ai_generation",
                    event_id="aig-err-1",
                    properties={
                        "$ai_provider": "anthropic",
                        "$ai_model": "claude-opus",
                        "$ai_is_error": True,
                        "$ai_error": "rate_limit_exceeded",
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    fails = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "ai_generation_error"
    ]
    assert len(fails) == 1
    assert fails[0].control_id == "DE-01"
    assert fails[0].result == "FAIL"
    assert result.decision == "BLOCK"


# ---------------------------------------------------------------------------
# AI metric events
# ---------------------------------------------------------------------------


def test_hallucination_high_fails() -> None:
    """$ai_metric metric_name=hallucination value > threshold → PR-03 FAIL."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$ai_metric",
                    event_id="aim-h-1",
                    properties={
                        "$ai_metric_name": "hallucination",
                        "$ai_metric_value": 0.85,
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "ai_metric_high_hallucination"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-03"
    assert findings[0].result == "FAIL"
    assert result.decision == "BLOCK"


# ---------------------------------------------------------------------------
# Sensitive set / pattern events
# ---------------------------------------------------------------------------


def test_sensitive_set_fails_block() -> None:
    """$identify with $set containing sensitive keys → PR-04 FAIL → BLOCK."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$identify",
                    event_id="id-1",
                    properties={
                        "$set": {
                            "email": "user@example.com",
                            "ssn": "***",
                            "credit_card": "***",
                        }
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "set_sensitive_property"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FAIL"
    sset_keys = findings[0].evidence_data["sensitive_set_keys"]
    assert "ssn" in sset_keys
    assert "credit_card" in sset_keys
    assert result.decision == "BLOCK"


def test_ssn_pattern_fails_block() -> None:
    """sensitive_patterns_matched contains ssn_like → PR-04 FAIL → BLOCK."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$autocapture",
                    event_id="ssn-1",
                    properties={
                        "contains_sensitive_pattern": True,
                        "sensitive_patterns_matched": ["ssn_like"],
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "sensitive_pattern_ssn"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FAIL"
    assert result.decision == "BLOCK"


# ---------------------------------------------------------------------------
# EU consent / session recording
# ---------------------------------------------------------------------------


def test_eu_recording_no_consent_flags() -> None:
    """$session_recording_started for EU user without consent → PR-04 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$session_recording_started",
                    event_id="rec-eu-1",
                    properties={
                        "$geoip_country_code": "DE",
                        "recording_disabled_for_user": False,
                        "$session_recording_started": True,
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "session_recording_eu_no_consent"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FLAG"
    assert result.decision == "FLAG"


# ---------------------------------------------------------------------------
# Audit-log events
# ---------------------------------------------------------------------------


def test_recording_share_link_fails_block() -> None:
    """activity=recording_share_link_created → PR-04 FAIL → BLOCK."""
    doc = json.dumps(
        {
            "audit_log": [
                _audit(
                    activity="recording_share_link_created",
                    scope="recording",
                    item_id="rec-abc1234567890",
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal")
        == "audit_recording_share_link_created"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FAIL"
    assert result.decision == "BLOCK"


def test_insight_public_fails() -> None:
    """activity=insight_shared_publicly → PR-04 FAIL."""
    doc = json.dumps(
        {
            "audit_log": [
                _audit(
                    activity="insight_shared_publicly",
                    scope="insight",
                    item_id="ins-abc1234567890",
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "audit_insight_shared_publicly"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-04"
    assert findings[0].result == "FAIL"
    assert result.decision == "BLOCK"


def test_data_export_flags() -> None:
    """activity=data_export → PR-04 FLAG."""
    doc = json.dumps(
        {"audit_log": [_audit(activity="data_export", scope="organization")]}
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
    assert result.decision == "FLAG"


def test_api_key_created_flags() -> None:
    """activity=api_key_created → PR-01 FLAG."""
    doc = json.dumps(
        {"audit_log": [_audit(activity="api_key_created", scope="user")]}
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "audit_api_key_created"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-01"
    assert findings[0].result == "FLAG"
    assert result.decision == "FLAG"


def test_plugin_install_flags() -> None:
    """activity=plugin_installed → PR-01 FLAG."""
    doc = json.dumps(
        {
            "audit_log": [
                _audit(activity="plugin_installed", scope="organization")
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "audit_plugin_installed"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-01"
    assert findings[0].result == "FLAG"


def test_role_admin_flags() -> None:
    """activity=team_member_role_changed new_role=admin → PR-02 FLAG."""
    doc = json.dumps(
        {
            "audit_log": [
                _audit(
                    activity="team_member_role_changed",
                    scope="organization",
                    detail={"new_value": "admin", "old_value": "member"},
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    findings = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "audit_role_admin_changed"
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "PR-02"
    assert findings[0].result == "FLAG"


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def test_ai_input_state_not_stored() -> None:
    """$ai_input_state / $ai_output_state RAW must NOT be stored — only summary."""
    secret_prompt = "PASSWORD: hunter2; SSN: 123-45-6789"
    secret_completion = "User SSN is 123-45-6789"
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$ai_generation",
                    event_id="state-1",
                    properties={
                        "$ai_provider": "openai",
                        "$ai_model": "gpt-4o",
                        "$ai_is_error": False,
                        "$ai_input_state": {
                            "messages": [{"role": "user", "content": secret_prompt}]
                        },
                        "$ai_output_state": {
                            "choices": [{"message": {"content": secret_completion}}]
                        },
                    },
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    # Walk all control evidence — secret content must never appear.
    blob = json.dumps([cr.evidence_data for cr in result.control_results])
    assert "hunter2" not in blob
    assert "123-45-6789" not in blob
    assert secret_prompt not in blob
    assert secret_completion not in blob
    # Summary structure must be present and contain length + sha256.
    pass_cr = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "ai_generation_pass"
    ][0]
    summary_in = pass_cr.evidence_data["ai_input_state_summary"]
    summary_out = pass_cr.evidence_data["ai_output_state_summary"]
    assert summary_in is not None
    assert "length" in summary_in and "sha256" in summary_in
    assert isinstance(summary_in["length"], int) and summary_in["length"] > 0
    assert len(summary_in["sha256"]) == 64
    assert summary_out is not None
    assert "length" in summary_out and "sha256" in summary_out


def test_distinct_id_truncated() -> None:
    """Full distinct_id must be truncated to last 8 chars."""
    full_distinct = "user-distinct-A1B2C3D4_PRIVATE_LONG_ID_9999"
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$pageview",
                    distinct_id=full_distinct,
                    event_id="dt-1",
                    properties={"$geoip_country_code": "US"},
                )
            ]
        }
    )
    [result] = PostHogImporter().parse_string(doc)
    blob = json.dumps([cr.evidence_data for cr in result.control_results])
    # Full id must NOT appear anywhere.
    assert "PRIVATE_LONG_ID" not in blob
    assert full_distinct not in blob
    # Suffix should be the last 8 chars of full_distinct.
    cr = result.control_results[0]
    assert cr.evidence_data["distinct_id_suffix"] == full_distinct[-8:]


# ---------------------------------------------------------------------------
# Mixed dispatch
# ---------------------------------------------------------------------------


def test_mixed_events_audit_dispatch() -> None:
    """Mixed envelope with both events + audit_log dispatches per record."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    event="$ai_generation",
                    event_id="mx-aig-1",
                    properties={"$ai_is_error": False, "$ai_provider": "openai"},
                ),
                _event(
                    event="$pageview",
                    event_id="mx-pv-1",
                    properties={"$geoip_country_code": "US"},
                ),
            ],
            "audit_log": [
                _audit(activity="data_export", scope="organization"),
                _audit(
                    activity="recording_share_link_created", scope="recording"
                ),
            ],
        }
    )
    results = PostHogImporter().parse_string(doc)
    # Should produce one EvaluationResult per record (no synthetics triggered).
    assert len(results) == 4
    decisions = sorted(r.decision for r in results)
    # ai_generation → ALLOW, pageview → ALLOW, data_export → FLAG,
    # recording_share_link_created → BLOCK.
    assert "ALLOW" in decisions
    assert "FLAG" in decisions
    assert "BLOCK" in decisions
    # Verify source_types.
    for r in results:
        assert r.source_type == "posthog_import"
    # Recording-share record must be a BLOCK.
    rec_share = [
        r
        for r in results
        if any(
            cr.evidence_data.get("signal")
            == "audit_recording_share_link_created"
            for cr in r.control_results
        )
    ]
    assert len(rec_share) == 1
    assert rec_share[0].decision == "BLOCK"
