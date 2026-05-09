"""Tests for the Zendesk audit-log importer."""

from __future__ import annotations

import json
from typing import Any

from ancilis.importers.zendesk import ZendeskImporter


# ---------------------------------------------------------------------------
# Fixture helpers — inline Zendesk audit records (no zenpy package required)
# ---------------------------------------------------------------------------


def _audit(
    *,
    id: int = 1,
    ticket_id: int = 100,
    created_at: str = "2026-04-01T12:00:00Z",
    actor_id: int = 42,
    author_id: int = 42,
    author_role: str = "agent",
    actor_is_ai: bool = False,
    actor_ai_model: str | None = None,
    via_channel: str = "email",
    events: list[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
    satisfaction_rating: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if events is None:
        events = [
            {
                "type": "Comment",
                "public": True,
                "body_length": 100,
                "html_body_length": 120,
                "via": {"channel": via_channel},
            }
        ]
    if metadata is None:
        metadata = {
            "system": {
                "ip_address": "8.8.4.4",
                "location": "Berlin, Germany",
                "client": "Mozilla/5.0",
            }
        }
    audit: dict[str, Any] = {
        "id": id,
        "ticket_id": ticket_id,
        "created_at": created_at,
        "actor_id": actor_id,
        "author_id": author_id,
        "author_role": author_role,
        "actor_is_ai": actor_is_ai,
        "actor_ai_model": actor_ai_model,
        "via": {"channel": via_channel},
        "events": events,
        "metadata": metadata,
    }
    if satisfaction_rating is not None:
        audit["satisfaction_rating"] = satisfaction_rating
    return audit


def _signals(result) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in result.control_results]


def _find(result, signal: str):
    return next(
        cr for cr in result.control_results if cr.evidence_data.get("signal") == signal
    )


# ---------------------------------------------------------------------------
# Public AI comment / internal note / voice
# ---------------------------------------------------------------------------


def test_ai_public_comment_flags() -> None:
    """actor_is_ai=true + Comment + public=true → PR-01 FLAG."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    id=1,
                    actor_is_ai=True,
                    actor_ai_model="zendesk-resolution-bot",
                    events=[
                        {
                            "type": "Comment",
                            "public": True,
                            "body_length": 250,
                            "html_body_length": 300,
                            "via": {"channel": "email"},
                        }
                    ],
                )
            ]
        }
    )
    [result] = ZendeskImporter().parse_string(doc)
    assert result.decision == "FLAG"
    assert result.source_type == "zendesk_import"
    cr = _find(result, "ai_public_comment")
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"


def test_ai_internal_note_passes() -> None:
    """actor_is_ai=true + Comment + public=false → PR-05 PASS, ALLOW."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    id=2,
                    actor_is_ai=True,
                    actor_ai_model="custom-bot-v2",
                    events=[
                        {
                            "type": "Comment",
                            "public": False,
                            "body_length": 80,
                            "html_body_length": 90,
                            "via": {"channel": "web"},
                        }
                    ],
                )
            ]
        }
    )
    [result] = ZendeskImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    cr = _find(result, "ai_internal_note")
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"


def test_ai_voice_response_flags() -> None:
    """actor_is_ai=true + public Comment + via.channel=voice → PR-04 FLAG."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    id=3,
                    actor_is_ai=True,
                    actor_ai_model="openai-gpt-4o",
                    via_channel="voice",
                    events=[
                        {
                            "type": "VoiceComment",
                            "public": True,
                            "body_length": 60,
                            "html_body_length": 0,
                            "via": {"channel": "voice"},
                        }
                    ],
                )
            ]
        }
    )
    [result] = ZendeskImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = _find(result, "ai_voice_public_response")
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"


# ---------------------------------------------------------------------------
# Autonomous status transitions
# ---------------------------------------------------------------------------


def test_ai_status_solved_fails_autonomous_resolution() -> None:
    """actor_is_ai=true + Change of field=status to 'solved' → PR-02 FAIL, BLOCK."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    id=4,
                    actor_is_ai=True,
                    actor_ai_model="zendesk-resolution-bot",
                    events=[
                        {
                            "type": "Change",
                            "public": False,
                            "field_name": "status",
                            "value": "solved",
                            "previous_value": "open",
                        }
                    ],
                )
            ]
        }
    )
    [result] = ZendeskImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = _find(result, "ai_autonomous_status_solved")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


def test_ai_status_closed_fails() -> None:
    """actor_is_ai=true + Change of field=status to 'closed' → PR-02 FAIL, BLOCK."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    id=5,
                    actor_is_ai=True,
                    actor_ai_model="custom-bot-v2",
                    events=[
                        {
                            "type": "Change",
                            "public": False,
                            "field_name": "status",
                            "value": "closed",
                            "previous_value": "solved",
                        }
                    ],
                )
            ]
        }
    )
    [result] = ZendeskImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = _find(result, "ai_autonomous_status_closed")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Priority / assignee changes
# ---------------------------------------------------------------------------


def test_ai_priority_change_flags() -> None:
    """actor_is_ai=true + Change of field=priority → PR-05 FLAG."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    id=6,
                    actor_is_ai=True,
                    actor_ai_model="custom-bot-v2",
                    events=[
                        {
                            "type": "Change",
                            "public": False,
                            "field_name": "priority",
                            "value": "urgent",
                            "previous_value": "normal",
                        }
                    ],
                )
            ]
        }
    )
    [result] = ZendeskImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = _find(result, "ai_priority_change")
    assert cr.control_id == "PR-05"
    assert cr.result == "FLAG"


def test_ai_assignee_change_flags() -> None:
    """actor_is_ai=true + Change of field=assignee_id → PR-05 FLAG."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    id=7,
                    actor_is_ai=True,
                    actor_ai_model="custom-bot-v2",
                    events=[
                        {
                            "type": "Change",
                            "public": False,
                            "field_name": "assignee_id",
                            "value": "999",
                            "previous_value": "111",
                        }
                    ],
                )
            ]
        }
    )
    [result] = ZendeskImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = _find(result, "ai_assignee_change")
    assert cr.control_id == "PR-05"
    assert cr.result == "FLAG"


# ---------------------------------------------------------------------------
# Bad satisfaction on AI ticket
# ---------------------------------------------------------------------------


def test_bad_satisfaction_on_ai_ticket_fails() -> None:
    """actor_is_ai=true + satisfaction_rating.score=bad → PR-04 FAIL, BLOCK."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    id=8,
                    actor_is_ai=True,
                    actor_ai_model="zendesk-resolution-bot",
                    events=[
                        {
                            "type": "Comment",
                            "public": True,
                            "body_length": 50,
                            "html_body_length": 50,
                            "via": {"channel": "email"},
                        }
                    ],
                    satisfaction_rating={"score": "bad", "comment_length": 25},
                )
            ]
        }
    )
    [result] = ZendeskImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = _find(result, "bad_satisfaction_on_ai_ticket")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    # comment text is never stored; only length surfaces.
    assert cr.evidence_data.get("satisfaction_comment_length") == 25


# ---------------------------------------------------------------------------
# Escalation tag by admin → PASS
# ---------------------------------------------------------------------------


def test_escalation_to_human_audit() -> None:
    """admin + Change tags including escalated_to_human → PR-05 PASS, ALLOW."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    id=9,
                    author_role="admin",
                    actor_is_ai=False,
                    events=[
                        {
                            "type": "Change",
                            "public": False,
                            "field_name": "tags",
                            "value": ["escalated_to_human", "vip"],
                            "previous_value": ["vip"],
                        }
                    ],
                )
            ]
        }
    )
    [result] = ZendeskImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    cr = _find(result, "escalation_to_human")
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"


# ---------------------------------------------------------------------------
# API autonomous create
# ---------------------------------------------------------------------------


def test_api_autonomous_create_flags() -> None:
    """via.channel=api on Create event → PR-01 FLAG."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    id=10,
                    via_channel="api",
                    actor_is_ai=False,
                    events=[
                        {
                            "type": "Create",
                            "public": True,
                            "body_length": 200,
                            "html_body_length": 220,
                            "via": {"channel": "api"},
                        }
                    ],
                )
            ]
        }
    )
    [result] = ZendeskImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = _find(result, "api_autonomous_create")
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"


# ---------------------------------------------------------------------------
# Synthetic: consecutive AI replies (>3 default)
# ---------------------------------------------------------------------------


def test_consecutive_ai_replies_synthetic() -> None:
    """5 consecutive public AI replies on same ticket → synthetic PR-04 FAIL."""
    audits = []
    base_ts = [
        "2026-04-01T12:00:00Z",
        "2026-04-01T12:05:00Z",
        "2026-04-01T12:10:00Z",
        "2026-04-01T12:15:00Z",
        "2026-04-01T12:20:00Z",
    ]
    for i, ts in enumerate(base_ts, start=1):
        audits.append(
            _audit(
                id=100 + i,
                ticket_id=777,
                created_at=ts,
                actor_id=42,
                actor_is_ai=True,
                actor_ai_model="zendesk-resolution-bot",
                events=[
                    {
                        "type": "Comment",
                        "public": True,
                        "body_length": 80,
                        "html_body_length": 100,
                        "via": {"channel": "email"},
                    }
                ],
            )
        )
    doc = json.dumps({"audits": audits})
    results = ZendeskImporter().parse_string(doc)
    # Locate the synthetic finding by its action_id prefix.
    synthetic = [r for r in results if r.action_id.startswith("zendesk-consecutive-ai-")]
    assert len(synthetic) == 1
    syn = synthetic[0]
    assert syn.decision == "BLOCK"
    cr = syn.control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert cr.evidence_data.get("consecutive_ai_run_length") == 5


# ---------------------------------------------------------------------------
# Synthetic: high-volume AI (>100 tickets in 1h default; lower threshold for test)
# ---------------------------------------------------------------------------


def test_high_volume_ai_synthetic() -> None:
    """Same model handling > threshold tickets in window → synthetic PR-04 FLAG."""
    audits = [
        _audit(
            id=200 + i,
            ticket_id=10_000 + i,
            created_at="2026-04-01T12:00:00Z",
            actor_id=99,
            actor_is_ai=True,
            actor_ai_model="custom-bot-v2",
            events=[
                {
                    "type": "Comment",
                    "public": True,
                    "body_length": 50,
                    "html_body_length": 50,
                    "via": {"channel": "email"},
                }
            ],
        )
        for i in range(6)
    ]
    doc = json.dumps({"audits": audits})
    results = ZendeskImporter(ai_volume_per_hour_threshold=4).parse_string(doc)
    synthetic = [r for r in results if r.action_id.startswith("zendesk-ai-volume-")]
    assert len(synthetic) == 1
    syn = synthetic[0]
    assert syn.decision == "FLAG"
    cr = syn.control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data.get("ai_volume_count") == 6


# ---------------------------------------------------------------------------
# Synthetic: bad-satisfaction rate
# ---------------------------------------------------------------------------


def test_bad_satisfaction_rate_synthetic() -> None:
    """Model with > X% bad satisfaction → synthetic PR-04 FAIL."""
    audits: list[dict[str, Any]] = []
    # 8 bad, 2 good = 80% bad on 10 ratings; threshold rate 0.05 with min sample 5.
    for i in range(8):
        audits.append(
            _audit(
                id=300 + i,
                ticket_id=20_000 + i,
                actor_id=99,
                actor_is_ai=True,
                actor_ai_model="custom-bot-v2",
                events=[
                    {
                        "type": "Comment",
                        "public": True,
                        "body_length": 50,
                        "html_body_length": 50,
                        "via": {"channel": "email"},
                    }
                ],
                satisfaction_rating={"score": "bad", "comment_length": 0},
            )
        )
    for i in range(2):
        audits.append(
            _audit(
                id=320 + i,
                ticket_id=20_100 + i,
                actor_id=99,
                actor_is_ai=True,
                actor_ai_model="custom-bot-v2",
                events=[
                    {
                        "type": "Comment",
                        "public": True,
                        "body_length": 50,
                        "html_body_length": 50,
                        "via": {"channel": "email"},
                    }
                ],
                satisfaction_rating={"score": "good", "comment_length": 0},
            )
        )
    doc = json.dumps({"audits": audits})
    results = ZendeskImporter(
        bad_satisfaction_min_sample=5,
        bad_satisfaction_rate_threshold=0.05,
    ).parse_string(doc)
    synthetic = [r for r in results if r.action_id.startswith("zendesk-bad-sat-rate-")]
    assert len(synthetic) == 1
    syn = synthetic[0]
    assert syn.decision == "BLOCK"
    cr = syn.control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert cr.evidence_data.get("bad_satisfaction_count") == 8
    assert cr.evidence_data.get("bad_satisfaction_total") == 10


# ---------------------------------------------------------------------------
# Sanitization tests
# ---------------------------------------------------------------------------


def test_event_body_text_never_stored() -> None:
    """Even when an event accidentally carries a 'body' string, no text persists."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    id=400,
                    actor_is_ai=True,
                    actor_ai_model="zendesk-resolution-bot",
                    events=[
                        {
                            "type": "Comment",
                            "public": True,
                            "body": "We're sorry your refund was delayed; here is "
                            "PII galore: SSN 123-45-6789",
                            "html_body": "<p>" + ("x" * 9999) + "</p>",
                            "body_length": 88,
                            "html_body_length": 10006,
                            "via": {"channel": "email"},
                        }
                    ],
                )
            ]
        }
    )
    [result] = ZendeskImporter().parse_string(doc)
    serialized = json.dumps(
        [cr.evidence_data for cr in result.control_results], default=str
    )
    assert "PII galore" not in serialized
    assert "SSN 123-45-6789" not in serialized
    assert "<p>" not in serialized
    # the length-only fields ARE captured
    cr = _find(result, "ai_public_comment")
    events_summary = cr.evidence_data.get("events") or []
    assert events_summary[0].get("body_length") == 88
    assert events_summary[0].get("html_body_length") == 10006


def test_field_value_never_stored() -> None:
    """For Change events the raw value/previous_value strings must NOT be stored."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    id=401,
                    actor_is_ai=True,
                    actor_ai_model="custom-bot-v2",
                    events=[
                        {
                            "type": "Change",
                            "public": False,
                            "field_name": "priority",
                            "value": "URGENT-HIGHLY-CONFIDENTIAL-MARKER-ZZZ",
                            "previous_value": "STALE-VALUE-AAA-MARKER",
                        },
                        {
                            "type": "Change",
                            "public": False,
                            "field_name": "assignee_id",
                            "value": "EMPLOYEE-ID-987-MARKER",
                            "previous_value": "EMPLOYEE-ID-111-MARKER",
                        },
                    ],
                )
            ]
        }
    )
    [result] = ZendeskImporter().parse_string(doc)
    serialized = json.dumps(
        [cr.evidence_data for cr in result.control_results], default=str
    )
    # No raw value strings of any kind should leak.
    for needle in (
        "URGENT-HIGHLY-CONFIDENTIAL-MARKER-ZZZ",
        "STALE-VALUE-AAA-MARKER",
        "EMPLOYEE-ID-987-MARKER",
        "EMPLOYEE-ID-111-MARKER",
    ):
        assert needle not in serialized
    # field_name IS stored for both events.
    cr = _find(result, "ai_priority_change")
    fields = [
        e.get("field_name")
        for e in (cr.evidence_data.get("events") or [])
    ]
    assert "priority" in fields
    assert "assignee_id" in fields


# ---------------------------------------------------------------------------
# Bonus coverage tests — JSONL, location dropping, IP masking
# ---------------------------------------------------------------------------


def test_metadata_location_dropped_and_ip_masked() -> None:
    """metadata.system.location is never stored; IPv4 is /16 masked."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    id=402,
                    actor_is_ai=True,
                    actor_ai_model="zendesk-resolution-bot",
                    events=[
                        {
                            "type": "Comment",
                            "public": True,
                            "body_length": 50,
                            "html_body_length": 50,
                            "via": {"channel": "email"},
                        }
                    ],
                    metadata={
                        "system": {
                            "ip_address": "8.8.4.4",
                            "location": "Berlin, Germany SECRETLOCATION-XYZ",
                            "client": "Mozilla/5.0",
                        }
                    },
                )
            ]
        }
    )
    [result] = ZendeskImporter().parse_string(doc)
    cr = _find(result, "ai_public_comment")
    assert cr.evidence_data.get("ip_address_redacted") == "8.8.0.0/16"
    serialized = json.dumps(
        [c.evidence_data for c in result.control_results], default=str
    )
    assert "SECRETLOCATION-XYZ" not in serialized
    assert "Berlin" not in serialized


def test_jsonl_format_supported() -> None:
    """JSONL input (one audit per line) is parsed correctly."""
    lines = [
        json.dumps(
            _audit(
                id=500,
                actor_is_ai=True,
                actor_ai_model="custom-bot-v2",
                events=[
                    {
                        "type": "Comment",
                        "public": False,
                        "body_length": 10,
                        "html_body_length": 10,
                        "via": {"channel": "web"},
                    }
                ],
            )
        ),
        json.dumps(
            _audit(
                id=501,
                ticket_id=101,
                actor_is_ai=True,
                actor_ai_model="custom-bot-v2",
                events=[
                    {
                        "type": "Comment",
                        "public": True,
                        "body_length": 10,
                        "html_body_length": 10,
                        "via": {"channel": "email"},
                    }
                ],
            )
        ),
    ]
    results = ZendeskImporter().parse_string("\n".join(lines))
    assert len(results) == 2
    sigs = [s for r in results for s in _signals(r)]
    assert "ai_internal_note" in sigs
    assert "ai_public_comment" in sigs


def test_ticket_merge_passes() -> None:
    """via.channel=ticket-merge → PR-05 PASS."""
    doc = json.dumps(
        {
            "audits": [
                _audit(
                    id=600,
                    via_channel="ticket-merge",
                    actor_is_ai=False,
                    events=[
                        {
                            "type": "Notification",
                            "public": False,
                            "body_length": 10,
                            "html_body_length": 10,
                            "via": {"channel": "ticket-merge"},
                        }
                    ],
                )
            ]
        }
    )
    [result] = ZendeskImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    cr = _find(result, "ticket_merge")
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
