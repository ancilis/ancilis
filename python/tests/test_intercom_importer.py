"""Tests for the Intercom conversation importer."""

from __future__ import annotations

import json
from typing import Any

from ancilis.importers.intercom import IntercomImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Intercom conversation builders (no python-intercom required)
# ---------------------------------------------------------------------------


def _conv(
    *,
    id: str = "conv-1",
    created_at: int = 1730000000,
    state: str = "closed",
    source_type: str = "conversation",
    source_delivered_as: str = "automated",
    contact_id: str | None = "contact-abc",
    assigned_to_ai: bool = True,
    fin_resolved: bool = False,
    fin_handoff_to_human: bool = False,
    rating: int | None = None,
    rating_remark_length: int = 0,
    parts: list[dict[str, Any]] | None = None,
    fin_message_count: int = 0,
    human_message_count: int = 0,
    time_to_resolve: float | None = None,
    first_response_time: float | None = 30.0,
    sla_status: str | None = None,
    sla_name: str | None = None,
    tags: list[dict[str, Any]] | None = None,
    cm_subject_length: int = 0,
    cm_body_length: int = 100,
    cm_delivered_as: str = "automated",
) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "id": id,
        "type": "conversation",
        "created_at": created_at,
        "state": state,
        "source": {"type": source_type, "delivered_as": source_delivered_as},
        "contact_id": contact_id,
        "assigned_to_ai": assigned_to_ai,
        "fin_resolved": fin_resolved,
        "fin_handoff_to_human": fin_handoff_to_human,
        "conversation_parts": parts or [],
        "statistics": {
            "first_response_time": first_response_time,
            "fin_message_count": fin_message_count,
            "human_message_count": human_message_count,
            "time_to_resolve": time_to_resolve,
        },
        "conversation_message": {
            "subject_length": cm_subject_length,
            "body_length": cm_body_length,
            "delivered_as": cm_delivered_as,
        },
    }
    if rating is not None:
        rec["conversation_rating"] = {
            "rating": rating,
            "remark_length": rating_remark_length,
        }
    if sla_status is not None:
        rec["sla_applied"] = {
            "sla_name": sla_name or "Standard SLA",
            "sla_status": sla_status,
        }
    if tags is not None:
        rec["tags"] = tags
    return rec


def _signals(result: Any) -> set[str]:
    return {
        cr.evidence_data.get("signal")
        for cr in result.control_results
        if cr.evidence_data.get("signal")
    }


# ---------------------------------------------------------------------------
# 1. fin_resolved → audit logged FLAG
# ---------------------------------------------------------------------------


def test_fin_resolved_passes_audit_logged() -> None:
    """fin_resolved=true with no low rating → PR-04 FLAG audit-logged, FLAG decision."""
    doc = json.dumps(
        {
            "conversations": [
                _conv(
                    id="cv-fr",
                    fin_resolved=True,
                    rating=5,
                    fin_message_count=3,
                    parts=[
                        {
                            "id": "p1",
                            "part_type": "fin_answer",
                            "author": {"type": "fin", "id": "fin"},
                            "body_length": 100,
                            "created_at": 1730000010,
                            "redacted": False,
                        }
                    ],
                )
            ]
        }
    )
    [result] = IntercomImporter().parse_string(doc)
    assert result.decision == "FLAG"
    assert "fin_resolved_audit_logged" in _signals(result)
    flags = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "fin_resolved_audit_logged"
    ]
    assert flags[0].control_id == "PR-04"
    assert flags[0].result == "FLAG"


# ---------------------------------------------------------------------------
# 2. fin_resolved + low rating → FAIL
# ---------------------------------------------------------------------------


def test_fin_resolved_low_rating_fails() -> None:
    """fin_resolved=true + rating<=2 → PR-04 FAIL false-resolution, BLOCK decision."""
    doc = json.dumps(
        {
            "conversations": [
                _conv(
                    id="cv-frlr",
                    fin_resolved=True,
                    rating=1,
                    fin_message_count=2,
                )
            ]
        }
    )
    [result] = IntercomImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    assert "fin_resolved_low_rating" in _signals(result)
    fails = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "fin_resolved_low_rating"
    ]
    assert fails[0].control_id == "PR-04"
    assert fails[0].result == "FAIL"
    # The plain fin_resolved_audit_logged FLAG should not be emitted in
    # addition — FAIL trumps FLAG for the same underlying signal.
    assert "fin_resolved_audit_logged" not in _signals(result)


# ---------------------------------------------------------------------------
# 3. fin_handoff_to_human → PASS
# ---------------------------------------------------------------------------


def test_fin_handoff_to_human_passes() -> None:
    """fin_handoff_to_human=true → PR-05 PASS, ALLOW decision."""
    doc = json.dumps(
        {
            "conversations": [
                _conv(
                    id="cv-handoff",
                    fin_handoff_to_human=True,
                    fin_resolved=False,
                    fin_message_count=2,
                    human_message_count=1,
                    parts=[
                        {
                            "id": "p1",
                            "part_type": "fin_handoff",
                            "author": {"type": "fin", "id": "fin"},
                            "body_length": 50,
                            "created_at": 1730000010,
                            "redacted": False,
                        }
                    ],
                )
            ]
        }
    )
    [result] = IntercomImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert "fin_handoff_to_human" in _signals(result)
    passes = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "fin_handoff_to_human"
    ]
    assert passes[0].control_id == "PR-05"
    assert passes[0].result == "PASS"


# ---------------------------------------------------------------------------
# 4. fin_message_loop → FAIL
# ---------------------------------------------------------------------------


def test_fin_message_loop_fails() -> None:
    """Many fin messages with no human → PR-04 FAIL Fin loop, BLOCK decision."""
    doc = json.dumps(
        {
            "conversations": [
                _conv(
                    id="cv-loop",
                    fin_message_count=15,
                    human_message_count=0,
                    parts=[
                        {
                            "id": f"p{i}",
                            "part_type": "fin_answer",
                            "author": {"type": "fin", "id": "fin"},
                            "body_length": 100,
                            "created_at": 1730000000 + i,
                            "redacted": False,
                        }
                        for i in range(15)
                    ],
                )
            ]
        }
    )
    [result] = IntercomImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    assert "fin_message_loop" in _signals(result)
    fails = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "fin_message_loop"
    ]
    assert fails[0].control_id == "PR-04"
    assert fails[0].result == "FAIL"


# ---------------------------------------------------------------------------
# 5. SLA missed by AI → FAIL
# ---------------------------------------------------------------------------


def test_sla_missed_ai_fails() -> None:
    """sla_status=missed AND assigned_to_ai=true → PR-02 FAIL, BLOCK decision."""
    doc = json.dumps(
        {
            "conversations": [
                _conv(
                    id="cv-sla",
                    assigned_to_ai=True,
                    sla_status="missed",
                    sla_name="Premium Response SLA",
                )
            ]
        }
    )
    [result] = IntercomImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    assert "sla_missed_ai" in _signals(result)
    fails = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "sla_missed_ai"
    ]
    assert fails[0].control_id == "PR-02"
    assert fails[0].result == "FAIL"


# ---------------------------------------------------------------------------
# 6. low rating with AI involvement → FAIL
# ---------------------------------------------------------------------------


def test_low_rating_with_ai_involvement_fails() -> None:
    """rating<=2 + fin_message_count>0 (without fin_resolved) → PR-04 FAIL."""
    doc = json.dumps(
        {
            "conversations": [
                _conv(
                    id="cv-lrai",
                    fin_resolved=False,
                    fin_handoff_to_human=True,  # produces a PASS too
                    fin_message_count=4,
                    human_message_count=1,
                    rating=2,
                )
            ]
        }
    )
    [result] = IntercomImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    assert "low_rating_with_ai_involvement" in _signals(result)
    fails = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "low_rating_with_ai_involvement"
    ]
    assert fails[0].control_id == "PR-04"
    assert fails[0].result == "FAIL"


# ---------------------------------------------------------------------------
# 7. redacted parts → PR-04 PASS
# ---------------------------------------------------------------------------


def test_redacted_part_audit_pass() -> None:
    """A redacted=true part → PR-04 PASS GDPR audit signal."""
    doc = json.dumps(
        {
            "conversations": [
                _conv(
                    id="cv-red",
                    fin_handoff_to_human=True,
                    parts=[
                        {
                            "id": "p1",
                            "part_type": "comment",
                            "author": {"type": "user", "id": "u1"},
                            "body_length": 30,
                            "created_at": 1730000010,
                            "redacted": True,
                        }
                    ],
                )
            ]
        }
    )
    [result] = IntercomImporter().parse_string(doc)
    assert "redacted_part_audit" in _signals(result)
    passes = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "redacted_part_audit"
    ]
    assert passes[0].control_id == "PR-04"
    assert passes[0].result == "PASS"
    # redacted_part_count should be captured in evidence_data.
    assert passes[0].evidence_data["redacted_part_count"] == 1


# ---------------------------------------------------------------------------
# 8. proactive AI engagement → PR-01 captured
# ---------------------------------------------------------------------------


def test_proactive_ai_engagement_captured() -> None:
    """source.type=ai_agent + delivered_as=customer_initiated → PR-01 PASS."""
    doc = json.dumps(
        {
            "conversations": [
                _conv(
                    id="cv-proactive",
                    source_type="ai_agent",
                    source_delivered_as="customer_initiated",
                )
            ]
        }
    )
    [result] = IntercomImporter().parse_string(doc)
    assert "ai_proactive_engagement" in _signals(result)
    passes = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "ai_proactive_engagement"
    ]
    assert passes[0].control_id == "PR-01"
    assert passes[0].result == "PASS"


# ---------------------------------------------------------------------------
# 9. Sensitive tag handled by AI → PR-04 FAIL
# ---------------------------------------------------------------------------


def test_sensitive_tag_handled_by_ai_fails() -> None:
    """Tag matching complaint/legal/regulator + assigned_to_ai → PR-04 FAIL."""
    doc = json.dumps(
        {
            "conversations": [
                _conv(
                    id="cv-sens",
                    assigned_to_ai=True,
                    fin_handoff_to_human=False,
                    tags=[
                        {"id": "t1", "name": "regulator-inquiry"},
                        {"id": "t2", "name": "vip"},
                    ],
                )
            ]
        }
    )
    [result] = IntercomImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    assert "sensitive_tag_handled_by_ai" in _signals(result)
    fails = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "sensitive_tag_handled_by_ai"
    ]
    assert fails[0].control_id == "PR-04"
    assert fails[0].result == "FAIL"
    # Ensure tag NAMES are sanitized (truncated + sha256), not raw.
    tags_in_evidence = fails[0].evidence_data["tags"]
    assert all("sha256" in t and "prefix" in t for t in tags_in_evidence)


# ---------------------------------------------------------------------------
# 10. Fin close → FLAG
# ---------------------------------------------------------------------------


def test_fin_close_flags() -> None:
    """part_type=close + author.type=fin → PR-02 FLAG autonomous close."""
    doc = json.dumps(
        {
            "conversations": [
                _conv(
                    id="cv-finclose",
                    fin_resolved=False,
                    parts=[
                        {
                            "id": "p1",
                            "part_type": "fin_answer",
                            "author": {"type": "fin", "id": "fin"},
                            "body_length": 100,
                            "created_at": 1730000010,
                            "redacted": False,
                        },
                        {
                            "id": "p2",
                            "part_type": "close",
                            "author": {"type": "fin", "id": "fin"},
                            "body_length": 0,
                            "created_at": 1730000020,
                            "redacted": False,
                        },
                    ],
                )
            ]
        }
    )
    [result] = IntercomImporter().parse_string(doc)
    assert "fin_close_autonomous" in _signals(result)
    flags = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "fin_close_autonomous"
    ]
    assert flags[0].control_id == "PR-02"
    assert flags[0].result == "FLAG"


# ---------------------------------------------------------------------------
# 11. suspiciously fast resolve → FLAG
# ---------------------------------------------------------------------------


def test_suspiciously_fast_ai_resolve_flags() -> None:
    """time_to_resolve<60 + fin_resolved → PR-04 FLAG suspiciously fast."""
    doc = json.dumps(
        {
            "conversations": [
                _conv(
                    id="cv-fast",
                    fin_resolved=True,
                    rating=5,
                    time_to_resolve=12.0,
                    fin_message_count=2,
                )
            ]
        }
    )
    [result] = IntercomImporter().parse_string(doc)
    assert "suspiciously_fast_ai_resolve" in _signals(result)
    flags = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "suspiciously_fast_ai_resolve"
    ]
    assert flags[0].control_id == "PR-04"
    assert flags[0].result == "FLAG"


# ---------------------------------------------------------------------------
# 12. high-volume Fin synthetic
# ---------------------------------------------------------------------------


def test_high_volume_fin_synthetic() -> None:
    """> N Fin-resolved conversations in 1h with little human verification → synthetic FLAG."""
    base_ts = 1730000000  # 2024-10-27 04:53:20 UTC — same hour
    convs = []
    for i in range(60):
        convs.append(
            _conv(
                id=f"cv-hv-{i}",
                created_at=base_ts + i * 10,  # all within one hour
                fin_resolved=True,
                fin_message_count=2,
                human_message_count=0,
                rating=5,
            )
        )
    doc = json.dumps({"conversations": convs})
    results = IntercomImporter().parse_string(doc)
    syn = [r for r in results if r.action_id.startswith("intercom-high-volume-fin-")]
    assert len(syn) == 1
    cr = syn[0].control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["resolved_count"] == 60
    assert cr.evidence_data["synthetic"] is True


# ---------------------------------------------------------------------------
# 13. bad-rating-concentration synthetic
# ---------------------------------------------------------------------------


def test_bad_rating_concentration_synthetic() -> None:
    """> X% of Fin-handled rated <=2 → synthetic PR-04 FAIL."""
    convs = []
    # 5 well-rated Fin-handled.
    for i in range(5):
        convs.append(
            _conv(
                id=f"cv-good-{i}",
                fin_resolved=False,
                fin_handoff_to_human=True,
                fin_message_count=2,
                human_message_count=1,
                rating=5,
            )
        )
    # 5 poorly-rated Fin-handled — drives concentration to 50% > 10%.
    for i in range(5):
        convs.append(
            _conv(
                id=f"cv-bad-{i}",
                fin_resolved=False,
                fin_handoff_to_human=True,
                fin_message_count=2,
                human_message_count=1,
                rating=1,
            )
        )
    doc = json.dumps({"conversations": convs})
    results = IntercomImporter().parse_string(doc)
    syn = [
        r for r in results if r.action_id == "intercom-bad-rating-concentration"
    ]
    assert len(syn) == 1
    cr = syn[0].control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert cr.evidence_data["fin_handled_total"] == 10
    assert cr.evidence_data["fin_handled_low_rated"] == 5
    assert cr.evidence_data["synthetic"] is True


# ---------------------------------------------------------------------------
# 14. message body text never stored
# ---------------------------------------------------------------------------


def test_message_body_text_never_stored() -> None:
    """conversation_parts.body / conversation_message.body raw text must NOT appear in evidence_data."""
    doc = json.dumps(
        {
            "conversations": [
                {
                    "id": "cv-body",
                    "type": "conversation",
                    "created_at": 1730000000,
                    "state": "closed",
                    "source": {
                        "type": "conversation",
                        "delivered_as": "automated",
                    },
                    "contact_id": "contact-x",
                    "assigned_to_ai": True,
                    "fin_resolved": True,
                    "fin_handoff_to_human": False,
                    "conversation_message": {
                        "subject_length": 0,
                        "body_length": 1234,
                        "delivered_as": "automated",
                        # If a body slipped in, the importer must still NOT keep it.
                        "body": "My SSN is 111-22-3333 please help",
                        "subject": "Urgent help needed",
                    },
                    "conversation_parts": [
                        {
                            "id": "p1",
                            "part_type": "fin_answer",
                            "author": {"type": "fin", "id": "fin"},
                            "body_length": 200,
                            "created_at": 1730000010,
                            "redacted": False,
                            "body": "Sorry, I can help — give me your SSN",
                        }
                    ],
                    "statistics": {
                        "first_response_time": 30,
                        "fin_message_count": 1,
                        "human_message_count": 0,
                        "time_to_resolve": 100,
                    },
                }
            ]
        }
    )
    [result] = IntercomImporter().parse_string(doc)
    blob = json.dumps(
        [cr.evidence_data for cr in result.control_results], default=str
    )
    assert "My SSN is 111-22-3333" not in blob
    assert "give me your SSN" not in blob
    assert "Urgent help needed" not in blob
    # But body lengths should be present.
    assert any(
        cr.evidence_data.get("conversation_message_body_length") == 1234
        for cr in result.control_results
    )


# ---------------------------------------------------------------------------
# 15. rating remark text never stored
# ---------------------------------------------------------------------------


def test_rating_remark_text_never_stored() -> None:
    """conversation_rating.remark raw text must NOT appear in evidence_data."""
    doc = json.dumps(
        {
            "conversations": [
                {
                    "id": "cv-remark",
                    "type": "conversation",
                    "created_at": 1730000000,
                    "state": "closed",
                    "source": {
                        "type": "conversation",
                        "delivered_as": "automated",
                    },
                    "contact_id": "contact-y",
                    "assigned_to_ai": True,
                    "fin_resolved": True,
                    "fin_handoff_to_human": False,
                    "conversation_rating": {
                        "rating": 1,
                        "remark_length": 75,
                        # If raw remark slipped in, importer must drop it.
                        "remark": (
                            "Worst experience ever, my account number is "
                            "987654321 and I want a refund"
                        ),
                    },
                    "conversation_parts": [],
                    "statistics": {
                        "first_response_time": 30,
                        "fin_message_count": 1,
                        "human_message_count": 0,
                        "time_to_resolve": 200,
                    },
                }
            ]
        }
    )
    [result] = IntercomImporter().parse_string(doc)
    blob = json.dumps(
        [cr.evidence_data for cr in result.control_results], default=str
    )
    assert "Worst experience ever" not in blob
    assert "987654321" not in blob
    # remark length should be present.
    assert any(
        cr.evidence_data.get("conversation_rating_remark_length") == 75
        for cr in result.control_results
    )


# ---------------------------------------------------------------------------
# Bonus — JSONL + {"data": [...]} envelope acceptance
# ---------------------------------------------------------------------------


def test_jsonl_envelope_accepted() -> None:
    """JSONL (one conversation per line) must parse correctly."""
    line1 = json.dumps(_conv(id="cv-l1", fin_resolved=True, rating=5))
    line2 = json.dumps(_conv(id="cv-l2", fin_handoff_to_human=True))
    results = IntercomImporter().parse_string(line1 + "\n" + line2 + "\n")
    assert len(results) == 2
    assert results[0].action_id == "intercom-cv-l1"
    assert results[1].action_id == "intercom-cv-l2"


def test_data_envelope_accepted() -> None:
    """{"data": [...]} envelope must parse correctly."""
    doc = json.dumps({"data": [_conv(id="cv-data", fin_handoff_to_human=True)]})
    [result] = IntercomImporter().parse_string(doc)
    assert result.action_id == "intercom-cv-data"
