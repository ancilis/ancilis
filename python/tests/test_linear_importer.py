"""Tests for the Linear audit-event importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers.linear import LinearImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Linear audit-event records (no linear-py package required)
# ---------------------------------------------------------------------------


def _event(
    *,
    id: str = "evt-1",
    type: str = "Issue",
    action: str = "create",
    created_at: str = "2026-04-01T12:00:00Z",
    actor_id: str = "user-1",
    actor_name: str = "Kevin Bauer",
    actor_is_bot: bool = False,
    actor_email: str = "kbauer@example.com",
    organization_id: str = "org-1",
    trigger: str = "user",
    data: dict | None = None,
) -> dict:
    if data is None:
        data = {
            "issueId": "iss-1",
            "issueIdentifier": "ENG-1",
            "title_length": 50,
            "description_length": 120,
            "priority": 3,
            "stateId": "state-1",
            "stateType": "backlog",
            "labelIds": ["lbl-a", "lbl-b"],
            "teamId": "team-1",
            "teamKey": "ENG",
        }
    return {
        "id": id,
        "type": type,
        "action": action,
        "createdAt": created_at,
        "actorId": actor_id,
        "actorName": actor_name,
        "actorIsBot": actor_is_bot,
        "actorEmail": actor_email,
        "organizationId": organization_id,
        "trigger": trigger,
        "data": data,
    }


def _findings_for_event(results: list, event_id: str) -> list:
    """Return the EvaluationResults whose action_id matches a given event id."""
    return [r for r in results if r.action_id == f"linear-{event_id}"]


# ---------------------------------------------------------------------------
# Issue lifecycle — create / update / remove / archive
# ---------------------------------------------------------------------------


def test_parse_user_created_issue() -> None:
    """Issue.create + actorIsBot=false trigger=user → PR-05 PASS, ALLOW."""
    doc = json.dumps({"events": [_event(id="evt-user-create")]})
    [result] = LinearImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "linear_import"
    signals = [cr.evidence_data.get("signal") for cr in result.control_results]
    assert "issue_create_user" in signals
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "issue_create_user")
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"


def test_bot_created_issue_flags() -> None:
    """Issue.create with actorIsBot=true OR trigger=agent → PR-01 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-bot-create",
                    actor_id="bot-1",
                    actor_is_bot=True,
                    trigger="agent",
                )
            ]
        }
    )
    [result] = LinearImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "agent_authored_issue"
    )
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"


def test_priority_escalation_by_bot_flags() -> None:
    """Issue.update with priority=1 by bot/agent → PR-02 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-priority-up",
                    type="Issue",
                    action="update",
                    actor_id="bot-1",
                    actor_is_bot=True,
                    trigger="agent",
                    data={
                        "issueId": "iss-1",
                        "issueIdentifier": "ENG-7",
                        "priority": 1,
                        "previousPriority": 3,
                        "stateType": "started",
                        "teamId": "team-1",
                        "teamKey": "ENG",
                    },
                )
            ]
        }
    )
    [result] = LinearImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "priority_escalation_by_bot"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data.get("priority") == 1


def test_state_regression_flags() -> None:
    """Issue.update from started/completed → backlog → PR-05 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-regression",
                    type="Issue",
                    action="update",
                    data={
                        "issueId": "iss-1",
                        "issueIdentifier": "ENG-8",
                        "priority": 3,
                        "stateType": "backlog",
                        "previousStateType": "started",
                        "teamId": "team-1",
                    },
                )
            ]
        }
    )
    [result] = LinearImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "issue_state_regression"
    )
    assert cr.control_id == "PR-05"
    assert cr.result == "FLAG"


def test_in_progress_issue_remove_fails_audit_destruction() -> None:
    """Issue.remove of in-progress (started/completed) issue → PR-02 FAIL, BLOCK."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-remove-started",
                    type="Issue",
                    action="remove",
                    actor_id="bot-1",
                    actor_is_bot=True,
                    data={
                        "issueId": "iss-99",
                        "issueIdentifier": "ENG-99",
                        "stateType": "started",
                        "teamId": "team-1",
                    },
                )
            ]
        }
    )
    [result] = LinearImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "issue_remove_in_progress"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Comment lifecycle
# ---------------------------------------------------------------------------


def test_bot_comment_on_high_priority_flags() -> None:
    """Comment.create by bot on priority 1 or 2 issue → PR-01 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-bot-comment",
                    type="Comment",
                    action="create",
                    actor_id="bot-1",
                    actor_is_bot=True,
                    data={
                        "issueId": "iss-1",
                        "issueIdentifier": "ENG-2",
                        "priority": 1,
                        "stateType": "started",
                        "teamId": "team-1",
                    },
                )
            ]
        }
    )
    [result] = LinearImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "bot_comment_high_priority"
    )
    assert cr.control_id == "PR-01"


# ---------------------------------------------------------------------------
# Team / Attachment / Trigger
# ---------------------------------------------------------------------------


def test_team_permission_change_flags() -> None:
    """Team.update with permission change → PR-02 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-team-perm",
                    type="Team",
                    action="update",
                    data={
                        "teamId": "team-1",
                        "teamKey": "ENG",
                        "permissionChanged": True,
                        "oldPermission": "member",
                        "newPermission": "admin",
                    },
                )
            ]
        }
    )
    [result] = LinearImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "team_permission_change"
    )
    assert cr.control_id == "PR-02"
    assert cr.evidence_data.get("new_permission") == "admin"


def test_external_attachment_flags() -> None:
    """Attachment.create with external host not in allowlist → PR-04 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-attachment",
                    type="Attachment",
                    action="create",
                    data={
                        "issueId": "iss-1",
                        "issueIdentifier": "ENG-3",
                        "url": "https://evil.example.com/leak.zip",
                        "teamId": "team-1",
                    },
                )
            ]
        }
    )
    [result] = LinearImporter(allowlist_attachment_hosts=["company.com"]).parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "external_attachment"
    )
    assert cr.control_id == "PR-04"
    assert cr.evidence_data.get("attachment_host") == "evil.example.com"


def test_webhook_trigger_flags_external() -> None:
    """trigger=webhook → PR-01 FLAG (external trigger — verify provenance)."""
    doc = json.dumps(
        {
            "events": [
                _event(id="evt-webhook", trigger="webhook"),
            ]
        }
    )
    [result] = LinearImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "trigger_webhook"
    )
    assert cr.control_id == "PR-01"


def test_automation_trigger_passes() -> None:
    """trigger=automation → PR-05 PASS (audit trail of automation)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-automation",
                    type="Issue",
                    action="archive",
                    trigger="automation",
                    data={
                        "issueId": "iss-1",
                        "issueIdentifier": "ENG-4",
                        "stateType": "completed",
                        "teamId": "team-1",
                    },
                ),
            ]
        }
    )
    [result] = LinearImporter().parse_string(doc)
    # Issue.archive PASS + trigger_automation PASS → ALLOW.
    assert result.decision == "ALLOW"
    signals = [cr.evidence_data.get("signal") for cr in result.control_results]
    assert "trigger_automation" in signals
    assert "issue_archive" in signals


# ---------------------------------------------------------------------------
# Long-content / synthetic patterns
# ---------------------------------------------------------------------------


def test_long_description_flags() -> None:
    """Issue with description_length > threshold → PR-04 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-long-desc",
                    type="Issue",
                    action="create",
                    actor_id="bot-1",
                    actor_is_bot=True,
                    data={
                        "issueId": "iss-1",
                        "issueIdentifier": "ENG-5",
                        "title_length": 50,
                        "description_length": 25000,
                        "priority": 3,
                        "stateType": "backlog",
                        "teamId": "team-1",
                    },
                )
            ]
        }
    )
    [result] = LinearImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "long_description"
    )
    assert cr.control_id == "PR-04"


def test_bot_velocity_synthetic() -> None:
    """Bot creating > N issues in 1h window yields a synthetic PR-02 FLAG."""
    bot = "bot-velocity-1"
    events = [
        _event(
            id=f"evt-{i}",
            type="Issue",
            action="create",
            actor_id=bot,
            actor_is_bot=True,
            trigger="agent",
            created_at=f"2026-04-01T12:{i:02d}:00Z",
            data={
                "issueId": f"iss-{i}",
                "issueIdentifier": f"ENG-{i}",
                "priority": 3,
                "stateType": "backlog",
                "teamId": "team-1",
                "teamKey": "ENG",
            },
        )
        for i in range(25)
    ]
    doc = json.dumps({"events": events})
    results = LinearImporter(bot_velocity_threshold=20).parse_string(doc)
    synthetic = [
        r
        for r in results
        if r.action_id == f"linear-bot-velocity-{bot}"
    ]
    assert len(synthetic) == 1
    cr = synthetic[0].control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data.get("synthetic") is True
    assert cr.evidence_data.get("bot_velocity_count") >= 21


def test_cross_team_synthetic() -> None:
    """Bot touching > N teams yields a synthetic PR-02 FLAG."""
    bot = "bot-cross-team-1"
    events = [
        _event(
            id=f"evt-team-{i}",
            type="Issue",
            action="create",
            actor_id=bot,
            actor_is_bot=True,
            trigger="agent",
            data={
                "issueId": f"iss-{i}",
                "issueIdentifier": f"ENG-{i}",
                "priority": 3,
                "stateType": "backlog",
                "teamId": f"team-{i}",
                "teamKey": f"T{i}",
            },
        )
        for i in range(7)
    ]
    doc = json.dumps({"events": events})
    results = LinearImporter(cross_team_threshold=5).parse_string(doc)
    synthetic = [
        r
        for r in results
        if r.action_id == f"linear-cross-team-{bot}"
    ]
    assert len(synthetic) == 1
    cr = synthetic[0].control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data.get("cross_team_team_count") == 7


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def test_email_only_domain_stored() -> None:
    """actorEmail is reduced to ``@domain`` only; no full address retained."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-email",
                    actor_email="alice.smith@acme.example.com",
                ),
            ]
        }
    )
    [result] = LinearImporter().parse_string(doc)
    cr = result.control_results[0]
    assert cr.evidence_data.get("actor_email_domain") == "@acme.example.com"
    # Full email never appears anywhere in evidence.
    raw = json.dumps(cr.evidence_data)
    assert "alice.smith@acme.example.com" not in raw
    assert "alice.smith" not in raw
    # actor_name_redacted carries length+sha256, not the raw name.
    redacted = cr.evidence_data.get("actor_name_redacted")
    assert isinstance(redacted, dict)
    assert "sha256" in redacted and "length" in redacted
    assert "Kevin Bauer" not in raw


def test_label_ids_count_only_stored() -> None:
    """labelIds raw values are NOT stored — only the count is captured."""
    labels = ["customer-acme", "internal-only", "pii-suspect"]
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-labels",
                    data={
                        "issueId": "iss-1",
                        "issueIdentifier": "ENG-6",
                        "priority": 3,
                        "stateType": "backlog",
                        "labelIds": labels,
                        "teamId": "team-1",
                    },
                ),
            ]
        }
    )
    [result] = LinearImporter().parse_string(doc)
    cr = result.control_results[0]
    assert cr.evidence_data.get("label_ids_count") == len(labels)
    raw = json.dumps(cr.evidence_data)
    for lbl in labels:
        assert lbl not in raw


# ---------------------------------------------------------------------------
# Bonus: parse-from-disk + provenance hash, JSONL shape
# ---------------------------------------------------------------------------


def test_parse_from_disk_hashes_file(tmp_path: Path) -> None:
    """parse(path) records source provenance with sha256 of the file."""
    payload = json.dumps({"events": [_event(id="evt-disk")]})
    path = tmp_path / "linear-export.json"
    path.write_text(payload)
    expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    [result] = LinearImporter().parse(path)
    cr = result.control_results[0]
    prov = cr.evidence_data["source_provenance"]
    assert prov["source_format"] == "linear_audit_log"
    assert prov["source_tool_name"] == "linear"
    assert prov["original_file_sha256"] == expected


def test_jsonl_envelope_is_supported() -> None:
    """JSONL: one event per line, mixed shapes."""
    lines = "\n".join(
        [
            json.dumps(_event(id="evt-jsonl-1")),
            json.dumps(_event(id="evt-jsonl-2", trigger="webhook")),
        ]
    )
    results = LinearImporter().parse_string(lines)
    assert len(results) == 2
    actions = {r.action_id for r in results}
    assert actions == {"linear-evt-jsonl-1", "linear-evt-jsonl-2"}
