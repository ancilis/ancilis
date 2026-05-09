"""Tests for the Discord audit-log importer."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ancilis.importers.discord import DiscordImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Discord audit_log_entries (no discord.py dependency)
# ---------------------------------------------------------------------------


def _entry(
    *,
    id: str = "1234567890",
    action_type: int = 22,
    user_id: str | None = "USER_ALICE",
    target_id: str | None = "TGT_BOB",
    created_at: str = "2026-05-09T12:00:00Z",
    actor_kind: str | None = None,
    user_bot: bool | None = None,
    changes: list[dict[str, Any]] | None = None,
    reason: str | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": id,
        "action_type": action_type,
        "created_at": created_at,
    }
    if user_id is not None:
        out["user_id"] = user_id
    if target_id is not None:
        out["target_id"] = target_id
    if actor_kind is not None:
        out["actor_kind"] = actor_kind
    if user_bot is not None:
        out["user"] = {"id": user_id, "bot": user_bot}
    if changes is not None:
        out["changes"] = changes
    if reason is not None:
        out["reason"] = reason
    if options is not None:
        out["options"] = options
    return out


def _envelope(entries: list[dict[str, Any]]) -> str:
    return json.dumps({"audit_log_entries": entries})


# ---------------------------------------------------------------------------
# Per-action-type tests
# ---------------------------------------------------------------------------


def test_member_ban_add_passes() -> None:
    """action_type=22 (MEMBER_BAN_ADD) → PR-05 PASS audit-trail capture."""
    doc = _envelope([_entry(action_type=22, reason="repeat ToS violations")])
    [result] = DiscordImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    [cr] = result.control_results
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "member_ban_add"
    assert cr.evidence_data["action_type"] == 22
    assert cr.evidence_data["action_type_name"] == "MEMBER_BAN_ADD"


def test_bot_kick_fails() -> None:
    """action_type=20 (MEMBER_KICK) by bot actor → PR-02 FAIL."""
    doc = _envelope([
        _entry(
            action_type=20,
            actor_kind="bot",
            user_id="BOT_AUTOMOD",
            user_bot=True,
        )
    ])
    [result] = DiscordImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    [cr] = result.control_results
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "bot_member_kick"
    assert cr.evidence_data["actor_kind"] == "bot"


def test_user_kick_passes() -> None:
    """action_type=20 (MEMBER_KICK) by human actor → PR-05 PASS."""
    doc = _envelope([_entry(action_type=20, user_id="USER_MOD")])
    [result] = DiscordImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    [cr] = result.control_results
    assert cr.evidence_data["signal"] == "member_kick"
    assert cr.result == "PASS"


def test_mass_prune_fails() -> None:
    """action_type=21 with options.members_removed > threshold → PR-02 FAIL."""
    doc = _envelope([
        _entry(
            action_type=21,
            options={"members_removed": "120", "delete_member_days": "30"},
        )
    ])
    [result] = DiscordImporter(mass_prune_threshold=50).parse_string(doc)
    assert result.decision == "BLOCK"
    [cr] = result.control_results
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "mass_member_prune"
    assert cr.evidence_data["options_members_removed"] == 120
    assert cr.evidence_data["options_delete_member_days"] == 30


def test_small_prune_passes() -> None:
    """action_type=21 with members_removed ≤ threshold → PR-05 PASS."""
    doc = _envelope([
        _entry(action_type=21, options={"members_removed": "5"})
    ])
    [result] = DiscordImporter(mass_prune_threshold=50).parse_string(doc)
    assert result.decision == "ALLOW"
    [cr] = result.control_results
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "member_prune_small"


def test_admin_role_grant_fails() -> None:
    """action_type=25 granting admin/moderator role → PR-02 FAIL."""
    doc = _envelope([
        _entry(
            action_type=25,
            target_id="USR_NEW",
            changes=[
                {
                    "key": "$add",
                    "new_value": [
                        {"id": "ROLE_ADMIN", "name": "Server Admin"}
                    ],
                }
            ],
        )
    ])
    [result] = DiscordImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    [cr] = result.control_results
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "privileged_role_grant"
    # Privileged-name VALUE should NOT appear anywhere in the evidence.
    blob = json.dumps(cr.evidence_data)
    assert "Server Admin" not in blob


def test_bot_add_flags() -> None:
    """action_type=28 (BOT_ADD) → PR-01 FLAG (new automation surface)."""
    doc = _envelope([_entry(action_type=28, target_id="BOT_NEW")])
    [result] = DiscordImporter().parse_string(doc)
    assert result.decision == "FLAG"
    [cr] = result.control_results
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "bot_add"


def test_channel_delete_flags() -> None:
    """action_type=12 (CHANNEL_DELETE) → PR-02 FLAG (audit completeness)."""
    doc = _envelope([_entry(action_type=12, target_id="CHAN_DEAD")])
    [result] = DiscordImporter().parse_string(doc)
    assert result.decision == "FLAG"
    [cr] = result.control_results
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "channel_delete"


def test_unlimited_invite_flags() -> None:
    """action_type=40 with max_uses=0 (unlimited) → PR-04 FLAG."""
    doc = _envelope([
        _entry(
            action_type=40,
            target_id="INV_PUBLIC",
            changes=[{"key": "max_uses", "new_value": 0}],
        )
    ])
    [result] = DiscordImporter().parse_string(doc)
    assert result.decision == "FLAG"
    [cr] = result.control_results
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "unlimited_invite_create"


def test_capped_invite_passes() -> None:
    """action_type=40 with max_uses>0 → PR-05 PASS."""
    doc = _envelope([
        _entry(
            action_type=40,
            changes=[{"key": "max_uses", "new_value": 25}],
        )
    ])
    [result] = DiscordImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    [cr] = result.control_results
    assert cr.evidence_data["signal"] == "invite_create_capped"


def test_webhook_create_flags() -> None:
    """action_type=50 (WEBHOOK_CREATE) → PR-01 FLAG (external surface)."""
    doc = _envelope([_entry(action_type=50, target_id="WH_NEW")])
    [result] = DiscordImporter().parse_string(doc)
    assert result.decision == "FLAG"
    [cr] = result.control_results
    assert cr.control_id == "PR-01"
    assert cr.evidence_data["signal"] == "webhook_create"


def test_webhook_url_change_flags() -> None:
    """action_type=51 changing 'url' key → PR-04 FLAG."""
    doc = _envelope([
        _entry(
            action_type=51,
            target_id="WH_X",
            changes=[
                {
                    "key": "url",
                    "old_value": "https://hooks.example.com/old",
                    "new_value": "https://attacker.example.com/new",
                }
            ],
        )
    ])
    [result] = DiscordImporter().parse_string(doc)
    assert result.decision == "FLAG"
    [cr] = result.control_results
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "webhook_url_change"
    # URL VALUES must NOT be stored.
    blob = json.dumps(cr.evidence_data)
    assert "attacker.example.com" not in blob
    assert "hooks.example.com" not in blob
    # change_keys IS stored.
    assert "url" in cr.evidence_data["change_keys"]


def test_mass_message_bulk_delete_fails() -> None:
    """action_type=73 (MESSAGE_BULK_DELETE) count > threshold → PR-02 FAIL."""
    doc = _envelope([
        _entry(
            action_type=73,
            target_id="CHAN_X",
            options={"count": "500", "channel_id": "CHAN_X"},
        )
    ])
    [result] = DiscordImporter(mass_bulk_delete_threshold=100).parse_string(doc)
    assert result.decision == "BLOCK"
    [cr] = result.control_results
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "mass_message_bulk_delete"
    assert cr.evidence_data["options_count"] == 500


def test_integration_create_flags() -> None:
    """action_type=80 (INTEGRATION_CREATE) → PR-01 FLAG."""
    doc = _envelope([_entry(action_type=80, target_id="INT_NEW")])
    [result] = DiscordImporter().parse_string(doc)
    assert result.decision == "FLAG"
    [cr] = result.control_results
    assert cr.control_id == "PR-01"
    assert cr.evidence_data["signal"] == "integration_create"


def test_automod_block_passes() -> None:
    """action_type=143 (AUTO_MODERATION_BLOCK_MESSAGE) → PR-05 PASS."""
    doc = _envelope([
        _entry(
            action_type=143,
            user_id="BOT_AUTOMOD_RULE_OWNER",
            options={"automod_rule_trigger_type": 1, "channel_id": "CH"},
        )
    ])
    [result] = DiscordImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    [cr] = result.control_results
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "automod_block_message"
    assert cr.evidence_data["automod_rule_trigger_type"] == 1


def test_automod_quarantine_passes() -> None:
    """action_type=146 (AUTO_MODERATION_QUARANTINE_USER) → PR-04 PASS."""
    doc = _envelope([
        _entry(
            action_type=146,
            user_id="BOT_AUTOMOD",
            target_id="USER_BAD",
            options={"automod_rule_trigger_type": 4},
        )
    ])
    [result] = DiscordImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    [cr] = result.control_results
    assert cr.control_id == "PR-04"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "automod_quarantine_user"


def test_clyde_ai_enabled_captured() -> None:
    """action_type=201 (CLYDE_AI_ENABLED) → captured as PR-05 PASS."""
    doc = _envelope([_entry(action_type=201, target_id="GUILD_X")])
    [result] = DiscordImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    [cr] = result.control_results
    assert cr.evidence_data["signal"] == "clyde_ai_enabled"
    assert cr.evidence_data["action_type_name"] == "CLYDE_AI_ENABLED"


# ---------------------------------------------------------------------------
# Synthetic findings
# ---------------------------------------------------------------------------


def test_bot_action_burst_synthetic() -> None:
    """Bot actor with > threshold actions in a 1h window → synthetic PR-02 FLAG."""
    base = datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)
    entries = []
    # 6 actions, threshold=5 → trigger.
    for i in range(6):
        entries.append(
            _entry(
                id=f"E{i}",
                action_type=72,  # MESSAGE_DELETE
                user_id="BOT_SPAM",
                actor_kind="bot",
                target_id=f"MSG_{i}",
                created_at=(base + timedelta(seconds=i * 30)).isoformat(),
            )
        )
    doc = _envelope(entries)
    results = DiscordImporter(
        bot_action_burst_threshold=5,
        bot_action_burst_window_seconds=3600,
    ).parse_string(doc)
    # 6 per-entry + 1 burst synthetic. Mass-message-delete pattern requires
    # threshold > 200 by default — 6 deletes shouldn't trigger that one.
    synthetic = [
        r for r in results
        if r.action_id.startswith("discord-bot-burst-")
    ]
    assert len(synthetic) == 1
    [cr] = synthetic[0].control_results
    assert cr.control_id == "PR-02"
    assert cr.evidence_data["signal"] == "bot_action_burst_pattern"
    assert cr.evidence_data["burst_action_count"] == 6
    assert cr.evidence_data["burst_threshold"] == 5
    assert cr.evidence_data["synthetic"] is True
    # Per-entry burst marker also present on each entry.
    per_entry_markers = [
        r for r in results
        if not r.action_id.startswith("discord-bot-burst-")
        and any(
            c.evidence_data.get("signal") == "bot_action_burst_pattern"
            for c in r.control_results
        )
    ]
    assert len(per_entry_markers) == 6


def test_mass_message_delete_synthetic() -> None:
    """Same actor with > threshold MESSAGE_DELETE in window → PR-04 FLAG synthetic."""
    base = datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)
    entries = []
    for i in range(11):
        entries.append(
            _entry(
                id=f"D{i}",
                action_type=72,
                user_id="USER_REDACTOR",
                target_id=f"MSG_{i}",
                created_at=(base + timedelta(seconds=i * 60)).isoformat(),
            )
        )
    doc = _envelope(entries)
    # mass-message-delete threshold lowered to 10; bot-burst raised so it
    # doesn't fire (actor is human).
    results = DiscordImporter(
        mass_message_delete_threshold=10,
        mass_message_delete_window_seconds=3600,
        bot_action_burst_threshold=1000,
    ).parse_string(doc)
    synthetic = [
        r for r in results
        if r.action_id.startswith("discord-mass-msg-delete-")
    ]
    assert len(synthetic) == 1
    [cr] = synthetic[0].control_results
    assert cr.control_id == "PR-04"
    assert cr.evidence_data["signal"] == "mass_message_delete_pattern"
    assert cr.evidence_data["delete_count"] == 11
    assert cr.evidence_data["delete_threshold"] == 10
    assert cr.evidence_data["synthetic"] is True


# ---------------------------------------------------------------------------
# Sanitization tests
# ---------------------------------------------------------------------------


def test_change_values_not_stored() -> None:
    """changes[].old_value / new_value are NEVER stored — only key names."""
    doc = _envelope([
        _entry(
            action_type=11,  # CHANNEL_UPDATE
            target_id="CHAN_X",
            changes=[
                {
                    "key": "topic",
                    "old_value": "Welcome to #acme-acquisition-q3",
                    "new_value": "Welcome to #acme-acquisition-q4",
                },
                {
                    "key": "name",
                    "old_value": "general",
                    "new_value": "merger-2026",
                },
            ],
        )
    ])
    [result] = DiscordImporter().parse_string(doc)
    [cr] = result.control_results
    blob = json.dumps(cr.evidence_data)
    # Sensitive values must NOT appear.
    assert "acme-acquisition" not in blob
    assert "merger-2026" not in blob
    # Only the change KEYS should be captured.
    assert sorted(cr.evidence_data["change_keys"]) == ["name", "topic"]


def test_reason_redacted() -> None:
    """``reason`` is reduced to {length, sha256} — raw text NEVER stored."""
    sensitive_reason = (
        "Banning user because they leaked the Q4 acquisition target "
        "list to a competitor on 2026-05-08 — IR-2026-0042."
    )
    doc = _envelope([_entry(action_type=22, reason=sensitive_reason)])
    [result] = DiscordImporter().parse_string(doc)
    [cr] = result.control_results
    redacted = cr.evidence_data["reason_redacted"]
    assert isinstance(redacted, dict)
    assert redacted["length"] == len(sensitive_reason)
    assert redacted["sha256"] == hashlib.sha256(
        sensitive_reason.encode("utf-8")
    ).hexdigest()
    # Raw text MUST NOT leak into evidence.
    blob = json.dumps(cr.evidence_data)
    assert "acquisition" not in blob
    assert "IR-2026" not in blob
    assert "competitor" not in blob


def test_role_name_redacted() -> None:
    """``options.role_name`` reduced to {length, sha256} — raw NEVER stored."""
    doc = _envelope([
        _entry(
            action_type=14,  # CHANNEL_OVERWRITE_CREATE
            target_id="CH_EXEC",
            options={
                "type": "role",
                "role_name": "Founders Circle (Q4-2026 cohort)",
            },
        )
    ])
    [result] = DiscordImporter().parse_string(doc)
    [cr] = result.control_results
    redacted = cr.evidence_data["options_role_name_redacted"]
    assert isinstance(redacted, dict)
    assert redacted["length"] == len("Founders Circle (Q4-2026 cohort)")
    blob = json.dumps(cr.evidence_data)
    assert "Founders Circle" not in blob


# ---------------------------------------------------------------------------
# Envelope / format support
# ---------------------------------------------------------------------------


def test_jsonl_envelope_supported() -> None:
    """JSONL — one entry per line — is supported."""
    lines = [
        json.dumps(_entry(id="A", action_type=22)),
        json.dumps(_entry(id="B", action_type=28, target_id="BOT_X")),
    ]
    results = DiscordImporter().parse_string("\n".join(lines))
    assert len(results) == 2
    assert results[0].action_id == "discord-A"
    assert results[1].action_id == "discord-B"


def test_data_envelope_supported() -> None:
    """``{"data":[...]}`` envelope is supported."""
    doc = json.dumps({"data": [_entry(id="X", action_type=22)]})
    [result] = DiscordImporter().parse_string(doc)
    assert result.action_id == "discord-X"


def test_events_envelope_supported() -> None:
    """``{"events":[...]}`` envelope is supported."""
    doc = json.dumps({"events": [_entry(id="Y", action_type=28)]})
    [result] = DiscordImporter().parse_string(doc)
    assert result.action_id == "discord-Y"


def test_parse_file_hashes_source(tmp_path: Path) -> None:
    """Parsing a file populates source_provenance.original_file_sha256."""
    path = tmp_path / "audit.json"
    body = _envelope([_entry(action_type=22)]).encode("utf-8")
    path.write_bytes(body)
    [result] = DiscordImporter().parse(path)
    [cr] = result.control_results
    expected = hashlib.sha256(body).hexdigest()
    assert cr.evidence_data["source_provenance"]["original_file_sha256"] == expected


def test_unknown_action_type_flagged() -> None:
    """Unmapped action_type → PR-05 FLAG (surfaced for review)."""
    doc = _envelope([_entry(action_type=999, target_id="X")])
    [result] = DiscordImporter().parse_string(doc)
    assert result.decision == "FLAG"
    [cr] = result.control_results
    assert cr.control_id == "PR-05"
    assert cr.evidence_data["signal"] == "unknown_action_type"
    assert cr.evidence_data["action_type_name"] == "ACTION_TYPE_999"
