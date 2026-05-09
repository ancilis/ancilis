"""Tests for the Microsoft Teams audit-log importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ancilis.importers.microsoft_teams import MicrosoftTeamsImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Microsoft Graph audit events (no microsoft-graph-core)
# ---------------------------------------------------------------------------


def _event(
    *,
    id: str = "evt-001",
    activity_dt: str = "2026-05-09T12:00:00Z",
    activity: str = "MessageSent",
    actor_type: str = "app",
    actor_id: str = "ACT_BOT_1",
    actor_email: str | None = "agent-bot@corp.example.com",
    target_id: str = "TGT_PUBLIC",
    target_type: str = "channel",
    target_name: str | None = None,
    target_name_length: int | None = 50,
    target_is_external: bool | None = False,
    target_is_private: bool | None = False,
    team_id: str | None = "TEAM_A",
    channel_type: str | None = "standard",
    tenant_id: str | None = "TENANT_X",
    tenant_primary_domain: str | None = "corp.example.com",
    ip: str | None = "203.0.113.42",
    app_id: str | None = None,
    bot_id: str | None = None,
    file_size_bytes: int | None = None,
    file_extension: str | None = None,
    has_link: bool | None = None,
    link_target_domain: str | None = None,
    dlp_rule: str | None = None,
    new_role: str | None = None,
) -> dict[str, Any]:
    actor: dict[str, Any] = {"type": actor_type, "id": actor_id}
    if actor_email is not None:
        actor["email"] = actor_email

    target: dict[str, Any] = {"id": target_id, "type": target_type}
    if target_name is not None:
        target["name"] = target_name
    if target_name_length is not None:
        target["name_length"] = target_name_length
    if target_is_external is not None:
        target["is_external"] = target_is_external
    if target_is_private is not None:
        target["is_private"] = target_is_private

    ctx: dict[str, Any] = {}
    if team_id is not None:
        ctx["team_id"] = team_id
    if channel_type is not None:
        ctx["channel_type"] = channel_type
    if tenant_id is not None:
        ctx["tenant_id"] = tenant_id
    if tenant_primary_domain is not None:
        ctx["tenant_primary_domain"] = tenant_primary_domain
    if ip is not None:
        ctx["ip"] = ip

    details: dict[str, Any] = {}
    if app_id is not None:
        details["app_id"] = app_id
    if bot_id is not None:
        details["bot_id"] = bot_id
    if file_size_bytes is not None:
        details["file_size_bytes"] = file_size_bytes
    if file_extension is not None:
        details["file_extension"] = file_extension
    if has_link is not None:
        details["has_link"] = has_link
    if link_target_domain is not None:
        details["link_target_domain"] = link_target_domain
    if dlp_rule is not None:
        details["dlp_rule"] = dlp_rule
    if new_role is not None:
        details["new_role"] = new_role

    return {
        "id": id,
        "activityDateTime": activity_dt,
        "activityDisplayName": activity,
        "actor": actor,
        "target": target,
        "context": ctx,
        "details": details,
    }


def _findings_for_event(results: list, event_id: str) -> list:
    return [r for r in results if r.action_id == f"teams-{event_id}"]


# ---------------------------------------------------------------------------
# Activity-pattern semantics
# ---------------------------------------------------------------------------


def test_message_sent_by_bot_to_public_channel_audit() -> None:
    """MessageSent by app/bot to public/standard channel → PR-04 PASS."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-msg",
                    activity="MessageSent",
                    actor_type="app",
                    channel_type="standard",
                )
            ]
        }
    )
    [result] = MicrosoftTeamsImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "microsoft_teams_import"
    assert result.action_id == "teams-evt-msg"
    [cr] = result.control_results
    assert cr.control_id == "PR-04"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "agent_message_sent"
    assert cr.evidence_data["activity"] == "MessageSent"
    assert cr.evidence_data["actor_type"] == "app"


def test_message_sent_by_bot_with_external_link_flags() -> None:
    """Bot MessageSent with has_link=true & external link_target_domain → PR-04 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-link",
                    activity="MessageSent",
                    actor_type="bot",
                    channel_type="standard",
                    has_link=True,
                    link_target_domain="external-attacker.com",
                    tenant_primary_domain="corp.example.com",
                )
            ]
        }
    )
    [result] = MicrosoftTeamsImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flag_crs = [cr for cr in result.control_results if cr.result == "FLAG"]
    assert any(
        cr.control_id == "PR-04"
        and cr.evidence_data["signal"] == "agent_message_external_link"
        for cr in flag_crs
    )


def test_file_shared_externally_blocks_top_priority() -> None:
    """FileSharedExternally → DE-01 FAIL → BLOCK (top-priority exfil)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-exfil",
                    activity="FileSharedExternally",
                    actor_type="user",
                    target_id="FILE_LEAK",
                    target_type="file",
                    target_is_external=True,
                    file_extension=".csv",
                    file_size_bytes=987654,
                )
            ]
        }
    )
    [result] = MicrosoftTeamsImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fail_crs = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.control_id == "DE-01"
        and cr.evidence_data["signal"] == "file_shared_externally"
        for cr in fail_crs
    )


def test_meeting_recording_shared_external_blocks() -> None:
    """MeetingRecordingShared with target.is_external=true → DE-01 FAIL → BLOCK."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-rec",
                    activity="MeetingRecordingShared",
                    actor_type="user",
                    target_id="REC_LEAK",
                    target_type="file",
                    target_is_external=True,
                )
            ]
        }
    )
    [result] = MicrosoftTeamsImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fail_crs = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.control_id == "DE-01"
        and cr.evidence_data["signal"] == "meeting_recording_shared_external"
        for cr in fail_crs
    )


def test_guest_added_to_team_flags() -> None:
    """GuestAddedToTeam → PR-02 FLAG (external guest joining is review surface)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-guest",
                    activity="GuestAddedToTeam",
                    actor_type="user",
                    target_id="USR_GUEST",
                    target_type="user",
                    target_is_external=True,
                )
            ]
        }
    )
    [result] = MicrosoftTeamsImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flag_crs = [cr for cr in result.control_results if cr.result == "FLAG"]
    assert any(
        cr.control_id == "PR-02"
        and cr.evidence_data["signal"] == "guest_added_to_team"
        for cr in flag_crs
    )


def test_member_added_owner_role_fails() -> None:
    """MemberAddedToTeam with new_role=Owner → PR-02 FAIL → BLOCK."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-owner",
                    activity="MemberAddedToTeam",
                    actor_type="user",
                    target_id="USR_NEW_OWNER",
                    target_type="user",
                    new_role="Owner",
                )
            ]
        }
    )
    [result] = MicrosoftTeamsImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fail_crs = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.control_id == "PR-02"
        and cr.evidence_data["signal"] == "owner_role_grant"
        for cr in fail_crs
    )


def test_app_installed_flags_new_automation_surface() -> None:
    """AppInstalled to a team → PR-01 FLAG (new automation surface)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-app",
                    activity="AppInstalled",
                    actor_type="user",
                    target_id="APP_NEW",
                    target_type="app",
                    app_id="com.acme.unverified",
                )
            ]
        }
    )
    [result] = MicrosoftTeamsImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flag_crs = [cr for cr in result.control_results if cr.result == "FLAG"]
    assert any(
        cr.control_id == "PR-01"
        and cr.evidence_data["signal"] == "app_installed"
        for cr in flag_crs
    )
    cr = next(c for c in flag_crs if c.evidence_data["signal"] == "app_installed")
    assert cr.evidence_data["app_id"] == "com.acme.unverified"


def test_policy_changed_fails_tenant_admin_event() -> None:
    """PolicyChanged on tenant → PR-02 FAIL → BLOCK (admin policy modification)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-policy",
                    activity="PolicyChanged",
                    actor_type="user",
                    target_id="POLICY_GLOBAL",
                    target_type="team",
                )
            ]
        }
    )
    [result] = MicrosoftTeamsImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fail_crs = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.control_id == "PR-02"
        and cr.evidence_data["signal"] == "tenant_policy_changed"
        for cr in fail_crs
    )


def test_dlp_pii_detected_fails() -> None:
    """DLPRuleMatched with dlp_rule=PII_DETECTED → PR-04 FAIL (DLP caught PII)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-dlp",
                    activity="DLPRuleMatched",
                    actor_type="bot",
                    target_id="MSG_PII",
                    target_type="chat",
                    dlp_rule="PII_DETECTED",
                )
            ]
        }
    )
    [result] = MicrosoftTeamsImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fail_crs = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.control_id == "PR-04"
        and cr.evidence_data["signal"] == "dlp_pii_detected"
        for cr in fail_crs
    )
    cr = next(
        c for c in fail_crs if c.evidence_data["signal"] == "dlp_pii_detected"
    )
    assert cr.evidence_data["dlp_rule"] == "PII_DETECTED"


def test_shared_channel_bot_flags_cross_tenant_surface() -> None:
    """channel_type=shared with bot actor → PR-04 FLAG (cross-tenant surface)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-shared",
                    activity="MessageSent",
                    actor_type="bot",
                    channel_type="shared",
                    has_link=False,
                )
            ]
        }
    )
    [result] = MicrosoftTeamsImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flag_crs = [cr for cr in result.control_results if cr.result == "FLAG"]
    assert any(
        cr.control_id == "PR-04"
        and cr.evidence_data["signal"] == "shared_channel_bot_activity"
        for cr in flag_crs
    )


def test_bot_added_to_conversation_flags() -> None:
    """BotAddedToConversation → PR-01 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-bot",
                    activity="BotAddedToConversation",
                    actor_type="user",
                    target_id="BOT_NEW",
                    target_type="app",
                    bot_id="bot-acme",
                )
            ]
        }
    )
    [result] = MicrosoftTeamsImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flag_crs = [cr for cr in result.control_results if cr.result == "FLAG"]
    assert any(
        cr.control_id == "PR-01"
        and cr.evidence_data["signal"] == "bot_added_to_conversation"
        for cr in flag_crs
    )


def test_system_actor_passes_audit() -> None:
    """actor.type=system → PR-05 PASS (Microsoft-internal event)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-sys",
                    activity="PolicyChanged",
                    actor_type="system",
                )
            ]
        }
    )
    [result] = MicrosoftTeamsImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    [cr] = result.control_results
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "system_actor_event"


# ---------------------------------------------------------------------------
# Cross-actor patterns
# ---------------------------------------------------------------------------


def test_cross_team_pattern_synthetic() -> None:
    """One bot acting in > cross_team_threshold teams → synthetic PR-02 FLAG."""
    events = [
        _event(
            id=f"evt-spread-{i}",
            activity="MessageSent",
            actor_type="bot",
            actor_id="ACT_BOT_SPREAD",
            team_id=f"TEAM_{i:02d}",
            tenant_id="TENANT_X",
        )
        for i in range(7)
    ]
    doc = json.dumps({"events": events})
    results = MicrosoftTeamsImporter(cross_team_threshold=5).parse_string(doc)

    # 7 per-event + 1 synthetic cross-team = 8 total.
    assert len(results) == 8
    synthetic = [
        r for r in results if r.action_id == "teams-cross-team-ACT_BOT_SPREAD"
    ]
    assert len(synthetic) == 1
    [cr] = synthetic[0].control_results
    assert cr.control_id == "PR-02"
    assert cr.evidence_data["signal"] == "cross_team_pattern"
    assert cr.evidence_data["cross_team_count"] == 7
    assert cr.evidence_data["cross_team_threshold"] == 5
    assert cr.evidence_data["synthetic"] is True

    contributing = _findings_for_event(results, "evt-spread-0")
    [per_event] = contributing
    assert any(
        c.evidence_data["signal"] == "cross_team_pattern"
        for c in per_event.control_results
    )


def test_cross_tenant_pattern_synthetic() -> None:
    """Same actor across multiple tenant_id values → synthetic PR-02 FLAG."""
    events = [
        _event(
            id="evt-tA",
            activity="MessageSent",
            actor_type="bot",
            actor_id="ACT_BOT_MULTI",
            tenant_id="TENANT_A",
            team_id="TEAM_A",
        ),
        _event(
            id="evt-tB",
            activity="MessageSent",
            actor_type="bot",
            actor_id="ACT_BOT_MULTI",
            tenant_id="TENANT_B",
            team_id="TEAM_B",
        ),
    ]
    doc = json.dumps({"events": events})
    results = MicrosoftTeamsImporter().parse_string(doc)
    synthetic = [
        r for r in results if r.action_id == "teams-cross-tenant-ACT_BOT_MULTI"
    ]
    assert len(synthetic) == 1
    [cr] = synthetic[0].control_results
    assert cr.control_id == "PR-02"
    assert cr.evidence_data["signal"] == "cross_tenant_pattern"
    assert cr.evidence_data["cross_tenant_count"] == 2
    assert sorted(cr.evidence_data["cross_tenant_tenants"]) == [
        "TENANT_A",
        "TENANT_B",
    ]


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def test_email_only_domain_stored() -> None:
    """actor.email reduced to '@domain' — local-part NEVER stored."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-email",
                    activity="MessageSent",
                    actor_type="user",
                    actor_email="alice.smith@corp.example.com",
                )
            ]
        }
    )
    [result] = MicrosoftTeamsImporter().parse_string(doc)
    cr = result.control_results[0]
    assert cr.evidence_data["actor_email_domain"] == "@corp.example.com"
    serialized = json.dumps(cr.evidence_data)
    assert "alice.smith" not in serialized
    assert "alice.smith@corp.example.com" not in serialized


def test_target_name_never_stored() -> None:
    """target.name is NEVER stored — only target.name_length is captured."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-tname",
                    activity="MessageSent",
                    actor_type="bot",
                    target_id="CHAN_SECRET",
                    target_type="channel",
                    target_name="acme-acquisition-q3-confidential",
                    target_name_length=33,
                )
            ]
        }
    )
    [result] = MicrosoftTeamsImporter().parse_string(doc)
    cr = result.control_results[0]
    serialized = json.dumps(cr.evidence_data)
    assert "acme-acquisition" not in serialized
    assert "confidential" not in serialized
    assert cr.evidence_data["target_name_length"] == 33
    assert "target_name" not in cr.evidence_data


def test_ip_address_redacted() -> None:
    """context.ip public IPv4 reduced to /16; private preserved."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-pub-ip",
                    activity="MessageSent",
                    actor_type="user",
                    ip="8.8.8.8",
                ),
                _event(
                    id="evt-priv-ip",
                    activity="MessageSent",
                    actor_type="user",
                    ip="10.0.0.1",
                ),
            ]
        }
    )
    results = MicrosoftTeamsImporter().parse_string(doc)
    pub = _findings_for_event(results, "evt-pub-ip")[0]
    priv = _findings_for_event(results, "evt-priv-ip")[0]
    pub_cr = pub.control_results[0]
    priv_cr = priv.control_results[0]
    assert pub_cr.evidence_data["ip_redacted"] == "8.8.0.0/16"
    serialized_pub = json.dumps(pub_cr.evidence_data)
    assert "8.8.8.8" not in serialized_pub
    assert priv_cr.evidence_data["ip_redacted"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# Format / source provenance
# ---------------------------------------------------------------------------


def test_jsonl_and_data_envelopes_and_file_hash(tmp_path: Path) -> None:
    """JSONL, {"data":[]}, single-event, and file hash are all supported."""
    importer = MicrosoftTeamsImporter()

    jsonl = "\n".join(
        json.dumps(_event(id=f"jl-{i}", activity="MeetingStarted", actor_type="user"))
        for i in range(2)
    )
    jl_results = importer.parse_string(jsonl)
    assert len(jl_results) == 2

    data_doc = json.dumps(
        {"data": [_event(id="env-1", activity="MeetingStarted", actor_type="user")]}
    )
    [data_res] = importer.parse_string(data_doc)
    assert data_res.action_id == "teams-env-1"

    single_doc = json.dumps(
        _event(id="bare-1", activity="MeetingStarted", actor_type="user")
    )
    [single_res] = importer.parse_string(single_doc)
    assert single_res.action_id == "teams-bare-1"

    file_doc = json.dumps(
        {"events": [_event(id="f-1", activity="MeetingStarted", actor_type="user")]}
    )
    p = tmp_path / "teams-export.json"
    p.write_text(file_doc)
    [file_res] = importer.parse(p)
    cr = file_res.control_results[0]
    expected = hashlib.sha256(file_doc.encode("utf-8")).hexdigest()
    assert cr.evidence_data["source_provenance"]["original_file_sha256"] == expected
    assert (
        cr.evidence_data["source_provenance"]["source_format"]
        == "microsoft_teams_audit"
    )
