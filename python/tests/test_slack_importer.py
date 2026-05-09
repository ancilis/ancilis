"""Tests for the Slack audit-log importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ancilis.importers.slack import SlackImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Slack audit-log entries (no slack-sdk required)
# ---------------------------------------------------------------------------


def _entry(
    *,
    id: str = "entry-001",
    date_create: int = 1730000000,
    action: str = "message_posted",
    actor_type: str = "app",
    actor_user_id: str = "U_BOT_1",
    actor_user_name: str = "agent-bot",
    actor_email: str | None = "agent-bot@corp.example.com",
    entity_type: str = "channel",
    channel_id: str | None = "C_INTERNAL",
    channel_name: str | None = "agent-output",
    channel_is_private: bool = False,
    channel_is_external_shared: bool = False,
    file_id: str | None = None,
    file_name: str | None = None,
    file_filetype: str | None = None,
    file_size: int | None = None,
    file_is_external: bool | None = None,
    message_text: str | None = None,
    message_text_length: int | None = None,
    message_has_links: bool | None = None,
    target_user_id: str | None = None,
    location_id: str = "T_WORKSPACE_1",
    location_domain: str = "example",
    location_name: str = "Example Corp",
    ip_address: str | None = "203.0.113.42",
    ua: str | None = "Slackbot 1.0 (+https://api.slack.com/robots)",
) -> dict[str, Any]:
    actor: dict[str, Any] = {"type": actor_type, "user": {}}
    if actor_user_id is not None:
        actor["user"]["id"] = actor_user_id
    if actor_user_name is not None:
        actor["user"]["name"] = actor_user_name
    if actor_email is not None:
        actor["user"]["email"] = actor_email

    entity: dict[str, Any] = {"type": entity_type}
    if channel_id is not None:
        ch: dict[str, Any] = {"id": channel_id}
        if channel_name is not None:
            ch["name"] = channel_name
        ch["is_private"] = channel_is_private
        ch["is_external_shared"] = channel_is_external_shared
        entity["channel"] = ch
    if file_id is not None or file_name is not None:
        f: dict[str, Any] = {}
        if file_id is not None:
            f["id"] = file_id
        if file_name is not None:
            f["name"] = file_name
        if file_filetype is not None:
            f["filetype"] = file_filetype
        if file_size is not None:
            f["size"] = file_size
        if file_is_external is not None:
            f["is_external"] = file_is_external
        entity["file"] = f
    if message_text is not None or message_text_length is not None:
        m: dict[str, Any] = {}
        if message_text is not None:
            m["text"] = message_text
        if message_text_length is not None:
            m["text_length"] = message_text_length
        if message_has_links is not None:
            m["has_links"] = message_has_links
        entity["message"] = m
    if target_user_id is not None:
        entity["user"] = {"id": target_user_id}

    ctx: dict[str, Any] = {
        "location": {
            "type": "workspace",
            "id": location_id,
            "domain": location_domain,
            "name": location_name,
        },
    }
    if ua is not None:
        ctx["ua"] = ua
    if ip_address is not None:
        ctx["ip_address"] = ip_address

    return {
        "id": id,
        "date_create": date_create,
        "action": action,
        "actor": actor,
        "entity": entity,
        "context": ctx,
    }


def _findings_for_entry(results: list, entry_id: str) -> list:
    return [r for r in results if r.action_id == f"slack-{entry_id}"]


# ---------------------------------------------------------------------------
# Action-pattern semantics
# ---------------------------------------------------------------------------


def test_parse_message_posted_by_bot() -> None:
    """message_posted by app actor → PR-04 PASS, ALLOW."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    id="entry-msg",
                    action="message_posted",
                    actor_type="app",
                    channel_is_external_shared=False,
                )
            ]
        }
    )
    [result] = SlackImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "slack_import"
    assert result.action_id == "slack-entry-msg"
    [cr] = result.control_results
    assert cr.control_id == "PR-04"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "agent_message_posted"
    assert cr.evidence_data["action"] == "message_posted"
    assert cr.evidence_data["actor_type"] == "app"


def test_message_posted_to_external_channel_flags() -> None:
    """message_posted to external-shared channel → PR-04 FLAG, FLAG decision."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    id="entry-ext",
                    action="message_posted",
                    actor_type="bot",
                    channel_id="C_EXTERNAL",
                    channel_is_external_shared=True,
                    message_text_length=500,
                    message_has_links=False,
                )
            ]
        }
    )
    [result] = SlackImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flag_crs = [cr for cr in result.control_results if cr.result == "FLAG"]
    assert any(
        cr.evidence_data["signal"] == "agent_message_external" for cr in flag_crs
    )
    cr = next(
        c for c in flag_crs if c.evidence_data["signal"] == "agent_message_external"
    )
    assert cr.control_id == "PR-04"
    assert cr.evidence_data["channel_is_external_shared"] is True


def test_message_with_links_to_external_fails() -> None:
    """message_posted to external-shared channel WITH has_links → PR-04 FAIL, BLOCK."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    id="entry-leak",
                    action="message_posted",
                    actor_type="app",
                    channel_id="C_EXTERNAL",
                    channel_is_external_shared=True,
                    message_text_length=120,
                    message_has_links=True,
                )
            ]
        }
    )
    [result] = SlackImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fail_crs = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.evidence_data["signal"] == "agent_message_external_with_links"
        for cr in fail_crs
    )
    cr = next(
        c
        for c in fail_crs
        if c.evidence_data["signal"] == "agent_message_external_with_links"
    )
    assert cr.control_id == "PR-04"
    assert cr.evidence_data["message_has_links"] is True


def test_file_uploaded_by_app_flags() -> None:
    """file_uploaded by app actor → PR-04 FLAG."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    id="entry-file",
                    action="file_uploaded",
                    actor_type="app",
                    entity_type="file",
                    channel_id=None,
                    file_id="F_REPORT",
                    file_name="report.pdf",
                    file_filetype="pdf",
                    file_size=123456,
                    file_is_external=False,
                )
            ]
        }
    )
    [result] = SlackImporter().parse_string(doc)
    assert result.decision == "FLAG"
    [cr] = result.control_results
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "agent_file_uploaded"
    # file size is preserved verbatim — useful posture metric
    assert cr.evidence_data["file_size"] == 123456
    assert cr.evidence_data["file_filetype"] == "pdf"


def test_file_shared_externally_fails_top_priority() -> None:
    """file_shared_externally is the top-priority exfil signal → DE-01 FAIL, BLOCK.

    This holds regardless of actor type — even a user-initiated external share
    is a critical exfil event for an agent-output channel.
    """
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    id="entry-exfil",
                    action="file_shared_externally",
                    actor_type="user",
                    entity_type="file",
                    channel_id="C_AGENT_OUT",
                    file_id="F_LEAK",
                    file_name="customer-list.csv",
                    file_filetype="csv",
                    file_size=987654,
                    file_is_external=True,
                )
            ]
        }
    )
    [result] = SlackImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fail_crs = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.control_id == "DE-01"
        and cr.evidence_data["signal"] == "file_shared_externally"
        for cr in fail_crs
    )


def test_external_user_added_flags() -> None:
    """external_user_added → PR-02 FLAG (external user joining is review surface)."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    id="entry-ext-usr",
                    action="external_user_added",
                    actor_type="user",
                    entity_type="user",
                    channel_id=None,
                    target_user_id="U_EXT_NEW",
                )
            ]
        }
    )
    [result] = SlackImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flag_crs = [cr for cr in result.control_results if cr.result == "FLAG"]
    assert any(
        cr.control_id == "PR-02" and cr.evidence_data["signal"] == "external_user_added"
        for cr in flag_crs
    )


def test_external_channel_created_flags() -> None:
    """channel_created with is_external_shared=true → PR-02 FLAG."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    id="entry-ext-ch",
                    action="channel_created",
                    actor_type="user",
                    channel_id="C_NEW_EXT",
                    channel_name="acme-shared",
                    channel_is_external_shared=True,
                )
            ]
        }
    )
    [result] = SlackImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flag_crs = [cr for cr in result.control_results if cr.result == "FLAG"]
    assert any(
        cr.control_id == "PR-02"
        and cr.evidence_data["signal"] == "external_channel_created"
        for cr in flag_crs
    )


def test_dm_created_by_bot_flags_social_engineering() -> None:
    """dm_created by app/bot → PR-04 FLAG (potential social-engineering surface).

    A bot opening DMs to users is a privileged escalation: it bypasses channel
    governance, makes the conversation private, and is the canonical pattern
    for agent-driven phishing or impersonation.
    """
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    id="entry-dm",
                    action="dm_created",
                    actor_type="app",
                    entity_type="message",
                    channel_id="D_PRIVATE_DM",
                    channel_is_private=True,
                    channel_is_external_shared=False,
                )
            ]
        }
    )
    [result] = SlackImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flag_crs = [cr for cr in result.control_results if cr.result == "FLAG"]
    assert any(
        cr.control_id == "PR-04" and cr.evidence_data["signal"] == "agent_dm_created"
        for cr in flag_crs
    )


def test_user_logout_audit() -> None:
    """user_logout → PR-05 PASS (audit trail event)."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    id="entry-logout",
                    action="user_logout",
                    actor_type="user",
                    entity_type="user",
                    channel_id=None,
                )
            ]
        }
    )
    [result] = SlackImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    [cr] = result.control_results
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "user_logout"


def test_dnsr_acknowledged_passes_compliance() -> None:
    """files_acknowledged_dnsr (Data Native State Removal) → PR-04 PASS compliance event."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    id="entry-dnsr",
                    action="files_acknowledged_dnsr",
                    actor_type="user",
                    entity_type="file",
                    channel_id=None,
                    file_id="F_DNSR",
                    file_filetype="pdf",
                    file_size=4096,
                )
            ]
        }
    )
    [result] = SlackImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    [cr] = result.control_results
    assert cr.control_id == "PR-04"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "dnsr_acknowledged"


# ---------------------------------------------------------------------------
# Cross-actor patterns
# ---------------------------------------------------------------------------


def test_cross_channel_pattern_synthetic() -> None:
    """One bot posting to >= cross_channel_threshold channels → synthetic PR-02 FLAG."""
    entries = [
        _entry(
            id=f"entry-spread-{i}",
            action="message_posted",
            actor_type="bot",
            actor_user_id="U_BOT_SPREAD",
            channel_id=f"C_CHANNEL_{i:02d}",
            channel_is_external_shared=False,
        )
        for i in range(12)
    ]
    doc = json.dumps({"entries": entries})
    results = SlackImporter(cross_channel_threshold=10).parse_string(doc)

    # One synthetic + 12 per-entry = 13 total.
    assert len(results) == 13
    synthetic = [
        r for r in results if r.action_id == "slack-cross-channel-U_BOT_SPREAD"
    ]
    assert len(synthetic) == 1
    [cr] = synthetic[0].control_results
    assert cr.control_id == "PR-02"
    assert cr.evidence_data["signal"] == "cross_channel_pattern"
    assert cr.evidence_data["cross_channel_channel_count"] == 12
    assert cr.evidence_data["cross_channel_threshold"] == 10
    assert cr.evidence_data["synthetic"] is True

    # Per-entry cross-channel marker present on contributing entries.
    contributing = _findings_for_entry(results, "entry-spread-0")
    [per_entry] = contributing
    assert any(
        c.evidence_data["signal"] == "cross_channel_pattern"
        for c in per_entry.control_results
    )


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def test_email_only_domain_stored() -> None:
    """actor.user.email reduced to '@domain' — local-part NEVER stored."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    id="entry-email",
                    action="user_logout",
                    actor_type="user",
                    actor_email="alice.smith@corp.example.com",
                    entity_type="user",
                    channel_id=None,
                )
            ]
        }
    )
    [result] = SlackImporter().parse_string(doc)
    [cr] = result.control_results
    assert cr.evidence_data["actor_email_domain"] == "@corp.example.com"
    # Local-part absent everywhere in the evidence.
    serialized = json.dumps(cr.evidence_data)
    assert "alice.smith" not in serialized
    assert "alice.smith@corp.example.com" not in serialized


def test_file_name_never_stored() -> None:
    """entity.file.name is NEVER stored — file names can carry confidential codenames."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    id="entry-fname",
                    action="file_uploaded",
                    actor_type="app",
                    entity_type="file",
                    channel_id=None,
                    file_id="F_SECRET",
                    file_name="acme-acquisition-q3-confidential.pdf",
                    file_filetype="pdf",
                    file_size=987654,
                    file_is_external=False,
                )
            ]
        }
    )
    [result] = SlackImporter().parse_string(doc)
    [cr] = result.control_results
    serialized = json.dumps(cr.evidence_data)
    # The file name (and any prefix of it) is absent from evidence_data.
    assert "acme-acquisition" not in serialized
    assert "confidential.pdf" not in serialized
    # But filetype and size are preserved.
    assert cr.evidence_data["file_filetype"] == "pdf"
    assert cr.evidence_data["file_size"] == 987654
    # No file_name key under any guise.
    assert "file_name" not in cr.evidence_data


def test_message_text_never_stored() -> None:
    """entity.message.text is NEVER stored — leak channel can BE the message text."""
    secret_text = "API_KEY=sk-leaked-1234567890ABCDEF customer SSN 123-45-6789"
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    id="entry-text",
                    action="message_posted",
                    actor_type="app",
                    channel_is_external_shared=False,
                    message_text=secret_text,
                    message_text_length=len(secret_text),
                    message_has_links=False,
                )
            ]
        }
    )
    [result] = SlackImporter().parse_string(doc)
    [cr] = result.control_results
    serialized = json.dumps(cr.evidence_data)
    assert "sk-leaked" not in serialized
    assert "123-45-6789" not in serialized
    assert "API_KEY" not in serialized
    # text_length and has_links preserved as posture metrics.
    assert cr.evidence_data["message_text_length"] == len(secret_text)
    assert cr.evidence_data["message_has_links"] is False
    # No raw message text under any key.
    assert "message_text" not in cr.evidence_data


def test_ip_address_redacted() -> None:
    """context.ip_address public IPv4 reduced to /16; private preserved."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    id="entry-pub-ip",
                    action="user_logout",
                    actor_type="user",
                    entity_type="user",
                    channel_id=None,
                    ip_address="8.8.8.8",
                ),
                _entry(
                    id="entry-priv-ip",
                    action="user_logout",
                    actor_type="user",
                    entity_type="user",
                    channel_id=None,
                    ip_address="10.0.0.1",
                ),
            ]
        }
    )
    results = SlackImporter().parse_string(doc)
    pub = _findings_for_entry(results, "entry-pub-ip")[0]
    priv = _findings_for_entry(results, "entry-priv-ip")[0]
    [pub_cr] = pub.control_results
    [priv_cr] = priv.control_results
    assert pub_cr.evidence_data["ip_redacted"] == "8.8.0.0/16"
    # full IP is gone
    serialized_pub = json.dumps(pub_cr.evidence_data)
    assert "8.8.8.8" not in serialized_pub
    # private IPs preserved verbatim (already non-routable)
    assert priv_cr.evidence_data["ip_redacted"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# Format / source provenance (sanity)
# ---------------------------------------------------------------------------


def test_jsonl_and_data_envelopes_and_file_hash(tmp_path: Path) -> None:
    """JSONL, {"data":[]}, single-entry, and file hash are all supported."""
    importer = SlackImporter()

    # JSONL
    jsonl = "\n".join(
        json.dumps(_entry(id=f"jl-{i}", action="user_logout", actor_type="user"))
        for i in range(2)
    )
    jl_results = importer.parse_string(jsonl)
    assert len(jl_results) == 2

    # data envelope
    data_doc = json.dumps(
        {"data": [_entry(id="env-1", action="user_logout", actor_type="user")]}
    )
    [data_res] = importer.parse_string(data_doc)
    assert data_res.action_id == "slack-env-1"

    # single bare entry
    single_doc = json.dumps(_entry(id="bare-1", action="user_logout", actor_type="user"))
    [single_res] = importer.parse_string(single_doc)
    assert single_res.action_id == "slack-bare-1"

    # disk path → file sha256 in source_provenance
    file_doc = json.dumps(
        {"entries": [_entry(id="f-1", action="user_logout", actor_type="user")]}
    )
    p = tmp_path / "slack-export.json"
    p.write_text(file_doc)
    [file_res] = importer.parse(p)
    [cr] = file_res.control_results
    expected = hashlib.sha256(file_doc.encode("utf-8")).hexdigest()
    assert cr.evidence_data["source_provenance"]["original_file_sha256"] == expected
    assert cr.evidence_data["source_provenance"]["source_format"] == "slack_audit"
