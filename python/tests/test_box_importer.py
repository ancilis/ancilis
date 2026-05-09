"""Tests for the Box admin-events importer."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from ancilis.importers.box import BoxImporter


# ---------------------------------------------------------------------------
# Fixture builders — produce admin-events-shaped entries.
# ---------------------------------------------------------------------------


def _entry(
    *,
    event_id: str = "evt-001",
    event_type: str = "PREVIEW",
    created_at: str = "2026-05-09T12:00:00Z",
    actor_user_id: str = "user-1234567890ab",
    actor_user_email: str = "agent-svc@example.com",
    actor_user_login: str = "agent-svc",
    actor_type: str = "user",
    ip_address: str = "203.0.113.42",
    source: dict[str, Any] | None = None,
    accessible_by: dict[str, Any] | None = None,
    additional_details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if source is None:
        source = {
            "item_type": "file",
            "item_id": "src-item-id-1234abcd",
            "name_length": 24,
            "folder_id": "folder-id-deadbeef",
            "extension": "pdf",
            "size_bytes": 1024,
            "shared_link": None,
        }
    e: dict[str, Any] = {
        "event_id": event_id,
        "event_type": event_type,
        "created_at": created_at,
        "actor_user_id": actor_user_id,
        "actor_user_email": actor_user_email,
        "actor_user_login": actor_user_login,
        "actor_type": actor_type,
        "ip_address": ip_address,
        "source": source,
    }
    if accessible_by is not None:
        e["accessible_by"] = accessible_by
    if additional_details is not None:
        e["additional_details"] = additional_details
    return e


def _signals(result) -> set[str]:
    return {cr.evidence_data.get("signal") for cr in result.control_results}


# ---------------------------------------------------------------------------
# Per-event classification
# ---------------------------------------------------------------------------


def test_preview_passes() -> None:
    """PREVIEW → PR-04 PASS, ALLOW."""
    e = _entry(event_type="PREVIEW", event_id="ev-preview")
    results = BoxImporter(agent_id="test").parse_string(
        json.dumps({"entries": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "ALLOW"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "PASS"
        and cr.evidence_data.get("signal") == "preview_event"
        for cr in r.control_results
    )


def test_agent_download_sensitive_extension_fails() -> None:
    """DOWNLOAD by service_account on csv → PR-04 FAIL, BLOCK."""
    e = _entry(
        event_id="ev-agent-dl",
        event_type="DOWNLOAD",
        actor_type="service_account",
        source={
            "item_type": "file",
            "item_id": "csv-item-id-cafebabe",
            "extension": "csv",
            "size_bytes": 5_000_000,
            "folder_id": "folder-id-1",
        },
    )
    results = BoxImporter(agent_id="test").parse_string(
        json.dumps({"entries": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert "agent_sensitive_download" in _signals(r)
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "agent_sensitive_download"
        for cr in r.control_results
    )


def test_large_download_flags() -> None:
    """DOWNLOAD with size > threshold → PR-04 FLAG."""
    e = _entry(
        event_id="ev-large-dl",
        event_type="DOWNLOAD",
        actor_type="user",
        source={
            "item_type": "file",
            "item_id": "big-item-id-12345678",
            "extension": "mp4",
            "size_bytes": 2_000_000_000,
            "folder_id": "folder-id-2",
        },
    )
    results = BoxImporter(agent_id="test").parse_string(
        json.dumps({"entries": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "large_download"
        for cr in r.control_results
    )


def test_public_unprotected_share_fails() -> None:
    """SHARE shared_link.access=open + is_password_enabled=false → DE-01 FAIL."""
    e = _entry(
        event_id="ev-share-open",
        event_type="SHARE",
        source={
            "item_type": "file",
            "item_id": "shared-item-id-aabbccdd",
            "extension": "pdf",
            "size_bytes": 1024,
            "folder_id": "folder-id-3",
            "shared_link": {
                "access": "open",
                "is_password_enabled": False,
                "effective_access": "open",
            },
        },
    )
    results = BoxImporter(agent_id="test").parse_string(
        json.dumps({"entries": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "DE-01"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "public_unprotected_share"
        for cr in r.control_results
    )


def test_share_password_protected_open_link_flags() -> None:
    """SHARE shared_link.access=open + is_password_enabled=true → PR-04 FLAG."""
    e = _entry(
        event_id="ev-share-pw",
        event_type="SHARE",
        source={
            "item_type": "file",
            "item_id": "pwitem-id-eeff0011",
            "extension": "pdf",
            "size_bytes": 1024,
            "folder_id": "folder-id-4",
            "shared_link": {
                "access": "open",
                "is_password_enabled": True,
                "effective_access": "open",
            },
        },
    )
    results = BoxImporter(agent_id="test").parse_string(
        json.dumps({"entries": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "public_protected_share"
        for cr in r.control_results
    )


def test_share_expiration_change_flags() -> None:
    """SHARE_EXPIRATION → PR-04 FLAG."""
    e = _entry(
        event_id="ev-share-exp",
        event_type="SHARE_EXPIRATION",
        additional_details={"reason": "extended"},
    )
    results = BoxImporter(agent_id="test").parse_string(
        json.dumps({"entries": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "share_expiration_change"
        for cr in r.control_results
    )


def test_external_collaboration_invite_flags() -> None:
    """COLLABORATION_INVITE accessible_by.login_email_domain != actor → PR-04 FLAG."""
    e = _entry(
        event_id="ev-collab-ext",
        event_type="COLLABORATION_INVITE",
        actor_user_email="alice@example.com",
        accessible_by={
            "id": "user-9988776655",
            "type": "user",
            "login_email_domain": "@external.com",
        },
    )
    results = BoxImporter(agent_id="test").parse_string(
        json.dumps({"entries": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "external_collaboration_invite"
        for cr in r.control_results
    )


def test_role_change_to_coowner_on_sensitive_flags() -> None:
    """COLLABORATION_ROLE_CHANGE new_role=co-owner → PR-02 FLAG."""
    e = _entry(
        event_id="ev-role-coowner",
        event_type="COLLABORATION_ROLE_CHANGE",
        additional_details={
            "new_role": "co-owner",
            "previous_role": "viewer",
        },
    )
    results = BoxImporter(agent_id="test").parse_string(
        json.dumps({"entries": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-02"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "role_privilege_expansion"
        for cr in r.control_results
    )


def test_file_marked_malicious_fails() -> None:
    """FILE_MARKED_MALICIOUS → DE-01 FAIL, BLOCK."""
    e = _entry(
        event_id="ev-malware",
        event_type="FILE_MARKED_MALICIOUS",
    )
    results = BoxImporter(agent_id="test").parse_string(
        json.dumps({"entries": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "DE-01"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "file_marked_malicious"
        for cr in r.control_results
    )


def test_dlp_violation_fails() -> None:
    """DLP_VIOLATION → PR-04 FAIL, BLOCK (top-priority)."""
    e = _entry(
        event_id="ev-dlp",
        event_type="DLP_VIOLATION",
        additional_details={"dlp_policy_name": "PII Detection"},
    )
    results = BoxImporter(agent_id="test").parse_string(
        json.dumps({"entries": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "dlp_violation"
        and cr.evidence_data.get("dlp_policy_name") == "PII Detection"
        for cr in r.control_results
    )


def test_shield_alert_high_fails() -> None:
    """SHIELD_ALERT priority=high → DE-01 FAIL, BLOCK."""
    e = _entry(
        event_id="ev-shield-high",
        event_type="SHIELD_ALERT",
        additional_details={
            "shield_alert_priority": "high",
            "shield_alert_type": "anomalous_download",
        },
    )
    results = BoxImporter(agent_id="test").parse_string(
        json.dumps({"entries": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "DE-01"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "shield_alert_high"
        and cr.evidence_data.get("shield_alert_type") == "anomalous_download"
        for cr in r.control_results
    )


def test_device_trust_check_failed_flags() -> None:
    """DEVICE_TRUST_CHECK_FAILED → PR-01 FLAG."""
    e = _entry(
        event_id="ev-device",
        event_type="DEVICE_TRUST_CHECK_FAILED",
    )
    results = BoxImporter(agent_id="test").parse_string(
        json.dumps({"entries": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-01"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "device_trust_failed"
        for cr in r.control_results
    )


def test_bulk_download_synthetic_fail() -> None:
    """Same actor with > N downloads in 1h → synthetic PR-04 FAIL."""
    base_time = datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)
    entries = []
    for i in range(35):
        ts = (base_time + timedelta(seconds=i * 60)).isoformat()
        entries.append(
            _entry(
                event_id=f"ev-bulk-{i}",
                event_type="DOWNLOAD",
                created_at=ts,
                actor_user_id="bulk-actor-id-12345678",
                actor_user_email="bulk@example.com",
                actor_type="user",
                source={
                    "item_type": "file",
                    "item_id": f"bulk-item-{i:08d}",
                    "extension": "pdf",
                    "size_bytes": 1024,
                    "folder_id": "folder-bulk",
                },
            )
        )
    results = BoxImporter(
        agent_id="test", bulk_download_threshold=30
    ).parse_string(json.dumps({"entries": entries}))
    # Per-event results + at least one synthetic.
    synthetic = [
        r for r in results if r.action_id.startswith("box-bulk-download-")
    ]
    assert len(synthetic) == 1
    s = synthetic[0]
    assert s.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "bulk_download_pattern"
        for cr in s.control_results
    )


def test_cross_folder_traversal_synthetic_flag() -> None:
    """Same actor accessing > N distinct folders in 1h → synthetic PR-04 FLAG."""
    base_time = datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)
    entries = []
    for i in range(105):
        ts = (base_time + timedelta(seconds=i * 10)).isoformat()
        entries.append(
            _entry(
                event_id=f"ev-fld-{i}",
                event_type="PREVIEW",
                created_at=ts,
                actor_user_id="recon-actor-aabbccdd",
                actor_user_email="recon@example.com",
                actor_type="user",
                source={
                    "item_type": "file",
                    "item_id": f"item-{i:08d}",
                    "extension": "pdf",
                    "size_bytes": 1024,
                    "folder_id": f"folder-{i:08d}",
                },
            )
        )
    results = BoxImporter(
        agent_id="test",
        cross_folder_traversal_threshold=100,
    ).parse_string(json.dumps({"entries": entries}))
    synthetic = [
        r
        for r in results
        if r.action_id.startswith("box-cross-folder-traversal-")
    ]
    assert len(synthetic) == 1
    s = synthetic[0]
    assert s.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "cross_folder_traversal_pattern"
        for cr in s.control_results
    )


def test_item_name_not_stored_verbatim() -> None:
    """source.name must NEVER be stored verbatim — only length + sha256."""
    sensitive_name = "Q4-acquisition-target-list-CONFIDENTIAL.xlsx"
    e = _entry(
        event_id="ev-name",
        event_type="PREVIEW",
        source={
            "item_type": "file",
            "item_id": "secret-item-id-99887766",
            "name": sensitive_name,
            "extension": "xlsx",
            "size_bytes": 1024,
            "folder_id": "folder-secret",
        },
    )
    results = BoxImporter(agent_id="test").parse_string(
        json.dumps({"entries": [e]})
    )
    assert len(results) == 1
    r = results[0]
    # Walk the entire control_results evidence and ensure the raw name
    # is never present anywhere.
    payload = json.dumps(
        [cr.evidence_data for cr in r.control_results], default=str
    )
    assert sensitive_name not in payload
    # And the redacted block is present with length + sha256.
    cr = r.control_results[0]
    redacted = cr.evidence_data.get("source_name_redacted")
    assert isinstance(redacted, dict)
    assert redacted.get("length") == len(sensitive_name)
    assert isinstance(redacted.get("sha256"), str)
    assert len(redacted.get("sha256")) == 64


def test_email_domain_only_stored() -> None:
    """actor_user_email full + actor_user_login must NOT be stored verbatim."""
    full_email = "alice.smith@example.com"
    full_login = "alice.smith"
    e = _entry(
        event_id="ev-email",
        event_type="PREVIEW",
        actor_user_email=full_email,
        actor_user_login=full_login,
    )
    results = BoxImporter(agent_id="test").parse_string(
        json.dumps({"entries": [e]})
    )
    assert len(results) == 1
    r = results[0]
    cr = r.control_results[0]
    payload = json.dumps(cr.evidence_data, default=str)
    # local-part of email and login must not appear verbatim
    assert "alice.smith" not in payload
    assert cr.evidence_data.get("actor_user_email_domain") == "@example.com"
    login_redacted = cr.evidence_data.get("actor_user_login_redacted")
    assert isinstance(login_redacted, dict)
    assert login_redacted.get("length") == len(full_login)
    assert isinstance(login_redacted.get("sha256"), str)
    assert len(login_redacted.get("sha256")) == 64


# ---------------------------------------------------------------------------
# Multi-format ingestion smoke checks (jsonl + data envelope).
# ---------------------------------------------------------------------------


def test_jsonl_ingestion() -> None:
    """JSONL input — one entry per line."""
    e1 = _entry(event_id="jsonl-1", event_type="PREVIEW")
    e2 = _entry(event_id="jsonl-2", event_type="DLP_VIOLATION",
                additional_details={"dlp_policy_name": "PCI"})
    content = json.dumps(e1) + "\n" + json.dumps(e2) + "\n"
    results = BoxImporter(agent_id="test").parse_string(content)
    assert len(results) == 2
