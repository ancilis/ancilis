"""Tests for the Dropbox team-activity-log importer."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from ancilis.importers.dropbox import DropboxImporter


# ---------------------------------------------------------------------------
# Fixture builders — produce team-log-shaped events.
# ---------------------------------------------------------------------------


def _event(
    *,
    event_id: str = "evt-001",
    event_type: str = "file_download",
    timestamp: str = "2026-05-09T12:00:00Z",
    actor_tag: str = "user",
    actor_email: str = "agent@example.com",
    account_id: str = "acct-1234567890ab",
    team_member_id: str = "tm-cafebabe1234",
    display_name_length: int = 50,
    asset: list[dict[str, Any]] | None = None,
    participants: list[dict[str, Any]] | None = None,
    origin: dict[str, Any] | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if asset is None:
        asset = [
            {
                ".tag": "file",
                "path_length": 80,
                "file_id": "id:abcdef1234567890",
                "display_name_length": 30,
                "file_size": 12345,
                "file_extension": "pdf",
            }
        ]
    if origin is None:
        origin = {
            "geo_location": {
                "city": "San Francisco",
                "region": "CA",
                "country": "US",
                "ip_address": "203.0.113.42",
            },
            "access_method": {".tag": "end_user"},
        }
    if details is None:
        details = {}
    e: dict[str, Any] = {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": {".tag": event_type, "description": event_type},
        "actor": {
            ".tag": actor_tag,
            "user": {
                "account_id": account_id,
                "email": actor_email,
                "display_name_length": display_name_length,
                "team_member_id": team_member_id,
            },
        },
        "context": {
            ".tag": "team_member",
            "account_id": account_id,
            "team_member_id": team_member_id,
        },
        "asset": asset,
        "origin": origin,
        "details": details,
    }
    if participants is not None:
        e["participants"] = participants
    return e


def _signals(result) -> set[str]:
    return {cr.evidence_data.get("signal") for cr in result.control_results}


def _has(result, *, control_id: str, result_value: str, signal: str) -> bool:
    return any(
        cr.control_id == control_id
        and cr.result == result_value
        and cr.evidence_data.get("signal") == signal
        for cr in result.control_results
    )


# ---------------------------------------------------------------------------
# Per-event classification
# ---------------------------------------------------------------------------


def test_user_download_passes() -> None:
    """file_download by user → PR-04 PASS, ALLOW."""
    e = _event(event_type="file_download", actor_tag="user")
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "ALLOW"
    assert _has(
        r, control_id="PR-04", result_value="PASS", signal="user_download"
    )


def test_agent_download_sensitive_extension_fails() -> None:
    """file_download by app on csv → PR-04 FAIL, BLOCK."""
    e = _event(
        event_id="ev-agent-dl",
        event_type="file_download",
        actor_tag="app",
        asset=[
            {
                ".tag": "file",
                "path_length": 40,
                "file_id": "id:csv-cafebabe",
                "display_name_length": 20,
                "file_size": 5_000_000,
                "file_extension": "csv",
            }
        ],
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert _has(
        r,
        control_id="PR-04",
        result_value="FAIL",
        signal="agent_sensitive_download",
    )


def test_large_download_flags() -> None:
    """file_download with file_size > 1GB → PR-04 FLAG."""
    e = _event(
        event_id="ev-large",
        event_type="file_download",
        actor_tag="user",
        asset=[
            {
                ".tag": "file",
                "path_length": 30,
                "file_id": "id:big-12345678",
                "display_name_length": 18,
                "file_size": 2_000_000_000,
                "file_extension": "zip",
            }
        ],
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert _has(
        r, control_id="PR-04", result_value="FLAG", signal="large_download"
    )


def test_public_shared_link_create_fails() -> None:
    """shared_link_create audience=public → DE-01 FAIL, BLOCK."""
    e = _event(
        event_id="ev-public-link",
        event_type="shared_link_create",
        details={
            "shared_link_audience": {".tag": "public"},
            "shared_link_id": "slid-aabbccdd1122",
        },
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert _has(
        r,
        control_id="DE-01",
        result_value="FAIL",
        signal="public_share_create",
    )


def test_password_protected_share_flags() -> None:
    """shared_link_create audience=password → PR-04 FLAG."""
    e = _event(
        event_id="ev-pwd-link",
        event_type="shared_link_create",
        details={
            "shared_link_audience": {".tag": "password"},
            "shared_link_id": "slid-ddeeff112233",
        },
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    r = results[0]
    assert r.decision == "FLAG"
    assert _has(
        r,
        control_id="PR-04",
        result_value="FLAG",
        signal="password_share_create",
    )


def test_visibility_change_to_public_fails() -> None:
    """shared_link_change_visibility → public → DE-01 FAIL."""
    e = _event(
        event_id="ev-vis-public",
        event_type="shared_link_change_visibility",
        details={"new_visibility": {".tag": "public"}},
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    r = results[0]
    assert r.decision == "BLOCK"
    assert _has(
        r,
        control_id="DE-01",
        result_value="FAIL",
        signal="public_share_visibility_change",
    )


def test_external_share_flags() -> None:
    """file_share to external domain → PR-04 FLAG."""
    e = _event(
        event_id="ev-ext-share",
        event_type="file_share",
        actor_email="alice@team.com",
        participants=[
            {
                "user": {
                    "email": "outsider@vendor.com",
                    "email_domain": "@vendor.com",
                }
            }
        ],
    )
    results = DropboxImporter(
        agent_id="test", primary_workspace_domain="team.com"
    ).parse_string(json.dumps({"events": [e]}))
    r = results[0]
    assert r.decision == "FLAG"
    assert _has(
        r, control_id="PR-04", result_value="FLAG", signal="external_share"
    )


def test_confidential_external_share_fails() -> None:
    """file_share with sensitivity_label=confidential to external → PR-04 FAIL."""
    e = _event(
        event_id="ev-conf-share",
        event_type="file_share",
        actor_email="alice@team.com",
        asset=[
            {
                ".tag": "file",
                "path_length": 30,
                "file_id": "id:secret-deadbeef",
                "display_name_length": 12,
                "file_size": 1234,
                "file_extension": "pdf",
                "sensitivity_label": "confidential",
            }
        ],
        participants=[
            {
                "user": {
                    "email": "outsider@vendor.com",
                    "email_domain": "@vendor.com",
                }
            }
        ],
    )
    results = DropboxImporter(
        agent_id="test", primary_workspace_domain="team.com"
    ).parse_string(json.dumps({"events": [e]}))
    r = results[0]
    assert r.decision == "BLOCK"
    assert _has(
        r,
        control_id="PR-04",
        result_value="FAIL",
        signal="confidential_external_share",
    )


def test_team_folder_permanently_delete_fails() -> None:
    """team_folder_permanently_delete → PR-02 FAIL."""
    e = _event(
        event_id="ev-tf-del",
        event_type="team_folder_permanently_delete",
        actor_tag="admin",
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    r = results[0]
    assert r.decision == "BLOCK"
    assert _has(
        r,
        control_id="PR-02",
        result_value="FAIL",
        signal="team_folder_permanently_delete",
    )


def test_admin_promotion_fails() -> None:
    """member_change_admin_role → admin → PR-02 FAIL."""
    e = _event(
        event_id="ev-admin-promo",
        event_type="member_change_admin_role",
        actor_tag="admin",
        details={"new_admin_role": {".tag": "team_admin"}},
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    r = results[0]
    assert r.decision == "BLOCK"
    assert _has(
        r, control_id="PR-02", result_value="FAIL", signal="admin_promotion"
    )


def test_sso_change_flags() -> None:
    """sso_change_settings → PR-02 FLAG."""
    e = _event(
        event_id="ev-sso",
        event_type="sso_change_settings",
        actor_tag="admin",
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    r = results[0]
    assert r.decision == "FLAG"
    assert _has(
        r, control_id="PR-02", result_value="FLAG", signal="sso_change"
    )


def test_two_factor_disable_fails() -> None:
    """two_step_verification_disable → PR-01 FAIL."""
    e = _event(
        event_id="ev-2fa-off",
        event_type="two_step_verification_disable",
        actor_tag="admin",
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    r = results[0]
    assert r.decision == "BLOCK"
    assert _has(
        r,
        control_id="PR-01",
        result_value="FAIL",
        signal="two_factor_disable",
    )


def test_data_residency_migration_flags() -> None:
    """data_residency_migration → PR-04 FLAG."""
    e = _event(
        event_id="ev-residency",
        event_type="data_residency_migration",
        actor_tag="admin",
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    r = results[0]
    assert r.decision == "FLAG"
    assert _has(
        r,
        control_id="PR-04",
        result_value="FLAG",
        signal="data_residency_change",
    )


def test_file_request_create_flags() -> None:
    """file_request_create → PR-04 FLAG."""
    e = _event(
        event_id="ev-file-req",
        event_type="file_request_create",
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    r = results[0]
    assert r.decision == "FLAG"
    assert _has(
        r,
        control_id="PR-04",
        result_value="FLAG",
        signal="file_request_create",
    )


def test_shared_link_disable_passes() -> None:
    """shared_link_disable → PR-05 PASS."""
    e = _event(
        event_id="ev-link-off",
        event_type="shared_link_disable",
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    r = results[0]
    assert r.decision == "ALLOW"
    assert _has(
        r,
        control_id="PR-05",
        result_value="PASS",
        signal="shared_link_disable",
    )


# ---------------------------------------------------------------------------
# Synthetic patterns
# ---------------------------------------------------------------------------


def test_bulk_download_synthetic_emitted() -> None:
    """Same actor with > N file_downloads in 1h → synthetic FAIL/BLOCK."""
    base = datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)
    events: list[dict[str, Any]] = []
    threshold = 5
    for i in range(threshold + 2):
        ts = (base + timedelta(seconds=30 * i)).isoformat()
        events.append(
            _event(
                event_id=f"ev-{i}",
                event_type="file_download",
                actor_tag="user",
                timestamp=ts,
            )
        )
    importer = DropboxImporter(
        agent_id="test", bulk_download_threshold=threshold
    )
    results = importer.parse_string(json.dumps({"events": events}))
    syn = [r for r in results if r.action_id.startswith("dropbox-bulk-download-")]
    assert len(syn) == 1
    s = syn[0]
    assert s.decision == "BLOCK"
    assert _has(
        s,
        control_id="PR-04",
        result_value="FAIL",
        signal="bulk_download_pattern",
    )


def test_external_recipient_synthetic_emitted() -> None:
    """Same actor sharing to > N distinct external domains in 1h → synthetic FLAG."""
    base = datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)
    events: list[dict[str, Any]] = []
    threshold = 3
    for i in range(threshold + 2):
        ts = (base + timedelta(seconds=60 * i)).isoformat()
        events.append(
            _event(
                event_id=f"ev-share-{i}",
                event_type="shared_link_create",
                actor_email="alice@team.com",
                actor_tag="user",
                timestamp=ts,
                participants=[
                    {
                        "user": {
                            "email": f"x@vendor{i}.com",
                            "email_domain": f"@vendor{i}.com",
                        }
                    }
                ],
                details={
                    "shared_link_audience": {".tag": "team"},
                    "shared_link_id": f"slid-{i:08d}",
                },
            )
        )
    importer = DropboxImporter(
        agent_id="test",
        primary_workspace_domain="team.com",
        external_recipient_threshold=threshold,
    )
    results = importer.parse_string(json.dumps({"events": events}))
    syn = [
        r
        for r in results
        if r.action_id.startswith("dropbox-external-recipient-")
    ]
    assert len(syn) == 1
    s = syn[0]
    assert s.decision == "FLAG"
    assert _has(
        s,
        control_id="PR-04",
        result_value="FLAG",
        signal="external_recipient_pattern",
    )


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def test_file_name_not_stored() -> None:
    """asset[].path is NEVER stored — only path_length retained."""
    e = _event(
        event_id="ev-sanitize",
        event_type="file_download",
        asset=[
            {
                ".tag": "file",
                "path_length": 95,
                "file_id": "id:full-id-1234567890abcdef",
                "display_name_length": 42,
                "file_size": 1024,
                "file_extension": "pdf",
            }
        ],
    )
    importer = DropboxImporter(agent_id="test")
    results = importer.parse_string(json.dumps({"events": [e]}))
    r = results[0]
    ev = r.control_results[0].evidence_data
    # No path or display_name string fields anywhere.
    blob = json.dumps(ev, default=str)
    assert "full-id-1234567890abcdef" not in blob  # only last 8
    assert ev["asset_path_lengths"] == [95]
    assert ev["asset_display_name_lengths"] == [42]
    # file_id_last8 is the trailing 8
    assert ev["asset_file_ids_last8"] == ["1234567890abcdef"[-8:]]


def test_email_domain_only() -> None:
    """actor.user.email is reduced to @domain only."""
    e = _event(
        event_id="ev-email",
        event_type="file_preview",
        actor_email="alice.smith@example.com",
    )
    importer = DropboxImporter(agent_id="test")
    results = importer.parse_string(json.dumps({"events": [e]}))
    r = results[0]
    ev = r.control_results[0].evidence_data
    blob = json.dumps(ev, default=str)
    assert "alice.smith" not in blob
    assert ev["actor_email_domain"] == "@example.com"


def test_city_not_stored() -> None:
    """origin.geo_location.city / region are dropped; only country retained."""
    e = _event(
        event_id="ev-geo",
        event_type="file_preview",
        origin={
            "geo_location": {
                "city": "Singapore",
                "region": "Central Region",
                "country": "SG",
                "ip_address": "8.8.8.8",
            },
            "access_method": {".tag": "end_user"},
        },
    )
    importer = DropboxImporter(agent_id="test")
    results = importer.parse_string(json.dumps({"events": [e]}))
    r = results[0]
    ev = r.control_results[0].evidence_data
    blob = json.dumps(ev, default=str)
    assert "Singapore" not in blob
    assert "Central Region" not in blob
    assert ev["origin_country"] == "SG"
    # IP must be masked /16
    assert ev["origin_ip_redacted"] == "8.8.0.0/16"


# ---------------------------------------------------------------------------
# Smoke: alternate envelopes
# ---------------------------------------------------------------------------


def test_data_envelope_supported() -> None:
    """{"data": [...]} envelope is parsed identically to {"events": [...]}"""
    e = _event(event_type="file_preview")
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"data": [e]})
    )
    assert len(results) == 1


def test_jsonl_envelope_supported() -> None:
    """One event per line is parsed identically to envelope shapes."""
    e1 = _event(event_id="a", event_type="file_preview")
    e2 = _event(event_id="b", event_type="file_download", actor_tag="user")
    text = json.dumps(e1) + "\n" + json.dumps(e2)
    results = DropboxImporter(agent_id="test").parse_string(text)
    assert len(results) == 2
