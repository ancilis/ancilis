"""Tests for the Dropbox team-audit-log importer."""

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
    event_type: str = "file_upload",
    event_category: str = "file_operations",
    timestamp: str = "2026-05-09T12:00:00Z",
    actor: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
    participants: list[dict[str, Any]] | None = None,
    assets: list[dict[str, Any]] | None = None,
    details: dict[str, Any] | None = None,
    origin: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if actor is None:
        actor = {
            ".tag": "user",
            "email": "agent@example.com",
            "display_name_length": 20,
            "team_member_id": "dbid:AAA-team-member-id-12345678",
        }
    if context is None:
        context = {
            ".tag": "team_member",
            "team_member_id": "dbid:CTX-team-member-id-87654321",
            "email_length": 40,
        }
    if assets is None:
        assets = [
            {
                ".tag": "file",
                "path": {".tag": "namespace_relative", "path_length": 80},
                "file_id": "id:DEADBEEFCAFEBABE",
                "extension": "pdf",
                "size_bytes": 12345,
            }
        ]
    if origin is None:
        origin = {
            ".tag": "endpoint",
            "ip_address": "203.0.113.42",
            "user_agent": "DropboxAPI/2.0 OfficialDropboxJavaSDKv2/3.1.5",
            "device_type": "web",
        }
    e: dict[str, Any] = {
        "timestamp": timestamp,
        "event_category": event_category,
        "event_type": {".tag": event_type},
        "actor": actor,
        "context": context,
        "assets": assets,
        "origin": origin,
    }
    if participants is not None:
        e["participants"] = participants
    if details is not None:
        e["details"] = details
    return e


def _signals(result) -> set[str]:
    return {cr.evidence_data.get("signal") for cr in result.control_results}


# ---------------------------------------------------------------------------
# Per-event classification
# ---------------------------------------------------------------------------


def test_file_upload_app_passes() -> None:
    """file_upload by actor=app → PR-04 PASS, ALLOW."""
    e = _event(
        event_type="file_upload",
        actor={
            ".tag": "app",
            "team_member_id": "dbid:AAA-app-actor-deadbeef",
        },
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "ALLOW"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "PASS"
        and cr.evidence_data.get("signal") == "service_account_upload"
        for cr in r.control_results
    )


def test_file_download_app_sensitive_fails() -> None:
    """file_download by actor=app on csv → PR-04 FAIL, BLOCK."""
    e = _event(
        event_type="file_download",
        actor={
            ".tag": "app",
            "team_member_id": "dbid:AAA-app-actor-aabbccdd",
        },
        assets=[
            {
                ".tag": "file",
                "path": {".tag": "namespace_relative", "path_length": 30},
                "file_id": "id:CSV-FILE-ID-1",
                "extension": "csv",
                "size_bytes": 5_000_000,
            }
        ],
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
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


def test_public_share_fails_block() -> None:
    """shared_link_create visibility=public → DE-01 FAIL, BLOCK."""
    e = _event(
        event_type="shared_link_create",
        event_category="sharing",
        details={
            "shared_link_visibility": "public",
            "shared_link_expires_at": "2027-01-01T00:00:00Z",
        },
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "DE-01"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "public_share"
        for cr in r.control_results
    )


def test_team_share_passes() -> None:
    """shared_link_create visibility=team_only with expiry → PR-05 PASS."""
    e = _event(
        event_type="shared_link_create",
        event_category="sharing",
        details={
            "shared_link_visibility": "team_only",
            "shared_link_expires_at": "2027-01-01T00:00:00Z",
        },
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "ALLOW"
    assert any(
        cr.control_id == "PR-05"
        and cr.result == "PASS"
        and cr.evidence_data.get("signal") == "team_only_share"
        for cr in r.control_results
    )


def test_permanent_share_fails() -> None:
    """shared_link_create visibility=public + expires_at=null → permanent_share FAIL."""
    e = _event(
        event_type="shared_link_create",
        event_category="sharing",
        details={
            "shared_link_visibility": "public",
            "shared_link_expires_at": None,
        },
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    # Public + no expiry → both public_share and permanent_share fire.
    sigs = _signals(r)
    assert "public_share" in sigs
    assert "permanent_share" in sigs
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "permanent_share"
        for cr in r.control_results
    )


def test_anyone_link_fails_block() -> None:
    """file_share_anyone_member_add → DE-01 FAIL, BLOCK."""
    e = _event(
        event_type="file_share_anyone_member_add",
        event_category="sharing",
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "DE-01"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "anyone_link_expansion"
        for cr in r.control_results
    )


def test_external_member_flags() -> None:
    """file_external_member_add → PR-04 FLAG."""
    e = _event(
        event_type="file_external_member_add",
        event_category="sharing",
        details={"external_user_email_domain": "@external.com"},
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "external_member_add"
        and cr.evidence_data.get("external_user_email_domain")
        == "@external.com"
        for cr in r.control_results
    )


def test_team_policy_fails() -> None:
    """team_policy_changed → PR-02 FAIL, BLOCK."""
    e = _event(
        event_type="team_policy_changed",
        event_category="team_policies",
        details={
            "new_value": "stricter",
            "previous_value": "default",
        },
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-02"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "team_policy_change"
        for cr in r.control_results
    )


def test_data_residency_fails_gdpr() -> None:
    """data_residency_change → PR-04 FAIL, BLOCK."""
    e = _event(
        event_type="data_residency_change",
        event_category="admin",
        details={"data_residency_region": "EU"},
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "data_residency_change"
        and cr.evidence_data.get("data_residency_region") == "EU"
        for cr in r.control_results
    )


def test_app_link_flags() -> None:
    """app_link_team → PR-01 FLAG."""
    e = _event(
        event_type="app_link_team",
        event_category="apps",
        details={"app_id": "appid-CAFEBABE-1234", "app_name": "Custom Bot"},
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-01"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "app_link_team"
        and cr.evidence_data.get("app_name") == "Custom Bot"
        for cr in r.control_results
    )


def test_dlp_high_fails_block() -> None:
    """dlp_match severity=high → PR-04 FAIL, BLOCK."""
    e = _event(
        event_type="dlp_match",
        event_category="reports",
        details={
            "dlp_rule_name": "PII Detection",
            "dlp_severity": "high",
        },
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "dlp_match_high"
        and cr.evidence_data.get("dlp_rule_name") == "PII Detection"
        for cr in r.control_results
    )


def test_emm_disabled_fails() -> None:
    """emm_state_change=disabled → PR-02 FAIL, BLOCK."""
    e = _event(
        event_type="emm_state_change",
        event_category="devices",
        details={"emm_state_change": "disabled"},
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-02"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "emm_disabled"
        for cr in r.control_results
    )


def test_two_factor_disabled_fails() -> None:
    """team_policy_changed details.is_two_factor_required=false → PR-01 FAIL."""
    e = _event(
        event_type="team_policy_changed",
        event_category="team_policies",
        details={"is_two_factor_required": False},
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    sigs = _signals(r)
    # Both team_policy_change FAIL and two_factor_disabled FAIL fire.
    assert "team_policy_change" in sigs
    assert "two_factor_disabled" in sigs
    assert any(
        cr.control_id == "PR-01"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "two_factor_disabled"
        for cr in r.control_results
    )


def test_bulk_download_synthetic() -> None:
    """Same actor with > N file_download in 1h → synthetic PR-04 FAIL → BLOCK."""
    base_time = datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)
    events = []
    for i in range(55):
        ts = (base_time + timedelta(seconds=i * 30)).isoformat()
        events.append(
            _event(
                event_type="file_download",
                timestamp=ts,
                actor={
                    ".tag": "user",
                    "email": "bulk@example.com",
                    "team_member_id": "dbid:bulk-actor-fixed-id-12345678",
                },
                assets=[
                    {
                        ".tag": "file",
                        "path": {
                            ".tag": "namespace_relative",
                            "path_length": 30,
                        },
                        "file_id": f"id:BULK-{i:08d}",
                        "extension": "pdf",
                        "size_bytes": 1024,
                    }
                ],
            )
        )
    results = DropboxImporter(
        agent_id="test", bulk_download_threshold=50
    ).parse_string(json.dumps({"events": events}))
    synthetic = [
        r for r in results if r.action_id.startswith("dropbox-bulk-download-")
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


def test_cross_team_share_synthetic() -> None:
    """Same actor with > N external-member adds in 1h → synthetic PR-04 FLAG."""
    base_time = datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)
    events = []
    for i in range(15):
        ts = (base_time + timedelta(seconds=i * 60)).isoformat()
        events.append(
            _event(
                event_type="file_external_member_add",
                event_category="sharing",
                timestamp=ts,
                actor={
                    ".tag": "user",
                    "email": "crossteam@example.com",
                    "team_member_id": "dbid:crossteam-actor-id-aabbccdd",
                },
                details={"external_user_email_domain": "@external.com"},
            )
        )
    results = DropboxImporter(
        agent_id="test", cross_team_share_threshold=10
    ).parse_string(json.dumps({"events": events}))
    synthetic = [
        r
        for r in results
        if r.action_id.startswith("dropbox-cross-team-share-")
    ]
    assert len(synthetic) == 1
    s = synthetic[0]
    assert s.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "cross_team_share_pattern"
        for cr in s.control_results
    )


def test_file_path_not_stored() -> None:
    """assets[].path raw must NEVER be stored — only path_length."""
    sensitive_path = "/Acquisitions/Q4-target-list-CONFIDENTIAL.xlsx"
    # Simulate a record where the raw path is present (defensive — Dropbox
    # may emit either path object). Confirm raw text is never echoed back.
    e = _event(
        event_type="file_download",
        actor={
            ".tag": "user",
            "team_member_id": "dbid:AAA-user-actor-12345678",
        },
        assets=[
            {
                ".tag": "file",
                "path": {
                    ".tag": "namespace_relative",
                    "path_length": len(sensitive_path),
                    # NB: explicitly include sensitive raw path; importer
                    # MUST drop it.
                    "raw_path": sensitive_path,
                    "namespace_relative": {"path": sensitive_path},
                },
                "file_id": "id:SECRET-FILE-1",
                "extension": "xlsx",
                "size_bytes": 1024,
            }
        ],
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    # Raw path must not appear anywhere in any evidence payload.
    payload = json.dumps(
        [cr.evidence_data for cr in r.control_results], default=str
    )
    assert sensitive_path not in payload
    assert "Q4-target-list-CONFIDENTIAL" not in payload
    # And the redacted asset block must keep path_length.
    cr = r.control_results[0]
    assets_red = cr.evidence_data.get("assets")
    assert isinstance(assets_red, list) and assets_red
    assert assets_red[0].get("path_length") == len(sensitive_path)


def test_email_domain_only() -> None:
    """actor.email full + actor.display_name + context.email must NOT be stored verbatim."""
    full_email = "alice.smith@example.com"
    e = _event(
        event_type="file_upload",
        actor={
            ".tag": "user",
            "email": full_email,
            "display_name_length": 12,
            "team_member_id": "dbid:AAA-user-actor-deadbeef",
            # NB: defensively include display_name + raw context.email; both
            # MUST be dropped.
            "display_name": "Alice Smith",
        },
        context={
            ".tag": "team_member",
            "team_member_id": "dbid:CTX-actor-id-87654321",
            "email_length": len(full_email),
            "email": full_email,
        },
    )
    results = DropboxImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    cr = r.control_results[0]
    payload = json.dumps(cr.evidence_data, default=str)
    # local-part of email and display_name must not appear verbatim
    assert "alice.smith" not in payload
    assert "Alice Smith" not in payload
    assert cr.evidence_data.get("actor_email_domain") == "@example.com"
    assert cr.evidence_data.get("actor_display_name_length") == 12
    assert cr.evidence_data.get("context_email_length") == len(full_email)


# ---------------------------------------------------------------------------
# Multi-format ingestion smoke checks (jsonl + data envelope).
# ---------------------------------------------------------------------------


def test_jsonl_ingestion() -> None:
    """JSONL input — one event per line."""
    e1 = _event(event_type="file_upload")
    e2 = _event(
        event_type="dlp_match",
        event_category="reports",
        details={"dlp_rule_name": "PCI", "dlp_severity": "high"},
    )
    content = json.dumps(e1) + "\n" + json.dumps(e2) + "\n"
    results = DropboxImporter(agent_id="test").parse_string(content)
    assert len(results) == 2
