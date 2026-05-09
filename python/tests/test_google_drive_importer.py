"""Tests for the Google Drive audit-event importer."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from ancilis.importers.google_drive import GoogleDriveImporter


# ---------------------------------------------------------------------------
# Fixture builders — produce Reports-API-shaped activity items.
# ---------------------------------------------------------------------------


def _param(name: str, *, value: Any = None, int_value: Any = None,
           bool_value: Any = None, string_value: Any = None) -> dict[str, Any]:
    p: dict[str, Any] = {"name": name}
    if value is not None:
        p["value"] = value
    if int_value is not None:
        p["intValue"] = int_value
    if bool_value is not None:
        p["boolValue"] = bool_value
    if string_value is not None:
        p["stringValue"] = string_value
    return p


def _item(
    *,
    actor_email: str = "agent-svc@example.com",
    caller_type: str = "USER",
    profile_id: str = "profile-123",
    ip_address: str = "203.0.113.42",
    time_iso: str = "2026-05-09T12:00:00Z",
    unique_qualifier: str = "uq-001",
    events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "kind": "admin#reports#activity",
        "id": {
            "time": time_iso,
            "uniqueQualifier": unique_qualifier,
            "applicationName": "drive",
        },
        "actor": {
            "email": actor_email,
            "profileId": profile_id,
            "callerType": caller_type,
        },
        "ipAddress": ip_address,
        "events": list(events or []),
    }


def _signals(result) -> set[str]:
    return {cr.evidence_data.get("signal") for cr in result.control_results}


def _findings_for(results, action_id_prefix: str):
    return [r for r in results if r.action_id.startswith(action_id_prefix)]


# ---------------------------------------------------------------------------
# Per-event classification
# ---------------------------------------------------------------------------


def test_view_passes() -> None:
    """access:view → PR-04 PASS, ALLOW."""
    item = _item(
        unique_qualifier="ev-view",
        events=[
            {
                "type": "access",
                "name": "view",
                "parameters": [
                    _param("doc_id", value="abcdef0123456789docId01"),
                    _param("doc_type", value="document"),
                ],
            }
        ],
    )
    importer = GoogleDriveImporter(agent_id="test")
    results = importer.parse_string(json.dumps({"items": [item]}))
    assert len(results) == 1
    r = results[0]
    assert r.decision == "ALLOW"
    assert any(
        cr.control_id == "PR-04" and cr.result == "PASS"
        and cr.evidence_data.get("signal") == "view_event"
        for cr in r.control_results
    )


def test_download_by_service_account_fails() -> None:
    """access:download by APPLICATION_SERVICE_ACCOUNT on doc_type=spreadsheet → PR-04 FAIL."""
    item = _item(
        actor_email="bot-runner@example.com",
        caller_type="APPLICATION_SERVICE_ACCOUNT",
        unique_qualifier="ev-agent-dl",
        events=[
            {
                "type": "access",
                "name": "download",
                "parameters": [
                    _param("doc_id", value="ssheet-id-deadbeef"),
                    _param("doc_type", value="spreadsheet"),
                ],
            }
        ],
    )
    results = GoogleDriveImporter(agent_id="test").parse_string(
        json.dumps({"items": [item]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert "agent_document_download" in _signals(r)
    assert any(
        cr.control_id == "PR-04" and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "agent_document_download"
        for cr in r.control_results
    )


def test_print_flags() -> None:
    """access:print → PR-04 FLAG."""
    item = _item(
        unique_qualifier="ev-print",
        events=[
            {
                "type": "access",
                "name": "print",
                "parameters": [_param("doc_id", value="printed-doc-1234abcd")],
            }
        ],
    )
    results = GoogleDriveImporter(agent_id="test").parse_string(
        json.dumps({"items": [item]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04" and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "print_event"
        for cr in r.control_results
    )


def test_share_outside_domain_fails() -> None:
    """acl_change:share_outside_domain → DE-01 FAIL, BLOCK."""
    item = _item(
        unique_qualifier="ev-share-out",
        events=[
            {
                "type": "acl_change",
                "name": "share_outside_domain",
                "parameters": [
                    _param("doc_id", value="shared-doc-extdomain"),
                    _param("target_user_email", value="external@evil.com"),
                    _param("target_user_email_domain", value="@evil.com"),
                ],
            }
        ],
    )
    results = GoogleDriveImporter(agent_id="test").parse_string(
        json.dumps({"items": [item]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "DE-01" and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "share_outside_domain"
        for cr in r.control_results
    )


def test_visibility_to_public_web_fails() -> None:
    """acl_change with old=private, new=public_on_the_web → PR-04 FAIL."""
    item = _item(
        unique_qualifier="ev-vis-public",
        events=[
            {
                "type": "acl_change",
                "name": "permission_change",
                "parameters": [
                    _param("doc_id", value="vis-doc-public01"),
                    _param("old_visibility", value="private"),
                    _param("new_visibility", value="public_on_the_web"),
                ],
            }
        ],
    )
    results = GoogleDriveImporter(agent_id="test").parse_string(
        json.dumps({"items": [item]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-04" and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "visibility_to_link"
        for cr in r.control_results
    )


def test_visibility_to_domain_flags() -> None:
    """acl_change with old=private, new=public_in_the_domain → PR-04 FLAG."""
    item = _item(
        unique_qualifier="ev-vis-domain",
        events=[
            {
                "type": "acl_change",
                "name": "permission_change",
                "parameters": [
                    _param("doc_id", value="vis-doc-domain01"),
                    _param("old_visibility", value="private"),
                    _param("new_visibility", value="public_in_the_domain"),
                ],
            }
        ],
    )
    results = GoogleDriveImporter(agent_id="test").parse_string(
        json.dumps({"items": [item]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04" and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "visibility_to_domain"
        for cr in r.control_results
    )


def test_external_grant_flags() -> None:
    """acl_change with target_user_email_domain != actor's primary domain → PR-04 FLAG."""
    item = _item(
        actor_email="alice@example.com",
        unique_qualifier="ev-ext-grant",
        events=[
            {
                "type": "acl_change",
                "name": "change_user_access",
                "parameters": [
                    _param("doc_id", value="ext-grant-doc-01"),
                    _param("target_user_email", value="bob@partner.com"),
                    _param("target_user_email_domain", value="@partner.com"),
                ],
            }
        ],
    )
    results = GoogleDriveImporter(agent_id="test").parse_string(
        json.dumps({"items": [item]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04" and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "external_grant"
        for cr in r.control_results
    )


def test_ownership_change_flags() -> None:
    """user_ownership:ownership_change → PR-02 FLAG."""
    item = _item(
        unique_qualifier="ev-own-change",
        events=[
            {
                "type": "user_ownership",
                "name": "ownership_change",
                "parameters": [
                    _param("doc_id", value="own-doc-01abcdef"),
                    _param("owner", value="alice@example.com"),
                ],
            }
        ],
    )
    results = GoogleDriveImporter(agent_id="test").parse_string(
        json.dumps({"items": [item]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-02" and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "ownership_change"
        for cr in r.control_results
    )


def test_permanent_delete_flags() -> None:
    """delete:delete (permanent) → PR-02 FLAG; trash:trash → PR-05 PASS."""
    item_delete = _item(
        unique_qualifier="ev-perm-delete",
        events=[
            {
                "type": "delete",
                "name": "delete",
                "parameters": [_param("doc_id", value="del-doc-deadbeef")],
            }
        ],
    )
    item_trash = _item(
        unique_qualifier="ev-trash",
        events=[
            {
                "type": "delete",
                "name": "trash",
                "parameters": [_param("doc_id", value="trash-doc-cafebabe")],
            }
        ],
    )
    results = GoogleDriveImporter(agent_id="test").parse_string(
        json.dumps({"items": [item_delete, item_trash]})
    )
    assert len(results) == 2
    r_perm = next(r for r in results if r.action_id.startswith("google-drive-ev-perm-delete"))
    r_trash = next(r for r in results if r.action_id.startswith("google-drive-ev-trash"))
    assert r_perm.decision == "FLAG"
    assert any(
        cr.control_id == "PR-02" and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "permanent_delete"
        for cr in r_perm.control_results
    )
    assert r_trash.decision == "ALLOW"
    assert any(
        cr.control_id == "PR-05" and cr.result == "PASS"
        and cr.evidence_data.get("signal") == "trash_event"
        for cr in r_trash.control_results
    )


def test_public_anonymous_access_fails() -> None:
    """actor.callerType=USER_PUBLIC → PR-01 FAIL regardless of event type."""
    item = _item(
        actor_email="anon@public",
        caller_type="USER_PUBLIC",
        unique_qualifier="ev-public-anon",
        events=[
            {
                "type": "access",
                "name": "view",
                "parameters": [_param("doc_id", value="anon-doc-pubview01")],
            }
        ],
    )
    results = GoogleDriveImporter(agent_id="test").parse_string(
        json.dumps({"items": [item]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-01" and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "public_anonymous_access"
        for cr in r.control_results
    )


def test_large_download_flags() -> None:
    """access:download with file_size_bytes > threshold → additive PR-04 FLAG."""
    item = _item(
        unique_qualifier="ev-big-download",
        events=[
            {
                "type": "access",
                "name": "download",
                "parameters": [
                    _param("doc_id", value="big-doc-01234567"),
                    _param("doc_type", value="video"),
                    _param("file_size_bytes", int_value=2_000_000_000),
                ],
            }
        ],
    )
    results = GoogleDriveImporter(agent_id="test").parse_string(
        json.dumps({"items": [item]})
    )
    assert len(results) == 1
    r = results[0]
    assert "large_download" in _signals(r)
    assert any(
        cr.control_id == "PR-04" and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "large_download"
        for cr in r.control_results
    )


def test_restricted_mime_download_flags() -> None:
    """access:download mime_type=text/csv by service account → additive PR-04 FLAG."""
    item = _item(
        actor_email="exporter-bot@example.com",
        caller_type="APPLICATION_SERVICE_ACCOUNT",
        unique_qualifier="ev-csv-dl",
        events=[
            {
                "type": "access",
                "name": "download",
                "parameters": [
                    _param("doc_id", value="csv-doc-abcd1234"),
                    # Use third_party_document so it does NOT trigger
                    # agent_document_download (which requires {spreadsheet,
                    # document, pdf}); we want to isolate restricted_mime.
                    _param("doc_type", value="third_party_document"),
                    _param("mime_type", value="text/csv"),
                ],
            }
        ],
    )
    results = GoogleDriveImporter(agent_id="test").parse_string(
        json.dumps({"items": [item]})
    )
    assert len(results) == 1
    r = results[0]
    assert "restricted_mime_download" in _signals(r)
    assert any(
        cr.control_id == "PR-04" and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "restricted_mime_download"
        for cr in r.control_results
    )


def test_bulk_export_synthetic() -> None:
    """Actor with > N downloads in 1h → synthetic PR-04 FAIL bulk_download_pattern."""
    base = datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)
    items: list[dict[str, Any]] = []
    for i in range(6):
        items.append(
            _item(
                actor_email="mass-dl@example.com",
                caller_type="USER",
                time_iso=(base + timedelta(minutes=i)).isoformat(),
                unique_qualifier=f"ev-bulk-{i:02d}",
                events=[
                    {
                        "type": "access",
                        "name": "download",
                        "parameters": [
                            _param("doc_id", value=f"bulkdoc{i:08d}"),
                            _param("doc_type", value="image"),
                        ],
                    }
                ],
            )
        )
    importer = GoogleDriveImporter(
        agent_id="test",
        bulk_download_threshold=5,
        bulk_download_window_seconds=3600,
    )
    results = importer.parse_string(json.dumps({"items": items}))
    # 6 per-event results + 1 synthetic = 7
    assert len(results) == 7
    synthetic = [r for r in results if r.action_id.startswith("google-drive-bulk-download-")]
    assert len(synthetic) == 1
    r = synthetic[0]
    assert r.decision == "BLOCK"
    cr = r.control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert cr.evidence_data.get("signal") == "bulk_download_pattern"
    assert cr.evidence_data.get("bulk_download_count") == 6
    assert cr.evidence_data.get("bulk_download_threshold") == 5


def test_cross_domain_share_synthetic() -> None:
    """Actor sharing > N files outside domain in 1h → synthetic PR-04 FAIL."""
    base = datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)
    items: list[dict[str, Any]] = []
    for i in range(4):
        items.append(
            _item(
                actor_email="leak-actor@example.com",
                caller_type="USER",
                time_iso=(base + timedelta(minutes=i)).isoformat(),
                unique_qualifier=f"ev-share-{i:02d}",
                events=[
                    {
                        "type": "acl_change",
                        "name": "share_outside_domain",
                        "parameters": [
                            _param("doc_id", value=f"sharedoc{i:08d}"),
                            _param("target_user_email_domain", value="@evil.com"),
                        ],
                    }
                ],
            )
        )
    importer = GoogleDriveImporter(
        agent_id="test",
        cross_domain_share_threshold=3,
        cross_domain_share_window_seconds=3600,
    )
    results = importer.parse_string(json.dumps({"items": items}))
    # 4 per-event results + 1 synthetic
    assert len(results) == 5
    synthetic = [
        r for r in results
        if r.action_id.startswith("google-drive-cross-domain-share-")
    ]
    assert len(synthetic) == 1
    r = synthetic[0]
    assert r.decision == "BLOCK"
    cr = r.control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert cr.evidence_data.get("signal") == "cross_domain_share_pattern"
    assert cr.evidence_data.get("cross_domain_share_count") == 4
    assert cr.evidence_data.get("cross_domain_share_threshold") == 3


def test_doc_id_truncated() -> None:
    """doc_id is reduced to last 8 characters in evidence — never stored full."""
    full_doc_id = "1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    item = _item(
        unique_qualifier="ev-doc-id-trunc",
        events=[
            {
                "type": "access",
                "name": "view",
                "parameters": [
                    _param("doc_id", value=full_doc_id),
                    _param("doc_type", value="document"),
                ],
            }
        ],
    )
    results = GoogleDriveImporter(agent_id="test").parse_string(
        json.dumps({"items": [item]})
    )
    assert len(results) == 1
    r = results[0]
    cr = r.control_results[0]
    last8 = full_doc_id[-8:]
    assert cr.evidence_data.get("doc_id_last8") == last8
    # Full doc_id must not appear anywhere in serialized evidence.
    serialized = json.dumps(cr.evidence_data, default=str)
    assert full_doc_id not in serialized


def test_email_only_domain_stored() -> None:
    """actor.email and target_user_email reduced to ``@domain`` only — local-part not stored."""
    item = _item(
        actor_email="sensitive-user@corp.example.com",
        unique_qualifier="ev-email-redact",
        events=[
            {
                "type": "acl_change",
                "name": "change_user_access",
                "parameters": [
                    _param("doc_id", value="emaildoc-12345678"),
                    _param("target_user_email", value="external-bob@partner.com"),
                ],
            }
        ],
    )
    results = GoogleDriveImporter(agent_id="test").parse_string(
        json.dumps({"items": [item]})
    )
    assert len(results) == 1
    r = results[0]
    # actor email domain captured, full address not.
    captured_actor = {
        cr.evidence_data.get("actor_email_domain") for cr in r.control_results
    }
    assert "@corp.example.com" in captured_actor
    captured_target = {
        cr.evidence_data.get("target_user_email_domain")
        for cr in r.control_results
    }
    assert "@partner.com" in captured_target
    serialized = json.dumps(
        [cr.evidence_data for cr in r.control_results], default=str
    )
    assert "sensitive-user" not in serialized
    assert "external-bob" not in serialized


# ---------------------------------------------------------------------------
# Envelope / structural sanity checks (free additions, not in the deliverable
# list but useful for catching structural regressions).
# ---------------------------------------------------------------------------


def test_jsonl_envelope_supported() -> None:
    """JSONL: one item per line is parsed equivalently to ``{"items": [...]}``."""
    item = _item(
        unique_qualifier="ev-jsonl",
        events=[
            {
                "type": "access",
                "name": "view",
                "parameters": [_param("doc_id", value="jsonl-doc-aabbccdd")],
            }
        ],
    )
    jsonl = json.dumps(item) + "\n"
    results = GoogleDriveImporter(agent_id="test").parse_string(jsonl)
    assert len(results) == 1
    assert results[0].decision == "ALLOW"


def test_data_envelope_supported() -> None:
    """``{"data": [...]}`` envelope is parsed equivalently to ``items``."""
    item = _item(
        unique_qualifier="ev-data-env",
        events=[
            {
                "type": "access",
                "name": "view",
                "parameters": [_param("doc_id", value="data-env-doc01234567")],
            }
        ],
    )
    results = GoogleDriveImporter(agent_id="test").parse_string(
        json.dumps({"data": [item]})
    )
    assert len(results) == 1
