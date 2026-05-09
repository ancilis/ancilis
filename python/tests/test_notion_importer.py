"""Tests for the Notion audit-event importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers.notion import NotionImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Notion audit-event records (no notion-client required)
# ---------------------------------------------------------------------------


def _event(
    *,
    id: str = "evt-1",
    type: str = "page.updated",
    timestamp: str = "2026-04-01T12:00:00Z",
    actor_id: str = "user-1",
    actor_type: str = "person",
    actor_name: str = "Kevin Bauer",
    actor_email: str = "kbauer@example.com",
    actor_is_external: bool = False,
    workspace_id: str = "ws-1",
    page_id: str | None = "page-1",
    page_title_length: int = 50,
    details: dict | None = None,
    ip_address: str = "8.8.8.8",
) -> dict:
    out: dict = {
        "id": id,
        "type": type,
        "timestamp": timestamp,
        "actor": {
            "id": actor_id,
            "type": actor_type,
            "name": actor_name,
            "email": actor_email,
            "is_external": actor_is_external,
        },
        "workspace_id": workspace_id,
        "page_title_length": page_title_length,
        "details": details or {},
        "ip_address": ip_address,
    }
    if page_id is not None:
        out["page_id"] = page_id
    return out


def _findings_for_event(results: list, event_id: str) -> list:
    """Return the EvaluationResults whose action_id matches a given event id."""
    return [r for r in results if r.action_id == f"notion-{event_id}"]


# ---------------------------------------------------------------------------
# Page lifecycle — create / update / delete
# ---------------------------------------------------------------------------


def test_bot_page_created_flags() -> None:
    """page.created + actor.type=bot → PR-01 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-bot-create",
                    type="page.created",
                    actor_id="bot-1",
                    actor_type="bot",
                )
            ]
        }
    )
    [result] = NotionImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "page_created_by_bot"
    )
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"


def test_user_page_created_passes() -> None:
    """page.created + actor.type=person → PR-05 PASS, ALLOW."""
    doc = json.dumps(
        {"events": [_event(id="evt-user-create", type="page.created")]}
    )
    [result] = NotionImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "page_created_by_user"
    )
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"


def test_bot_page_deleted_fails_audit_destruction() -> None:
    """page.deleted + actor.type=bot → PR-02 FAIL, BLOCK.

    Bot deleting a Notion page is treated as audit-trail destruction unless
    explicitly approved. This is a hard FAIL because deleting agent-created
    knowledge silently removes the only record of what the agent had stored.
    """
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-bot-delete",
                    type="page.deleted",
                    actor_id="bot-1",
                    actor_type="bot",
                )
            ]
        }
    )
    [result] = NotionImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "page_deleted_by_bot"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Public-share posture
# ---------------------------------------------------------------------------


def test_public_unprotected_share_fails() -> None:
    """page.shared_publicly + is_password_protected=false → DE-01 FAIL."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-pub-unprot",
                    type="page.shared_publicly",
                    details={
                        "publicly_shared_link": {
                            "id": "link-abcdefgh12345678",
                            "is_password_protected": False,
                            "expires_at": "2026-12-31T00:00:00Z",
                        }
                    },
                )
            ]
        }
    )
    [result] = NotionImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "public_unprotected_share"
    )
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    # Link id is truncated to last-8 only.
    assert cr.evidence_data["publicly_shared_link_id_last8"] == "12345678"


def test_public_protected_share_flags() -> None:
    """page.shared_publicly + is_password_protected=true (and expires_at set) → PR-04 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-pub-prot",
                    type="page.shared_publicly",
                    details={
                        "publicly_shared_link": {
                            "id": "link-abcdefgh12345678",
                            "is_password_protected": True,
                            "expires_at": "2026-12-31T00:00:00Z",
                        }
                    },
                )
            ]
        }
    )
    [result] = NotionImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "public_protected_share"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"


def test_public_no_expiry_fails() -> None:
    """page.shared_publicly + expires_at=null → PR-04 FAIL (permanent public link)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-pub-noexp",
                    type="page.shared_publicly",
                    details={
                        "publicly_shared_link": {
                            "id": "link-abcdefgh12345678",
                            "is_password_protected": True,
                            "expires_at": None,
                        }
                    },
                )
            ]
        }
    )
    [result] = NotionImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "public_no_expiry"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


def test_external_share_flags() -> None:
    """page.shared_with_user with non-primary domain → PR-04 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-ext-share",
                    type="page.shared_with_user",
                    details={
                        "shared_with_user_id": "user-99",
                        "shared_with_email_domain": "@external.com",
                    },
                )
            ]
        }
    )
    importer = NotionImporter(primary_workspace_domain="@example.com")
    [result] = importer.parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "external_share"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["shared_with_email_domain"] == "@external.com"


# ---------------------------------------------------------------------------
# Database / schema / row events
# ---------------------------------------------------------------------------


def test_schema_column_removal_flags() -> None:
    """database.schema_changed with removed_column → PR-05 FLAG, column names NOT stored."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-schema",
                    type="database.schema_changed",
                    details={
                        "schema_changes": [
                            "added_column:supersecretproject",
                            "removed_column:salaryowner",
                            "removed_column:customerpiicolumn",
                        ]
                    },
                )
            ]
        }
    )
    [result] = NotionImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "schema_column_removal"
    )
    assert cr.control_id == "PR-05"
    assert cr.result == "FLAG"
    # We capture counts only — column names must NOT leak.
    assert cr.evidence_data["schema_changes_count"] == 3
    assert cr.evidence_data["schema_changes_added"] == 1
    assert cr.evidence_data["schema_changes_removed"] == 2
    # Verify no raw column-name strings show up in the evidence.
    blob = json.dumps(cr.evidence_data)
    assert "salaryowner" not in blob
    assert "customerpiicolumn" not in blob
    assert "supersecretproject" not in blob


# ---------------------------------------------------------------------------
# Integrations
# ---------------------------------------------------------------------------


def test_integration_added_flags() -> None:
    """integration.added → PR-01 FLAG (new automation surface)."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-int-add",
                    type="integration.added",
                    details={"integration_id": "int-99"},
                )
            ]
        }
    )
    [result] = NotionImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "integration_added"
    )
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"


def test_write_scope_grant_flags() -> None:
    """integration.scope_added with update_content → PR-02 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-int-scope",
                    type="integration.scope_added",
                    details={
                        "integration_id": "int-99",
                        "scope_added": "update_content",
                    },
                )
            ]
        }
    )
    [result] = NotionImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "write_scope_grant"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["scope_added"] == "update_content"


# ---------------------------------------------------------------------------
# Workspace export — bulk exfiltration surface
# ---------------------------------------------------------------------------


def test_workspace_export_html_large_fails() -> None:
    """workspace.exported format=html size > threshold → PR-04 FAIL.

    HTML format is treated as the highest-bandwidth bulk-exfiltration path
    (preserves links, structure, and all content). When combined with a
    size above the configured threshold (default 100 MB) this is a FAIL,
    not a FLAG.
    """
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-export",
                    type="workspace.exported",
                    page_id=None,
                    details={
                        "export_format": "html",
                        "export_size_bytes": 200_000_000,
                    },
                )
            ]
        }
    )
    [result] = NotionImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "workspace_export_html_large"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# User events
# ---------------------------------------------------------------------------


def test_external_user_added_flags() -> None:
    """user.added by external person actor → PR-02 FLAG."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-user-add",
                    type="user.added",
                    actor_id="user-7",
                    actor_type="person",
                    actor_is_external=True,
                )
            ]
        }
    )
    [result] = NotionImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = next(
        c
        for c in result.control_results
        if c.evidence_data.get("signal") == "external_user_added"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"


# ---------------------------------------------------------------------------
# Synthetic patterns — bot velocity / cross-page sweep
# ---------------------------------------------------------------------------


def test_bot_velocity_synthetic() -> None:
    """A bot doing > N edits in a 1h window → synthetic PR-02 FLAG appears."""
    # Threshold lowered for test economy (default is 50).
    base = "2026-04-01T12:00:00Z"
    events = [
        _event(
            id=f"evt-{i}",
            type="page.updated",
            actor_id="bot-fast",
            actor_type="bot",
            timestamp=f"2026-04-01T12:00:{i:02d}Z",
            page_id=f"page-{i}",
        )
        for i in range(6)
    ]
    # Throw in the seed value so timestamps are stable.
    _ = base
    doc = json.dumps({"events": events})
    importer = NotionImporter(
        bot_velocity_threshold=3,
        bot_velocity_window_seconds=3600,
        cross_page_threshold=1000,  # disable cross-page during this test
    )
    results = importer.parse_string(doc)
    synthetic = [
        r for r in results if r.action_id == "notion-bot-velocity-bot-fast"
    ]
    assert len(synthetic) == 1
    [synth] = synthetic
    assert synth.decision == "FLAG"
    assert synth.control_results[0].control_id == "PR-02"
    assert synth.control_results[0].evidence_data["synthetic"] is True
    assert synth.control_results[0].evidence_data["bot_velocity_count"] >= 4


def test_cross_page_bot_synthetic() -> None:
    """A bot touching > N distinct page_ids → synthetic PR-02 FLAG appears."""
    events = [
        _event(
            id=f"evt-cp-{i}",
            type="page.updated",
            actor_id="bot-sweep",
            actor_type="bot",
            timestamp=f"2026-04-01T12:00:{i:02d}Z",
            page_id=f"page-{i}",
        )
        for i in range(5)
    ]
    doc = json.dumps({"events": events})
    importer = NotionImporter(
        bot_velocity_threshold=10_000,  # disable velocity during this test
        cross_page_threshold=3,
    )
    results = importer.parse_string(doc)
    synthetic = [
        r for r in results if r.action_id == "notion-cross-page-bot-sweep"
    ]
    assert len(synthetic) == 1
    [synth] = synthetic
    assert synth.decision == "FLAG"
    assert synth.control_results[0].control_id == "PR-02"
    assert synth.control_results[0].evidence_data["synthetic"] is True
    assert synth.control_results[0].evidence_data["cross_page_page_count"] == 5


# ---------------------------------------------------------------------------
# Sanitization — emails, page titles, raw IPs, raw column names
# ---------------------------------------------------------------------------


def test_email_only_domain_stored() -> None:
    """Actor email is stored as ``@domain`` only — local part NEVER retained."""
    doc = json.dumps(
        {
            "events": [
                _event(
                    id="evt-email",
                    type="page.created",
                    actor_email="alice.johnson+secret@example.com",
                )
            ]
        }
    )
    [result] = NotionImporter().parse_string(doc)
    cr = result.control_results[0]
    assert cr.evidence_data["actor_email_domain"] == "@example.com"
    blob = json.dumps(cr.evidence_data)
    # Local part must not leak.
    assert "alice.johnson" not in blob
    assert "secret" not in blob
    # Actor name is captured as length+sha256, not raw.
    assert cr.evidence_data["actor_name_redacted"] is not None
    assert "Kevin Bauer" not in blob


def test_page_title_text_never_stored() -> None:
    """We accept ``page_title_length`` only; raw title text is NEVER stored.

    Even if a producer were to send a ``page_title`` field by mistake, the
    importer drops it on the floor — we only capture the integer length.
    """
    sneaky_title = "Project Apollo: Customer XYZ acquisition memo"
    doc = json.dumps(
        {
            "events": [
                {
                    "id": "evt-title",
                    "type": "page.updated",
                    "timestamp": "2026-04-01T12:00:00Z",
                    "actor": {
                        "id": "bot-1",
                        "type": "bot",
                        "name": "Notes Agent",
                        "email": "bot@example.com",
                    },
                    "workspace_id": "ws-1",
                    "page_id": "page-1",
                    "page_title": sneaky_title,
                    "page_title_length": len(sneaky_title),
                    "details": {},
                }
            ]
        }
    )
    [result] = NotionImporter().parse_string(doc)
    cr = result.control_results[0]
    assert cr.evidence_data["page_title_length"] == len(sneaky_title)
    blob = json.dumps(cr.evidence_data)
    assert sneaky_title not in blob
    assert "Apollo" not in blob
    assert "Customer XYZ" not in blob


# ---------------------------------------------------------------------------
# File-on-disk + JSONL parsing + source-provenance hash
# ---------------------------------------------------------------------------


def test_parse_jsonl_and_file_hash(tmp_path: Path) -> None:
    """parse() supports JSONL on disk and records original_file_sha256."""
    lines = [
        json.dumps(_event(id="evt-jsonl-1", type="page.created")),
        json.dumps(
            _event(
                id="evt-jsonl-2",
                type="page.deleted",
                actor_id="bot-1",
                actor_type="bot",
            )
        ),
    ]
    text = "\n".join(lines) + "\n"
    p = tmp_path / "notion.jsonl"
    p.write_text(text, encoding="utf-8")
    expected_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    results = NotionImporter().parse(p)
    assert len(results) == 2
    for r in results:
        cr = r.control_results[0]
        assert (
            cr.evidence_data["source_provenance"]["original_file_sha256"]
            == expected_sha
        )
        assert (
            cr.evidence_data["source_provenance"]["source_format"]
            == "notion_audit_log"
        )


def test_data_envelope_and_single_event() -> None:
    """{"data": [...]} envelope and a bare single-event dict both parse."""
    # Envelope variant.
    doc_data = json.dumps({"data": [_event(id="evt-data-1", type="page.created")]})
    [r1] = NotionImporter().parse_string(doc_data)
    assert r1.action_id == "notion-evt-data-1"
    # Bare single-event variant.
    doc_single = json.dumps(_event(id="evt-single-1", type="user.removed"))
    [r2] = NotionImporter().parse_string(doc_single)
    assert r2.action_id == "notion-evt-single-1"
    assert r2.decision == "ALLOW"
