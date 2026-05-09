"""Tests for the Confluence audit-record importer."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from ancilis.importers.confluence import ConfluenceImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Confluence audit records (no atlassian-python-api required)
# ---------------------------------------------------------------------------


def _record(
    *,
    id: str = "rec-1",
    creation_date: str = "2026-04-01T12:00:00Z",
    summary: str = "Page updated",
    category: str = "page",
    subject_type: str = "page",
    subject_id: str = "page-1",
    subject_name: str = "Customer Onboarding",
    space_key: str | None = "ENG",
    author_account_id: str = "557058:user-1",
    author_display_name: str = "Kevin Bauer",
    author_email: str = "kbauer@example.com",
    author_type: str = "user",
    author_is_bot: bool = False,
    action_from_author: str = "user",
    is_automated_action: bool = False,
    remote_address: str = "8.8.8.8",
    user_agent: str = "Mozilla/5.0",
    context: dict | None = None,
    associated_items: list[dict] | None = None,
) -> dict:
    out: dict = {
        "id": id,
        "creationDate": creation_date,
        "summary": summary,
        "category": category,
        "subjectType": subject_type,
        "subjectId": subject_id,
        "subjectName": subject_name,
        "author": {
            "accountId": author_account_id,
            "displayName": author_display_name,
            "email": author_email,
            "type": author_type,
            "isBot": author_is_bot,
        },
        "actionFromAuthor": action_from_author,
        "isAutomatedAction": is_automated_action,
        "remoteAddress": remote_address,
        "userAgent": user_agent,
        "context": context or {},
        "associatedItems": associated_items or [],
    }
    if space_key is not None:
        out["spaceKey"] = space_key
    return out


def _findings_for(results: list, record_id: str) -> list:
    return [r for r in results if r.action_id == f"confluence-{record_id}"]


def _signal(result, signal: str):
    return next(
        c for c in result.control_results if c.evidence_data.get("signal") == signal
    )


# ---------------------------------------------------------------------------
# Page lifecycle — bot create / bot delete
# ---------------------------------------------------------------------------


def test_bot_page_created_flags() -> None:
    """category=page summary 'Page created' + author.isBot=true → PR-01 FLAG."""
    doc = json.dumps(
        {
            "results": [
                _record(
                    id="rec-bot-create",
                    summary="Page created",
                    author_account_id="bot-1",
                    author_is_bot=True,
                )
            ]
        }
    )
    [result] = ConfluenceImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = _signal(result, "page_created_by_bot")
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"


def test_bot_page_deleted_fails_audit_destruction() -> None:
    """category=page summary 'Page deleted' + author.isBot=true → PR-02 FAIL.

    Bot deleting a Confluence page is treated as audit-trail destruction
    (matching the Notion bot-deletion logic): the page may have been agent-
    created knowledge whose only record is now gone.
    """
    doc = json.dumps(
        {
            "results": [
                _record(
                    id="rec-bot-delete",
                    summary="Page deleted",
                    author_account_id="bot-1",
                    author_is_bot=True,
                )
            ]
        }
    )
    [result] = ConfluenceImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = _signal(result, "page_deleted_by_bot")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Exports — small flag, large fail
# ---------------------------------------------------------------------------


def test_pdf_export_flags() -> None:
    """Page exported as PDF (small) → PR-04 FLAG."""
    doc = json.dumps(
        {
            "results": [
                _record(
                    id="rec-pdf",
                    summary="Page exported as PDF",
                    context={"exportSizeBytes": 1_000_000},
                )
            ]
        }
    )
    [result] = ConfluenceImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = _signal(result, "page_export")
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"


def test_large_export_fails() -> None:
    """Page exported as PDF over threshold → PR-04 FAIL."""
    doc = json.dumps(
        {
            "results": [
                _record(
                    id="rec-pdf-big",
                    summary="Page exported as PDF",
                    context={"exportSizeBytes": 200_000_000},
                )
            ]
        }
    )
    [result] = ConfluenceImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = _signal(result, "page_export_large")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Restriction removal
# ---------------------------------------------------------------------------


def test_restrictions_removed_fails() -> None:
    """Restriction removal (changedValues field=restrictions, less restrictive)
    → PR-04 FAIL — parallels Jira's security-level-to-public logic."""
    doc = json.dumps(
        {
            "results": [
                _record(
                    id="rec-rest",
                    summary="Page updated",
                    context={
                        "changedValues": [
                            {
                                "field": "restrictions",
                                "changedFrom": "view-restricted",
                                "changedTo": "open",
                            }
                        ]
                    },
                )
            ]
        }
    )
    [result] = ConfluenceImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = _signal(result, "restrictions_removed")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    # Ensure raw changed values are NOT persisted.
    assert "view-restricted" not in json.dumps(cr.evidence_data)
    assert "open" not in cr.evidence_data.get("changed_value_field_names", [])


# ---------------------------------------------------------------------------
# Anonymous access enabled (DE-01 FAIL)
# ---------------------------------------------------------------------------


def test_anonymous_access_enabled_fails() -> None:
    doc = json.dumps(
        {
            "results": [
                _record(
                    id="rec-anon",
                    category="permissions",
                    summary="Anonymous access enabled",
                    subject_type="permission",
                )
            ]
        }
    )
    [result] = ConfluenceImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = _signal(result, "anonymous_access_enabled")
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Space deletion — audit destruction
# ---------------------------------------------------------------------------


def test_space_deleted_fails() -> None:
    doc = json.dumps(
        {
            "results": [
                _record(
                    id="rec-space-del",
                    category="space",
                    summary="Space deleted",
                    subject_type="space",
                )
            ]
        }
    )
    [result] = ConfluenceImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = _signal(result, "space_deleted")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# AppLink user provisioning
# ---------------------------------------------------------------------------


def test_app_link_user_added_flags() -> None:
    doc = json.dumps(
        {
            "results": [
                _record(
                    id="rec-app-add",
                    category="user",
                    summary="User added to organization",
                    subject_type="user",
                    author_type="appLink",
                    # appLink author still uses an actionFromAuthor value;
                    # use 'user' here so we isolate the user-add signal from
                    # the more general app_link_action signal.
                    action_from_author="user",
                )
            ]
        }
    )
    [result] = ConfluenceImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = _signal(result, "app_link_user_added")
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"


# ---------------------------------------------------------------------------
# Anonymous edits
# ---------------------------------------------------------------------------


def test_anonymous_action_fails() -> None:
    """actionFromAuthor=anonymous → PR-01 FAIL."""
    doc = json.dumps(
        {
            "results": [
                _record(
                    id="rec-anon-edit",
                    summary="Page updated",
                    action_from_author="anonymous",
                )
            ]
        }
    )
    [result] = ConfluenceImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = _signal(result, "anonymous_action")
    assert cr.control_id == "PR-01"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# AppLink action (non-user-add)
# ---------------------------------------------------------------------------


def test_app_link_action_flags() -> None:
    """actionFromAuthor=appLink → PR-01 FLAG."""
    doc = json.dumps(
        {
            "results": [
                _record(
                    id="rec-app-act",
                    summary="Page updated",
                    action_from_author="appLink",
                    author_type="appLink",
                )
            ]
        }
    )
    [result] = ConfluenceImporter().parse_string(doc)
    assert result.decision == "FLAG"
    cr = _signal(result, "app_link_action")
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"


# ---------------------------------------------------------------------------
# Automated page event passes
# ---------------------------------------------------------------------------


def test_automated_page_event_passes() -> None:
    """isAutomatedAction=true + category=page → PR-05 PASS."""
    doc = json.dumps(
        {
            "results": [
                _record(
                    id="rec-auto",
                    summary="Page updated",
                    is_automated_action=True,
                )
            ]
        }
    )
    [result] = ConfluenceImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    cr = _signal(result, "automated_page_event")
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"


# ---------------------------------------------------------------------------
# Bot velocity synthetic
# ---------------------------------------------------------------------------


def test_bot_velocity_synthetic() -> None:
    """Bot author > N edits within window → synthetic PR-02 FLAG."""
    base = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
    records = []
    for i in range(40):
        ts = (base + timedelta(seconds=i * 10)).isoformat()
        records.append(
            _record(
                id=f"rec-vel-{i}",
                creation_date=ts,
                author_account_id="bot-velocity-1",
                author_is_bot=True,
                summary="Page updated",
                space_key="ENG",
            )
        )
    doc = json.dumps({"results": records})
    results = ConfluenceImporter(bot_velocity_threshold=30).parse_string(doc)
    synthetic = [
        r
        for r in results
        if r.action_id == "confluence-bot-velocity-bot-velocity-1"
    ]
    assert len(synthetic) == 1
    cr = synthetic[0].control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["bot_velocity_count"] > 30


# ---------------------------------------------------------------------------
# Cross-space synthetic
# ---------------------------------------------------------------------------


def test_cross_space_synthetic() -> None:
    """Bot touching > N spaces → synthetic PR-02 FLAG."""
    records = []
    for i in range(7):
        records.append(
            _record(
                id=f"rec-cs-{i}",
                author_account_id="bot-cross-1",
                author_is_bot=True,
                summary="Page updated",
                space_key=f"SPACE{i}",
            )
        )
    doc = json.dumps({"results": records})
    results = ConfluenceImporter(cross_space_threshold=5).parse_string(doc)
    synthetic = [
        r for r in results if r.action_id == "confluence-cross-space-bot-cross-1"
    ]
    assert len(synthetic) == 1
    cr = synthetic[0].control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["cross_space_space_count"] > 5


# ---------------------------------------------------------------------------
# Sanitization tests
# ---------------------------------------------------------------------------


def test_subject_name_redacted() -> None:
    """subjectName (page title) is NEVER stored verbatim — only length+sha256."""
    secret_title = "Customer Onboarding — ACME Corp Confidential"
    doc = json.dumps(
        {
            "results": [
                _record(
                    id="rec-name-red",
                    summary="Page updated",
                    subject_name=secret_title,
                )
            ]
        }
    )
    [result] = ConfluenceImporter().parse_string(doc)
    blob = json.dumps(result.control_results[0].evidence_data)
    assert "Customer Onboarding" not in blob
    assert "ACME Corp" not in blob
    redacted = result.control_results[0].evidence_data["subject_name_redacted"]
    assert redacted is not None
    assert redacted["length"] == len(secret_title)
    assert redacted["sha256"] == hashlib.sha256(
        secret_title.encode("utf-8")
    ).hexdigest()


def test_changed_values_field_names_only() -> None:
    """changedValues retains ONLY field names — changedFrom/changedTo VALUES
    are stripped from evidence_data."""
    doc = json.dumps(
        {
            "results": [
                _record(
                    id="rec-cv",
                    summary="Page updated",
                    context={
                        "changedValues": [
                            {
                                "field": "title",
                                "changedFrom": "old-secret-title",
                                "changedTo": "new-secret-title",
                            },
                            {
                                "field": "labels",
                                "changedFrom": "internal",
                                "changedTo": "public",
                            },
                        ]
                    },
                )
            ]
        }
    )
    [result] = ConfluenceImporter().parse_string(doc)
    cr = result.control_results[0]
    assert cr.evidence_data["changed_value_field_names"] == ["title", "labels"]
    assert cr.evidence_data["changed_values_count"] == 2
    blob = json.dumps(cr.evidence_data)
    assert "old-secret-title" not in blob
    assert "new-secret-title" not in blob
    # Ensure the raw changedValues array is NOT echoed in evidence.
    assert "changedFrom" not in blob
    assert "changedTo" not in blob
