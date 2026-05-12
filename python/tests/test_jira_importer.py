"""Tests for the Jira audit-record importer."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ancilis.importers.jira import JiraImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Jira audit-record builders (no atlassian client required)
# ---------------------------------------------------------------------------


def _record(
    *,
    id: int | str = 1,
    summary: str = "User updated",
    category: str = "user management",
    author_key: str | None = "user-key-abc",
    author_account_id: str | None = "557058:abc-def",
    event_source: str | None = "AUDIT",
    description: str | None = None,
    object_item: dict | None = None,
    changed_values: list[dict] | None = None,
    associated_items: list[dict] | None = None,
    is_automated_action: bool = False,
    remote_address: str | None = "10.0.0.1",
    created: str = "2026-04-01T12:00:00.000+0000",
) -> dict:
    record: dict = {
        "id": id,
        "summary": summary,
        "category": category,
        "authorKey": author_key,
        "authorAccountId": author_account_id,
        "eventSource": event_source,
        "isAutomatedAction": is_automated_action,
        "created": created,
    }
    if description is not None:
        record["description"] = description
    if object_item is not None:
        record["objectItem"] = object_item
    if changed_values is not None:
        record["changedValues"] = changed_values
    if associated_items is not None:
        record["associatedItems"] = associated_items
    if remote_address is not None:
        record["remoteAddress"] = remote_address
    return record


def _findings_for_record(results: list, rec_id: str) -> list:
    return [r for r in results if r.action_id == f"jira-{rec_id}"]


# ---------------------------------------------------------------------------
# 1. user_management — created/deleted/perms
# ---------------------------------------------------------------------------


def test_parse_user_created_flags() -> None:
    """user management + 'User created' summary → PR-01 FLAG, FLAG decision."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    id="rec-uc",
                    summary="User created jdoe@example.com",
                    category="user management",
                    object_item={"id": "u-1", "name": "jdoe", "typeName": "USER"},
                )
            ]
        }
    )
    [result] = JiraImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flags = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "user_created"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-01"
    assert flags[0].result == "FLAG"


def test_user_deleted_audit() -> None:
    """user management + 'User deleted' summary → PR-05 PASS, ALLOW decision."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    id="rec-ud",
                    summary="User deleted jdoe@example.com",
                    category="user management",
                )
            ]
        }
    )
    [result] = JiraImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    pass_ = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "user_deleted"
    ]
    assert len(pass_) == 1
    assert pass_[0].control_id == "PR-05"
    assert pass_[0].result == "PASS"


def test_user_permission_change_flags() -> None:
    """user management + 'User permissions updated' → PR-02 FLAG."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    id="rec-up",
                    summary="User permissions updated for jdoe",
                    category="user management",
                )
            ]
        }
    )
    [result] = JiraImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flags = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "user_permission_change"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-02"
    assert flags[0].result == "FLAG"


# ---------------------------------------------------------------------------
# 2. permissions
# ---------------------------------------------------------------------------


def test_global_permission_grant_fails() -> None:
    """permissions + 'Global permission ... granted' → PR-02 FAIL, BLOCK.

    Org-level permission grants must run through governance review before
    they take effect. We FAIL conservatively so the evidence pipeline forces
    a human to acknowledge the grant.
    """
    doc = json.dumps(
        {
            "records": [
                _record(
                    id="rec-gp",
                    summary="Global permission ADMINISTER granted to group jira-admins",
                    category="permissions",
                )
            ]
        }
    )
    [result] = JiraImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fails = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert len(fails) == 1
    assert fails[0].control_id == "PR-02"
    assert fails[0].evidence_data["signal"] == "global_permission_grant"


def test_project_permission_scheme_change_flags() -> None:
    """permissions + 'Project permission scheme changed' → PR-02 FLAG."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    id="rec-pps",
                    summary="Project permission scheme changed for project ABC",
                    category="permissions",
                )
            ]
        }
    )
    [result] = JiraImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flags = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "project_permission_scheme_change"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-02"


# ---------------------------------------------------------------------------
# 3. workflows
# ---------------------------------------------------------------------------


def test_workflow_scheme_update_automated_flags() -> None:
    """workflows + 'Workflow scheme updated' + isAutomatedAction=True → PR-05 FLAG."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    id="rec-wsu",
                    summary="Workflow scheme updated",
                    category="workflows",
                    is_automated_action=True,
                )
            ]
        }
    )
    [result] = JiraImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flags = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "workflow_scheme_automated_update"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-05"
    assert flags[0].result == "FLAG"


def test_workflow_scheme_deleted_fails() -> None:
    """workflows + 'Workflow scheme deleted' → PR-02 FAIL, BLOCK."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    id="rec-wsd",
                    summary="Workflow scheme deleted",
                    category="workflows",
                )
            ]
        }
    )
    [result] = JiraImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fails = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.evidence_data.get("signal") == "workflow_scheme_deleted" for cr in fails
    )


# ---------------------------------------------------------------------------
# 4. issue events — bot-author / sprint-deletion
# ---------------------------------------------------------------------------


def test_bot_created_issue_flags() -> None:
    """issue + 'Issue created' by bot account → PR-01 FLAG."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    id="rec-bot-issue",
                    summary="Issue created in project ABC",
                    category="issue",
                    author_account_id="agent-claude-1",
                    object_item={
                        "id": "10001",
                        "name": "ABC-1",
                        "typeName": "ISSUE",
                        "parentId": "100",
                    },
                )
            ]
        }
    )
    [result] = JiraImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flags = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "agent_authored_issue"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-01"
    assert flags[0].evidence_data["author_is_bot"] is True


def test_active_sprint_issue_deleted_fails() -> None:
    """issue + 'Issue deleted' in active sprint → PR-02 FAIL, BLOCK.

    Sprint membership detection is engine territory — tested here by feeding
    the importer a known active-sprint issue id allowlist. The importer
    flags conservatively only when the deleted issue id is in the allowlist.
    """
    doc = json.dumps(
        {
            "records": [
                _record(
                    id="rec-del",
                    summary="Issue deleted ABC-42",
                    category="issue",
                    object_item={
                        "id": "ABC-42",
                        "name": "ABC-42",
                        "typeName": "ISSUE",
                        "parentId": "100",
                    },
                )
            ]
        }
    )
    importer = JiraImporter(active_sprint_issue_ids=["ABC-42"])
    [result] = importer.parse_string(doc)
    assert result.decision == "BLOCK"
    fails = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.evidence_data.get("signal") == "active_sprint_issue_deleted"
        for cr in fails
    )


# ---------------------------------------------------------------------------
# 5. changedValues — security level + reporter
# ---------------------------------------------------------------------------


def test_security_level_to_public_fails() -> None:
    """Issue Security Level changed (restrictive → Public) → PR-04 FAIL, BLOCK.

    Visibility-increase = potential data exposure. The importer detects the
    direction by inspecting changedFrom/changedTo in-flight, but never stores
    the raw values in evidence — only the boolean.
    """
    doc = json.dumps(
        {
            "records": [
                _record(
                    id="rec-sec",
                    summary="Issue updated ABC-1",
                    category="issue",
                    object_item={
                        "id": "ABC-1",
                        "typeName": "ISSUE",
                        "parentId": "100",
                    },
                    changed_values=[
                        {
                            "fieldName": "Issue Security Level",
                            "changedFrom": "Restricted",
                            "changedTo": "Public",
                        }
                    ],
                )
            ]
        }
    )
    [result] = JiraImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fails = [cr for cr in result.control_results if cr.result == "FAIL"]
    sec_fail = [
        cr
        for cr in fails
        if cr.evidence_data.get("signal") == "security_level_to_public"
    ]
    assert len(sec_fail) == 1
    assert sec_fail[0].control_id == "PR-04"
    # Raw value must NOT have been retained.
    serialized = json.dumps(sec_fail[0].evidence_data)
    assert "Restricted" not in serialized
    assert sec_fail[0].evidence_data["has_visibility_increase"] is True


def test_reporter_post_creation_change_flags() -> None:
    """Reporter changed after issue creation → PR-05 FLAG (audit anomaly)."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    id="rec-reporter",
                    summary="Issue updated ABC-1",
                    category="issue",
                    object_item={
                        "id": "ABC-1",
                        "typeName": "ISSUE",
                        "parentId": "100",
                    },
                    changed_values=[
                        {
                            "fieldName": "Reporter",
                            "changedFrom": "user-1",
                            "changedTo": "user-2",
                        }
                    ],
                )
            ]
        }
    )
    [result] = JiraImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flags = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "reporter_post_creation_change"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-05"


# ---------------------------------------------------------------------------
# 6. eventSource = AUTOMATION
# ---------------------------------------------------------------------------


def test_automation_event_passes() -> None:
    """eventSource=AUTOMATION → PR-05 PASS (Jira Automation audit captured)."""
    doc = json.dumps(
        {
            "records": [
                _record(
                    id="rec-auto",
                    summary="Issue updated by automation",
                    category="issue",
                    event_source="AUTOMATION",
                    is_automated_action=True,
                )
            ]
        }
    )
    [result] = JiraImporter().parse_string(doc)
    automation_passes = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "automation_event"
    ]
    assert len(automation_passes) == 1
    assert automation_passes[0].control_id == "PR-05"
    assert automation_passes[0].result == "PASS"


# ---------------------------------------------------------------------------
# 7. Synthetic findings
# ---------------------------------------------------------------------------


def test_bot_velocity_synthetic() -> None:
    """A bot account creating > 20 issues in 1h → synthetic PR-02 FLAG."""
    base = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
    records = [
        _record(
            id=f"rec-bv-{i}",
            summary="Issue created",
            category="issue",
            author_account_id="agent-spam",
            object_item={
                "id": f"X-{i}",
                "typeName": "ISSUE",
                "parentId": "100",
            },
            created=(base + timedelta(seconds=i * 60)).isoformat(),
        )
        for i in range(25)
    ]
    doc = json.dumps({"records": records})
    results = JiraImporter().parse_string(doc)

    synthetics = [r for r in results if r.action_id == "jira-bot-velocity-agent-spam"]
    assert len(synthetics) == 1
    syn = synthetics[0]
    assert syn.decision == "FLAG"
    assert syn.control_results[0].control_id == "PR-02"
    assert syn.control_results[0].evidence_data["bot_velocity_count"] >= 21
    assert syn.control_results[0].evidence_data["synthetic"] is True


def test_cross_project_synthetic() -> None:
    """One account touching > 10 projects → synthetic PR-02 FLAG."""
    records = [
        _record(
            id=f"rec-cp-{i}",
            summary="Issue updated",
            category="issue",
            author_account_id="agent-spreader",
            object_item={
                "id": f"X-{i}",
                "typeName": "ISSUE",
                "parentId": str(1000 + i),
            },
        )
        for i in range(11)
    ]
    doc = json.dumps({"records": records})
    results = JiraImporter().parse_string(doc)

    synthetics = [
        r for r in results if r.action_id == "jira-cross-project-agent-spreader"
    ]
    assert len(synthetics) == 1
    syn = synthetics[0]
    assert syn.decision == "FLAG"
    assert syn.control_results[0].control_id == "PR-02"
    assert syn.control_results[0].evidence_data["cross_project_project_count"] == 11
    assert syn.control_results[0].evidence_data["synthetic"] is True


# ---------------------------------------------------------------------------
# 8. Sanitization
# ---------------------------------------------------------------------------


def test_changed_values_field_names_only() -> None:
    """changedValues retains ONLY fieldName — never changedFrom / changedTo values."""
    sensitive_from = "internal-customer-merger-secret"
    sensitive_to = "tenant-acme-corp-confidential"
    doc = json.dumps(
        {
            "records": [
                _record(
                    id="rec-cv",
                    summary="Issue updated",
                    category="issue",
                    object_item={
                        "id": "ABC-1",
                        "typeName": "ISSUE",
                        "parentId": "100",
                    },
                    changed_values=[
                        {
                            "fieldName": "Description",
                            "changedFrom": sensitive_from,
                            "changedTo": sensitive_to,
                        },
                        {
                            "fieldName": "Summary",
                            "changedFrom": "old summary",
                            "changedTo": "new summary",
                        },
                    ],
                )
            ]
        }
    )
    [result] = JiraImporter().parse_string(doc)
    serialized = json.dumps([cr.evidence_data for cr in result.control_results])
    # Field names retained.
    assert "Description" in serialized
    assert "Summary" in serialized
    # Values must NOT appear anywhere in evidence data.
    assert sensitive_from not in serialized
    assert sensitive_to not in serialized
    assert "old summary" not in serialized
    assert "new summary" not in serialized
    # Evidence data exposes the structured count + names list, no raw cv structure.
    for cr in result.control_results:
        assert cr.evidence_data["changed_value_field_names"] == [
            "Description",
            "Summary",
        ]
        assert cr.evidence_data["changed_values_count"] == 2
        assert "changed_values" not in cr.evidence_data
        assert "changedValues" not in cr.evidence_data


def test_remote_address_redacted() -> None:
    """Public IPv4 remoteAddress → reduced to /16 in evidence; private kept verbatim."""
    public_record = _record(
        id="rec-pub",
        summary="User created jdoe",
        category="user management",
        remote_address="8.8.8.8",
    )
    private_record = _record(
        id="rec-priv",
        summary="User created jdoe",
        category="user management",
        remote_address="10.0.0.5",
    )
    doc = json.dumps({"records": [public_record, private_record]})
    results = JiraImporter().parse_string(doc)
    pub = _findings_for_record(results, "rec-pub")[0]
    priv = _findings_for_record(results, "rec-priv")[0]
    pub_serialized = json.dumps([cr.evidence_data for cr in pub.control_results])
    priv_serialized = json.dumps([cr.evidence_data for cr in priv.control_results])
    # Public IP → /16 mask, full address absent.
    assert "8.8.8.8" not in pub_serialized
    assert "8.8.0.0/16" in pub_serialized
    # Private (RFC1918) IP preserved verbatim.
    assert "10.0.0.5" in priv_serialized


# ---------------------------------------------------------------------------
# 9. Source provenance + envelope shape parsing
# ---------------------------------------------------------------------------


def test_source_provenance_includes_file_hash(tmp_path: Path) -> None:
    """parse(path) hashes the file bytes; parse_string omits the hash."""
    payload = json.dumps(
        {
            "records": [
                _record(
                    id="rec-prov",
                    summary="User deleted jdoe",
                    category="user management",
                )
            ]
        }
    ).encode("utf-8")
    expected_sha = hashlib.sha256(payload).hexdigest()
    file_path = tmp_path / "jira-export.json"
    file_path.write_bytes(payload)

    [result] = JiraImporter().parse(file_path)
    cr = result.control_results[0]
    provenance = cr.evidence_data["source_provenance"]
    assert provenance["source_format"] == "jira_audit_record"
    assert provenance["source_tool_name"] == "jira"
    assert provenance["record_id"] == "rec-prov"
    assert provenance["original_file_sha256"] == expected_sha

    [result_str] = JiraImporter().parse_string(payload.decode("utf-8"))
    assert (
        "original_file_sha256"
        not in result_str.control_results[0].evidence_data["source_provenance"]
    )


def test_envelope_shapes_and_jsonl() -> None:
    """Importer accepts {"records":[]}, {"events":[]}, {"data":[]}, JSONL, single record."""
    rec1 = _record(id="rec-env-1", summary="User deleted u1", category="user management")
    rec2 = _record(id="rec-env-2", summary="User deleted u2", category="user management")

    for envelope in ("records", "events", "data"):
        doc = json.dumps({envelope: [rec1, rec2]})
        results = JiraImporter().parse_string(doc)
        assert {r.action_id for r in results} == {"jira-rec-env-1", "jira-rec-env-2"}

    # JSONL.
    jsonl = "\n".join([json.dumps(rec1), json.dumps(rec2), ""])
    results_jsonl = JiraImporter().parse_string(jsonl)
    assert {r.action_id for r in results_jsonl} == {
        "jira-rec-env-1",
        "jira-rec-env-2",
    }

    # Single record (no envelope).
    [single] = JiraImporter().parse_string(json.dumps(rec1))
    assert single.action_id == "jira-rec-env-1"


def test_summary_truncated_with_hash() -> None:
    """A long summary is truncated to 200 chars + sha256 + length is captured."""
    long_summary = "User permissions updated " + ("X" * 500)
    full_hash = hashlib.sha256(long_summary.encode("utf-8")).hexdigest()
    doc = json.dumps(
        {
            "records": [
                _record(
                    id="rec-trunc",
                    summary=long_summary,
                    category="user management",
                )
            ]
        }
    )
    [result] = JiraImporter().parse_string(doc)
    cr = result.control_results[0]
    assert cr.evidence_data["summary"]["length"] == len(long_summary)
    assert cr.evidence_data["summary"]["sha256"] == full_hash
    assert len(cr.evidence_data["summary"]["prefix"]) == 200


def test_importer_exported_from_package() -> None:
    """JiraImporter is re-exported from ancilis.importers."""
    from ancilis.importers import JiraImporter as Exported

    assert Exported is JiraImporter


def test_mapping_table_is_valid_json() -> None:
    """Shipped mapping table is valid JSON with the required signals & metadata."""
    mapping_path = (
        Path(__file__).resolve().parent.parent.parent
        / "shared"
        / "mappings"
        / "jira-aksi-controls.json"
    )
    data = json.loads(mapping_path.read_text())
    meta = data["_metadata"]
    assert meta["bot_velocity_threshold"] == 20
    assert meta["cross_project_threshold"] == 10
    assert isinstance(meta["bot_account_patterns"], list)
    mappings = data["mappings"]
    assert mappings["user_created"] == "PR-01"
    assert mappings["user_deleted"] == "PR-05"
    assert mappings["user_permission_change"] == "PR-02"
    assert mappings["global_permission_grant"] == "PR-02"
    assert mappings["workflow_scheme_deleted"] == "PR-02"
    assert mappings["workflow_scheme_automated_update"] == "PR-05"
    assert mappings["security_level_to_public"] == "PR-04"
    assert mappings["agent_authored_issue"] == "PR-01"
    assert mappings["active_sprint_issue_deleted"] == "PR-02"
    assert mappings["bot_velocity_pattern"] == "PR-02"
    assert mappings["cross_project_pattern"] == "PR-02"
