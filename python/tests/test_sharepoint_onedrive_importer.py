"""Tests for the SharePoint Online + OneDrive for Business importer."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from ancilis.importers.sharepoint_onedrive import SharePointOneDriveImporter


# ---------------------------------------------------------------------------
# Fixture builders — produce Microsoft 365 Unified Audit Log shaped events.
# ---------------------------------------------------------------------------


def _event(
    *,
    event_id: str = "evt-001",
    operation: str = "FileAccessed",
    created_at: str = "2026-05-09T12:00:00Z",
    user_principal_name: str = "agent@example.com",
    user_type: str = "Regular",
    result_status: str = "Success",
    workload: str = "OneDrive",
    client_ip: str = "203.0.113.42",
    user_agent: str = "OneDrive/2026.05.0",
    site_url: str = "https://example.sharepoint.com/sites/team",
    object_id: str = "https://example.sharepoint.com/sites/team/x/12345abc",
    item_type: str = "File",
    source_file_extension: str = "pdf",
    source_file_name_length: int = 50,
    source_relative_url_length: int = 80,
    file_size: int = 1024,
    sensitivity_label_name: str | None = "Confidential",
    sharing_target_type: str | None = None,
    sharing_permission: str | None = None,
    target_user_or_group_name_domain: str | None = None,
    modified_properties: list[dict[str, Any]] | None = None,
    audit_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    e: dict[str, Any] = {
        "id": event_id,
        "operation": operation,
        "createdDateTime": created_at,
        "userPrincipalName": user_principal_name,
        "userType": user_type,
        "resultStatus": result_status,
        "workload": workload,
        "clientIP": client_ip,
        "userAgent": user_agent,
        "siteUrl": site_url,
        "objectId": object_id,
        "itemType": item_type,
        "sourceFileExtension": source_file_extension,
        "sourceFileName_length": source_file_name_length,
        "sourceRelativeUrl_length": source_relative_url_length,
        "fileSize": file_size,
    }
    if sensitivity_label_name is not None:
        e["sensitivityLabelName"] = sensitivity_label_name
        e["sensitivityLabelId"] = "label-id-confidential"
    if sharing_target_type is not None:
        e["sharingTargetType"] = sharing_target_type
    if sharing_permission is not None:
        e["sharingPermission"] = sharing_permission
    if target_user_or_group_name_domain is not None:
        e["targetUserOrGroupName_domain"] = target_user_or_group_name_domain
    if modified_properties is not None:
        e["modifiedProperties"] = modified_properties
    if audit_data is not None:
        e["auditData"] = audit_data
    return e


def _signals(result) -> set[str]:
    return {cr.evidence_data.get("signal") for cr in result.control_results}


# ---------------------------------------------------------------------------
# Per-event classification
# ---------------------------------------------------------------------------


def test_file_accessed_passes() -> None:
    """FileAccessed → PR-04 PASS, ALLOW."""
    e = _event(event_id="ev-access", operation="FileAccessed")
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "ALLOW"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "PASS"
        and cr.evidence_data.get("signal") == "file_accessed_or_previewed"
        for cr in r.control_results
    )


def test_agent_download_sensitive_extension_fails() -> None:
    """FileDownloaded by Application on csv → PR-04 FAIL, BLOCK."""
    e = _event(
        event_id="ev-agent-dl",
        operation="FileDownloaded",
        user_type="Application",
        source_file_extension="csv",
    )
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
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


def test_full_sync_flags() -> None:
    """FileSyncDownloadedFull → PR-04 FLAG."""
    e = _event(
        event_id="ev-full-sync",
        operation="FileSyncDownloadedFull",
        workload="OneDrive",
    )
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "full_sync_download"
        for cr in r.control_results
    )


def test_anonymous_link_fails() -> None:
    """AnonymousLinkCreated → DE-01 FAIL, BLOCK (parallel to Box public-unprotected)."""
    e = _event(
        event_id="ev-anon-link",
        operation="AnonymousLinkCreated",
    )
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "DE-01"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "anonymous_link_created"
        for cr in r.control_results
    )


def test_external_guest_share_flags() -> None:
    """SecureLinkCreated + sharingTargetType=Guest → PR-04 FLAG."""
    e = _event(
        event_id="ev-guest",
        operation="SecureLinkCreated",
        sharing_target_type="Guest",
    )
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "external_guest_share"
        for cr in r.control_results
    )


def test_sensitivity_downgrade_fails() -> None:
    """FileSensitivityLabelChanged to a more permissive label → PR-04 FAIL."""
    e = _event(
        event_id="ev-label-down",
        operation="FileSensitivityLabelChanged",
        sensitivity_label_name="Public",
        modified_properties=[
            {
                "name": "SensitivityLabel",
                "oldValue_length": 12,
                "newValue_length": 6,
            }
        ],
    )
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "sensitivity_downgrade"
        and cr.evidence_data.get("sensitivity_label_name") == "Public"
        for cr in r.control_results
    )


def test_sharing_policy_changed_fails() -> None:
    """SharingPolicyChanged → PR-02 FAIL."""
    e = _event(
        event_id="ev-policy",
        operation="SharingPolicyChanged",
        user_type="Admin",
    )
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-02"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "sharing_policy_changed"
        for cr in r.control_results
    )


def test_anonymous_site_perms_fails() -> None:
    """SitePermissionsModified to AllowAnonymousAccess → DE-01 FAIL."""
    e = _event(
        event_id="ev-site-anon",
        operation="SitePermissionsModified",
        modified_properties=[
            {
                "name": "AllowAnonymousAccess",
                "oldValue_length": 5,
                "newValue_length": 4,
            }
        ],
    )
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "DE-01"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "anonymous_site_permissions"
        for cr in r.control_results
    )


def test_dlp_high_fails() -> None:
    """DLPRuleMatch DLPSeverity=high → PR-04 FAIL, BLOCK (top priority)."""
    e = _event(
        event_id="ev-dlp-high",
        operation="DLPRuleMatch",
        audit_data={
            "DLPRuleId": "rule-id-cafebabe1234",
            "DLPRuleName": "PII Detection",
            "DLPSeverity": "high",
            "DLPMatchedConditions": ["customer-pii", "financial-data"],
            "DLPSourceUserName_domain": "@example.com",
        },
    )
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "dlp_rule_high"
        and cr.evidence_data.get("dlp_rule_name") == "PII Detection"
        and cr.evidence_data.get("dlp_severity") == "high"
        and cr.evidence_data.get("dlp_matched_conditions")
        == ["customer-pii", "financial-data"]
        for cr in r.control_results
    )


def test_malware_detected_fails() -> None:
    """FileMalwareDetected → DE-01 FAIL, BLOCK."""
    e = _event(
        event_id="ev-malware",
        operation="FileMalwareDetected",
    )
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "DE-01"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "file_malware_detected"
        for cr in r.control_results
    )


def test_bulk_download_synthetic_fail() -> None:
    """Same userPrincipalName with > N FileDownloaded in 1h → synthetic PR-04 FAIL."""
    base_time = datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)
    events = []
    for i in range(55):
        ts = (base_time + timedelta(seconds=i * 30)).isoformat()
        events.append(
            _event(
                event_id=f"ev-bulk-{i}",
                operation="FileDownloaded",
                created_at=ts,
                user_principal_name="bulk@example.com",
                user_type="Regular",
                source_file_extension="pdf",
            )
        )
    results = SharePointOneDriveImporter(
        agent_id="test", bulk_download_threshold=50
    ).parse_string(json.dumps({"events": events}))
    synthetic = [
        r for r in results if r.action_id.startswith("m365-bulk-download-")
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


def test_cross_site_synthetic_flag() -> None:
    """Same user touching > N siteUrl in 1h → synthetic PR-04 FLAG."""
    base_time = datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)
    events = []
    for i in range(8):
        ts = (base_time + timedelta(seconds=i * 30)).isoformat()
        events.append(
            _event(
                event_id=f"ev-site-{i}",
                operation="FileAccessed",
                created_at=ts,
                user_principal_name="recon@example.com",
                user_type="Regular",
                site_url=f"https://example.sharepoint.com/sites/team-{i}",
                object_id=(
                    f"https://example.sharepoint.com/sites/team-{i}/x/"
                    f"obj-{i:08d}"
                ),
            )
        )
    results = SharePointOneDriveImporter(
        agent_id="test",
        cross_site_threshold=5,
    ).parse_string(json.dumps({"events": events}))
    synthetic = [
        r for r in results if r.action_id.startswith("m365-cross-site-")
    ]
    assert len(synthetic) == 1
    s = synthetic[0]
    assert s.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "cross_site_pattern"
        for cr in s.control_results
    )


def test_file_name_not_stored_verbatim() -> None:
    """sourceFileName + sourceRelativeUrl + siteUrl-full-path must NEVER be stored verbatim — length only / hostname+first-segment only."""
    sensitive_name = "Q4-acquisition-target-list-CONFIDENTIAL.xlsx"
    sensitive_rel = (
        "/sites/team/SecretFolder/Q4-acquisition-target-list-CONFIDENTIAL.xlsx"
    )
    sensitive_site = (
        "https://example.sharepoint.com/sites/team/SecretFolder/sub"
    )
    e = _event(
        event_id="ev-name",
        operation="FileAccessed",
        site_url=sensitive_site,
        object_id=(
            "https://example.sharepoint.com/sites/team/SecretFolder/"
            "secrets-abcdef-99887766"
        ),
        source_file_extension="xlsx",
    )
    # Drop pre-computed lengths so the importer derives them from the raw
    # values — and inject the raw name + relative URL. The importer must
    # reduce both to length only and never store the value verbatim.
    e.pop("sourceFileName_length", None)
    e.pop("sourceRelativeUrl_length", None)
    e["sourceFileName"] = sensitive_name
    e["sourceRelativeUrl"] = sensitive_rel
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    payload = json.dumps(
        [cr.evidence_data for cr in r.control_results], default=str
    )
    # Raw file name and relative URL must not appear verbatim.
    assert sensitive_name not in payload
    assert sensitive_rel not in payload
    # Full siteUrl path beyond first segment must also not appear verbatim.
    assert "SecretFolder" not in payload
    cr = r.control_results[0]
    assert cr.evidence_data.get("source_file_name_length") == len(
        sensitive_name
    )
    assert cr.evidence_data.get("source_relative_url_length") == len(
        sensitive_rel
    )
    # site_url_redacted should be host + first path segment only.
    assert (
        cr.evidence_data.get("site_url_redacted")
        == "example.sharepoint.com/sites"
    )
    # objectId should be the trailing 8 chars only.
    assert cr.evidence_data.get("object_id_last8") == "99887766"


def test_email_domain_only_stored() -> None:
    """userPrincipalName + DLPSourceUserName must NOT be stored verbatim — domain only."""
    full_upn = "alice.smith@example.com"
    full_dlp_user = "bob.jones@another.com"
    e = _event(
        event_id="ev-email",
        operation="DLPRuleMatch",
        user_principal_name=full_upn,
        audit_data={
            "DLPRuleName": "PII",
            "DLPSeverity": "high",
            "DLPSourceUserName": full_dlp_user,
        },
    )
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    cr = r.control_results[0]
    payload = json.dumps(cr.evidence_data, default=str)
    # Local-parts of UPN and DLP source user must never appear verbatim.
    assert "alice.smith" not in payload
    assert "bob.jones" not in payload
    assert (
        cr.evidence_data.get("user_principal_name_domain") == "@example.com"
    )
    assert cr.evidence_data.get("dlp_source_user_domain") == "@another.com"


def test_external_full_control_grant_fails() -> None:
    """sharingPermission=FullControl/Owner granted to external → PR-02 FAIL."""
    e = _event(
        event_id="ev-broad-ext",
        operation="SecureLinkCreated",
        sharing_target_type="Guest",
        sharing_permission="FullControl",
        target_user_or_group_name_domain="@external.com",
    )
    results = SharePointOneDriveImporter(
        agent_id="test", tenant_primary_domain="example.com"
    ).parse_string(json.dumps({"events": [e]}))
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-02"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "external_full_control_grant"
        for cr in r.control_results
    )


def test_failed_access_denied_passes() -> None:
    """resultStatus=Failed on FileAccessed → PR-02 PASS (correctly denied)."""
    e = _event(
        event_id="ev-access-denied",
        operation="FileAccessed",
        result_status="Failed",
    )
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "ALLOW"
    assert any(
        cr.control_id == "PR-02"
        and cr.result == "PASS"
        and cr.evidence_data.get("signal") == "failed_access_denied"
        for cr in r.control_results
    )


def test_external_sharing_invitation_flags() -> None:
    """SharingInvitationCreated to non-tenant-primary domain → PR-04 FLAG."""
    e = _event(
        event_id="ev-invite-ext",
        operation="SharingInvitationCreated",
        target_user_or_group_name_domain="@external.com",
    )
    results = SharePointOneDriveImporter(
        agent_id="test", tenant_primary_domain="example.com"
    ).parse_string(json.dumps({"events": [e]}))
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "external_sharing_invitation"
        for cr in r.control_results
    )


def test_jsonl_ingestion() -> None:
    """JSONL input — one event per line."""
    e1 = _event(event_id="jsonl-1", operation="FileAccessed")
    e2 = _event(
        event_id="jsonl-2",
        operation="DLPRuleMatch",
        audit_data={"DLPRuleName": "PCI", "DLPSeverity": "high"},
    )
    content = json.dumps(e1) + "\n" + json.dumps(e2) + "\n"
    results = SharePointOneDriveImporter(agent_id="test").parse_string(content)
    assert len(results) == 2


def test_data_envelope_ingestion() -> None:
    """``{"data": [...]}`` envelope is also accepted."""
    e = _event(event_id="data-1", operation="FileAccessed")
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"data": [e]})
    )
    assert len(results) == 1


def test_site_deleted_fails() -> None:
    """SiteDeleted → PR-02 FAIL (site destruction)."""
    e = _event(
        event_id="ev-site-del",
        operation="SiteDeleted",
        user_type="Admin",
    )
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "BLOCK"
    assert any(
        cr.control_id == "PR-02"
        and cr.result == "FAIL"
        and cr.evidence_data.get("signal") == "site_deleted"
        for cr in r.control_results
    )


def test_site_admin_added_flags() -> None:
    """SiteCollectionAdminAdded → PR-02 FLAG (admin role grant)."""
    e = _event(
        event_id="ev-admin-add",
        operation="SiteCollectionAdminAdded",
    )
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-02"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "site_admin_added"
        for cr in r.control_results
    )


def test_dlp_medium_flags() -> None:
    """DLPRuleMatch DLPSeverity=medium → PR-04 FLAG."""
    e = _event(
        event_id="ev-dlp-med",
        operation="DLPRuleMatch",
        audit_data={
            "DLPRuleName": "Internal-Watch",
            "DLPSeverity": "medium",
            "DLPMatchedConditions": ["watchword"],
        },
    )
    results = SharePointOneDriveImporter(agent_id="test").parse_string(
        json.dumps({"events": [e]})
    )
    assert len(results) == 1
    r = results[0]
    assert r.decision == "FLAG"
    assert any(
        cr.control_id == "PR-04"
        and cr.result == "FLAG"
        and cr.evidence_data.get("signal") == "dlp_rule_medium"
        for cr in r.control_results
    )
