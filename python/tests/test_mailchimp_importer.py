"""Tests for the Mailchimp marketing-email audit-log importer."""

from __future__ import annotations

import json

from ancilis.importers.mailchimp import MailchimpImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Mailchimp audit-log records (no mailchimp-marketing pkg)
# ---------------------------------------------------------------------------


def _campaign_sent(
    *,
    event_id: str = "evt-0001",
    timestamp: str = "2026-04-01T12:00:00Z",
    actor_user_id: str = "user-001",
    actor_email: str = "agent@example.com",
    is_api_user: bool = False,
    is_workspace_admin: bool = False,
    is_marketing: bool = True,
    consent_basis: str | None = "opt_in",
    recipient_count: int = 50000,
    contains_eu_subscribers: bool = False,
    is_double_optin: bool = True,
    contains_pii_columns: bool = True,
    audience_id: str = "aud-abcdefgh12345678",
    campaign_id: str = "camp-001",
    audience_size: int = 50000,
    compliance_check_passed: bool = True,
    unsubscribe_link_present: bool = True,
    physical_address_present: bool = True,
    spf: bool = True,
    dkim: bool = True,
    dmarc: bool = True,
    bimi: bool = False,
    deliverability_score: int = 98,
    complaint_rate: float = 0.001,
    bounce_rate: float = 0.005,
) -> dict:
    return {
        "id": event_id,
        "timestamp": timestamp,
        "event_type": "campaign_sent",
        "actor": {
            "user_id": actor_user_id,
            "email": actor_email,
            "is_api_user": is_api_user,
            "is_workspace_admin": is_workspace_admin,
        },
        "campaign": {
            "id": campaign_id,
            "subject_length": 50,
            "audience_id": audience_id,
            "contains_personalization": True,
            "recipient_count": recipient_count,
            "is_marketing": is_marketing,
            "consent_basis": consent_basis,
            "compliance_check_passed": compliance_check_passed,
            "contains_dma_required_disclosures": True,
            "audience_size": audience_size,
            "unsubscribe_link_present": unsubscribe_link_present,
            "physical_address_present": physical_address_present,
            "sender_authentication": {
                "spf": spf,
                "dkim": dkim,
                "dmarc": dmarc,
                "bimi": bimi,
            },
            "deliverability_score": deliverability_score,
            "complaint_rate": complaint_rate,
            "bounce_rate": bounce_rate,
        },
        "audience": {
            "id": audience_id,
            "name_length": 20,
            "contains_pii_columns": contains_pii_columns,
            "member_count": audience_size,
            "is_double_optin": is_double_optin,
            "contains_eu_subscribers": contains_eu_subscribers,
        },
        "action_metadata": {
            "target_count": 1,
            "is_bulk": False,
            "ip_address": "10.0.0.1",
            "sender_email_domain": "@example.com",
        },
    }


def _findings_for_action(results, action_id: str):
    return [r for r in results if r.action_id == action_id]


def _signals(result):
    return {
        cr.evidence_data.get("signal")
        for cr in result.control_results
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_marketing_no_consent_blocks() -> None:
    """campaign_sent + is_marketing=true + consent_basis=null → DE-01 FAIL."""
    importer = MailchimpImporter()
    rec = _campaign_sent(event_id="m-001", consent_basis=None)
    results = importer.parse_string(json.dumps({"events": [rec]}))
    findings = _findings_for_action(results, "mailchimp-m-001")
    assert len(findings) == 1
    fr = findings[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "marketing_no_consent_canspam"
    )
    assert primary.control_id == "DE-01"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_marketing_eu_no_optin_fails() -> None:
    """campaign_sent + EU subscribers + consent_basis=legitimate_interest → PR-04 FAIL."""
    importer = MailchimpImporter()
    rec = _campaign_sent(
        event_id="m-002",
        consent_basis="legitimate_interest",
        contains_eu_subscribers=True,
    )
    results = importer.parse_string(json.dumps({"events": [rec]}))
    fr = _findings_for_action(results, "mailchimp-m-002")[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "marketing_eu_no_optin"
    )
    assert primary.control_id == "PR-04"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_missing_unsubscribe_link_fails() -> None:
    """campaign_sent + unsubscribe_link_present=false → PR-05 FAIL."""
    importer = MailchimpImporter()
    rec = _campaign_sent(event_id="m-003", unsubscribe_link_present=False)
    results = importer.parse_string(json.dumps({"events": [rec]}))
    fr = _findings_for_action(results, "mailchimp-m-003")[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "missing_unsubscribe_link"
    )
    assert primary.control_id == "PR-05"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_missing_physical_address_fails() -> None:
    """campaign_sent + physical_address_present=false → PR-05 FAIL."""
    importer = MailchimpImporter()
    rec = _campaign_sent(event_id="m-004", physical_address_present=False)
    results = importer.parse_string(json.dumps({"events": [rec]}))
    fr = _findings_for_action(results, "mailchimp-m-004")[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "missing_physical_address"
    )
    assert primary.control_id == "PR-05"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_compliance_check_failed_fails() -> None:
    """campaign_sent + compliance_check_passed=false → PR-04 FAIL."""
    importer = MailchimpImporter()
    rec = _campaign_sent(event_id="m-005", compliance_check_passed=False)
    results = importer.parse_string(json.dumps({"events": [rec]}))
    fr = _findings_for_action(results, "mailchimp-m-005")[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "compliance_check_failed"
    )
    assert primary.control_id == "PR-04"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_sender_auth_missing_fails() -> None:
    """campaign_sent + spf=false → PR-04 FAIL (sender auth missing)."""
    importer = MailchimpImporter()
    rec = _campaign_sent(event_id="m-006", spf=False)
    results = importer.parse_string(json.dumps({"events": [rec]}))
    fr = _findings_for_action(results, "mailchimp-m-006")[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "sender_auth_missing"
    )
    assert primary.control_id == "PR-04"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_complaint_rate_too_high_fails() -> None:
    """campaign_sent + complaint_rate > 0.005 → PR-04 FAIL."""
    importer = MailchimpImporter()
    rec = _campaign_sent(event_id="m-007", complaint_rate=0.01)
    results = importer.parse_string(json.dumps({"events": [rec]}))
    fr = _findings_for_action(results, "mailchimp-m-007")[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "complaint_rate_high"
    )
    assert primary.control_id == "PR-04"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_bounce_rate_too_high_fails() -> None:
    """campaign_sent + bounce_rate > 0.05 → PR-04 FAIL."""
    importer = MailchimpImporter()
    rec = _campaign_sent(event_id="m-008", bounce_rate=0.10)
    results = importer.parse_string(json.dumps({"events": [rec]}))
    fr = _findings_for_action(results, "mailchimp-m-008")[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "bounce_rate_high"
    )
    assert primary.control_id == "PR-04"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_list_imported_pii_flags() -> None:
    """list_imported + contains_pii_columns=true → PR-04 FLAG."""
    importer = MailchimpImporter()
    rec = {
        "id": "li-001",
        "timestamp": "2026-04-01T12:00:00Z",
        "event_type": "list_imported",
        "actor": {"user_id": "user-001", "email": "agent@example.com"},
        "audience": {
            "id": "aud-zzz12345678",
            "name_length": 10,
            "contains_pii_columns": True,
            "is_double_optin": True,
            "member_count": 1000,
            "contains_eu_subscribers": False,
        },
    }
    results = importer.parse_string(json.dumps({"events": [rec]}))
    fr = _findings_for_action(results, "mailchimp-li-001")[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "list_imported_pii"
    )
    assert primary.control_id == "PR-04"
    assert primary.result == "FLAG"
    assert fr.decision == "FLAG"


def test_list_imported_single_optin_fails() -> None:
    """list_imported + is_double_optin=false → PR-04 FAIL."""
    importer = MailchimpImporter()
    rec = {
        "id": "li-002",
        "timestamp": "2026-04-01T12:00:00Z",
        "event_type": "list_imported",
        "actor": {"user_id": "user-001", "email": "agent@example.com"},
        "audience": {
            "id": "aud-yyy87654321",
            "name_length": 10,
            "contains_pii_columns": False,
            "is_double_optin": False,
            "member_count": 1000,
            "contains_eu_subscribers": False,
        },
    }
    results = importer.parse_string(json.dumps({"events": [rec]}))
    fr = _findings_for_action(results, "mailchimp-li-002")[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "list_imported_single_optin"
    )
    assert primary.control_id == "PR-04"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_list_exported_flags() -> None:
    """list_exported → PR-04 FLAG."""
    importer = MailchimpImporter()
    rec = {
        "id": "le-001",
        "timestamp": "2026-04-01T12:00:00Z",
        "event_type": "list_exported",
        "actor": {"user_id": "user-001", "email": "agent@example.com"},
        "audience": {"id": "aud-xxx00009999"},
    }
    results = importer.parse_string(json.dumps({"events": [rec]}))
    fr = _findings_for_action(results, "mailchimp-le-001")[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "list_exported"
    )
    assert primary.control_id == "PR-04"
    assert primary.result == "FLAG"
    assert fr.decision == "FLAG"


def test_list_deleted_fails() -> None:
    """list_deleted → PR-02 FAIL."""
    importer = MailchimpImporter()
    rec = {
        "id": "ld-001",
        "timestamp": "2026-04-01T12:00:00Z",
        "event_type": "list_deleted",
        "actor": {"user_id": "user-001", "email": "agent@example.com"},
        "audience": {"id": "aud-doomed12345"},
    }
    results = importer.parse_string(json.dumps({"events": [rec]}))
    fr = _findings_for_action(results, "mailchimp-ld-001")[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "list_deleted"
    )
    assert primary.control_id == "PR-02"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_member_added_no_consent_fails() -> None:
    """list_member_added + audience.is_double_optin=false + no consent → PR-04 FAIL."""
    importer = MailchimpImporter()
    rec = {
        "id": "ma-001",
        "timestamp": "2026-04-01T12:00:00Z",
        "event_type": "list_member_added",
        "actor": {"user_id": "user-001", "email": "agent@example.com"},
        "audience": {
            "id": "aud-zzzzzzzz1234",
            "is_double_optin": False,
        },
        "campaign": {
            "consent_basis": None,
        },
    }
    results = importer.parse_string(json.dumps({"events": [rec]}))
    fr = _findings_for_action(results, "mailchimp-ma-001")[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "member_added_no_consent"
    )
    assert primary.control_id == "PR-04"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_webhook_external_flags() -> None:
    """webhook_added with host not in allowlist → PR-04 FLAG."""
    importer = MailchimpImporter(webhook_host_allowlist=["internal.example.com"])
    rec = {
        "id": "wh-001",
        "timestamp": "2026-04-01T12:00:00Z",
        "event_type": "webhook_added",
        "actor": {"user_id": "user-001", "email": "agent@example.com"},
        "action_metadata": {
            "webhook_url_host": "https://external.attacker.test/hook?x=1",
        },
    }
    results = importer.parse_string(json.dumps({"events": [rec]}))
    fr = _findings_for_action(results, "mailchimp-wh-001")[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "webhook_external"
    )
    assert primary.control_id == "PR-04"
    assert primary.result == "FLAG"
    assert fr.decision == "FLAG"
    # URL path/query never preserved.
    assert "external.attacker.test" in primary.evidence_data["action_metadata"]["webhook_url_host"]
    assert "hook" not in primary.evidence_data["action_metadata"]["webhook_url_host"]


def test_role_admin_fails() -> None:
    """team_member_role_changed + new_role=admin → PR-02 FAIL."""
    importer = MailchimpImporter()
    rec = {
        "id": "rm-001",
        "timestamp": "2026-04-01T12:00:00Z",
        "event_type": "team_member_role_changed",
        "actor": {"user_id": "user-001", "email": "agent@example.com"},
        "action_metadata": {
            "new_role": "admin",
            "old_role": "viewer",
        },
    }
    results = importer.parse_string(json.dumps({"events": [rec]}))
    fr = _findings_for_action(results, "mailchimp-rm-001")[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "role_promoted_admin"
    )
    assert primary.control_id == "PR-02"
    assert primary.result == "FAIL"
    assert fr.decision == "BLOCK"


def test_gdpr_deletion_passes() -> None:
    """gdpr_data_deletion → PR-05 PASS (compliance audit trail)."""
    importer = MailchimpImporter()
    rec = {
        "id": "gd-001",
        "timestamp": "2026-04-01T12:00:00Z",
        "event_type": "gdpr_data_deletion",
        "actor": {"user_id": "user-001", "email": "agent@example.com"},
    }
    results = importer.parse_string(json.dumps({"events": [rec]}))
    fr = _findings_for_action(results, "mailchimp-gd-001")[0]
    primary = next(
        cr for cr in fr.control_results
        if cr.evidence_data.get("signal") == "gdpr_data_deletion"
    )
    assert primary.control_id == "PR-05"
    assert primary.result == "PASS"
    assert fr.decision == "ALLOW"


def test_cross_list_synthetic() -> None:
    """One actor touching > N audiences in window → synthetic PR-04 FLAG."""
    importer = MailchimpImporter(cross_list_threshold=2)
    actor = {"user_id": "noisy", "email": "agent@example.com"}
    base_ts = "2026-04-01T12:0{m}:00Z"
    events = [
        {
            "id": f"x-{i}",
            "timestamp": base_ts.format(m=i),
            "event_type": "list_member_added",
            "actor": actor,
            "audience": {"id": f"aud-{i}xxxxxxxx", "is_double_optin": True},
        }
        for i in range(4)
    ]
    results = importer.parse_string(json.dumps({"events": events}))
    synthetic = [
        r for r in results
        if r.action_id.startswith("mailchimp-cross-list-")
    ]
    assert len(synthetic) == 1
    fr = synthetic[0]
    cr = fr.control_results[0]
    assert cr.evidence_data.get("signal") == "cross_list_pattern"
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert fr.decision == "FLAG"
    assert cr.evidence_data["cross_list_count"] == 4
    assert cr.evidence_data["cross_list_threshold"] == 2


def test_email_domain_only() -> None:
    """actor.email full local-part must NEVER appear in any evidence."""
    importer = MailchimpImporter()
    rec = _campaign_sent(
        event_id="san-001",
        actor_email="alice.private.local@corp.example.com",
    )
    results = importer.parse_string(json.dumps({"events": [rec]}))
    serialized = json.dumps(
        [
            {
                "decision_reason": r.decision_reason,
                "control_results": [cr.evidence_data for cr in r.control_results],
            }
            for r in results
        ]
    )
    # Local-part must never appear.
    assert "alice" not in serialized
    assert "alice.private.local" not in serialized
    # Domain-only form should appear.
    assert "@corp.example.com" in serialized
    fr = _findings_for_action(results, "mailchimp-san-001")[0]
    primary_evidence = fr.control_results[0].evidence_data
    assert primary_evidence["actor"]["email_domain"] == "@corp.example.com"
    # actor.email raw must never be a key.
    assert "email" not in primary_evidence["actor"]


def test_subject_text_never_stored() -> None:
    """campaign.subject text must NEVER survive — only subject_length."""
    importer = MailchimpImporter()
    leaked = "VERY-SECRET-OTP-7771-DO-NOT-LOG"
    rec = _campaign_sent(event_id="san-002")
    rec["campaign"]["subject"] = leaked
    rec["campaign"]["subject_length"] = len(leaked)
    results = importer.parse_string(json.dumps({"events": [rec]}))
    serialized = json.dumps(
        [
            {
                "decision_reason": r.decision_reason,
                "control_results": [cr.evidence_data for cr in r.control_results],
            }
            for r in results
        ]
    )
    assert leaked not in serialized
    assert "VERY-SECRET" not in serialized
    fr = _findings_for_action(results, "mailchimp-san-002")[0]
    campaign_evidence = fr.control_results[0].evidence_data["campaign"]
    assert campaign_evidence["subject_length"] == len(leaked)
    assert "subject" not in campaign_evidence
