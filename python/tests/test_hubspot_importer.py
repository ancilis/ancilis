"""Tests for the HubSpot CRM audit-log importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers.hubspot import HubSpotImporter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _event(
    *,
    event_id: str = "evt-1",
    event_type: str = "contact.creation",
    timestamp: int = 1_730_000_000_000,
    actor_user_id: str = "user-12345678",
    actor_email: str = "agent@example.com",
    is_breeze_agent: bool = False,
    agent_action: str | None = None,
    object_type: str = "contact",
    object_id: str = "obj-87654321",
    record_count: int = 1,
    is_marketing_contact: bool = False,
    properties_changed: list[str] | None = None,
    is_bulk: bool = False,
    is_breeze_generated: bool = False,
    breeze_confidence_score: float | None = None,
    export_size_bytes: int | None = None,
    workflow_id: str | None = None,
    app_id: str | None = None,
    webhook_url_host: str | None = None,
    client_ip: str = "10.0.0.1",
    tenant_id: str = "company",
    subscription_tier: str = "Professional",
    amount: float | None = None,
    new_stage: str | None = None,
    new_role: str | None = None,
) -> dict:
    payload: dict = {
        "id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "actor": {
            "user_id": actor_user_id,
            "email": actor_email,
            "is_breeze_agent": is_breeze_agent,
            "agent_action": agent_action,
        },
        "target": {
            "object_type": object_type,
            "object_id": object_id,
            "record_count": record_count,
            "is_marketing_contact": is_marketing_contact,
        },
        "properties_changed": properties_changed or [],
        "is_bulk": is_bulk,
        "is_breeze_generated": is_breeze_generated,
        "breeze_confidence_score": breeze_confidence_score,
        "export_size_bytes": export_size_bytes,
        "workflow_id": workflow_id,
        "app_id": app_id,
        "webhook_url_host": webhook_url_host,
        "client_ip": client_ip,
        "tenant_id": tenant_id,
        "subscription_tier": subscription_tier,
    }
    if amount is not None:
        payload["amount"] = amount
    if new_stage is not None:
        payload["new_stage"] = new_stage
    if new_role is not None:
        payload["new_role"] = new_role
    return payload


def _findings(results: list, event_id: str) -> list:
    return [r for r in results if r.action_id == f"hubspot-{event_id}"]


def _signals(result) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in result.control_results]


# ---------------------------------------------------------------------------
# 1. Breeze contact creation FLAG
# ---------------------------------------------------------------------------


def test_breeze_contact_creation_flags() -> None:
    ev = _event(
        event_id="evt-create",
        event_type="contact.creation",
        is_breeze_agent=True,
    )
    importer = HubSpotImporter()
    results = importer.parse_string(json.dumps({"events": [ev]}))
    finding = _findings(results, "evt-create")[0]
    assert "breeze_contact_creation" in _signals(finding)
    assert finding.decision == "FLAG"
    cr = next(
        cr
        for cr in finding.control_results
        if cr.evidence_data.get("signal") == "breeze_contact_creation"
    )
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"


# ---------------------------------------------------------------------------
# 2. Breeze contact deletion FAIL → BLOCK
# ---------------------------------------------------------------------------


def test_breeze_contact_deletion_fails() -> None:
    ev = _event(
        event_id="evt-del",
        event_type="contact.deletion",
        is_breeze_agent=True,
    )
    importer = HubSpotImporter()
    results = importer.parse_string(json.dumps({"events": [ev]}))
    finding = _findings(results, "evt-del")[0]
    cr = next(
        cr
        for cr in finding.control_results
        if cr.evidence_data.get("signal") == "breeze_contact_deletion"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert finding.decision == "BLOCK"


# ---------------------------------------------------------------------------
# 3. Sensitive PII property change FAIL → BLOCK
# ---------------------------------------------------------------------------


def test_sensitive_property_fails_block() -> None:
    ev = _event(
        event_id="evt-pii",
        event_type="contact.propertyChange",
        is_breeze_agent=True,
        is_breeze_generated=True,
        properties_changed=["email", "ssn"],
    )
    importer = HubSpotImporter()
    results = importer.parse_string(json.dumps({"events": [ev]}))
    finding = _findings(results, "evt-pii")[0]
    cr = next(
        cr
        for cr in finding.control_results
        if cr.evidence_data.get("signal") == "sensitive_property_change"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert finding.decision == "BLOCK"
    assert "ssn" in cr.evidence_data["sensitive_properties_changed"]


# ---------------------------------------------------------------------------
# 4. Large autonomous deal amount change FAIL → BLOCK
# ---------------------------------------------------------------------------


def test_large_deal_by_breeze_fails() -> None:
    ev = _event(
        event_id="evt-amt",
        event_type="deal.creation.amountChange",
        object_type="deal",
        is_breeze_agent=True,
        amount=10_000_000.0,  # $100k in cents
    )
    importer = HubSpotImporter()
    results = importer.parse_string(json.dumps({"events": [ev]}))
    finding = _findings(results, "evt-amt")[0]
    cr = next(
        cr
        for cr in finding.control_results
        if cr.evidence_data.get("signal") == "large_deal_amount_change"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert finding.decision == "BLOCK"


# ---------------------------------------------------------------------------
# 5. Autonomous deal closure (Closed Won) FAIL → BLOCK
# ---------------------------------------------------------------------------


def test_autonomous_deal_closure_fails() -> None:
    ev = _event(
        event_id="evt-close",
        event_type="deal.creation.stageChange",
        object_type="deal",
        is_breeze_agent=True,
        new_stage="Closed Won",
    )
    importer = HubSpotImporter()
    results = importer.parse_string(json.dumps({"events": [ev]}))
    finding = _findings(results, "evt-close")[0]
    cr = next(
        cr
        for cr in finding.control_results
        if cr.evidence_data.get("signal") == "autonomous_deal_closure"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert finding.decision == "BLOCK"


# ---------------------------------------------------------------------------
# 6. Breeze-generated outbound email FLAG
# ---------------------------------------------------------------------------


def test_breeze_email_flags() -> None:
    ev = _event(
        event_id="evt-email",
        event_type="engagement.email",
        is_breeze_generated=True,
    )
    importer = HubSpotImporter()
    results = importer.parse_string(json.dumps({"events": [ev]}))
    finding = _findings(results, "evt-email")[0]
    cr = next(
        cr
        for cr in finding.control_results
        if cr.evidence_data.get("signal") == "breeze_email_sent"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert finding.decision == "FLAG"


# ---------------------------------------------------------------------------
# 7. Low-confidence Breeze deal creation FLAG
# ---------------------------------------------------------------------------


def test_low_confidence_flags() -> None:
    ev = _event(
        event_id="evt-low",
        event_type="deal.creation",
        object_type="deal",
        is_breeze_agent=True,
        breeze_confidence_score=0.4,
    )
    importer = HubSpotImporter()
    results = importer.parse_string(json.dumps({"events": [ev]}))
    finding = _findings(results, "evt-low")[0]
    cr = next(
        cr
        for cr in finding.control_results
        if cr.evidence_data.get("signal") == "breeze_low_confidence_deal"
    )
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"


# ---------------------------------------------------------------------------
# 8. Bulk contact export FAIL → BLOCK
# ---------------------------------------------------------------------------


def test_bulk_export_fails() -> None:
    ev = _event(
        event_id="evt-export",
        event_type="export.contacts",
        export_size_bytes=20_000_000,  # 20 MB > 10 MB threshold
    )
    importer = HubSpotImporter()
    results = importer.parse_string(json.dumps({"events": [ev]}))
    finding = _findings(results, "evt-export")[0]
    cr = next(
        cr
        for cr in finding.control_results
        if cr.evidence_data.get("signal") == "bulk_contact_export"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert finding.decision == "BLOCK"


# ---------------------------------------------------------------------------
# 9. External webhook FLAG (host not in allowlist)
# ---------------------------------------------------------------------------


def test_webhook_external_flags() -> None:
    ev = _event(
        event_id="evt-wh",
        event_type="webhook.created",
        webhook_url_host="evil.example.net",
    )
    importer = HubSpotImporter(webhook_host_allowlist=["api.trusted.com"])
    results = importer.parse_string(json.dumps({"events": [ev]}))
    finding = _findings(results, "evt-wh")[0]
    cr = next(
        cr
        for cr in finding.control_results
        if cr.evidence_data.get("signal") == "webhook_external"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["webhook_url_host"] == "evil.example.net"


# ---------------------------------------------------------------------------
# 10. App install FLAG
# ---------------------------------------------------------------------------


def test_app_install_flags() -> None:
    ev = _event(
        event_id="evt-app",
        event_type="app.install",
        app_id="zoom-meetings",
    )
    importer = HubSpotImporter()
    results = importer.parse_string(json.dumps({"events": [ev]}))
    finding = _findings(results, "evt-app")[0]
    cr = next(
        cr
        for cr in finding.control_results
        if cr.evidence_data.get("signal") == "app_install"
    )
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"


# ---------------------------------------------------------------------------
# 11. Super Admin promotion FAIL → BLOCK
# ---------------------------------------------------------------------------


def test_super_admin_promotion_fails() -> None:
    ev = _event(
        event_id="evt-role",
        event_type="user.role.update",
        new_role="Super Admin",
    )
    importer = HubSpotImporter()
    results = importer.parse_string(json.dumps({"events": [ev]}))
    finding = _findings(results, "evt-role")[0]
    cr = next(
        cr
        for cr in finding.control_results
        if cr.evidence_data.get("signal") == "super_admin_promotion"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert finding.decision == "BLOCK"


# ---------------------------------------------------------------------------
# 12. Cross-object synthetic FLAG
# ---------------------------------------------------------------------------


def test_cross_object_synthetic() -> None:
    base_ts = 1_730_000_000_000
    breeze_actor = {
        "user_id": "breeze-aaaaaaaa",
        "email": "breeze@portal.example.com",
        "is_breeze_agent": True,
        "agent_action": None,
    }
    events = [
        {
            "id": f"evt-cross-{i}",
            "timestamp": base_ts + i * 1000,
            "event_type": "contact.propertyChange",
            "actor": breeze_actor,
            "target": {
                "object_type": obj_type,
                "object_id": f"obj-{obj_type}-1234",
                "record_count": 1,
                "is_marketing_contact": False,
            },
            "properties_changed": ["lifecycle_stage"],
            "is_bulk": False,
            "is_breeze_generated": False,
            "breeze_confidence_score": None,
            "export_size_bytes": None,
            "workflow_id": None,
            "app_id": None,
            "webhook_url_host": None,
            "client_ip": "203.0.113.10",
            "tenant_id": "company",
            "subscription_tier": "Enterprise",
        }
        for i, obj_type in enumerate(
            ["contact", "deal", "company", "ticket", "product"]
        )
    ]
    importer = HubSpotImporter()
    results = importer.parse_string(json.dumps({"events": events}))
    synthetics = [r for r in results if "cross-object" in r.action_id]
    assert len(synthetics) == 1
    cr = synthetics[0].control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["cross_object_object_count"] == 5


# ---------------------------------------------------------------------------
# 13. Bot-velocity synthetic FLAG
# ---------------------------------------------------------------------------


def test_bot_velocity_synthetic() -> None:
    base_ts = 1_730_000_000_000
    breeze_actor = {
        "user_id": "breeze-bbbbbbbb",
        "email": "bot@portal.example.com",
        "is_breeze_agent": True,
        "agent_action": None,
    }
    # Lower threshold to make test fast.
    importer = HubSpotImporter(bot_velocity_threshold=10)
    events = [
        {
            "id": f"evt-velocity-{i}",
            "timestamp": base_ts + i * 1000,
            "event_type": "contact.propertyChange",
            "actor": breeze_actor,
            "target": {
                "object_type": "contact",
                "object_id": f"obj-velocity-{i}",
                "record_count": 1,
                "is_marketing_contact": False,
            },
            "properties_changed": ["company"],
            "is_bulk": False,
            "is_breeze_generated": False,
            "client_ip": "203.0.113.20",
            "tenant_id": "company",
            "subscription_tier": "Enterprise",
        }
        for i in range(15)
    ]
    results = importer.parse_string(json.dumps({"events": events}))
    synthetics = [r for r in results if "bot-velocity" in r.action_id]
    assert len(synthetics) == 1
    cr = synthetics[0].control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["action_count"] == 15


# ---------------------------------------------------------------------------
# 14. High-touch contact synthetic FLAG
# ---------------------------------------------------------------------------


def test_high_touch_contact_synthetic() -> None:
    base_ts = 1_730_000_000_000
    contact_id = "contact-hightouch-cccccccc"
    events = [
        {
            "id": f"evt-touch-{i}",
            "timestamp": base_ts + i * 1000,
            "event_type": "contact.propertyChange",
            "actor": {
                "user_id": f"user-{i:08d}",
                "email": "user@example.com",
                "is_breeze_agent": False,
                "agent_action": None,
            },
            "target": {
                "object_type": "contact",
                "object_id": contact_id,
                "record_count": 1,
                "is_marketing_contact": False,
            },
            "properties_changed": ["lifecycle_stage"],
            "is_bulk": False,
            "is_breeze_generated": False,
            "client_ip": "203.0.113.30",
            "tenant_id": "company",
            "subscription_tier": "Professional",
        }
        for i in range(7)
    ]
    importer = HubSpotImporter()
    results = importer.parse_string(json.dumps({"events": events}))
    synthetics = [r for r in results if "high-touch" in r.action_id]
    assert len(synthetics) == 1
    cr = synthetics[0].control_results[0]
    assert cr.control_id == "PR-05"
    assert cr.result == "FLAG"
    assert cr.evidence_data["modification_count"] == 7
    # Object id reduced to last-8.
    assert cr.evidence_data["target_object_id_last8"] == contact_id[-8:]


# ---------------------------------------------------------------------------
# 15. properties VALUES are not stored — only key list.
# ---------------------------------------------------------------------------


def test_properties_values_not_stored() -> None:
    # Even if the source carried full property payloads, the importer must only
    # store the key list. Construct an event with raw payload-like keys and
    # assert nothing values-shaped leaks into evidence.
    raw = {
        "events": [
            {
                "id": "evt-keys",
                "timestamp": 1_730_000_000_000,
                "event_type": "contact.propertyChange",
                "actor": {
                    "user_id": "user-12345678",
                    "email": "agent@example.com",
                    "is_breeze_agent": True,
                    "agent_action": None,
                },
                "target": {
                    "object_type": "contact",
                    "object_id": "obj-87654321",
                    "record_count": 1,
                    "is_marketing_contact": False,
                },
                "properties_changed": ["email", "phone"],
                "property_values": {
                    "email": "victim@target.example.com",
                    "phone": "+1-555-0000",
                },
                "is_bulk": False,
                "is_breeze_generated": True,
                "client_ip": "10.0.0.1",
                "tenant_id": "company",
                "subscription_tier": "Professional",
            }
        ]
    }
    importer = HubSpotImporter()
    results = importer.parse_string(json.dumps(raw))
    finding = _findings(results, "evt-keys")[0]
    for cr in finding.control_results:
        # Key list is captured.
        assert cr.evidence_data.get("properties_changed") == ["email", "phone"]
        # Values are never captured anywhere.
        for v in cr.evidence_data.values():
            if isinstance(v, str):
                assert "victim@target.example.com" not in v
                assert "555-0000" not in v
            elif isinstance(v, dict):
                # property_values shape must not have been carried through.
                assert "victim@target.example.com" not in json.dumps(v)
        assert "property_values" not in cr.evidence_data


# ---------------------------------------------------------------------------
# 16. actor email reduced to domain only.
# ---------------------------------------------------------------------------


def test_email_domain_only() -> None:
    ev = _event(
        event_id="evt-email-dom",
        event_type="contact.creation",
        is_breeze_agent=True,
        actor_email="alice.smith+breeze@hub.example.com",
        actor_user_id="long-actor-user-id-99887766",
    )
    importer = HubSpotImporter()
    results = importer.parse_string(json.dumps({"events": [ev]}))
    finding = _findings(results, "evt-email-dom")[0]
    cr = finding.control_results[0]
    assert cr.evidence_data["actor_email_domain"] == "hub.example.com"
    # Full email never stored.
    blob = json.dumps(cr.evidence_data)
    assert "alice.smith" not in blob
    assert "+breeze" not in blob
    # actor.user_id reduced to last-8.
    assert cr.evidence_data["actor_user_id_last8"] == "99887766"
    assert "long-actor-user-id-99887766" not in blob


# ---------------------------------------------------------------------------
# 17. parse() on disk hashes file for source_provenance.
# ---------------------------------------------------------------------------


def test_parse_file_hashes_for_provenance(tmp_path: Path) -> None:
    payload = {
        "events": [
            _event(
                event_id="evt-hash",
                event_type="contact.creation",
                is_breeze_agent=True,
            )
        ]
    }
    raw = json.dumps(payload).encode("utf-8")
    p = tmp_path / "hubspot.json"
    p.write_bytes(raw)
    expected = hashlib.sha256(raw).hexdigest()

    importer = HubSpotImporter()
    results = importer.parse(p)
    finding = _findings(results, "evt-hash")[0]
    cr = finding.control_results[0]
    assert cr.evidence_data["source_provenance"]["original_file_sha256"] == expected
