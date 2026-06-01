"""Tests for the Zapier audit-log importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers.zapier import ZapierImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Zapier audit-log records (no zapier-platform-cli required)
# ---------------------------------------------------------------------------


def _actor(
    *,
    user_id: str = "user-uuid-AABBCCDD11223344",
    email: str = "agent@example.com",
    is_admin: bool = False,
    role: str = "Member",
) -> dict:
    return {
        "user_id": user_id,
        "email": email,
        "is_admin": is_admin,
        "role": role,
    }


def _event(
    *,
    id: str = "evt-001",
    timestamp: str = "2026-04-01T12:00:00Z",
    action: str = "zap.run",
    actor: dict | None = None,
    zap_id: str = "zap-id-AABBCCDD11223344",
    zap_name_length: int = 50,
    zap_owner_id: str = "owner-uuid-AABBCCDD11223344",
    trigger_app: str = "schedule",
    action_apps: list[str] | None = None,
    action_count: int = 2,
    steps_count: int = 3,
    contains_code_step: bool = False,
    contains_webhook_step: bool = False,
    requires_premium_app: bool = False,
    team_id: str = "team-id-AABBCCDD11223344",
    team_size: int = 42,
    is_shared_team: bool = False,
    task_count_in_run: int = 1,
    task_status: str = "success",
    execution_duration_ms: int = 1500,
    chatgpt_action_id: str | None = None,
    webhook_target_host: str = "",
    ip_address: str = "10.1.2.3",
    is_authenticated_partner: bool = False,
    data_processed_bytes: int = 12345,
    **extra,
) -> dict:
    if actor is None:
        actor = _actor()
    if action_apps is None:
        action_apps = ["slack", "gmail"]
    payload = {
        "id": id,
        "timestamp": timestamp,
        "action": action,
        "actor": actor,
        "zap_id": zap_id,
        "zap_name_length": zap_name_length,
        "zap_owner_id": zap_owner_id,
        "trigger_app": trigger_app,
        "action_apps": action_apps,
        "action_count": action_count,
        "steps_count": steps_count,
        "contains_code_step": contains_code_step,
        "contains_webhook_step": contains_webhook_step,
        "requires_premium_app": requires_premium_app,
        "team_id": team_id,
        "team_size": team_size,
        "is_shared_team": is_shared_team,
        "task_count_in_run": task_count_in_run,
        "task_status": task_status,
        "execution_duration_ms": execution_duration_ms,
        "chatgpt_action_id": chatgpt_action_id,
        "webhook_target_host": webhook_target_host,
        "ip_address": ip_address,
        "is_authenticated_partner": is_authenticated_partner,
        "data_processed_bytes": data_processed_bytes,
    }
    payload.update(extra)
    return payload


def _signals(result) -> set[str]:
    return {
        cr.evidence_data.get("signal")
        for cr in result.control_results
        if cr.evidence_data.get("signal")
    }


# ---------------------------------------------------------------------------
# Action-specific signals
# ---------------------------------------------------------------------------


def test_zap_run_passes() -> None:
    """zap.run + task_status=success → PR-05 PASS, ALLOW decision."""
    doc = json.dumps({"audit_logs": [_event()]})
    [result] = ZapierImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "zapier_import"
    signals = _signals(result)
    assert "zap_run_success" in signals
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "zap_run_success"
    )
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    # Common evidence captured.
    ev = cr.evidence_data
    assert ev["action"] == "zap.run"
    assert ev["zap_id_last8"] == "11223344"
    assert ev["zap_owner_id_last8"] == "11223344"
    assert ev["team_id_last8"] == "11223344"
    assert ev["zap_name_length"] == 50
    assert ev["task_status"] == "success"
    assert ev["execution_duration_ms"] == 1500.0


def test_zap_failed_flags() -> None:
    """action=zap.failed → DE-01 FAIL, BLOCK."""
    doc = json.dumps({"audit_logs": [_event(action="zap.failed")]})
    [result] = ZapierImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "zap_failed"
    )
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


def test_code_step_flags() -> None:
    """zap.run + contains_code_step=true → PR-03 FLAG (Code by Zapier)."""
    doc = json.dumps(
        {"audit_logs": [_event(id="evt-code", contains_code_step=True)]}
    )
    [result] = ZapierImporter().parse_string(doc)
    assert "code_step_used" in _signals(result)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "code_step_used"
    )
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert result.decision == "FLAG"


def test_external_webhook_flags() -> None:
    """zap.run + contains_webhook_step=true + non-allowlisted host → PR-04 FLAG."""
    doc = json.dumps(
        {
            "audit_logs": [
                _event(
                    id="evt-hook",
                    contains_webhook_step=True,
                    webhook_target_host="https://hooks.attacker.example.com/v1/in",
                )
            ]
        }
    )
    [result] = ZapierImporter().parse_string(doc)
    assert "external_webhook_step" in _signals(result)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "external_webhook_step"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    # Host-only — full URL must NOT be in evidence.
    serialized = json.dumps(
        [c.evidence_data for c in result.control_results]
    )
    assert "/v1/in" not in serialized
    assert "https://" not in serialized
    assert "hooks.attacker.example.com" in serialized


def test_large_data_sensitive_app_flags() -> None:
    """zap.run with sensitive app + data > 10MB → PR-04 FLAG."""
    doc = json.dumps(
        {
            "audit_logs": [
                _event(
                    id="evt-big",
                    action_apps=["slack", "postgresql"],
                    data_processed_bytes=15_000_000,
                )
            ]
        }
    )
    [result] = ZapierImporter().parse_string(doc)
    assert "large_data_sensitive_app" in _signals(result)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "large_data_sensitive_app"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert "postgresql" in cr.evidence_data["sensitive_action_apps"]


def test_member_creates_sensitive_zap_flags() -> None:
    """zap.created by non-admin + sensitive action_apps → PR-04 FLAG."""
    doc = json.dumps(
        {
            "audit_logs": [
                _event(
                    id="evt-create",
                    action="zap.created",
                    actor=_actor(role="Member", is_admin=False),
                    action_apps=["salesforce", "slack"],
                    task_status="success",
                )
            ]
        }
    )
    [result] = ZapierImporter().parse_string(doc)
    assert "member_creates_sensitive_zap" in _signals(result)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "member_creates_sensitive_zap"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert "salesforce" in cr.evidence_data["sensitive_apps_in_zap"]


def test_role_promotion_fails() -> None:
    """team_role.changed Member→Admin → PR-02 FAIL (privilege escalation)."""
    doc = json.dumps(
        {
            "audit_logs": [
                _event(
                    id="evt-promo",
                    action="team_role.changed",
                    actor=_actor(role="Owner", is_admin=True),
                    old_role="Member",
                    new_role="Admin",
                )
            ]
        }
    )
    [result] = ZapierImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "role_promotion"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["new_role"] == "admin"
    assert cr.evidence_data["old_role"] == "member"


def test_app_connection_created_flags() -> None:
    """app_connection.created → PR-01 FLAG (new credential surface)."""
    doc = json.dumps(
        {
            "audit_logs": [
                _event(
                    id="evt-conn",
                    action="app_connection.created",
                    task_status="success",
                )
            ]
        }
    )
    [result] = ZapierImporter().parse_string(doc)
    assert "app_connection_created" in _signals(result)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "app_connection_created"
    )
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"


def test_connection_shared_flags() -> None:
    """connection.shared → PR-01 FLAG (credential sharing)."""
    doc = json.dumps(
        {"audit_logs": [_event(id="evt-share", action="connection.shared")]}
    )
    [result] = ZapierImporter().parse_string(doc)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "connection_shared"
    )
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"
    assert result.decision == "FLAG"


def test_public_share_link_flags() -> None:
    """manual_zap.share_link_created → PR-04 FLAG (public share link)."""
    doc = json.dumps(
        {
            "audit_logs": [
                _event(
                    id="evt-publink",
                    action="manual_zap.share_link_created",
                )
            ]
        }
    )
    [result] = ZapierImporter().parse_string(doc)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "public_share_link"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"


def test_ai_action_created_flags() -> None:
    """ai_action.created → PR-01 FLAG (new agent-callable surface)."""
    doc = json.dumps(
        {"audit_logs": [_event(id="evt-aiac", action="ai_action.created")]}
    )
    [result] = ZapierImporter().parse_string(doc)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "ai_action_created"
    )
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"


def test_export_ran_flags() -> None:
    """export.ran → PR-04 FLAG (data export from Zapier)."""
    doc = json.dumps({"audit_logs": [_event(id="evt-exp", action="export.ran")]})
    [result] = ZapierImporter().parse_string(doc)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "export_ran"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"


def test_member_deletes_production_zap_flags() -> None:
    """zap.deleted of production zap → PR-02 FLAG (audit completeness)."""
    doc = json.dumps(
        {
            "audit_logs": [
                _event(
                    id="evt-prod-del",
                    action="zap.deleted",
                    actor=_actor(role="Member", is_admin=False),
                    is_production=True,
                    zap_tags=["production"],
                )
            ]
        }
    )
    [result] = ZapierImporter().parse_string(doc)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "member_deletes_production_zap"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["is_member_actor"] is True


# ---------------------------------------------------------------------------
# Synthetic findings
# ---------------------------------------------------------------------------


def test_high_volume_synthetic() -> None:
    """Same actor running > N zap.run events in 1h → synthetic PR-05 FLAG."""
    base_ts = "2026-04-01T12:00:%02dZ"
    events = [
        _event(
            id=f"evt-{i}",
            timestamp=base_ts % (i % 60),
        )
        for i in range(6)
    ]
    importer = ZapierImporter(high_volume_threshold=5)
    results = importer.parse_string(json.dumps({"audit_logs": events}))
    # 6 per-event results + 1 synthetic.
    assert len(results) == 7
    synthetic = [r for r in results if r.action_id.startswith("zapier-high-volume-")]
    assert len(synthetic) == 1
    syn = synthetic[0]
    assert syn.decision == "FLAG"
    assert syn.control_results[0].control_id == "PR-05"
    assert syn.control_results[0].evidence_data["high_volume_peak"] == 6
    assert syn.control_results[0].evidence_data["synthetic"] is True
    # Per-event records that contributed should also carry the high_volume_runs signal.
    contributing = [
        r for r in results if r.action_id.startswith("zapier-evt-")
        and "high_volume_runs" in {
            c.evidence_data.get("signal") for c in r.control_results
        }
    ]
    assert len(contributing) == 6


def test_cross_app_synthetic() -> None:
    """Same Zap touching > N distinct external apps in single run → PR-04 FLAG."""
    doc = json.dumps(
        {
            "audit_logs": [
                _event(
                    id="evt-many-apps",
                    action_apps=[
                        "slack",
                        "gmail",
                        "salesforce",
                        "hubspot",
                        "stripe",
                        "notion",
                        "asana",
                    ],
                )
            ]
        }
    )
    [result] = ZapierImporter().parse_string(doc)
    assert "cross_app_run" in _signals(result)
    cr = next(
        c for c in result.control_results
        if c.evidence_data.get("signal") == "cross_app_run"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["cross_app_threshold"] == 5
    assert len(cr.evidence_data["cross_app_apps"]) == 7


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def test_zap_name_not_stored() -> None:
    """Raw zap_name is never stored — only zap_name_length surfaces."""
    secret_name = "Customer SSN export to Dropbox — DO NOT DELETE"
    doc = json.dumps(
        {
            "audit_logs": [
                _event(
                    id="evt-name",
                    zap_name=secret_name,
                    zap_name_length=len(secret_name),
                )
            ]
        }
    )
    [result] = ZapierImporter().parse_string(doc)
    serialized = json.dumps([c.evidence_data for c in result.control_results])
    assert secret_name not in serialized
    assert "Customer SSN" not in serialized
    cr = result.control_results[0]
    assert cr.evidence_data["zap_name_length"] == len(secret_name)
    assert "zap_name" not in cr.evidence_data


def test_email_domain_only() -> None:
    """actor.email reduced to DOMAIN ONLY; user_id/team_id last 8 chars only."""
    doc = json.dumps(
        {
            "audit_logs": [
                _event(
                    id="evt-pii",
                    actor=_actor(
                        user_id="u-aaaaaaaa-bbbb-cccc-FINAL999",
                        email="kevin.bauer@personal-domain.example",
                    ),
                    team_id="team-aaaaaaaa-bbbb-cccc-OTHEREND",
                    zap_id="zap-aaaaaaaa-bbbb-LASTBITS",
                    chatgpt_action_id="cgpt-aaa-DEADBEEF",
                    ip_address="192.168.45.67",
                )
            ]
        }
    )
    [result] = ZapierImporter().parse_string(doc)
    serialized = json.dumps([c.evidence_data for c in result.control_results])
    # Full email and full IDs must not leak.
    assert "kevin.bauer@" not in serialized
    assert "kevin.bauer" not in serialized
    assert "u-aaaaaaaa-bbbb-cccc-FINAL999" not in serialized
    assert "team-aaaaaaaa-bbbb-cccc-OTHEREND" not in serialized
    assert "zap-aaaaaaaa-bbbb-LASTBITS" not in serialized
    # Full IPv4 must not leak — must be /16 masked.
    assert "192.168.45.67" not in serialized
    # Domain-only and last-8 surfaces ARE present.
    assert "personal-domain.example" in serialized
    cr = result.control_results[0]
    actor = cr.evidence_data["actor"]
    assert actor["email_domain"] == "personal-domain.example"
    assert actor["user_id_last8"] == "FINAL999"
    assert "email" not in actor
    assert "user_id" not in actor
    assert cr.evidence_data["team_id_last8"] == "OTHEREND"
    assert cr.evidence_data["zap_id_last8"] == "LASTBITS"
    assert cr.evidence_data["chatgpt_action_id_last8"] == "DEADBEEF"
    assert cr.evidence_data["ip_masked"] == "192.168.0.0/16"


# ---------------------------------------------------------------------------
# Format coverage
# ---------------------------------------------------------------------------


def test_jsonl_stream_and_envelopes() -> None:
    """JSONL + {"events":[]} + {"data":[]} envelopes are all accepted."""
    # JSONL.
    lines = [
        json.dumps(_event(id="e1")),
        json.dumps(_event(id="e2", action="zap.failed")),
    ]
    res = ZapierImporter().parse_string("\n".join(lines))
    # 2 per-event results (no synthetic for this small set).
    assert {r.action_id for r in res} == {"zapier-e1", "zapier-e2"}
    # events envelope.
    [r] = ZapierImporter().parse_string(
        json.dumps({"events": [_event(id="env1")]})
    )
    assert r.action_id == "zapier-env1"
    # data envelope.
    [r2] = ZapierImporter().parse_string(
        json.dumps({"data": [_event(id="env2")]})
    )
    assert r2.action_id == "zapier-env2"


def test_source_provenance_includes_file_hash(tmp_path: Path) -> None:
    """parse(path) records sha256 of the input file in source_provenance."""
    payload = json.dumps({"audit_logs": [_event(id="evt-hash")]})
    p = tmp_path / "zapier-export.json"
    p.write_text(payload)
    [result] = ZapierImporter().parse(p)
    expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    cr = result.control_results[0]
    prov = cr.evidence_data["source_provenance"]
    assert prov["original_file_sha256"] == expected
    assert prov["source_format"] == "zapier"
    assert prov["source_tool_name"] == "zapier"
    assert prov["event_id"] == "evt-hash"
