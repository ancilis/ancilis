"""Tests for the Vercel audit-event importer."""

from __future__ import annotations

import json
from typing import Any

from ancilis.importers.vercel import VercelImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Vercel records (no vercel package required)
# ---------------------------------------------------------------------------


def _deployment(
    *,
    deployment_id: str = "dpl_abcdef1234567890",
    url: str = "https://agent-output-abc.vercel.app",
    target: str | None = "production",
    source: str = "git",
    creator_username: str = "kbauer",
    creator_is_bot: bool = False,
    branch: str = "main",
    repo: str = "ancilis/agent-output",
    provider: str = "github",
    commit_sha: str = "abcdef1234567890deadbeef",
    commit_message_length: int = 50,
    commit_author_login: str = "kbauer",
    build_skipped: bool = False,
    duration_ms: int = 45000,
    ready_state: str = "READY",
    build_error_count: int = 0,
    via_template: str | None = None,
) -> dict[str, Any]:
    return {
        "id": deployment_id,
        "url": url,
        "target": target,
        "source": source,
        "creator": {"username": creator_username, "is_bot": creator_is_bot},
        "git_metadata": {
            "commit_sha": commit_sha,
            "commit_message_length": commit_message_length,
            "commit_author_login": commit_author_login,
            "branch": branch,
            "repo": repo,
            "provider": provider,
        },
        "build_skipped": build_skipped,
        "duration_ms": duration_ms,
        "ready_state": ready_state,
        "build_error_count": build_error_count,
        "via_template": via_template,
    }


def _event(
    *,
    event_id: str | None = None,
    event_type: str = "deployment.created",
    created_at: int | str = 1730000000000,
    user_email: str = "kbauer@example.com",
    user_username: str = "kbauer",
    user_id: str = "user_abc",
    team_slug: str = "ancilis",
    team_id: str = "team_abc",
    project_id: str = "prj_abc",
    project_name: str = "agent-output",
    project_framework: str | None = "nextjs",
    deployment: dict | None = None,
    env_var_changes: list[dict] | None = None,
    domain: dict | None = None,
    team_member: dict | None = None,
    secret: dict | None = None,
    checks: dict | None = None,
    ip: str = "8.8.8.42",
    user_agent: str = "vercel-cli/30.0.0 darwin-arm64 node-v20",
) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "id": event_id or f"ev_{event_type}_{created_at}",
        "createdAt": created_at,
        "type": event_type,
        "user": {"id": user_id, "email": user_email, "username": user_username},
        "team": {"id": team_id, "slug": team_slug},
        "project": {"id": project_id, "name": project_name, "framework": project_framework},
        "ip": ip,
        "user_agent": user_agent,
    }
    if deployment is not None:
        ev["deployment"] = deployment
    if env_var_changes is not None:
        ev["env_var_changes"] = env_var_changes
    if domain is not None:
        ev["domain"] = domain
    if team_member is not None:
        ev["team_member"] = team_member
    if secret is not None:
        ev["secret"] = secret
    if checks is not None:
        ev["checks"] = checks
    return ev


def _findings_for_signal(results, signal: str):
    out = []
    for r in results:
        for cr in r.control_results:
            if cr.evidence_data.get("signal") == signal:
                out.append((r, cr))
    return out


# ---------------------------------------------------------------------------
# Deployment tests
# ---------------------------------------------------------------------------


def test_normal_production_deployment() -> None:
    """A human production deploy from git is PR-05 PASS, ALLOW decision."""
    doc = json.dumps({"events": [_event(deployment=_deployment())]})
    results = VercelImporter().parse_string(doc)
    assert len(results) == 1
    res = results[0]
    assert res.decision == "ALLOW"
    signals = {cr.evidence_data.get("signal") for cr in res.control_results}
    assert "deployment_created" in signals
    assert "production_deployment_audit" in signals
    # No agent flag — human creator.
    assert "agent_production_deployment" not in signals


def test_bot_production_deployment_flags() -> None:
    """A bot production deploy is PR-01 FLAG, FLAG decision."""
    doc = json.dumps({"events": [_event(
        deployment=_deployment(creator_is_bot=True, creator_username="agent-bot")
    )]})
    results = VercelImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "FLAG"
    findings = _findings_for_signal(results, "agent_production_deployment")
    assert len(findings) == 1
    _, cr = findings[0]
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"


def test_template_deployment_flags() -> None:
    """deployment.created via_template set on production → PR-01 FLAG."""
    doc = json.dumps({"events": [_event(
        deployment=_deployment(via_template="v0-template-xyz"),
    )]})
    results = VercelImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "FLAG"
    findings = _findings_for_signal(results, "agent_production_deployment")
    assert len(findings) == 1


def test_preview_deployment_passes() -> None:
    """Preview deployments are normal CI artifacts → PASS, ALLOW."""
    doc = json.dumps({"events": [_event(
        deployment=_deployment(target="preview", url="https://x-pr-3.vercel.app"),
    )]})
    results = VercelImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "ALLOW"
    signals = {cr.evidence_data.get("signal") for cr in res.control_results}
    assert "preview_deployment_audit" in signals
    assert "agent_production_deployment" not in signals


def test_deployment_error_flags() -> None:
    """deployment.error with build_error_count > 0 → PR-03 FLAG."""
    doc = json.dumps({"events": [_event(
        event_type="deployment.error",
        deployment=_deployment(
            ready_state="ERROR",
            build_error_count=3,
        ),
    )]})
    results = VercelImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "FLAG"
    findings = _findings_for_signal(results, "deployment_build_error")
    assert len(findings) == 1
    assert findings[0][1].control_id == "PR-03"


def test_bot_promote_to_production_fails() -> None:
    """deployment.promoted to production by bot → PR-02 FAIL, BLOCK."""
    doc = json.dumps({"events": [_event(
        event_type="deployment.promoted",
        deployment=_deployment(
            creator_is_bot=True,
            creator_username="auto-promoter",
            target="production",
        ),
    )]})
    results = VercelImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "BLOCK"
    findings = _findings_for_signal(results, "autonomous_production_promote")
    assert len(findings) == 1
    assert findings[0][1].control_id == "PR-02"
    assert findings[0][1].result == "FAIL"


def test_domain_added_flags() -> None:
    """domain.added → PR-04 FLAG (new public surface)."""
    doc = json.dumps({"events": [_event(
        event_type="domain.added",
        domain={"name": "agent.example.com", "redirect": None},
    )]})
    results = VercelImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "FLAG"
    findings = _findings_for_signal(results, "domain_added")
    assert len(findings) == 1
    assert findings[0][1].control_id == "PR-04"
    # Domain stored verbatim — public DNS.
    assert findings[0][1].evidence_data.get("domain_name") == "agent.example.com"


def test_production_secret_change_flags() -> None:
    """env.updated with API_KEY in production → PR-01 FLAG."""
    doc = json.dumps({"events": [_event(
        event_type="env.updated",
        env_var_changes=[
            {"key": "OPENAI_API_KEY", "change": "updated", "target": ["production"]},
        ],
    )]})
    results = VercelImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "FLAG"
    findings = _findings_for_signal(results, "production_secret_change")
    assert len(findings) == 1
    assert findings[0][1].control_id == "PR-01"


def test_owner_promotion_fails() -> None:
    """team.member.role.updated VIEWER → OWNER → PR-02 FAIL, BLOCK."""
    doc = json.dumps({"events": [_event(
        event_type="team.member.role.updated",
        team_member={"role_changed_to": "OWNER", "previous_role": "VIEWER"},
    )]})
    results = VercelImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "BLOCK"
    findings = _findings_for_signal(results, "owner_role_promotion")
    assert len(findings) == 1
    assert findings[0][1].result == "FAIL"
    assert findings[0][1].control_id == "PR-02"


def test_team_transfer_fails() -> None:
    """team.transfer.requested → PR-02 FAIL, BLOCK."""
    doc = json.dumps({"events": [_event(event_type="team.transfer.requested")]})
    results = VercelImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "BLOCK"
    findings = _findings_for_signal(results, "team_transfer_requested")
    assert len(findings) == 1
    assert findings[0][1].result == "FAIL"
    assert findings[0][1].control_id == "PR-02"


def test_sso_config_change_flags() -> None:
    """team.sso.config.updated → PR-02 FLAG."""
    doc = json.dumps({"events": [_event(event_type="team.sso.config.updated")]})
    results = VercelImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "FLAG"
    findings = _findings_for_signal(results, "team_sso_config_updated")
    assert len(findings) == 1
    assert findings[0][1].result == "FLAG"
    assert findings[0][1].control_id == "PR-02"


def test_integration_added_flags() -> None:
    """integration.added → PR-01 FLAG."""
    doc = json.dumps({"events": [_event(event_type="integration.added")]})
    results = VercelImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "FLAG"
    findings = _findings_for_signal(results, "integration_added")
    assert len(findings) == 1
    assert findings[0][1].control_id == "PR-01"


def test_project_deleted_fails() -> None:
    """project.deleted → PR-02 FAIL, BLOCK (irreversible)."""
    doc = json.dumps({"events": [_event(event_type="project.deleted")]})
    results = VercelImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "BLOCK"
    findings = _findings_for_signal(results, "project_deleted")
    assert len(findings) == 1
    assert findings[0][1].result == "FAIL"


def test_blocking_check_failure_fails() -> None:
    """checks.created blocking=true conclusion=failure on production → PR-03 FAIL."""
    doc = json.dumps({"events": [_event(
        event_type="checks.created",
        deployment=_deployment(),
        checks={
            "name": "linting",
            "status": "completed",
            "conclusion": "failure",
            "blocking": True,
        },
    )]})
    results = VercelImporter().parse_string(doc)
    res = results[0]
    assert res.decision == "BLOCK"
    findings = _findings_for_signal(results, "blocking_check_failure")
    assert len(findings) == 1
    assert findings[0][1].control_id == "PR-03"
    assert findings[0][1].result == "FAIL"


def test_bot_velocity_synthetic() -> None:
    """A bot doing > N production deploys in 1h triggers a synthetic PR-02 FLAG."""
    base = 1730000000000
    events = [
        _event(
            event_id=f"ev_{i}",
            event_type="deployment.created",
            created_at=base + i * 60_000,  # 1 minute apart
            deployment=_deployment(
                creator_is_bot=True,
                creator_username="prod-bot",
                target="production",
            ),
        )
        for i in range(8)
    ]
    doc = json.dumps({"events": events})
    results = VercelImporter().parse_string(doc)
    # We expect 8 per-event results plus 1 synthetic.
    assert len(results) >= 9
    synthetic = [
        r for r in results
        if any(
            cr.evidence_data.get("synthetic")
            and cr.evidence_data.get("signal") == "bot_velocity_pattern"
            for cr in r.control_results
        )
    ]
    assert len(synthetic) == 1
    assert synthetic[0].decision == "FLAG"


def test_secret_key_names_redacted() -> None:
    """Keys matching secret patterns are redacted in evidence_data."""
    doc = json.dumps({"events": [_event(
        event_type="env.created",
        env_var_changes=[
            {"key": "STRIPE_API_KEY", "change": "created", "target": ["production"]},
            {"key": "PUBLIC_FEATURE_FLAG", "change": "created", "target": ["production"]},
        ],
    )]})
    results = VercelImporter().parse_string(doc)
    res = results[0]
    # Find the primary-classification ControlResult.
    cr = next(
        c for c in res.control_results
        if c.evidence_data.get("signal") == "env_created"
    )
    changes = cr.evidence_data["env_var_changes"]
    by_secret = {c["is_secret_key_pattern"]: c for c in changes}
    assert True in by_secret and False in by_secret
    secret_entry = by_secret[True]
    nonsecret_entry = by_secret[False]
    # Secret key MUST be redacted (not stored verbatim).
    assert secret_entry["key"] != "STRIPE_API_KEY"
    assert secret_entry["key"].startswith("STRI")
    assert "..." in secret_entry["key"]
    # Non-secret key stored verbatim.
    assert nonsecret_entry["key"] == "PUBLIC_FEATURE_FLAG"


def test_email_only_domain_stored() -> None:
    """user.email reduced to @domain only; user.username reduced to length+sha256."""
    doc = json.dumps({"events": [_event(
        user_email="kevin.bauer@gmail.com",
        user_username="kbauer-supersecret",
        deployment=_deployment(),
    )]})
    results = VercelImporter().parse_string(doc)
    res = results[0]
    cr = next(
        c for c in res.control_results
        if c.evidence_data.get("signal") == "deployment_created"
    )
    assert cr.evidence_data["user_email_domain"] == "@gmail.com"
    # Username MUST NOT be stored verbatim.
    redacted = cr.evidence_data["user_username_redacted"]
    assert isinstance(redacted, dict)
    assert redacted["length"] == len("kbauer-supersecret")
    assert "kbauer" not in str(cr.evidence_data["user_username_redacted"])
    # Deployment URL is host-only.
    assert cr.evidence_data["deployment_url_host"] == "agent-output-abc.vercel.app"
    # Commit SHA is last 8 only.
    assert cr.evidence_data["git_commit_sha_last8"] == "deadbeef"
    # IP is /16 reduced.
    assert cr.evidence_data["ip_redacted"] == "8.8.0.0/16"
    # User-agent prefix + sha256.
    ua = cr.evidence_data["user_agent_redacted"]
    assert isinstance(ua, dict)
    assert "sha256" in ua and "prefix" in ua


# ---------------------------------------------------------------------------
# Format-detection / source-provenance tests
# ---------------------------------------------------------------------------


def test_jsonl_envelope_supported() -> None:
    """One event per line (JSONL) is supported."""
    line1 = json.dumps(_event(deployment=_deployment()))
    line2 = json.dumps(_event(event_type="domain.removed", domain={"name": "x.example.com"}))
    doc = line1 + "\n" + line2
    results = VercelImporter().parse_string(doc)
    assert len(results) == 2


def test_data_envelope_supported() -> None:
    """``{"data": [...]}`` envelope is supported."""
    doc = json.dumps({"data": [_event(deployment=_deployment())]})
    results = VercelImporter().parse_string(doc)
    assert len(results) == 1
