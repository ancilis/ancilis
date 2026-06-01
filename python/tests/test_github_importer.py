"""Tests for the GitHub audit-log importer."""

from __future__ import annotations

import json
from typing import Any

from ancilis.importers.github import GitHubImporter


# ---------------------------------------------------------------------------
# Fixtures — inline GitHub audit-log event records (no PyGithub required)
# ---------------------------------------------------------------------------


def _event(
    *,
    document_id: str = "doc-001",
    action: str = "git.push",
    actor: str = "kbauer",
    actor_is_bot: bool = False,
    org: str = "ancilis",
    repo: str = "ancilis/ancilis",
    repo_id: int = 11111,
    ref: str | None = "refs/heads/feature/x",
    timestamp_ms: int = 1730000000000,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "@timestamp": timestamp_ms,
        "_document_id": document_id,
        "action": action,
        "actor": actor,
        "actor_id": 12345,
        "actor_is_bot": actor_is_bot,
        "user": actor,
        "org": org,
        "org_id": 67890,
        "repo": repo,
        "repo_id": repo_id,
    }
    if ref is not None:
        ev["ref"] = ref
    if extra:
        ev.update(extra)
    return ev


def _findings_for(results: list, document_id: str) -> list:
    return [r for r in results if r.action_id == f"github-{document_id}"]


# ---------------------------------------------------------------------------
# 1. Normal git.push — non-protected branch, ALLOW + PR-05 PASS.
# ---------------------------------------------------------------------------


def test_parse_normal_push() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    document_id="evt-push-feature",
                    action="git.push",
                    ref="refs/heads/feature/foo",
                    extra={"transport_protocol_name": "SSH"},
                )
            ]
        }
    )
    [result] = GitHubImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "github_import"
    assert result.action_id == "github-evt-push-feature"
    assert len(result.control_results) == 1
    cr = result.control_results[0]
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "git_push"
    assert cr.evidence_data["transport_protocol_name"] == "SSH"


# ---------------------------------------------------------------------------
# 2. branch_protection_evasion non-null on git.push to protected → PR-02 FAIL.
# ---------------------------------------------------------------------------


def test_protected_branch_evasion_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    document_id="evt-evasion",
                    action="git.push",
                    ref="refs/heads/main",
                    extra={
                        "branch_protection_evasion":
                            "branch_protection_admin_action_required",
                        "transport_protocol_name": "HTTPS",
                    },
                )
            ]
        }
    )
    [result] = GitHubImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fail_results = [c for c in result.control_results if c.result == "FAIL"]
    assert any(
        c.evidence_data["signal"] == "branch_protection_evasion"
        and c.control_id == "PR-02"
        for c in fail_results
    )
    bpe_finding = next(
        c for c in fail_results
        if c.evidence_data["signal"] == "branch_protection_evasion"
    )
    # branch_protection_evasion captured verbatim.
    assert (
        bpe_finding.evidence_data["branch_protection_evasion"]
        == "branch_protection_admin_action_required"
    )


# ---------------------------------------------------------------------------
# 3. PR from a fork → PR-04 FLAG.
# ---------------------------------------------------------------------------


def test_pr_from_fork_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    document_id="evt-fork",
                    action="git.push",
                    ref="refs/heads/feature/contrib",
                    extra={"head_repository": "external-user/ancilis"},
                )
            ]
        }
    )
    [result] = GitHubImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flag_signals = {
        c.evidence_data["signal"] for c in result.control_results
        if c.result == "FLAG"
    }
    assert "fork_head_push" in flag_signals
    fork_cr = next(
        c for c in result.control_results
        if c.evidence_data["signal"] == "fork_head_push"
    )
    assert fork_cr.control_id == "PR-04"
    assert fork_cr.evidence_data["head_repository"] == "external-user/ancilis"


# ---------------------------------------------------------------------------
# 4. PR opened by a bot → PR-01 FLAG (agent-authored — needs human review).
# ---------------------------------------------------------------------------


def test_bot_authored_pr_flags_human_review() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    document_id="evt-bot-pr",
                    action="pull_request.create",
                    actor="claude-code-bot",
                    actor_is_bot=True,
                    ref=None,
                    extra={
                        "pull_request_id": 42,
                        "is_ml_powered_action": True,
                        "external_app_name": "Claude Code",
                    },
                )
            ]
        }
    )
    [result] = GitHubImporter().parse_string(doc)
    assert result.decision == "FLAG"
    agent_pr = [
        c for c in result.control_results
        if c.evidence_data["signal"] == "agent_authored_pr"
    ]
    assert agent_pr, "expected agent_authored_pr signal"
    assert agent_pr[0].control_id == "PR-01"
    assert agent_pr[0].result == "FLAG"
    # actor sanitization: bot suffix.
    assert agent_pr[0].evidence_data["actor"] == "claude-code-bot_bot"
    assert agent_pr[0].evidence_data["external_app_name"] == "Claude Code"
    assert agent_pr[0].evidence_data["pull_request_id"] == 42


# ---------------------------------------------------------------------------
# 5. repo.destroy → PR-02 FAIL (irreversible).
# ---------------------------------------------------------------------------


def test_repo_destroy_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    document_id="evt-destroy",
                    action="repo.destroy",
                    ref=None,
                )
            ]
        }
    )
    [result] = GitHubImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fail = [c for c in result.control_results if c.result == "FAIL"]
    assert any(
        c.control_id == "PR-02" and c.evidence_data["signal"] == "repo_destroy"
        for c in fail
    )


# ---------------------------------------------------------------------------
# 6. repo.create with private=false → PR-04 FLAG (public IP exposure).
# ---------------------------------------------------------------------------


def test_public_repo_creation_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    document_id="evt-public",
                    action="repo.create",
                    ref=None,
                    extra={"private": False, "visibility": "public"},
                )
            ]
        }
    )
    [result] = GitHubImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flagged = [
        c for c in result.control_results
        if c.evidence_data["signal"] == "public_repo_create"
    ]
    assert flagged
    assert flagged[0].control_id == "PR-04"
    assert flagged[0].result == "FLAG"


# ---------------------------------------------------------------------------
# 7. members.update_role new_role=owner → PR-02 FAIL (owner promotion).
# ---------------------------------------------------------------------------


def test_owner_role_promotion_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    document_id="evt-owner",
                    action="members.update_role",
                    ref=None,
                    extra={"old_role": "member", "new_role": "owner"},
                )
            ]
        }
    )
    [result] = GitHubImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fail = [c for c in result.control_results if c.result == "FAIL"]
    promo = [
        c for c in fail
        if c.evidence_data["signal"] == "owner_role_promotion"
    ]
    assert promo
    assert promo[0].control_id == "PR-02"
    assert promo[0].evidence_data["new_role"] == "owner"


# ---------------------------------------------------------------------------
# 8. org.invite_member to external email domain → PR-02 FLAG.
# ---------------------------------------------------------------------------


def test_external_invite_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    document_id="evt-invite",
                    action="org.invite_member",
                    ref=None,
                    extra={"invitee_email": "stranger@example.com"},
                )
            ]
        }
    )
    [result] = GitHubImporter(org_domain="ancilis.com").parse_string(doc)
    assert result.decision == "FLAG"
    ext = [
        c for c in result.control_results
        if c.evidence_data["signal"] == "external_invite"
    ]
    assert ext
    assert ext[0].control_id == "PR-02"
    # Email reduced to domain-only.
    assert ext[0].evidence_data["invitee_domain"] == "@example.com"


# ---------------------------------------------------------------------------
# 9. secret_scanning.alert.create → DE-01 FAIL.
# ---------------------------------------------------------------------------


def test_secret_scanning_alert_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    document_id="evt-secret",
                    action="secret_scanning.alert.create",
                    ref=None,
                    extra={"secret_scan_alert_state": "open"},
                )
            ]
        }
    )
    [result] = GitHubImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    secret = [
        c for c in result.control_results
        if c.evidence_data["signal"] == "secret_scanning_alert"
    ]
    assert secret
    assert secret[0].control_id == "DE-01"
    assert secret[0].result == "FAIL"


# ---------------------------------------------------------------------------
# 10. code_scanning.alert.dismiss with severity=critical → PR-02 FAIL.
# ---------------------------------------------------------------------------


def test_code_scanning_dismiss_critical_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    document_id="evt-codescan",
                    action="code_scanning.alert.dismiss",
                    ref=None,
                    extra={"code_scan_alert_severity": "critical"},
                )
            ]
        }
    )
    [result] = GitHubImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    dismiss = [
        c for c in result.control_results
        if c.evidence_data["signal"] == "code_scan_dismiss_critical"
    ]
    assert dismiss
    assert dismiss[0].control_id == "PR-02"
    assert dismiss[0].evidence_data["code_scan_alert_severity"] == "critical"


# ---------------------------------------------------------------------------
# 11. personal_access_token.create → PR-01 FLAG.
# ---------------------------------------------------------------------------


def test_pat_creation_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    document_id="evt-pat",
                    action="personal_access_token.create",
                    ref=None,
                )
            ]
        }
    )
    [result] = GitHubImporter().parse_string(doc)
    assert result.decision == "FLAG"
    pat = [
        c for c in result.control_results
        if c.evidence_data["signal"] == "pat_create"
    ]
    assert pat
    assert pat[0].control_id == "PR-01"
    assert pat[0].result == "FLAG"


# ---------------------------------------------------------------------------
# 12. branch_protection.update weakening (admin → write) → PR-02 FAIL.
# ---------------------------------------------------------------------------


def test_branch_protection_weakening_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    document_id="evt-weaken",
                    action="branch_protection.update",
                    ref="refs/heads/main",
                    extra={
                        "old_permission": "admin",
                        "permission": "write",
                    },
                )
            ]
        }
    )
    [result] = GitHubImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    weakening = [
        c for c in result.control_results
        if c.evidence_data["signal"] == "branch_protection_weakening"
    ]
    assert weakening
    assert weakening[0].control_id == "PR-02"
    assert weakening[0].result == "FAIL"


# ---------------------------------------------------------------------------
# 13. Cross-repo pattern — single bot touching > N repos → synthetic FLAG.
# ---------------------------------------------------------------------------


def test_cross_repo_pattern_synthetic() -> None:
    events = []
    # Bot touches 6 repos (threshold default = 5).
    for i in range(6):
        events.append(
            _event(
                document_id=f"evt-cross-{i}",
                action="git.push",
                actor="velocity-bot",
                actor_is_bot=True,
                ref="refs/heads/feature/x",
                repo=f"ancilis/repo{i}",
                repo_id=20000 + i,
                timestamp_ms=1730000000000 + i * 1000,
            )
        )
    doc = json.dumps({"events": events})
    results = GitHubImporter().parse_string(doc)
    # 6 per-event results + 1 synthetic.
    synthetics = [r for r in results if r.action_id.startswith("github-cross-repo-")]
    assert len(synthetics) == 1
    syn = synthetics[0]
    assert syn.decision == "FLAG"
    [cr] = syn.control_results
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "cross_repo_pattern"
    assert cr.evidence_data["cross_repo_repo_count"] == 6
    assert cr.evidence_data["actor"] == "velocity-bot_bot"


# ---------------------------------------------------------------------------
# 14. Bot-velocity pattern — > N PRs in 1h window → synthetic FLAG.
# ---------------------------------------------------------------------------


def test_bot_velocity_pattern_synthetic() -> None:
    events = []
    base_ts = 1730000000000
    # 12 PR.create events in a 1-hour window from a bot (threshold default = 10).
    for i in range(12):
        events.append(
            _event(
                document_id=f"evt-vel-{i}",
                action="pull_request.create",
                actor="auto-bot",
                actor_is_bot=True,
                ref=None,
                repo="ancilis/ancilis",
                timestamp_ms=base_ts + i * 60 * 1000,  # one per minute
                extra={"pull_request_id": 100 + i},
            )
        )
    doc = json.dumps({"events": events})
    results = GitHubImporter().parse_string(doc)
    synthetics = [
        r for r in results if r.action_id.startswith("github-bot-velocity-")
    ]
    assert len(synthetics) == 1
    syn = synthetics[0]
    [cr] = syn.control_results
    assert cr.control_id == "PR-02"
    assert cr.evidence_data["signal"] == "bot_velocity_pattern"
    assert cr.evidence_data["bot_velocity_count"] == 12
    assert cr.evidence_data["bot_velocity_threshold"] == 10


# ---------------------------------------------------------------------------
# 15. actor_ip — public IPv4 reduced to /16, RFC1918 preserved.
# ---------------------------------------------------------------------------


def test_actor_ip_redacted() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    document_id="evt-ip-pub",
                    action="git.push",
                    extra={"actor_ip": "8.8.8.8"},
                ),
                _event(
                    document_id="evt-ip-priv",
                    action="git.push",
                    extra={"actor_ip": "10.0.0.5"},
                ),
            ]
        }
    )
    results = GitHubImporter().parse_string(doc)
    [pub] = _findings_for(results, "evt-ip-pub")
    [priv] = _findings_for(results, "evt-ip-priv")
    assert pub.control_results[0].evidence_data["actor_ip_redacted"] == "8.8.0.0/16"
    # RFC1918 preserved verbatim.
    assert priv.control_results[0].evidence_data["actor_ip_redacted"] == "10.0.0.5"


# ---------------------------------------------------------------------------
# 16. user_agent — captured as first-80 prefix + sha256 of full UA.
# ---------------------------------------------------------------------------


def test_user_agent_redacted() -> None:
    long_ua = (
        "MyCustomAgent/2.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36 token=abcdef123456"
    )
    doc = json.dumps(
        {
            "events": [
                _event(
                    document_id="evt-ua",
                    action="git.push",
                    extra={"user_agent": long_ua},
                )
            ]
        }
    )
    [result] = GitHubImporter().parse_string(doc)
    ua = result.control_results[0].evidence_data["user_agent_redacted"]
    assert isinstance(ua, dict)
    assert ua["prefix"] == long_ua[:80]
    # The full UA (which carried "token=...") is NOT in the prefix; only its hash.
    assert "token=" not in ua["prefix"]
    assert len(ua["sha256"]) == 64
    # Hash must match.
    import hashlib as _h
    assert ua["sha256"] == _h.sha256(long_ua.encode("utf-8")).hexdigest()
