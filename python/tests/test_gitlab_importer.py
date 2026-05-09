"""Tests for the GitLab audit-events importer."""

from __future__ import annotations

import json
from typing import Any

from ancilis.importers.gitlab import GitLabImporter


# ---------------------------------------------------------------------------
# Fixtures — inline GitLab audit-event records (no python-gitlab required)
# ---------------------------------------------------------------------------


def _event(
    *,
    event_id: int = 1234,
    event_name: str = "push",
    author_id: int = 42,
    author_name: str = "Kevin Bauer",
    entity_type: str = "Project",
    entity_id: int = 7,
    created_at: str = "2026-04-01T12:00:00Z",
    ip_address: str | None = "10.0.0.1",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "id": event_id,
        "author_id": author_id,
        "author_name": author_name,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "event_name": event_name,
        "created_at": created_at,
    }
    if ip_address is not None:
        ev["ip_address"] = ip_address
    if details is not None:
        ev["details"] = details
    return ev


def _findings_for(results: list, event_id: int) -> list:
    return [r for r in results if r.action_id == f"gitlab-{event_id}"]


# ---------------------------------------------------------------------------
# 1. Normal push — non-protected branch, ALLOW + PR-05 PASS.
# ---------------------------------------------------------------------------


def test_parse_normal_push() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id=1,
                    event_name="push",
                    details={
                        "author_class": "User",
                        "branch_name": "feature/foo",
                        "operation_method": "ssh",
                        "force_push": False,
                    },
                )
            ]
        }
    )
    [result] = GitLabImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "gitlab_import"
    assert result.action_id == "gitlab-1"
    assert len(result.control_results) == 1
    cr = result.control_results[0]
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "gitlab_push"
    assert cr.evidence_data["branch_name"] == "feature/foo"
    assert cr.evidence_data["operation_method"] == "ssh"
    assert cr.evidence_data["force_push"] is False


# ---------------------------------------------------------------------------
# 2. Force-push to protected branch → PR-02 FAIL.
# ---------------------------------------------------------------------------


def test_force_push_protected_branch_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id=2,
                    event_name="push",
                    details={
                        "author_class": "User",
                        "branch_name": "main",
                        "force_push": True,
                        "operation_method": "ssh",
                    },
                )
            ]
        }
    )
    [result] = GitLabImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fail_signals = [
        cr for cr in result.control_results if cr.result == "FAIL"
    ]
    assert any(
        cr.evidence_data["signal"] == "force_push_protected"
        and cr.control_id == "PR-02"
        for cr in fail_signals
    )


# ---------------------------------------------------------------------------
# 3. Bot-authored MR → PR-01 FLAG.
# ---------------------------------------------------------------------------


def test_bot_authored_mr_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id=3,
                    event_name="merge_request_created",
                    author_name="dependabot[bot]",
                    details={
                        "author_class": "Bot",
                        "target_type": "MergeRequest",
                        "target_details": "feature/x",
                    },
                )
            ]
        }
    )
    [result] = GitLabImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flags = [cr for cr in result.control_results if cr.result == "FLAG"]
    assert any(
        cr.evidence_data["signal"] == "agent_authored_mr"
        and cr.control_id == "PR-01"
        for cr in flags
    )


# ---------------------------------------------------------------------------
# 4. MR merged with zero approvals → PR-02 FAIL.
# ---------------------------------------------------------------------------


def test_mr_merged_no_approval_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id=4,
                    event_name="merge_request_merged",
                    details={
                        "author_class": "User",
                        "target_details": "main",
                        "merge_method": "merge",
                        "approval_count": 0,
                    },
                )
            ]
        }
    )
    [result] = GitLabImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fails = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.evidence_data["signal"] == "mr_merged_no_approval"
        and cr.control_id == "PR-02"
        for cr in fails
    )


# ---------------------------------------------------------------------------
# 5. policy_violation → PR-02 FAIL.
# ---------------------------------------------------------------------------


def test_policy_violation_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id=5,
                    event_name="policy_violation",
                    details={
                        "author_class": "User",
                        "custom_message": "scan-execution-policy denied",
                    },
                )
            ]
        }
    )
    [result] = GitLabImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fails = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.evidence_data["signal"] == "gitlab_policy_violation"
        for cr in fails
    )


# ---------------------------------------------------------------------------
# 6. Non-expiring PAT → PR-01 FAIL.
# ---------------------------------------------------------------------------


def test_non_expiring_pat_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id=6,
                    event_name="personal_access_token_created",
                    details={
                        "author_class": "User",
                        "scope_list": ["api", "read_repository"],
                        "expires_at": None,
                    },
                )
            ]
        }
    )
    [result] = GitLabImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fails = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.evidence_data["signal"] == "non_expiring_pat"
        and cr.control_id == "PR-01"
        for cr in fails
    )


# ---------------------------------------------------------------------------
# 7. Long-lived API-scoped PAT → PR-01 FLAG.
# ---------------------------------------------------------------------------


def test_long_lived_api_scoped_pat_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id=7,
                    event_name="personal_access_token_created",
                    created_at="2026-01-01T00:00:00Z",
                    details={
                        "author_class": "User",
                        "scope_list": ["api"],
                        # 2 years out — well beyond the 365-day threshold.
                        "expires_at": "2028-01-01T00:00:00Z",
                    },
                )
            ]
        }
    )
    [result] = GitLabImporter().parse_string(doc)
    flags = [cr for cr in result.control_results if cr.result == "FLAG"]
    assert any(
        cr.evidence_data["signal"] == "long_lived_api_pat"
        and cr.control_id == "PR-01"
        for cr in flags
    )


# ---------------------------------------------------------------------------
# 8. Permission escalation → PR-02 FAIL.
# ---------------------------------------------------------------------------


def test_permission_escalation_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id=8,
                    event_name="permission_changed",
                    details={
                        "author_class": "User",
                        "target_type": "User",
                        "from": "developer",
                        "to": "maintainer",
                    },
                )
            ]
        }
    )
    [result] = GitLabImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fails = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.evidence_data["signal"] == "permission_escalation"
        and cr.control_id == "PR-02"
        for cr in fails
    )


# ---------------------------------------------------------------------------
# 9. Protected branch destroyed → PR-02 FAIL.
# ---------------------------------------------------------------------------


def test_protected_branch_destroyed_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id=9,
                    event_name="protected_branch_destroyed",
                    details={
                        "author_class": "User",
                        "target_details": "main",
                    },
                )
            ]
        }
    )
    [result] = GitLabImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fails = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.evidence_data["signal"] == "gitlab_protected_branch_destroyed"
        and cr.control_id == "PR-02"
        for cr in fails
    )


# ---------------------------------------------------------------------------
# 10. Vulnerability dismissed at critical severity → PR-02 FAIL.
# ---------------------------------------------------------------------------


def test_vulnerability_dismissed_critical_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id=10,
                    event_name="vulnerability_dismissed",
                    details={
                        "author_class": "User",
                        "severity": "critical",
                    },
                )
            ]
        }
    )
    [result] = GitLabImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fails = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.evidence_data["signal"] == "vulnerability_dismissed_critical"
        and cr.control_id == "PR-02"
        for cr in fails
    )


# ---------------------------------------------------------------------------
# 11. secret_detection_finding → DE-01 FAIL.
# ---------------------------------------------------------------------------


def test_secret_detection_finding_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id=11,
                    event_name="secret_detection_finding",
                    details={
                        "author_class": "User",
                        "target_type": "Note",
                        "custom_message": "AWS_SECRET_ACCESS_KEY",
                    },
                )
            ]
        }
    )
    [result] = GitLabImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fails = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert any(
        cr.evidence_data["signal"] == "gitlab_secret_detection_finding"
        and cr.control_id == "DE-01"
        for cr in fails
    )


# ---------------------------------------------------------------------------
# 12. No-MFA on push to protected branch → PR-01 FLAG.
# ---------------------------------------------------------------------------


def test_no_mfa_on_protected_push_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id=12,
                    event_name="push",
                    details={
                        "author_class": "User",
                        "branch_name": "main",
                        "force_push": False,
                        "is_two_factor_enabled": False,
                    },
                )
            ]
        }
    )
    [result] = GitLabImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flags = [cr for cr in result.control_results if cr.result == "FLAG"]
    assert any(
        cr.evidence_data["signal"] == "no_mfa_protected_push"
        and cr.control_id == "PR-01"
        for cr in flags
    )


# ---------------------------------------------------------------------------
# 13. Cross-project pattern — synthetic.
# Same author_id touching > 5 projects → synthetic PR-02 FLAG.
# ---------------------------------------------------------------------------


def test_cross_project_pattern_synthetic() -> None:
    events = [
        _event(
            event_id=100 + i,
            event_name="merge_request_created",
            author_id=999,
            entity_id=200 + i,
            details={
                "author_class": "User",
                "target_type": "MergeRequest",
            },
        )
        for i in range(6)  # 6 projects > threshold 5
    ]
    doc = json.dumps({"events": events})
    results = GitLabImporter().parse_string(doc)
    synthetic_action_id = "gitlab-cross-project-999"
    synthetics = [r for r in results if r.action_id == synthetic_action_id]
    assert len(synthetics) == 1
    syn = synthetics[0]
    assert syn.decision == "FLAG"
    assert len(syn.control_results) == 1
    cr = syn.control_results[0]
    assert cr.evidence_data["signal"] == "cross_project_pattern"
    assert cr.evidence_data["cross_project_project_count"] == 6
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 14. Bot-velocity pattern — synthetic.
# Same Bot author creating > 10 MRs in 1h → synthetic PR-02 FLAG.
# ---------------------------------------------------------------------------


def test_bot_velocity_pattern_synthetic() -> None:
    events = []
    for i in range(11):  # 11 MRs > threshold 10
        events.append(
            _event(
                event_id=200 + i,
                event_name="merge_request_created",
                author_id=777,
                author_name="claude-bot",
                entity_id=300,  # all in same project
                created_at=f"2026-04-01T12:{i:02d}:00Z",  # all within 1 hour
                details={
                    "author_class": "Bot",
                    "target_type": "MergeRequest",
                },
            )
        )
    doc = json.dumps({"events": events})
    results = GitLabImporter().parse_string(doc)
    synthetic_action_id = "gitlab-bot-velocity-777"
    synthetics = [r for r in results if r.action_id == synthetic_action_id]
    assert len(synthetics) == 1
    syn = synthetics[0]
    assert syn.decision == "FLAG"
    cr = syn.control_results[0]
    assert cr.evidence_data["signal"] == "bot_velocity_pattern"
    assert cr.evidence_data["bot_velocity_count"] >= 11
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 15. IP redaction — public IPv4 reduced to /16.
# ---------------------------------------------------------------------------


def test_ip_redacted() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id=15,
                    event_name="push",
                    ip_address="8.8.8.8",  # public IPv4
                    details={
                        "author_class": "User",
                        "branch_name": "feature/x",
                    },
                )
            ]
        }
    )
    [result] = GitLabImporter().parse_string(doc)
    cr = result.control_results[0]
    redacted = cr.evidence_data["ip_redacted"]
    assert redacted == "8.8.0.0/16"
    # Raw IP is NOT stored.
    serialized = json.dumps(cr.evidence_data, default=str)
    assert "8.8.8.8" not in serialized


# ---------------------------------------------------------------------------
# 16. User-agent redaction — first 80 chars + sha256.
# ---------------------------------------------------------------------------


def test_user_agent_redacted() -> None:
    long_ua = (
        "GitLab-Workhorse/15.11 (linux; x86_64) "
        "git/2.40.0 with-token-bearing-fingerprint-must-not-leak-AAAA"
        "BBBBCCCCDDDDEEEEFFFF1234567890"
    )
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id=16,
                    event_name="push",
                    details={
                        "author_class": "User",
                        "branch_name": "feature/x",
                        "user_agent": long_ua,
                    },
                )
            ]
        }
    )
    [result] = GitLabImporter().parse_string(doc)
    cr = result.control_results[0]
    ua = cr.evidence_data["user_agent_redacted"]
    assert isinstance(ua, dict)
    assert len(ua["prefix"]) == 80
    assert ua["prefix"] == long_ua[:80]
    assert len(ua["sha256"]) == 64
    # The long token-bearing-fingerprint tail must not leak.
    assert "1234567890" not in ua["prefix"]
    serialized = json.dumps(cr.evidence_data, default=str)
    assert long_ua not in serialized
