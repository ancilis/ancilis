"""Tests for the Composio tool-execution audit importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers.composio import ComposioImporter


# ---------------------------------------------------------------------------
# Fixtures — inline Composio execution records (no composio package required)
# ---------------------------------------------------------------------------


def _exec(
    *,
    id: str = "exec-abc123",
    action: str = "GMAIL_SEND_EMAIL",
    app: str = "gmail",
    connection_id: str = "conn-xyz",
    user_id: str = "user-1",
    agent_id: str = "agent-1",
    auth_scheme: str = "OAUTH2",
    scopes_used: list[str] | None = None,
    input_param_keys: list[str] | None = None,
    input_param_count: int | None = None,
    result_status: str = "success",
    error_code: str | None = None,
    latency_ms: int = 250,
    executed_at: str = "2026-04-01T12:00:00Z",
    triggered_by: str = "agent",
    approval_required: bool = False,
    approval_status: str | None = None,
    redact_pii_in_input: bool = True,
    external_destination_kind: str = "email",
) -> dict:
    if scopes_used is None:
        scopes_used = ["mail.send", "user.read"]
    if input_param_keys is None:
        input_param_keys = ["recipient_email", "subject", "body"]
    if input_param_count is None:
        input_param_count = len(input_param_keys)
    return {
        "id": id,
        "action": action,
        "app": app,
        "connection_id": connection_id,
        "user_id": user_id,
        "agent_id": agent_id,
        "auth_scheme": auth_scheme,
        "scopes_used": scopes_used,
        "input_param_keys": input_param_keys,
        "input_param_count": input_param_count,
        "result_status": result_status,
        "error_code": error_code,
        "latency_ms": latency_ms,
        "executed_at": executed_at,
        "triggered_by": triggered_by,
        "approval_required": approval_required,
        "approval_status": approval_status,
        "redact_pii_in_input": redact_pii_in_input,
        "external_destination_kind": external_destination_kind,
    }


def _findings_for_exec(results: list, exec_id: str) -> list:
    """Return the EvaluationResults whose action_id matches a given exec id."""
    return [r for r in results if r.action_id == f"composio-{exec_id}"]


# ---------------------------------------------------------------------------
# Approval / scope semantics
# ---------------------------------------------------------------------------


def test_parse_success_with_approval() -> None:
    """success + approval_status=approved → PR-02 PASS, ALLOW decision."""
    doc = json.dumps(
        {
            "executions": [
                _exec(
                    id="exec-approved",
                    action="GITHUB_CREATE_ISSUE",
                    app="github",
                    scopes_used=["repo", "issues.read"],
                    approval_required=True,
                    approval_status="approved",
                    external_destination_kind="issue_tracker",
                    triggered_by="agent",
                )
            ]
        }
    )
    [result] = ComposioImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "composio_import"
    assert len(result.control_results) == 1
    cr = result.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "result_status_success_approved"
    assert cr.evidence_data["action"] == "GITHUB_CREATE_ISSUE"
    assert cr.evidence_data["app"] == "github"


def test_missing_approval_fails() -> None:
    """success + approval_required=true + approval_status=null → PR-02 FAIL, BLOCK."""
    doc = json.dumps(
        {
            "executions": [
                _exec(
                    id="exec-no-approval",
                    action="SALESFORCE_UPDATE_RECORD",
                    app="salesforce",
                    approval_required=True,
                    approval_status=None,
                    external_destination_kind="crm",
                )
            ]
        }
    )
    [result] = ComposioImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fails = [cr for cr in result.control_results if cr.result == "FAIL"]
    assert len(fails) == 1
    assert fails[0].control_id == "PR-02"
    assert fails[0].evidence_data["signal"] == "missing_approval"


def test_failure_marks_fail() -> None:
    """result_status=failure → DE-01 FAIL, BLOCK decision."""
    doc = json.dumps(
        {
            "executions": [
                _exec(
                    id="exec-fail",
                    result_status="failure",
                    error_code="UPSTREAM_5XX",
                )
            ]
        }
    )
    [result] = ComposioImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    de01 = [cr for cr in result.control_results if cr.control_id == "DE-01"]
    assert len(de01) == 1
    assert de01[0].result == "FAIL"
    assert de01[0].evidence_data["signal"] == "result_status_failure"
    assert de01[0].evidence_data["error_code"] == "UPSTREAM_5XX"


def test_rate_limited_flags() -> None:
    """result_status=rate_limited → PR-02 FLAG (capacity / abuse)."""
    doc = json.dumps(
        {
            "executions": [
                _exec(id="exec-rate", result_status="rate_limited")
            ]
        }
    )
    [result] = ComposioImporter().parse_string(doc)
    assert result.decision == "FLAG"
    pr02 = [cr for cr in result.control_results if cr.control_id == "PR-02"]
    flags = [cr for cr in pr02 if cr.evidence_data.get("signal") == "result_status_rate_limited"]
    assert len(flags) == 1
    assert flags[0].result == "FLAG"


def test_auth_expired_flags_identity() -> None:
    """result_status=auth_expired → PR-01 FLAG (re-auth)."""
    doc = json.dumps(
        {
            "executions": [
                _exec(id="exec-auth", result_status="auth_expired")
            ]
        }
    )
    [result] = ComposioImporter().parse_string(doc)
    assert result.decision == "FLAG"
    pr01 = [cr for cr in result.control_results if cr.control_id == "PR-01"]
    flags = [cr for cr in pr01 if cr.evidence_data.get("signal") == "result_status_auth_expired"]
    assert len(flags) == 1
    assert flags[0].result == "FLAG"


def test_denied_logged_audit() -> None:
    """approval_status=denied → PR-05 PASS (audit trail of denial)."""
    doc = json.dumps(
        {
            "executions": [
                _exec(
                    id="exec-denied",
                    result_status="failure",
                    approval_required=True,
                    approval_status="denied",
                    error_code="APPROVAL_DENIED",
                )
            ]
        }
    )
    [result] = ComposioImporter().parse_string(doc)
    pr05 = [cr for cr in result.control_results if cr.control_id == "PR-05"]
    denial_log = [cr for cr in pr05 if cr.evidence_data.get("signal") == "denied_approval"]
    assert len(denial_log) == 1
    assert denial_log[0].result == "PASS"


def test_external_destination_email_flags() -> None:
    """external_destination_kind=email → PR-04 FLAG (exfiltration surface)."""
    doc = json.dumps(
        {
            "executions": [
                _exec(
                    id="exec-ext",
                    action="GMAIL_SEND_EMAIL",
                    app="gmail",
                    approval_required=False,
                    approval_status=None,
                    external_destination_kind="email",
                    redact_pii_in_input=True,
                )
            ]
        }
    )
    [result] = ComposioImporter().parse_string(doc)
    assert result.decision == "FLAG"
    pr04 = [cr for cr in result.control_results if cr.control_id == "PR-04"]
    ext = [cr for cr in pr04 if cr.evidence_data.get("signal") == "external_destination"]
    assert len(ext) == 1
    assert ext[0].result == "FLAG"
    assert ext[0].evidence_data["external_destination_kind"] == "email"


def test_webhook_trigger_flags() -> None:
    """triggered_by=webhook → PR-01 FLAG (verify provenance)."""
    doc = json.dumps(
        {
            "executions": [
                _exec(
                    id="exec-webhook",
                    triggered_by="webhook",
                    approval_required=False,
                    external_destination_kind="issue_tracker",
                )
            ]
        }
    )
    [result] = ComposioImporter().parse_string(doc)
    assert result.decision == "FLAG"
    pr01 = [cr for cr in result.control_results if cr.control_id == "PR-01"]
    webhooks = [cr for cr in pr01 if cr.evidence_data.get("signal") == "trigger_webhook"]
    assert len(webhooks) == 1
    assert webhooks[0].result == "FLAG"


def test_scheduler_trigger_passes() -> None:
    """triggered_by=scheduler → PR-05 PASS (audit-trail expected)."""
    doc = json.dumps(
        {
            "executions": [
                _exec(
                    id="exec-sched",
                    triggered_by="scheduler",
                    approval_required=False,
                    external_destination_kind="issue_tracker",
                    scopes_used=["issues.read"],
                )
            ]
        }
    )
    [result] = ComposioImporter().parse_string(doc)
    pr05 = [cr for cr in result.control_results if cr.control_id == "PR-05"]
    sched = [cr for cr in pr05 if cr.evidence_data.get("signal") == "trigger_scheduler"]
    assert len(sched) == 1
    assert sched[0].result == "PASS"


def test_pii_unredacted_flags() -> None:
    """redact_pii_in_input=false on email/chat destination → PR-04 FLAG."""
    doc = json.dumps(
        {
            "executions": [
                _exec(
                    id="exec-pii",
                    action="SLACK_POST_MESSAGE",
                    app="slack",
                    approval_required=False,
                    external_destination_kind="chat",
                    redact_pii_in_input=False,
                    scopes_used=["chat.write"],
                )
            ]
        }
    )
    [result] = ComposioImporter().parse_string(doc)
    assert result.decision == "FLAG"
    pii_flags = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "pii_unredacted"
    ]
    assert len(pii_flags) == 1
    assert pii_flags[0].control_id == "PR-04"
    assert pii_flags[0].result == "FLAG"


def test_broad_scope_flags() -> None:
    """Broad-scope tokens (e.g. admin.*, *.write, *.delete) → PR-02 FLAG."""
    doc = json.dumps(
        {
            "executions": [
                _exec(
                    id="exec-broad",
                    action="SLACK_POST_MESSAGE",
                    app="slack",
                    scopes_used=["admin.users", "chat.write", "files.delete"],
                    approval_required=False,
                    external_destination_kind="chat",
                    redact_pii_in_input=True,
                )
            ]
        }
    )
    [result] = ComposioImporter().parse_string(doc)
    assert result.decision == "FLAG"
    broad = [
        cr
        for cr in result.control_results
        if cr.evidence_data.get("signal") == "broad_scope"
    ]
    assert len(broad) == 1
    assert broad[0].control_id == "PR-02"
    matches = broad[0].evidence_data["broad_scope_matches"]
    # admin.users matches "admin.*", chat.write matches "*.write", files.delete matches "*.delete"
    assert "admin.users" in matches
    assert "chat.write" in matches
    assert "files.delete" in matches


def test_cross_app_pattern_synthetic_finding() -> None:
    """Same agent_id touching > 5 apps → synthetic PR-02 FLAG (and per-exec context flags)."""
    apps = ["gmail", "slack", "github", "salesforce", "notion", "jira"]
    executions = [
        _exec(
            id=f"exec-cross-{i}",
            agent_id="agent-spreader",
            action=f"{app.upper()}_DO_THING",
            app=app,
            approval_required=False,
            external_destination_kind="issue_tracker",
            scopes_used=["read"],
        )
        for i, app in enumerate(apps)
    ]
    doc = json.dumps({"executions": executions})
    results = ComposioImporter().parse_string(doc)

    # 6 per-execution + 1 synthetic = 7 results.
    assert len(results) == 7

    # Synthetic finding present with the cross_app_pattern signal.
    synthetics = [
        r for r in results if r.action_id == "composio-cross-app-agent-spreader"
    ]
    assert len(synthetics) == 1
    syn = synthetics[0]
    assert syn.decision == "FLAG"
    assert len(syn.control_results) == 1
    syn_cr = syn.control_results[0]
    assert syn_cr.control_id == "PR-02"
    assert syn_cr.result == "FLAG"
    assert syn_cr.evidence_data["signal"] == "cross_app_pattern"
    assert syn_cr.evidence_data["cross_app_app_count"] == 6
    assert sorted(syn_cr.evidence_data["cross_app_apps"]) == sorted(apps)
    assert syn_cr.evidence_data["synthetic"] is True

    # And each per-exec result also carries a cross_app_pattern context flag.
    per_exec = [r for r in results if r.action_id != "composio-cross-app-agent-spreader"]
    for r in per_exec:
        sigs = [cr.evidence_data.get("signal") for cr in r.control_results]
        assert "cross_app_pattern" in sigs

    # Below the threshold — no synthetic finding emitted.
    few = [
        _exec(id=f"exec-few-{i}", agent_id="agent-narrow", app=a)
        for i, a in enumerate(["gmail", "slack"])
    ]
    results_narrow = ComposioImporter().parse_string(json.dumps({"executions": few}))
    assert all(
        r.action_id != "composio-cross-app-agent-narrow" for r in results_narrow
    )


def test_input_param_values_never_stored() -> None:
    """Only input_param_keys (names) are surfaced — never input_param values, bodies, or texts."""
    # Build a record with realistic-looking sensitive payload-shaped fields.
    raw = _exec(
        id="exec-pii-leak",
        action="GMAIL_SEND_EMAIL",
        app="gmail",
        input_param_keys=["recipient_email", "subject", "body"],
        input_param_count=3,
    )
    # Inject hostile would-be-leakable values that the importer must IGNORE.
    raw["input_params"] = {
        "recipient_email": "victim@example.com",
        "subject": "TOP SECRET MERGER",
        "body": "Confidential customer SSN 123-45-6789 etc.",
    }
    raw["request_body"] = {"content": "raw email body must not be retained"}
    doc = json.dumps({"executions": [raw]})
    [result] = ComposioImporter().parse_string(doc)
    serialized = json.dumps([cr.evidence_data for cr in result.control_results])
    # The keys array survives.
    assert "recipient_email" in serialized
    assert "subject" in serialized
    assert "body" in serialized
    # But none of the would-be-leakable VALUES survive.
    assert "victim@example.com" not in serialized
    assert "TOP SECRET MERGER" not in serialized
    assert "123-45-6789" not in serialized
    assert "raw email body must not be retained" not in serialized
    # And the importer never adds an "input_params" or "request_body" field
    # to evidence_data — only the explicit keys list / count.
    for cr in result.control_results:
        assert "input_params" not in cr.evidence_data
        assert "request_body" not in cr.evidence_data
        assert cr.evidence_data["input_param_keys"] == [
            "recipient_email",
            "subject",
            "body",
        ]
        assert cr.evidence_data["input_param_count"] == 3


def test_source_provenance_includes_file_hash(tmp_path: Path) -> None:
    """parse(path) hashes the file bytes and surfaces the hash in source_provenance."""
    payload = json.dumps(
        {"executions": [_exec(id="exec-prov", approval_required=False)]}
    ).encode("utf-8")
    expected_sha = hashlib.sha256(payload).hexdigest()
    file_path = tmp_path / "composio-export.json"
    file_path.write_bytes(payload)

    [result] = ComposioImporter().parse(file_path)
    cr = result.control_results[0]
    provenance = cr.evidence_data["source_provenance"]
    assert provenance["source_format"] == "composio"
    assert provenance["source_tool_name"] == "composio"
    assert provenance["execution_id"] == "exec-prov"
    assert provenance["original_file_sha256"] == expected_sha

    # parse_string omits original_file_sha256 — there is no on-disk file.
    [result_str] = ComposioImporter().parse_string(payload.decode("utf-8"))
    assert (
        "original_file_sha256"
        not in result_str.control_results[0].evidence_data["source_provenance"]
    )


# ---------------------------------------------------------------------------
# Shape parsing — extras
# ---------------------------------------------------------------------------


def test_data_envelope_and_jsonl_shapes() -> None:
    """Importer accepts {"data": [...]} envelope and JSONL streams."""
    data_doc = json.dumps(
        {"data": [_exec(id="exec-data-1"), _exec(id="exec-data-2")]}
    )
    results_data = ComposioImporter().parse_string(data_doc)
    assert {r.action_id for r in results_data} == {
        "composio-exec-data-1",
        "composio-exec-data-2",
    }

    jsonl = "\n".join(
        [
            json.dumps(_exec(id="exec-jsonl-1")),
            json.dumps(_exec(id="exec-jsonl-2")),
            "",  # blank line tolerated
        ]
    )
    results_jsonl = ComposioImporter().parse_string(jsonl)
    assert {r.action_id for r in results_jsonl} == {
        "composio-exec-jsonl-1",
        "composio-exec-jsonl-2",
    }


def test_importer_exported_from_package() -> None:
    """ComposioImporter is exported from ancilis.importers."""
    from ancilis.importers import ComposioImporter as Exported

    assert Exported is ComposioImporter


def test_mapping_table_is_valid_json() -> None:
    """Shipped mapping table is valid JSON with the required signals & metadata."""
    mapping_path = (
        Path(__file__).resolve().parent.parent.parent
        / "shared"
        / "mappings"
        / "composio-aksi-controls.json"
    )
    data = json.loads(mapping_path.read_text())
    assert data["_metadata"]["cross_app_threshold"] == 5
    assert data["_metadata"]["broad_scope_patterns"] == [
        "*.write",
        "admin.*",
        "*.delete",
    ]
    mappings = data["mappings"]
    assert mappings["result_status_success_approved"] == "PR-02"
    assert mappings["missing_approval"] == "PR-02"
    assert mappings["result_status_failure"] == "DE-01"
    assert mappings["result_status_rate_limited"] == "PR-02"
    assert mappings["result_status_auth_expired"] == "PR-01"
    assert mappings["denied_approval"] == "PR-05"
    assert mappings["external_destination"] == "PR-04"
    assert mappings["trigger_webhook"] == "PR-01"
    assert mappings["trigger_scheduler"] == "PR-05"
    assert mappings["pii_unredacted"] == "PR-04"
    assert mappings["broad_scope"] == "PR-02"
    assert mappings["cross_app_pattern"] == "PR-02"
