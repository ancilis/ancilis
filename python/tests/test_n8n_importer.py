"""Tests for the n8n workflow-execution importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ancilis.importers.n8n import N8nImporter


# ---------------------------------------------------------------------------
# Fixtures — inline n8n execution records (no n8n install required)
# ---------------------------------------------------------------------------


def _node(
    *,
    node_name: str = "OpenAI Chat",
    node_type: str = "@n8n/n8n-nodes-langchain.openAi",
    executed_at: str = "2026-04-01T12:00:01Z",
    duration_ms: int = 1500,
    input_keys: list[str] | None = None,
    output_keys: list[str] | None = None,
    items_in: int = 1,
    items_out: int = 1,
    errored: bool = False,
    error_message: str | None = None,
    credentials_used: list[str] | None = None,
    url: str | None = None,
) -> dict:
    if input_keys is None:
        input_keys = ["chatInput"]
    if output_keys is None:
        output_keys = ["text"]
    if credentials_used is None:
        credentials_used = ["openai-api-creds"]
    n: dict = {
        "node_name": node_name,
        "node_type": node_type,
        "executed_at": executed_at,
        "duration_ms": duration_ms,
        "input_keys": input_keys,
        "output_keys": output_keys,
        "items_in": items_in,
        "items_out": items_out,
        "errored": errored,
        "error_message": error_message,
        "credentials_used": credentials_used,
    }
    if url is not None:
        n["url"] = url
    return n


def _exec(
    *,
    id: str = "exec-abc123",
    workflow_id: str = "wf-001",
    workflow_name: str = "customer-support-agent",
    started_at: str = "2026-04-01T12:00:00Z",
    finished_at: str = "2026-04-01T12:00:12Z",
    duration_ms: int = 12345,
    mode: str = "manual",
    trigger_type: str | None = "manual",
    status: str = "success",
    user_id: str = "user-1",
    node_executions: list[dict] | None = None,
    execution_url_host: str = "n8n.example.com",
    errors_count: int = 0,
    credentials_referenced: list[str] | None = None,
    external_calls_count: int = 5,
    is_retry: bool = False,
) -> dict:
    if node_executions is None:
        node_executions = [_node()]
    if credentials_referenced is None:
        credentials_referenced = ["openai-api-creds"]
    return {
        "id": id,
        "workflow_id": workflow_id,
        "workflow_name": workflow_name,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_ms": duration_ms,
        "mode": mode,
        "trigger_type": trigger_type,
        "status": status,
        "user_id": user_id,
        "node_executions": node_executions,
        "execution_url_host": execution_url_host,
        "errors_count": errors_count,
        "credentials_referenced": credentials_referenced,
        "external_calls_count": external_calls_count,
        "is_retry": is_retry,
    }


def _signals(result) -> set[str]:
    return {
        cr.evidence_data.get("signal")
        for cr in result.control_results
        if cr.evidence_data.get("signal")
    }


# ---------------------------------------------------------------------------
# Status semantics
# ---------------------------------------------------------------------------


def test_parse_success_workflow() -> None:
    """status=success + manual mode → PR-05 PASS, ALLOW decision."""
    doc = json.dumps({"data": [_exec()]})
    [result] = N8nImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "n8n_import"
    signals = _signals(result)
    assert "status_success" in signals
    # Status PASS uses PR-05.
    status_cr = next(
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "status_success"
    )
    assert status_cr.control_id == "PR-05"
    assert status_cr.result == "PASS"
    # Common evidence captured.
    ev = status_cr.evidence_data
    assert ev["workflow_id"] == "wf-001"
    assert ev["workflow_name"] == "customer-support-agent"
    assert ev["mode"] == "manual"
    assert ev["duration_ms"] == 12345.0
    assert ev["node_count"] == 1
    assert ev["execution_url_host"] == "n8n.example.com"
    assert ev["primary_llm_node"] == "@n8n/n8n-nodes-langchain.openAi"


def test_failed_workflow_marks_fail() -> None:
    """status=failed → DE-01 FAIL, BLOCK; first errored node captured."""
    nodes = [
        _node(node_name="Fetch", node_type="n8n-nodes-base.httpRequest", errored=False),
        _node(
            node_name="Send Email",
            node_type="n8n-nodes-base.gmail",
            errored=True,
            error_message="upstream 500: gmail send failed for recipient",
        ),
        _node(node_name="Notify", node_type="n8n-nodes-base.slack", errored=False),
    ]
    doc = json.dumps(
        {
            "data": [
                _exec(
                    id="exec-fail",
                    status="failed",
                    errors_count=1,
                    node_executions=nodes,
                )
            ]
        }
    )
    [result] = N8nImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    fail_cr = next(
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "status_failed"
    )
    assert fail_cr.control_id == "DE-01"
    assert fail_cr.result == "FAIL"
    first_errored = fail_cr.evidence_data["first_errored_node"]
    assert first_errored["node_name"] == "Send Email"
    assert first_errored["node_type"] == "n8n-nodes-base.gmail"
    # Raw error_message must NOT be in evidence; only length+sha256.
    assert "error_message" not in first_errored
    assert first_errored["error_message_length"] == len(
        "upstream 500: gmail send failed for recipient"
    )
    assert first_errored["error_message_sha256"] == hashlib.sha256(
        b"upstream 500: gmail send failed for recipient"
    ).hexdigest()


def test_canceled_workflow_audit() -> None:
    """status=canceled → PR-05 PASS (audit trail of cancellation)."""
    doc = json.dumps({"data": [_exec(id="exec-can", status="canceled")]})
    [result] = N8nImporter().parse_string(doc)
    cr = next(
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "status_canceled"
    )
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert result.decision == "ALLOW"


def test_waiting_workflow_flags() -> None:
    """status=waiting → PR-02 FLAG (long-pending workflow)."""
    doc = json.dumps({"data": [_exec(id="exec-wait", status="waiting")]})
    [result] = N8nImporter().parse_string(doc)
    cr = next(
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "status_waiting"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert result.decision == "FLAG"


# ---------------------------------------------------------------------------
# Trigger / mode semantics
# ---------------------------------------------------------------------------


def test_webhook_trigger_flags() -> None:
    """mode=webhook + trigger_type=webhook → PR-01 FLAG (external trigger)."""
    doc = json.dumps(
        {
            "data": [
                _exec(
                    id="exec-hook",
                    mode="webhook",
                    trigger_type="webhook",
                )
            ]
        }
    )
    [result] = N8nImporter().parse_string(doc)
    assert "trigger_webhook" in _signals(result)
    cr = next(
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "trigger_webhook"
    )
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"
    assert result.decision == "FLAG"


# ---------------------------------------------------------------------------
# Node-type fingerprints
# ---------------------------------------------------------------------------


def test_code_node_flags_arbitrary_js() -> None:
    """A code node executing → PR-03 FLAG (arbitrary JS surface)."""
    nodes = [
        _node(
            node_name="Transform",
            node_type="n8n-nodes-base.code",
            input_keys=["json"],
            output_keys=["json"],
            credentials_used=[],
        )
    ]
    doc = json.dumps({"data": [_exec(id="exec-code", node_executions=nodes)]})
    [result] = N8nImporter().parse_string(doc)
    assert "code_node_used" in _signals(result)
    cr = next(
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "code_node_used"
    )
    assert cr.control_id == "PR-03"
    assert cr.result == "FLAG"
    assert cr.evidence_data["code_nodes_used"] == ["Transform"]
    assert result.decision == "FLAG"


def test_http_request_to_external_host_flags() -> None:
    """HTTP-Request node to non-allowlisted host → PR-04 FLAG (external egress).

    Allowlist is empty by default, so any external host flags.
    """
    nodes = [
        _node(
            node_name="Call API",
            node_type="n8n-nodes-base.httpRequest",
            url="https://api.external-service.com/v1/widgets",
            input_keys=["url"],
            output_keys=["body"],
            credentials_used=[],
        )
    ]
    doc = json.dumps({"data": [_exec(id="exec-http", node_executions=nodes)]})
    [result] = N8nImporter().parse_string(doc)
    assert "http_external_host" in _signals(result)
    cr = next(
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "http_external_host"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert "api.external-service.com" in cr.evidence_data["external_http_hosts"]


def test_database_write_node_flags() -> None:
    """Postgres / S3 / Mongo write node executed → PR-04 FLAG (data-write surface)."""
    nodes = [
        _node(
            node_name="Persist Customer",
            node_type="n8n-nodes-base.postgres",
            input_keys=["query", "values"],
            output_keys=["rows"],
            credentials_used=["postgres-prod"],
        )
    ]
    doc = json.dumps({"data": [_exec(id="exec-db", node_executions=nodes)]})
    [result] = N8nImporter().parse_string(doc)
    assert "db_write_node" in _signals(result)
    cr = next(
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "db_write_node"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["db_write_nodes_used"] == ["Persist Customer"]


def test_langchain_agent_node_passes() -> None:
    """LangChain agent node executed → PR-01 PASS, surface model + tool count."""
    nodes = [
        _node(
            node_name="Support Agent",
            node_type="@n8n/n8n-nodes-langchain.agent",
            input_keys=["input", "tools"],
            output_keys=["output"],
            credentials_used=[],
        )
    ]
    doc = json.dumps({"data": [_exec(id="exec-agent", node_executions=nodes)]})
    [result] = N8nImporter().parse_string(doc)
    assert "agent_node_used" in _signals(result)
    cr = next(
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "agent_node_used"
    )
    assert cr.control_id == "PR-01"
    assert cr.result == "PASS"
    assert cr.evidence_data["agent_nodes_used"] == ["Support Agent"]
    # primary_llm_node falls back to the agent node when no LLM node present.
    assert cr.evidence_data["primary_llm_node"] == "@n8n/n8n-nodes-langchain.agent"


# ---------------------------------------------------------------------------
# Credential / surface flags
# ---------------------------------------------------------------------------


def test_credential_sprawl_flags() -> None:
    """credentials_referenced > threshold (default 5) → PR-02 FLAG."""
    creds = [f"cred-{i}" for i in range(7)]
    doc = json.dumps(
        {"data": [_exec(id="exec-spr", credentials_referenced=creds)]}
    )
    [result] = N8nImporter().parse_string(doc)
    assert "credential_sprawl" in _signals(result)
    cr = next(
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "credential_sprawl"
    )
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["credentials_threshold"] == 5


def test_external_calls_high_flags() -> None:
    """external_calls_count > threshold (default 20) → PR-04 FLAG (high surface)."""
    doc = json.dumps(
        {"data": [_exec(id="exec-many", external_calls_count=42)]}
    )
    [result] = N8nImporter().parse_string(doc)
    assert "external_calls_high" in _signals(result)
    cr = next(
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "external_calls_high"
    )
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["external_calls_threshold"] == 20


def test_retry_pattern_logged() -> None:
    """is_retry=true with errors_count>0 → PR-05 PASS, retry pattern in evidence."""
    doc = json.dumps(
        {
            "data": [
                _exec(
                    id="exec-retry",
                    is_retry=True,
                    errors_count=2,
                    status="success",
                )
            ]
        }
    )
    [result] = N8nImporter().parse_string(doc)
    cr = next(
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "status_success"
    )
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert cr.evidence_data["retry_after_error"] is True
    assert cr.evidence_data["retry_errors_count"] == 2
    assert cr.evidence_data["is_retry"] is True


# ---------------------------------------------------------------------------
# Sanitization — node payloads, error messages, credential values
# ---------------------------------------------------------------------------


def test_node_input_output_values_never_stored() -> None:
    """Raw node input/output values are stripped — only structural keys remain."""
    nodes = [
        {
            "node_name": "OpenAI Chat",
            "node_type": "@n8n/n8n-nodes-langchain.openAi",
            "executed_at": "2026-04-01T12:00:01Z",
            "duration_ms": 1500,
            "input_keys": ["chatInput"],
            "output_keys": ["text"],
            "items_in": 1,
            "items_out": 1,
            "errored": False,
            "error_message": None,
            "credentials_used": ["openai-api-creds"],
            # Hostile fields that MUST NOT be stored.
            "input": {"chatInput": "Hello, my SSN is 123-45-6789"},
            "output": {"text": "I cannot share PII"},
            "input_values": {"chatInput": "secret"},
            "output_values": {"text": "secret"},
            "raw_payload": "PII PII PII",
        }
    ]
    doc = json.dumps({"data": [_exec(id="exec-sani", node_executions=nodes)]})
    [result] = N8nImporter().parse_string(doc)
    serialized = json.dumps(
        [cr.evidence_data for cr in result.control_results]
    )
    assert "123-45-6789" not in serialized
    assert "PII PII PII" not in serialized
    assert "Hello, my SSN" not in serialized
    assert "I cannot share PII" not in serialized
    # Verify the sanitized node carries only the allowed structural fields.
    cr = result.control_results[0]
    sanitized_node = cr.evidence_data["node_executions"][0]
    assert set(sanitized_node.keys()) == {
        "node_name",
        "node_type",
        "executed_at",
        "duration_ms",
        "input_keys",
        "output_keys",
        "items_in",
        "items_out",
        "errored",
        "credentials_used",
        "error_message_length",
        "error_message_sha256",
    }


def test_error_message_redacted() -> None:
    """error_message text is replaced with length + sha256 only."""
    secret_msg = "DB connection failed: postgres://user:p4ssw0rd@10.0.0.5/prod"
    nodes = [
        _node(
            node_name="DB",
            node_type="n8n-nodes-base.postgres",
            errored=True,
            error_message=secret_msg,
        )
    ]
    doc = json.dumps(
        {
            "data": [
                _exec(
                    id="exec-err",
                    status="failed",
                    errors_count=1,
                    node_executions=nodes,
                )
            ]
        }
    )
    [result] = N8nImporter().parse_string(doc)
    serialized = json.dumps(
        [cr.evidence_data for cr in result.control_results]
    )
    assert "p4ssw0rd" not in serialized
    assert secret_msg not in serialized
    cr = result.control_results[0]
    sanitized_node = cr.evidence_data["node_executions"][0]
    assert sanitized_node["error_message_length"] == len(secret_msg)
    assert sanitized_node["error_message_sha256"] == hashlib.sha256(
        secret_msg.encode("utf-8")
    ).hexdigest()
    assert "error_message" not in sanitized_node


def test_credential_values_never_stored() -> None:
    """Credential VALUES from any input shape are never stored; only names/IDs.

    n8n credential names (e.g. ``openai-api-creds``) are aliases that resolve
    to the encrypted secret out-of-band, so the names themselves are safe.
    But if the export accidentally embeds raw secret material in a
    credential-shaped object, we must not propagate it.
    """
    nodes = [
        {
            "node_name": "OpenAI Chat",
            "node_type": "@n8n/n8n-nodes-langchain.openAi",
            "executed_at": "2026-04-01T12:00:01Z",
            "duration_ms": 1500,
            "input_keys": ["chatInput"],
            "output_keys": ["text"],
            "items_in": 1,
            "items_out": 1,
            "errored": False,
            "error_message": None,
            "credentials_used": ["openai-api-creds"],
            # Hostile credential payload — must not propagate.
            "credential_values": {"openai-api-creds": "sk-live-deadbeef"},
            "credentials_payload": {"apiKey": "sk-live-deadbeef"},
        }
    ]
    exec_obj = _exec(
        id="exec-cred",
        node_executions=nodes,
        credentials_referenced=["openai-api-creds"],
    )
    # Add hostile top-level field too.
    exec_obj["credentials_payload"] = {"apiKey": "sk-live-deadbeef"}
    doc = json.dumps({"data": [exec_obj]})
    [result] = N8nImporter().parse_string(doc)
    serialized = json.dumps(
        [cr.evidence_data for cr in result.control_results]
    )
    assert "sk-live-deadbeef" not in serialized
    # But the credential alias name IS preserved (it's safe).
    assert "openai-api-creds" in serialized


# ---------------------------------------------------------------------------
# Format coverage: JSONL, single-object, executions-envelope, file-hash provenance
# ---------------------------------------------------------------------------


def test_jsonl_stream() -> None:
    """JSONL format — one execution per line."""
    lines = [
        json.dumps(_exec(id="e1")),
        json.dumps(_exec(id="e2", status="failed", errors_count=1)),
        json.dumps(_exec(id="e3", status="canceled")),
    ]
    results = N8nImporter().parse_string("\n".join(lines))
    assert len(results) == 3
    assert {r.action_id for r in results} == {"n8n-e1", "n8n-e2", "n8n-e3"}


def test_executions_envelope_and_single_object() -> None:
    """{"executions": [...]} envelope and a naked single object are both accepted."""
    env_doc = json.dumps({"executions": [_exec(id="env-1")]})
    [r1] = N8nImporter().parse_string(env_doc)
    assert r1.action_id == "n8n-env-1"

    single = json.dumps(_exec(id="single-1"))
    [r2] = N8nImporter().parse_string(single)
    assert r2.action_id == "n8n-single-1"


def test_source_provenance_includes_file_hash(tmp_path: Path) -> None:
    """parse(path) records sha256 of the input file in source_provenance."""
    payload = json.dumps({"data": [_exec(id="exec-hash")]})
    p = tmp_path / "n8n-export.json"
    p.write_text(payload)
    [result] = N8nImporter().parse(p)
    expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    cr = result.control_results[0]
    prov = cr.evidence_data["source_provenance"]
    assert prov["original_file_sha256"] == expected
    assert prov["source_format"] == "n8n"
    assert prov["source_tool_name"] == "n8n"
    assert prov["execution_id"] == "exec-hash"


