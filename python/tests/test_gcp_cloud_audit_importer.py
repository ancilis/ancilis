"""Tests for the GCP Cloud Audit Logs importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ancilis.importers.gcp_cloud_audit import GcpCloudAuditImporter


# ---------------------------------------------------------------------------
# Fixtures — inline LogEntry records (no google-cloud-logging required)
# ---------------------------------------------------------------------------


def _entry(
    *,
    insert_id: str = "evt-001",
    timestamp: str = "2026-04-01T12:00:00Z",
    severity: str = "INFO",
    log_name: str = "projects/my-proj/logs/cloudaudit.googleapis.com%2Factivity",
    trace: str = "projects/my-proj/traces/abc",
    span_id: str = "span-abc",
    resource_type: str = "aiplatform.googleapis.com/PublisherModel",
    resource_labels: dict[str, str] | None = None,
    operation_id: str = "op-abc",
    service_name: str = "aiplatform.googleapis.com",
    method_name: str = "google.cloud.aiplatform.v1.PredictionService.Predict",
    resource_name: str = "projects/my-proj/locations/us-central1/publishers/google/models/gemini-1.5",
    principal_email: str = "agent-svc@my-proj.iam.gserviceaccount.com",
    principal_subject: str = "serviceAccount:agent-svc@my-proj.iam.gserviceaccount.com",
    authority_selector: str | None = None,
    sa_key_name: str | None = None,
    authorization_info: list[dict[str, Any]] | None = None,
    caller_ip: str = "203.0.113.42",
    caller_user_agent: str = "google-api-python-client/2.0",
    request: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
    status_code: int | None = None,
    status_message: str | None = None,
    num_response_items: int | str | None = None,
) -> dict[str, Any]:
    if request is None:
        request = {"instances": "<redacted-body>", "parameters": "<redacted>"}
    if response is None:
        response = {"predictions": "<redacted-output>"}
    if authorization_info is None:
        authorization_info = [
            {
                "resource": resource_name,
                "permission": "aiplatform.endpoints.predict",
                "granted": True,
            }
        ]
    auth_info: dict[str, Any] = {
        "principalEmail": principal_email,
        "principalSubject": principal_subject,
    }
    if authority_selector is not None:
        auth_info["authoritySelector"] = authority_selector
    if sa_key_name is not None:
        auth_info["serviceAccountKeyName"] = sa_key_name

    proto_payload: dict[str, Any] = {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "serviceName": service_name,
        "methodName": method_name,
        "resourceName": resource_name,
        "authenticationInfo": auth_info,
        "authorizationInfo": authorization_info,
        "requestMetadata": {
            "callerIp": caller_ip,
            "callerSuppliedUserAgent": caller_user_agent,
            "requestAttributes": {"time": timestamp},
            "destinationAttributes": {},
        },
        "request": request,
        "response": response,
    }
    if status_code is None:
        proto_payload["status"] = {}
    else:
        s: dict[str, Any] = {"code": status_code}
        if status_message is not None:
            s["message"] = status_message
        proto_payload["status"] = s
    if num_response_items is not None:
        proto_payload["numResponseItems"] = num_response_items

    entry: dict[str, Any] = {
        "insertId": insert_id,
        "timestamp": timestamp,
        "severity": severity,
        "logName": log_name,
        "trace": trace,
        "spanId": span_id,
        "resource": {
            "type": resource_type,
            "labels": resource_labels or {"project_id": "my-proj"},
        },
        "operation": {"id": operation_id, "producer": service_name, "first": False, "last": True},
        "protoPayload": proto_payload,
    }
    return entry


def _findings_for_event(results: list, insert_id: str) -> list:
    return [r for r in results if r.action_id == f"gcp-audit-{insert_id}"]


# ---------------------------------------------------------------------------
# Vertex AI / Compute / Identity
# ---------------------------------------------------------------------------


def test_parse_aiplatform_predict() -> None:
    """aiplatform * Predict → PR-01 PASS, ALLOW."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-vertex",
                    service_name="aiplatform.googleapis.com",
                    method_name="google.cloud.aiplatform.v1.PredictionService.Predict",
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "gcp_cloud_audit_import"
    assert result.action_id == "gcp-audit-evt-vertex"
    primary = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") in {"vertex_predict", "vertex_generate_content"}
    ]
    assert primary, [cr.evidence_data.get("signal") for cr in result.control_results]
    assert primary[0].control_id == "PR-01"
    assert primary[0].result == "PASS"
    assert primary[0].evidence_data["service_name"] == "aiplatform.googleapis.com"
    assert primary[0].evidence_data["region"] == "us-central1"


def test_aiplatform_publish_model_flags() -> None:
    """aiplatform * PublishModel → PR-05 FLAG (model lifecycle is high-impact)."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-publish",
                    service_name="aiplatform.googleapis.com",
                    method_name="google.cloud.aiplatform.v1.ModelService.PublishModel",
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    assert result.decision == "FLAG"
    primary = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "vertex_model_lifecycle"
    ]
    assert len(primary) == 1
    assert primary[0].control_id == "PR-05"
    assert primary[0].result == "FLAG"


def test_storage_get_passes() -> None:
    """storage * storage.objects.get → PR-04 PASS."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-gcs-get",
                    service_name="storage.googleapis.com",
                    method_name="storage.objects.get",
                    resource_name="projects/my-proj/buckets/secret-bucket/objects/file.csv",
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    primary = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "gcs_read"
    ]
    assert len(primary) == 1
    assert primary[0].control_id == "PR-04"
    assert primary[0].result == "PASS"


def test_storage_create_flags() -> None:
    """storage * storage.objects.create → PR-04 FLAG."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-gcs-put",
                    service_name="storage.googleapis.com",
                    method_name="storage.objects.create",
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    assert result.decision == "FLAG"
    primary = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "gcs_write"
    ]
    assert len(primary) == 1
    assert primary[0].control_id == "PR-04"
    assert primary[0].result == "FLAG"


def test_set_iam_policy_flags_privilege() -> None:
    """iam * SetIamPolicy → PR-02 FLAG (privilege escalation surface)."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-setiam",
                    service_name="iam.googleapis.com",
                    method_name="google.iam.v1.IAMPolicy.SetIamPolicy",
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    assert result.decision == "FLAG"
    primary = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "iam_privilege_change"
    ]
    assert len(primary) == 1
    assert primary[0].control_id == "PR-02"
    assert primary[0].result == "FLAG"


def test_create_service_account_key_flags() -> None:
    """iam * CreateServiceAccountKey → PR-01 FLAG (key issuance)."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-key-issue",
                    service_name="iam.googleapis.com",
                    method_name="google.iam.admin.v1.CreateServiceAccountKey",
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    assert result.decision == "FLAG"
    primary = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "iam_key_issuance"
    ]
    assert len(primary) == 1
    assert primary[0].control_id == "PR-01"
    assert primary[0].result == "FLAG"


def test_secret_access_flags() -> None:
    """secretmanager * AccessSecretVersion → PR-04 FLAG."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-secret",
                    service_name="secretmanager.googleapis.com",
                    method_name="google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    assert result.decision == "FLAG"
    primary = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "secret_access"
    ]
    assert len(primary) == 1
    assert primary[0].control_id == "PR-04"
    assert primary[0].result == "FLAG"


def test_kms_decrypt_passes() -> None:
    """cloudkms * Decrypt → PR-04 PASS (sensitive data access)."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-kms-dec",
                    service_name="cloudkms.googleapis.com",
                    method_name="google.cloud.kms.v1.KeyManagementService.Decrypt",
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    primary = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "kms_decrypt"
    ]
    assert len(primary) == 1
    assert primary[0].control_id == "PR-04"
    assert primary[0].result == "PASS"


def test_kms_destroy_key_fails() -> None:
    """cloudkms * DestroyCryptoKeyVersion → PR-02 FAIL (key destruction)."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-kms-destroy",
                    service_name="cloudkms.googleapis.com",
                    method_name="google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion",
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    primary = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "kms_destroy_key"
    ]
    assert len(primary) == 1
    assert primary[0].control_id == "PR-02"
    assert primary[0].result == "FAIL"


# ---------------------------------------------------------------------------
# Status code overlays
# ---------------------------------------------------------------------------


def test_permission_denied_fails() -> None:
    """status.code=7 PERMISSION_DENIED → PR-02 FAIL, BLOCK."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-perm",
                    service_name="storage.googleapis.com",
                    method_name="storage.objects.get",
                    status_code=7,
                    status_message="Permission denied on resource.",
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    [cr] = [
        c for c in result.control_results
        if c.evidence_data.get("signal") == "permission_denied"
    ]
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["status_code"] == 7


def test_unauthenticated_fails() -> None:
    """status.code=16 UNAUTHENTICATED → PR-01 FAIL, BLOCK."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-unauth",
                    service_name="aiplatform.googleapis.com",
                    method_name="google.cloud.aiplatform.v1.PredictionService.Predict",
                    status_code=16,
                    status_message="Caller is not authenticated.",
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    [cr] = [
        c for c in result.control_results
        if c.evidence_data.get("signal") == "unauthenticated"
    ]
    assert cr.control_id == "PR-01"
    assert cr.result == "FAIL"


def test_resource_exhausted_flags() -> None:
    """status.code=8 RESOURCE_EXHAUSTED → PR-02 FLAG."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-rate",
                    service_name="aiplatform.googleapis.com",
                    method_name="google.cloud.aiplatform.v1.PredictionService.Predict",
                    status_code=8,
                    status_message="Quota exceeded.",
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    assert result.decision == "FLAG"
    [cr] = [
        c for c in result.control_results
        if c.evidence_data.get("signal") == "resource_exhausted"
    ]
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"


def test_internal_error_de01_fails() -> None:
    """status.code=13 INTERNAL → DE-01 FAIL."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-internal",
                    service_name="aiplatform.googleapis.com",
                    method_name="google.cloud.aiplatform.v1.PredictionService.Predict",
                    status_code=13,
                    status_message="Internal error.",
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    [cr] = [
        c for c in result.control_results
        if c.evidence_data.get("signal") == "internal_error"
    ]
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Authorization / identity overlays
# ---------------------------------------------------------------------------


def test_authorization_denied_audit() -> None:
    """authorizationInfo[*].granted=false → PR-02 PASS audit-trail signal."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-authz-denied",
                    service_name="storage.googleapis.com",
                    method_name="storage.objects.get",
                    authorization_info=[
                        {
                            "resource": "projects/my-proj/buckets/x",
                            "permission": "storage.objects.get",
                            "granted": False,
                        }
                    ],
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    [cr] = [
        c for c in result.control_results
        if c.evidence_data.get("signal") == "authorization_denied"
    ]
    assert cr.control_id == "PR-02"
    assert cr.result == "PASS"
    assert cr.evidence_data["authorization_denied_count"] == 1


def test_service_account_key_auth_flags() -> None:
    """serviceAccountKeyName present → PR-01 FLAG (key-based auth)."""
    sa_key = (
        "projects/my-proj/serviceAccounts/agent@my-proj.iam.gserviceaccount.com/"
        "keys/abcdef1234567890ABCDEF1234567890ZZZZ9999"
    )
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-sa-key",
                    sa_key_name=sa_key,
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    [cr] = [
        c for c in result.control_results
        if c.evidence_data.get("signal") == "service_account_key_auth"
    ]
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"
    fp = cr.evidence_data["service_account_key_fingerprint"]
    assert fp.startswith("key:***")
    # Last 4 of the keyId.
    assert fp.endswith("9999")
    # Full key path must NOT appear in evidence.
    assert sa_key not in json.dumps(cr.evidence_data)


def test_cross_project_pattern_synthetic_finding() -> None:
    """Single principalEmail touching 2+ projectIds → synthetic PR-02 FLAG."""
    email = "shared-agent@example.com"
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-proj-1",
                    principal_email=email,
                    log_name="projects/proj-a/logs/cloudaudit.googleapis.com%2Factivity",
                    resource_name="projects/proj-a/locations/us-central1/datasets/x",
                ),
                _entry(
                    insert_id="evt-proj-2",
                    principal_email=email,
                    log_name="projects/proj-b/logs/cloudaudit.googleapis.com%2Factivity",
                    resource_name="projects/proj-b/locations/us-central1/datasets/y",
                ),
            ]
        }
    )
    results = GcpCloudAuditImporter().parse_string(doc)
    # 2 per-event results + 1 synthetic.
    assert len(results) == 3
    synthetic = [
        r for r in results if r.action_id.startswith("gcp-audit-cross-project-")
    ]
    assert len(synthetic) == 1
    syn = synthetic[0]
    assert syn.decision == "FLAG"
    [cr] = syn.control_results
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "cross_project_pattern"
    assert sorted(cr.evidence_data["cross_project_project_ids"]) == [
        "proj-a",
        "proj-b",
    ]
    # Each per-event result should also carry the cross-project marker.
    for ev_id in ("evt-proj-1", "evt-proj-2"):
        [r] = _findings_for_event(results, ev_id)
        signals = {c.evidence_data.get("signal") for c in r.control_results}
        assert "cross_project_pattern" in signals
    # Synthetic action_id must not embed the raw email.
    assert email not in syn.action_id


# ---------------------------------------------------------------------------
# Sanitization / privacy
# ---------------------------------------------------------------------------


def test_principal_email_local_part_redacted() -> None:
    """principalEmail local part is redacted; domain is preserved."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-email",
                    principal_email="alice.smith@example.com",
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    cr = result.control_results[0]
    assert cr.evidence_data["principal_email_redacted"] == "***@example.com"
    assert cr.evidence_data["principal_domain"] == "example.com"
    assert "alice.smith" not in json.dumps(cr.evidence_data)


def test_caller_ip_redacted_to_slash16() -> None:
    """Public IPv4 callerIp is reduced to a /16 pattern."""
    doc = json.dumps(
        {"entries": [_entry(insert_id="evt-pub-ip", caller_ip="8.8.8.8")]}
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    cr = result.control_results[0]
    assert cr.evidence_data["caller_ip_redacted"] == "8.8.0.0/16"


def test_caller_ip_gcp_internal_marker() -> None:
    """``gce-internal-ip`` is normalized to ``GCP Internal``."""
    doc = json.dumps(
        {"entries": [_entry(insert_id="evt-gcp-int", caller_ip="gce-internal-ip")]}
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    cr = result.control_results[0]
    assert cr.evidence_data["caller_ip_redacted"] == "GCP Internal"


def test_caller_ip_rfc1918_intact() -> None:
    """RFC1918 callerIp preserved verbatim (already non-routable)."""
    doc = json.dumps(
        {"entries": [_entry(insert_id="evt-priv-ip", caller_ip="10.0.0.1")]}
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    cr = result.control_results[0]
    assert cr.evidence_data["caller_ip_redacted"] == "10.0.0.1"


def test_request_response_values_never_stored() -> None:
    """request / response VALUES are never captured — only top-level KEYS."""
    sensitive = "/customers/email-addresses/2026/marketing-list.csv"
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-keys-only",
                    service_name="storage.googleapis.com",
                    method_name="storage.objects.get",
                    request={
                        "bucket": "internal-bucket",
                        "object": sensitive,
                        "secretField": "SHOULD_NOT_APPEAR",
                    },
                    response={
                        "etag": "ETAG_SHOULD_NOT_APPEAR",
                        "generation": 1,
                    },
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    cr = result.control_results[0]
    serialized = json.dumps(cr.evidence_data)
    assert sensitive not in serialized
    assert "SHOULD_NOT_APPEAR" not in serialized
    assert "ETAG_SHOULD_NOT_APPEAR" not in serialized
    assert cr.evidence_data["request_keys"] == ["bucket", "object", "secretField"]
    assert cr.evidence_data["response_keys"] == ["etag", "generation"]


def test_user_agent_truncated_with_hash() -> None:
    """callerSuppliedUserAgent is reduced to first 80 chars + sha256."""
    long_ua = "ancilis-agent/" + ("X" * 200)
    doc = json.dumps(
        {"entries": [_entry(insert_id="evt-ua", caller_user_agent=long_ua)]}
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    cr = result.control_results[0]
    redacted = cr.evidence_data["caller_user_agent_redacted"]
    expected_prefix = long_ua[:80]
    expected_hash = hashlib.sha256(long_ua.encode("utf-8")).hexdigest()
    assert redacted.startswith(expected_prefix)
    assert expected_hash in redacted
    # The full UA tail is NOT retained.
    assert long_ua not in redacted


def test_resource_name_trimmed_after_locations() -> None:
    """resourceName beyond /locations/<region>/ is summarized to /...."""
    deep = (
        "projects/my-proj/locations/us-central1/buckets/secret-bucket/"
        "objects/customers/2026/leads.csv"
    )
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-trim",
                    service_name="storage.googleapis.com",
                    method_name="storage.objects.get",
                    resource_name=deep,
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    cr = result.control_results[0]
    trimmed = cr.evidence_data["resource_name_trimmed"]
    assert trimmed.startswith("projects/my-proj/locations/us-central1")
    assert trimmed.endswith("/...")
    assert "leads.csv" not in trimmed


# ---------------------------------------------------------------------------
# Format / shape parsing
# ---------------------------------------------------------------------------


def test_jsonl_stream() -> None:
    """JSONL — one entry per line — is accepted."""
    lines = [
        json.dumps(_entry(insert_id="evt-jl-1")),
        "",
        json.dumps(
            _entry(
                insert_id="evt-jl-2",
                service_name="storage.googleapis.com",
                method_name="storage.objects.get",
            )
        ),
    ]
    content = "\n".join(lines) + "\n"
    results = GcpCloudAuditImporter().parse_string(content)
    assert len(results) == 2
    assert {r.action_id for r in results} == {
        "gcp-audit-evt-jl-1",
        "gcp-audit-evt-jl-2",
    }


def test_data_envelope_shape() -> None:
    """``{"data": [...]}`` envelope is accepted alongside ``entries``."""
    doc = json.dumps({"data": [_entry(insert_id="evt-env-data")]})
    [result] = GcpCloudAuditImporter().parse_string(doc)
    assert result.action_id == "gcp-audit-evt-env-data"


def test_single_entry_shape() -> None:
    """A bare single LogEntry (no envelope) is accepted."""
    doc = json.dumps(_entry(insert_id="evt-single"))
    [result] = GcpCloudAuditImporter().parse_string(doc)
    assert result.action_id == "gcp-audit-evt-single"


def test_unknown_event_flags() -> None:
    """An unmapped service/method surfaces as PR-05 FLAG (not silent)."""
    doc = json.dumps(
        {
            "entries": [
                _entry(
                    insert_id="evt-unknown",
                    service_name="bigquery.googleapis.com",
                    method_name="jobservice.insert",
                )
            ]
        }
    )
    [result] = GcpCloudAuditImporter().parse_string(doc)
    primary = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "unknown_event"
    ]
    assert len(primary) == 1
    assert primary[0].control_id == "PR-05"
    assert primary[0].result == "FLAG"


def test_source_provenance_includes_file_hash(tmp_path: Path) -> None:
    """parse(path) hashes the file bytes and surfaces the hash in source_provenance."""
    payload = json.dumps({"entries": [_entry(insert_id="evt-prov")]}).encode("utf-8")
    expected_sha = hashlib.sha256(payload).hexdigest()
    file_path = tmp_path / "gcp-audit-export.json"
    file_path.write_bytes(payload)

    [result] = GcpCloudAuditImporter().parse(file_path)
    cr = result.control_results[0]
    provenance = cr.evidence_data["source_provenance"]
    assert provenance["source_format"] == "gcp_cloud_audit"
    assert provenance["source_tool_name"] == "gcp_cloud_audit"
    assert provenance["event_id"] == "evt-prov"
    assert provenance["original_file_sha256"] == expected_sha

    [result_str] = GcpCloudAuditImporter().parse_string(payload.decode("utf-8"))
    assert (
        "original_file_sha256"
        not in result_str.control_results[0].evidence_data["source_provenance"]
    )
