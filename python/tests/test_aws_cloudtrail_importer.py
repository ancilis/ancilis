"""Tests for the AWS CloudTrail audit-event importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ancilis.importers.aws_cloudtrail import AwsCloudTrailImporter


# ---------------------------------------------------------------------------
# Fixtures — inline CloudTrail event records (no boto3 required)
# ---------------------------------------------------------------------------


def _record(
    *,
    event_id: str = "evt-001",
    event_source: str = "bedrock.amazonaws.com",
    event_name: str = "InvokeModel",
    event_time: str = "2026-04-01T12:00:00Z",
    aws_region: str = "us-east-1",
    request_id: str = "req-abc",
    event_type: str = "AwsApiCall",
    read_only: bool = True,
    error_code: str | None = None,
    error_message: str | None = None,
    user_identity_type: str = "IAMUser",
    principal_id: str = "AIDAEXAMPLE12345678",
    access_key_id: str = "AKIAEXAMPLE12345678",
    user_name: str | None = "agent-svc",
    account_id: str = "123456789012",
    arn: str | None = "arn:aws:iam::123456789012:user/agent-svc",
    mfa_authenticated: str | None = "true",
    source_ip: str = "203.0.113.42",
    request_parameters: dict[str, Any] | None = None,
    response_elements: dict[str, Any] | None = None,
    resources: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if request_parameters is None:
        request_parameters = {"modelId": "claude-3", "messages": "<redacted-body>"}
    if response_elements is None:
        response_elements = {"completion": "<redacted-output>"}
    if resources is None:
        resources = []
    session_attrs: dict[str, Any] = {}
    if mfa_authenticated is not None:
        session_attrs["mfaAuthenticated"] = mfa_authenticated
    rec: dict[str, Any] = {
        "eventVersion": "1.10",
        "eventID": event_id,
        "eventSource": event_source,
        "eventName": event_name,
        "eventTime": event_time,
        "awsRegion": aws_region,
        "requestID": request_id,
        "eventType": event_type,
        "readOnly": read_only,
        "sourceIPAddress": source_ip,
        "userAgent": "aws-cli/2.0",
        "userIdentity": {
            "type": user_identity_type,
            "principalId": principal_id,
            "accessKeyId": access_key_id,
            "accountId": account_id,
            "userName": user_name,
            "arn": arn,
            "sessionContext": {"attributes": session_attrs} if session_attrs else {},
        },
        "requestParameters": request_parameters,
        "responseElements": response_elements,
        "resources": resources,
    }
    if error_code is not None:
        rec["errorCode"] = error_code
    if error_message is not None:
        rec["errorMessage"] = error_message
    return rec


def _findings_for_event(results: list, event_id: str) -> list:
    """Return the EvaluationResults whose action_id matches a given event id."""
    return [r for r in results if r.action_id == f"cloudtrail-{event_id}"]


# ---------------------------------------------------------------------------
# Compute / Identity
# ---------------------------------------------------------------------------


def test_parse_bedrock_invoke_model() -> None:
    """bedrock.amazonaws.com:InvokeModel → PR-01 PASS, ALLOW."""
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-bedrock",
                    event_source="bedrock.amazonaws.com",
                    event_name="InvokeModel",
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "aws_cloudtrail_import"
    assert result.action_id == "cloudtrail-evt-bedrock"
    [cr] = result.control_results
    assert cr.control_id == "PR-01"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "bedrock_invoke_model"
    assert cr.evidence_data["event_source"] == "bedrock.amazonaws.com"
    assert cr.evidence_data["event_name"] == "InvokeModel"


def test_parse_lambda_invoke() -> None:
    """lambda.amazonaws.com:Invoke → PR-02 PASS."""
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-lambda",
                    event_source="lambda.amazonaws.com",
                    event_name="Invoke",
                    request_parameters={"functionName": "agent-runner"},
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    [cr] = result.control_results
    assert cr.control_id == "PR-02"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "lambda_invoke"


def test_parse_s3_get_object_passes() -> None:
    """s3.amazonaws.com:GetObject → PR-04 PASS."""
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-s3-get",
                    event_source="s3.amazonaws.com",
                    event_name="GetObject",
                    request_parameters={
                        "bucketName": "secret-bucket",
                        "key": "secret/customer/file.csv",
                    },
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    [cr] = result.control_results
    assert cr.control_id == "PR-04"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "s3_read"


def test_parse_s3_put_object_flags() -> None:
    """s3.amazonaws.com:PutObject → PR-04 FLAG (data write surface)."""
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-s3-put",
                    event_source="s3.amazonaws.com",
                    event_name="PutObject",
                    read_only=False,
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    assert result.decision == "FLAG"
    [cr] = result.control_results
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "s3_write"


def test_iam_attach_policy_flags_privilege() -> None:
    """iam.amazonaws.com:AttachUserPolicy → PR-02 FLAG."""
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-iam-attach",
                    event_source="iam.amazonaws.com",
                    event_name="AttachUserPolicy",
                    read_only=False,
                    request_parameters={
                        "userName": "agent-svc",
                        "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    },
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    assert result.decision == "FLAG"
    flags = [cr for cr in result.control_results if cr.evidence_data.get("signal") == "iam_privilege_change"]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-02"
    assert flags[0].result == "FLAG"


def test_create_access_key_flags_credential() -> None:
    """iam.amazonaws.com:CreateAccessKey → PR-01 FLAG (credential lifecycle)."""
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-create-key",
                    event_source="iam.amazonaws.com",
                    event_name="CreateAccessKey",
                    read_only=False,
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    assert result.decision == "FLAG"
    primary = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "iam_credential_lifecycle"
    ]
    assert len(primary) == 1
    assert primary[0].control_id == "PR-01"
    assert primary[0].result == "FLAG"


def test_kms_decrypt_passes() -> None:
    """kms.amazonaws.com:Decrypt → PR-04 PASS (sensitive data access)."""
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-kms",
                    event_source="kms.amazonaws.com",
                    event_name="Decrypt",
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    primary = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "kms_decrypt"
    ]
    assert len(primary) == 1
    assert primary[0].control_id == "PR-04"
    assert primary[0].result == "PASS"


def test_secrets_manager_get_value_flags() -> None:
    """secretsmanager.amazonaws.com:GetSecretValue → PR-04 FLAG."""
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-secret",
                    event_source="secretsmanager.amazonaws.com",
                    event_name="GetSecretValue",
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    assert result.decision == "FLAG"
    primary = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "secrets_get_value"
    ]
    assert len(primary) == 1
    assert primary[0].control_id == "PR-04"
    assert primary[0].result == "FLAG"


def test_root_identity_fails() -> None:
    """userIdentity.type=Root → PR-01 FAIL, BLOCK decision.

    Root usage is a critical compliance violation in most AWS environments
    (PCI-DSS, SOC 2, AWS Well-Architected). It must always FAIL regardless of
    the API being called.
    """
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-root",
                    user_identity_type="Root",
                    event_source="s3.amazonaws.com",
                    event_name="GetObject",
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    root_results = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "root_identity"
    ]
    assert len(root_results) == 1
    assert root_results[0].control_id == "PR-01"
    assert root_results[0].result == "FAIL"


def test_no_mfa_on_privileged_op_flags() -> None:
    """MFA=false on iam/kms/secretsmanager → PR-01 FLAG, additive."""
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-no-mfa",
                    event_source="iam.amazonaws.com",
                    event_name="UpdateAccessKey",
                    mfa_authenticated="false",
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    mfa_flags = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "no_mfa_on_privileged"
    ]
    assert len(mfa_flags) == 1
    assert mfa_flags[0].control_id == "PR-01"
    assert mfa_flags[0].result == "FLAG"
    # Decision is at least FLAG (no FAILs in this record).
    assert result.decision == "FLAG"


def test_no_mfa_on_non_privileged_does_not_flag() -> None:
    """MFA=false on a non-privileged service does NOT trigger no_mfa flag."""
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-bedrock-no-mfa",
                    event_source="bedrock.amazonaws.com",
                    event_name="InvokeModel",
                    mfa_authenticated="false",
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    signals = {cr.evidence_data.get("signal") for cr in result.control_results}
    assert "no_mfa_on_privileged" not in signals


def test_access_denied_marks_fail() -> None:
    """errorCode=AccessDenied → PR-02 FAIL, BLOCK."""
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-denied",
                    event_source="s3.amazonaws.com",
                    event_name="GetObject",
                    error_code="AccessDenied",
                    error_message="User is not authorized",
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    [cr] = result.control_results
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "access_denied"
    assert cr.evidence_data["error_code"] == "AccessDenied"


def test_throttling_flags() -> None:
    """errorCode=ThrottlingException → PR-02 FLAG."""
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-throttle",
                    event_source="bedrock.amazonaws.com",
                    event_name="InvokeModel",
                    error_code="ThrottlingException",
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    [cr] = result.control_results
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "throttling"


def test_internal_service_error_marks_de01_fail() -> None:
    """errorCode=InternalServerError → DE-01 FAIL via prefix match."""
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-internal",
                    event_source="lambda.amazonaws.com",
                    event_name="Invoke",
                    error_code="InternalServerError",
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    [cr] = result.control_results
    assert cr.control_id == "DE-01"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "internal_service_error"


def test_console_action_flags_audit() -> None:
    """eventType=AwsConsoleAction → PR-05 FLAG (interactive console)."""
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-console",
                    event_source="signin.amazonaws.com",
                    event_name="ConsoleLogin",
                    event_type="AwsConsoleAction",
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    console_flags = [
        cr for cr in result.control_results
        if cr.evidence_data.get("signal") == "console_action"
    ]
    assert len(console_flags) == 1
    assert console_flags[0].control_id == "PR-05"
    assert console_flags[0].result == "FLAG"


def test_cross_account_pattern_synthetic_finding() -> None:
    """Single principalId touching 2+ accountIds → synthetic PR-02 FLAG."""
    pid = "AIDACROSSACCT123456"
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-acct-1",
                    principal_id=pid,
                    account_id="111111111111",
                ),
                _record(
                    event_id="evt-acct-2",
                    principal_id=pid,
                    account_id="222222222222",
                ),
            ]
        }
    )
    results = AwsCloudTrailImporter().parse_string(doc)
    # 2 per-event results + 1 synthetic.
    assert len(results) == 3
    synthetic = [r for r in results if r.action_id.startswith("cloudtrail-cross-account-")]
    assert len(synthetic) == 1
    syn = synthetic[0]
    assert syn.decision == "FLAG"
    [cr] = syn.control_results
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "cross_account_pattern"
    assert sorted(cr.evidence_data["cross_account_account_ids"]) == [
        "111111111111",
        "222222222222",
    ]
    # Each per-event result should also carry the cross-account marker.
    for ev_id in ("evt-acct-1", "evt-acct-2"):
        [r] = _findings_for_event(results, ev_id)
        signals = {c.evidence_data.get("signal") for c in r.control_results}
        assert "cross_account_pattern" in signals


def test_request_parameter_values_never_stored() -> None:
    """requestParameters / responseElements VALUES are never captured.

    Only the top-level KEY LIST is stored. This is security-critical because
    CloudTrail can contain S3 object keys with sensitive paths, secret ARNs,
    etc., in the request parameter values.
    """
    sensitive_value = "/customers/email-addresses/2026/marketing-list.csv"
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-secret-keys",
                    event_source="s3.amazonaws.com",
                    event_name="GetObject",
                    request_parameters={
                        "bucketName": "internal-bucket",
                        "key": sensitive_value,
                        "secretField": "SHOULD_NOT_APPEAR",
                    },
                    response_elements={
                        "x-amz-version-id": "v1",
                        "etag": "ETAG_SHOULD_NOT_APPEAR",
                    },
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    [cr] = result.control_results
    serialized = json.dumps(cr.evidence_data)
    assert sensitive_value not in serialized
    assert "SHOULD_NOT_APPEAR" not in serialized
    assert "ETAG_SHOULD_NOT_APPEAR" not in serialized
    # Keys are present (sorted).
    assert cr.evidence_data["request_parameter_keys"] == ["bucketName", "key", "secretField"]
    assert cr.evidence_data["response_element_keys"] == ["etag", "x-amz-version-id"]


def test_access_key_id_redacted() -> None:
    """userIdentity.accessKeyId is redacted to last-4 only."""
    aki = "AKIATESTREDACT9999"
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-aki",
                    access_key_id=aki,
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    [cr] = result.control_results
    redacted = cr.evidence_data["access_key_id_redacted"]
    assert redacted == "***9999"
    # Full AKI should not appear anywhere in the serialized evidence.
    assert aki not in json.dumps(cr.evidence_data)


def test_principal_id_redacted() -> None:
    """principalId is redacted to <prefix>...<last-4>."""
    pid = "AIDAVERYLONGPRINCIPALID12345"
    doc = json.dumps({"Records": [_record(event_id="evt-pid", principal_id=pid)]})
    [result] = AwsCloudTrailImporter().parse_string(doc)
    [cr] = result.control_results
    redacted = cr.evidence_data["principal_id_redacted"]
    assert redacted == "AIDA...2345"
    assert pid not in json.dumps(cr.evidence_data)


def test_source_ip_redaction_public_v4() -> None:
    """Public IPv4 source addresses are reduced to a /16 pattern.

    Note: TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
    are classified as private by stdlib ``ipaddress`` and would be preserved
    intact. We use 8.8.8.8 (a globally routable address) for this test.
    """
    doc = json.dumps(
        {"Records": [_record(event_id="evt-pub-ip", source_ip="8.8.8.8")]}
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    [cr] = result.control_results
    assert cr.evidence_data["source_ip_redacted"] == "8.8.0.0/16"


def test_source_ip_redaction_aws_internal() -> None:
    """``AWS Internal`` is preserved verbatim."""
    doc = json.dumps(
        {"Records": [_record(event_id="evt-aws-int", source_ip="AWS Internal")]}
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    [cr] = result.control_results
    assert cr.evidence_data["source_ip_redacted"] == "AWS Internal"


def test_source_ip_redaction_private_v4_intact() -> None:
    """RFC1918 addresses are preserved verbatim (already non-routable)."""
    doc = json.dumps(
        {"Records": [_record(event_id="evt-priv-ip", source_ip="10.0.0.1")]}
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    [cr] = result.control_results
    assert cr.evidence_data["source_ip_redacted"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# Format / shape parsing
# ---------------------------------------------------------------------------


def test_jsonl_stream() -> None:
    """JSONL — one record per line — is accepted."""
    lines = [
        json.dumps(_record(event_id="evt-jl-1")),
        "",
        json.dumps(
            _record(
                event_id="evt-jl-2",
                event_source="s3.amazonaws.com",
                event_name="GetObject",
            )
        ),
    ]
    content = "\n".join(lines) + "\n"
    results = AwsCloudTrailImporter().parse_string(content)
    assert len(results) == 2
    assert {r.action_id for r in results} == {
        "cloudtrail-evt-jl-1",
        "cloudtrail-evt-jl-2",
    }


def test_data_envelope_shape() -> None:
    """``{"data": [...]}`` envelope is accepted alongside ``Records``."""
    doc = json.dumps({"data": [_record(event_id="evt-env-data")]})
    [result] = AwsCloudTrailImporter().parse_string(doc)
    assert result.action_id == "cloudtrail-evt-env-data"


def test_single_record_shape() -> None:
    """A bare single record (no envelope) is accepted."""
    doc = json.dumps(_record(event_id="evt-single"))
    [result] = AwsCloudTrailImporter().parse_string(doc)
    assert result.action_id == "cloudtrail-evt-single"


def test_unknown_event_flags() -> None:
    """An unmapped event source/name surfaces as PR-05 FLAG (not silent)."""
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-unknown",
                    event_source="rds.amazonaws.com",
                    event_name="DescribeDBInstances",
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    [cr] = result.control_results
    assert cr.control_id == "PR-05"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "unknown_event"


def test_source_provenance_includes_file_hash(tmp_path: Path) -> None:
    """parse(path) hashes the file bytes and surfaces the hash in source_provenance."""
    payload = json.dumps({"Records": [_record(event_id="evt-prov")]}).encode("utf-8")
    expected_sha = hashlib.sha256(payload).hexdigest()
    file_path = tmp_path / "cloudtrail-export.json"
    file_path.write_bytes(payload)

    [result] = AwsCloudTrailImporter().parse(file_path)
    cr = result.control_results[0]
    provenance = cr.evidence_data["source_provenance"]
    assert provenance["source_format"] == "aws_cloudtrail"
    assert provenance["source_tool_name"] == "aws_cloudtrail"
    assert provenance["event_id"] == "evt-prov"
    assert provenance["original_file_sha256"] == expected_sha

    # parse_string omits original_file_sha256 — there is no on-disk file.
    [result_str] = AwsCloudTrailImporter().parse_string(payload.decode("utf-8"))
    assert (
        "original_file_sha256"
        not in result_str.control_results[0].evidence_data["source_provenance"]
    )


def test_sts_assume_role_captures_role_arn() -> None:
    """sts.amazonaws.com:AssumeRole → PR-01 PASS, role ARN captured."""
    role_arn = "arn:aws:iam::123456789012:role/agent-role"
    doc = json.dumps(
        {
            "Records": [
                _record(
                    event_id="evt-sts",
                    event_source="sts.amazonaws.com",
                    event_name="AssumeRole",
                    resources=[
                        {"accountId": "123456789012", "type": "AWS::IAM::Role", "ARN": role_arn},
                    ],
                )
            ]
        }
    )
    [result] = AwsCloudTrailImporter().parse_string(doc)
    [cr] = result.control_results
    assert cr.control_id == "PR-01"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "sts_assume_role"
    assert role_arn in cr.evidence_data["assumed_role_arns"]
    assert role_arn in cr.evidence_data["resource_arns"]
