"""Tests for the AWS ECR importer (container-registry supply-chain evidence)."""

from __future__ import annotations

import json
from typing import Any

from ancilis.importers.aws_ecr import AwsEcrImporter


# ---------------------------------------------------------------------------
# Fixtures — inline ECR event records (no boto3 required)
# ---------------------------------------------------------------------------


def _event(
    *,
    event_id: str = "evt-001",
    event_name: str = "PutImage",
    event_time: str = "2026-04-01T12:00:00Z",
    aws_region: str = "us-east-1",
    request_id: str = "req-abc",
    user_identity_type: str = "IAMUser",
    arn: str | None = "arn:aws:iam::123456789012:user/ci-bot",
    account_id: str = "123456789012",
    user_name: str | None = "ci-bot",
    principal_id: str | None = "AIDAEXAMPLE12345678",
    repository_name: str | None = "agent-svc",
    image_tag: str | None = "v1.2.3",
    image_digest: str | None = "sha256:abcdef0123456789aabbccddeeff00112233445566778899aabbccddeeff0011",
    registry_id: str | None = "123456789012",
    image_scanning_configuration: dict[str, Any] | None = None,
    image_tag_mutability: str | None = None,
    lifecycle_policy_text_length: int | None = None,
    registry_policy_text_length: int | None = None,
    response_image_manifest_length: int | None = 1234,
    source_ip: str = "203.0.113.42",
    user_agent: str = "docker/24.0",
    scan_findings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    request_parameters: dict[str, Any] = {}
    if repository_name is not None:
        request_parameters["repositoryName"] = repository_name
    if image_tag is not None:
        request_parameters["imageTag"] = image_tag
    if registry_id is not None:
        request_parameters["registryId"] = registry_id
    if image_digest is not None:
        request_parameters["imageIdentifier"] = {
            "imageDigest": image_digest,
            "imageTag": image_tag if image_tag is not None else "",
        }
    if image_scanning_configuration is not None:
        request_parameters["imageScanningConfiguration"] = image_scanning_configuration
    if image_tag_mutability is not None:
        request_parameters["imageTagMutability"] = image_tag_mutability
    if lifecycle_policy_text_length is not None:
        request_parameters["lifecyclePolicyText_length"] = lifecycle_policy_text_length
    if registry_policy_text_length is not None:
        request_parameters["registryPolicyText_length"] = registry_policy_text_length

    response_elements: dict[str, Any] = {}
    if response_image_manifest_length is not None and image_digest is not None:
        response_elements["image"] = {
            "imageId": {"imageDigest": image_digest},
            "imageManifest_length": response_image_manifest_length,
            "registryId": registry_id or "",
        }

    rec: dict[str, Any] = {
        "eventID": event_id,
        "eventName": event_name,
        "eventTime": event_time,
        "awsRegion": aws_region,
        "requestID": request_id,
        "sourceIPAddress": source_ip,
        "userAgent": user_agent,
        "userIdentity": {
            "type": user_identity_type,
            "principalId": principal_id,
            "accountId": account_id,
            "userName": user_name,
            "arn": arn,
        },
        "requestParameters": request_parameters,
        "responseElements": response_elements,
    }
    if scan_findings is not None:
        rec["scan_findings"] = scan_findings
    return rec


def _scan(
    *,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    informational: int = 0,
    undefined: int = 0,
    vulnerabilities: list[dict[str, Any]] | None = None,
    image_scan_status: str = "COMPLETE",
    signature_status: str = "SIGNED",
    is_signed: bool = True,
    sbom_present: bool = True,
    image_age_days: int = 30,
) -> dict[str, Any]:
    return {
        "criticalSeverityCount": critical,
        "highSeverityCount": high,
        "mediumSeverityCount": medium,
        "lowSeverityCount": low,
        "informationalCount": informational,
        "undefinedCount": undefined,
        "vulnerabilities": vulnerabilities or [],
        "image_scan_status": image_scan_status,
        "signature_status": signature_status,
        "is_signed": is_signed,
        "sbom_present": sbom_present,
        "image_age_days": image_age_days,
    }


def _findings_for(results: list, event_id: str) -> list:
    """Return EvaluationResults whose action_id matches a given event id."""
    return [r for r in results if r.action_id == f"ecr-{event_id}"]


def _signals(result) -> set[str]:
    return {cr.evidence_data.get("signal") for cr in result.control_results}


# ---------------------------------------------------------------------------
# 1. Clean PutImage → PR-05 PASS, ALLOW
# ---------------------------------------------------------------------------


def test_putimage_clean_passes() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="evt-clean",
                    event_name="PutImage",
                    repository_name="agent-svc",
                    image_tag="v1.2.3",
                    scan_findings=_scan(
                        critical=0, high=0, medium=2, low=3, informational=10,
                        signature_status="SIGNED", is_signed=True,
                        sbom_present=True, image_age_days=10,
                    ),
                )
            ]
        }
    )
    importer = AwsEcrImporter()
    results = importer.parse_string(doc)
    findings = _findings_for(results, "evt-clean")
    assert len(findings) == 1
    r = findings[0]
    assert r.decision == "ALLOW"
    assert any(cr.control_id == "PR-05" and cr.result == "PASS" for cr in r.control_results)
    # Repository + tag are captured verbatim (non-sensitive structured names).
    ev = r.control_results[0].evidence_data
    assert ev["repository_name"] == "agent-svc"
    assert ev["image_tag"] == "v1.2.3"


# ---------------------------------------------------------------------------
# 2. Critical-vuln push → PR-03 FAIL, BLOCK
# ---------------------------------------------------------------------------


def test_putimage_critical_vuln_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="evt-crit",
                    repository_name="agent-svc",
                    image_tag="v9.9.9",
                    scan_findings=_scan(critical=2, high=0),
                )
            ]
        }
    )
    importer = AwsEcrImporter()
    findings = _findings_for(importer.parse_string(doc), "evt-crit")
    r = findings[0]
    assert r.decision == "BLOCK"
    assert "critical_vuln_push" in _signals(r)
    crit = next(cr for cr in r.control_results if cr.evidence_data.get("signal") == "critical_vuln_push")
    assert crit.control_id == "PR-03"
    assert crit.result == "FAIL"


# ---------------------------------------------------------------------------
# 3. Unsigned production push → PR-04 FAIL
# ---------------------------------------------------------------------------


def test_putimage_unsigned_prod_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="evt-unsigned-prod",
                    repository_name="prod-agent-svc",
                    image_tag="v1.0.0",
                    scan_findings=_scan(
                        signature_status="UNSIGNED", is_signed=False,
                    ),
                )
            ]
        }
    )
    importer = AwsEcrImporter()
    findings = _findings_for(importer.parse_string(doc), "evt-unsigned-prod")
    r = findings[0]
    assert r.decision == "BLOCK"
    assert "unsigned_prod_push" in _signals(r)
    unsigned = next(cr for cr in r.control_results if cr.evidence_data.get("signal") == "unsigned_prod_push")
    assert unsigned.control_id == "PR-04"
    assert unsigned.result == "FAIL"


# ---------------------------------------------------------------------------
# 4. Signature verification failure → DE-01 FAIL
# ---------------------------------------------------------------------------


def test_putimage_signature_failure_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="evt-sig-fail",
                    repository_name="prod-agent-svc",
                    scan_findings=_scan(
                        signature_status="VERIFICATION_FAILED",
                        is_signed=True,
                    ),
                )
            ]
        }
    )
    importer = AwsEcrImporter()
    findings = _findings_for(importer.parse_string(doc), "evt-sig-fail")
    r = findings[0]
    assert r.decision == "BLOCK"
    sig_fail = next(cr for cr in r.control_results if cr.evidence_data.get("signal") == "signature_verification_fail")
    assert sig_fail.control_id == "DE-01"
    assert sig_fail.result == "FAIL"


# ---------------------------------------------------------------------------
# 5. latest-tag in production → PR-05 FLAG
# ---------------------------------------------------------------------------


def test_putimage_latest_tag_prod_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="evt-latest-prod",
                    repository_name="prod-agent-svc",
                    image_tag="latest",
                    scan_findings=_scan(),
                )
            ]
        }
    )
    importer = AwsEcrImporter()
    findings = _findings_for(importer.parse_string(doc), "evt-latest-prod")
    r = findings[0]
    assert r.decision == "FLAG"
    assert "mutable_tag_in_prod" in _signals(r)
    mut = next(cr for cr in r.control_results if cr.evidence_data.get("signal") == "mutable_tag_in_prod")
    assert mut.control_id == "PR-05"
    assert mut.result == "FLAG"


# ---------------------------------------------------------------------------
# 6. PutImageTagMutability → MUTABLE in production → PR-02 FAIL
# ---------------------------------------------------------------------------


def test_tag_mutability_mutable_prod_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="evt-tagmut",
                    event_name="PutImageTagMutability",
                    repository_name="prod-agent-svc",
                    image_tag=None,
                    image_digest=None,
                    image_tag_mutability="MUTABLE",
                    response_image_manifest_length=None,
                )
            ]
        }
    )
    importer = AwsEcrImporter()
    findings = _findings_for(importer.parse_string(doc), "evt-tagmut")
    r = findings[0]
    assert r.decision == "BLOCK"
    tagmut = next(cr for cr in r.control_results if cr.evidence_data.get("signal") == "tag_mutability_to_mutable")
    assert tagmut.control_id == "PR-02"
    assert tagmut.result == "FAIL"


# ---------------------------------------------------------------------------
# 7. DeleteRepository → PR-02 FAIL
# ---------------------------------------------------------------------------


def test_deleterepository_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="evt-delrepo",
                    event_name="DeleteRepository",
                    repository_name="prod-agent-svc",
                    image_tag=None,
                    image_digest=None,
                    response_image_manifest_length=None,
                )
            ]
        }
    )
    importer = AwsEcrImporter()
    findings = _findings_for(importer.parse_string(doc), "evt-delrepo")
    r = findings[0]
    assert r.decision == "BLOCK"
    base = next(cr for cr in r.control_results if cr.evidence_data.get("signal") == "ecr_delete_repository")
    assert base.control_id == "PR-02"
    assert base.result == "FAIL"


# ---------------------------------------------------------------------------
# 8. PutImageScanningConfiguration scanOnPush=false → PR-03 FAIL
# ---------------------------------------------------------------------------


def test_scanning_config_disabled_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="evt-scan-off",
                    event_name="PutImageScanningConfiguration",
                    repository_name="agent-svc",
                    image_tag=None,
                    image_digest=None,
                    image_scanning_configuration={"scanOnPush": False},
                    response_image_manifest_length=None,
                )
            ]
        }
    )
    importer = AwsEcrImporter()
    findings = _findings_for(importer.parse_string(doc), "evt-scan-off")
    r = findings[0]
    assert r.decision == "BLOCK"
    scan_off = next(cr for cr in r.control_results if cr.evidence_data.get("signal") == "scan_on_push_disabled")
    assert scan_off.control_id == "PR-03"
    assert scan_off.result == "FAIL"


# ---------------------------------------------------------------------------
# 9. PutRegistryPolicy → flagged as registry-access-widening (FAIL).
# ---------------------------------------------------------------------------


def test_registry_policy_cross_account_flags() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="evt-regpol",
                    event_name="PutRegistryPolicy",
                    repository_name=None,
                    image_tag=None,
                    image_digest=None,
                    registry_policy_text_length=2048,
                    response_image_manifest_length=None,
                )
            ]
        }
    )
    importer = AwsEcrImporter()
    findings = _findings_for(importer.parse_string(doc), "evt-regpol")
    r = findings[0]
    # Registry-policy widening is a FAIL per the mapping (PR-04).
    assert r.decision == "BLOCK"
    widen = next(cr for cr in r.control_results if cr.evidence_data.get("signal") == "registry_policy_widening")
    assert widen.control_id == "PR-04"
    assert widen.result == "FAIL"


# ---------------------------------------------------------------------------
# 10. Root user PutImage → PR-01 FAIL (regardless of clean scan)
# ---------------------------------------------------------------------------


def test_root_user_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="evt-root",
                    event_name="PutImage",
                    user_identity_type="Root",
                    arn="arn:aws:iam::123456789012:root",
                    user_name=None,
                    repository_name="agent-svc",
                    scan_findings=_scan(),
                )
            ]
        }
    )
    importer = AwsEcrImporter()
    findings = _findings_for(importer.parse_string(doc), "evt-root")
    r = findings[0]
    assert r.decision == "BLOCK"
    root = next(cr for cr in r.control_results if cr.evidence_data.get("signal") == "root_identity")
    assert root.control_id == "PR-01"
    assert root.result == "FAIL"


# ---------------------------------------------------------------------------
# 11. Critical-package vulnerability (openssl HIGH) → PR-03 FAIL
# ---------------------------------------------------------------------------


def test_critical_package_vuln_fails() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="evt-pkgvuln",
                    repository_name="agent-svc",
                    scan_findings=_scan(
                        critical=0,
                        high=1,
                        vulnerabilities=[
                            {
                                "name": "CVE-2025-1111",
                                "severity": "HIGH",
                                "package": "openssl",
                                "fixedInVersion": "3.2.1",
                            }
                        ],
                    ),
                )
            ]
        }
    )
    importer = AwsEcrImporter()
    findings = _findings_for(importer.parse_string(doc), "evt-pkgvuln")
    r = findings[0]
    assert r.decision == "BLOCK"
    pkg = next(cr for cr in r.control_results if cr.evidence_data.get("signal") == "critical_package_vuln")
    assert pkg.control_id == "PR-03"
    assert pkg.result == "FAIL"
    # Vulnerabilities array NOT stored verbatim — only count + max severity + top CVEs.
    ev = pkg.evidence_data
    assert ev["vulnerability_count"] == 1
    assert ev["max_vulnerability_severity"] == "HIGH"
    assert ev["top_cve_ids"] == ["CVE-2025-1111"]
    assert "vulnerabilities" not in ev  # raw array not present in evidence


# ---------------------------------------------------------------------------
# 12. Vulnerability-concentration synthetic finding (>3 OPEN crits in same repo)
# ---------------------------------------------------------------------------


def test_vulnerability_concentration_synthetic() -> None:
    events = [
        _event(
            event_id=f"evt-vuln-{i}",
            repository_name="hot-spot-repo",
            image_tag=f"v{i}",
            scan_findings=_scan(critical=2),
        )
        for i in range(3)
    ]
    doc = json.dumps({"events": events})
    importer = AwsEcrImporter()
    results = importer.parse_string(doc)
    synthetics = [r for r in results if r.action_id == "ecr-vuln-concentration-hot-spot-repo"]
    assert len(synthetics) == 1
    syn = synthetics[0]
    assert syn.decision == "BLOCK"
    cr = syn.control_results[0]
    assert cr.control_id == "PR-03"
    assert cr.result == "FAIL"
    assert cr.evidence_data["repository_name"] == "hot-spot-repo"
    assert cr.evidence_data["open_critical_count"] == 6
    assert cr.evidence_data["synthetic"] is True


# ---------------------------------------------------------------------------
# 13. Cross-account pull synthetic finding
# ---------------------------------------------------------------------------


def test_cross_account_pull_synthetic() -> None:
    # Threshold of 2 to keep the test small.
    events = [
        _event(
            event_id=f"evt-pull-{i}",
            event_name="BatchGetImage",
            repository_name="agent-svc",
            image_tag=None,
            image_digest=None,
            account_id="999999999999",   # external account
            registry_id="123456789012",  # registry owner
            response_image_manifest_length=None,
        )
        for i in range(3)
    ]
    doc = json.dumps({"events": events})
    importer = AwsEcrImporter(cross_account_pull_threshold=2)
    results = importer.parse_string(doc)
    synthetics = [r for r in results if r.action_id == "ecr-cross-account-pull-999999999999"]
    assert len(synthetics) == 1
    syn = synthetics[0]
    assert syn.decision == "FLAG"
    cr = syn.control_results[0]
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["external_account_id"] == "999999999999"
    assert cr.evidence_data["pull_count"] == 3


# ---------------------------------------------------------------------------
# 14. imageManifest content NOT stored — only length is captured.
# ---------------------------------------------------------------------------


def test_image_manifest_not_stored() -> None:
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="evt-manifest",
                    repository_name="agent-svc",
                    image_tag="v1.2.3",
                    response_image_manifest_length=98765,
                    scan_findings=_scan(),
                )
            ]
        }
    )
    importer = AwsEcrImporter()
    findings = _findings_for(importer.parse_string(doc), "evt-manifest")
    r = findings[0]
    base_ev = r.control_results[0].evidence_data
    # Length captured, raw manifest content NEVER surfaced.
    assert base_ev["image_manifest_length"] == 98765
    for cr in r.control_results:
        assert "imageManifest" not in cr.evidence_data
        assert "image_manifest" not in cr.evidence_data
        # No accidental dump of large/raw fields.
        for v in cr.evidence_data.values():
            if isinstance(v, str):
                assert len(v) < 4096


# ---------------------------------------------------------------------------
# 15. sourceIPAddress redacted to /16 (privacy)
# ---------------------------------------------------------------------------


def test_ip_redacted() -> None:
    # 8.8.8.8 — true public IPv4, should reduce to /16; 10.0.0.1 — RFC1918 stays.
    doc = json.dumps(
        {
            "events": [
                _event(
                    event_id="evt-ip-public",
                    repository_name="agent-svc",
                    source_ip="8.8.8.8",
                    scan_findings=_scan(),
                ),
                _event(
                    event_id="evt-ip-priv",
                    repository_name="agent-svc",
                    source_ip="10.0.0.1",
                    scan_findings=_scan(),
                ),
            ]
        }
    )
    importer = AwsEcrImporter()
    results = importer.parse_string(doc)
    pub = _findings_for(results, "evt-ip-public")[0]
    priv = _findings_for(results, "evt-ip-priv")[0]
    assert pub.control_results[0].evidence_data["source_ip_redacted"] == "8.8.0.0/16"
    assert priv.control_results[0].evidence_data["source_ip_redacted"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# 16. JSONL ingestion shape works
# ---------------------------------------------------------------------------


def test_jsonl_shape() -> None:
    line1 = json.dumps(
        _event(event_id="evt-jl-1", repository_name="agent-svc", scan_findings=_scan())
    )
    line2 = json.dumps(
        _event(
            event_id="evt-jl-2",
            event_name="DeleteRepository",
            repository_name="prod-old",
            image_tag=None,
            image_digest=None,
            response_image_manifest_length=None,
        )
    )
    content = line1 + "\n" + line2 + "\n"
    importer = AwsEcrImporter()
    results = importer.parse_string(content)
    ids = {r.action_id for r in results}
    assert "ecr-evt-jl-1" in ids
    assert "ecr-evt-jl-2" in ids
    # Second event is DeleteRepository → BLOCK.
    delrepo = _findings_for(results, "evt-jl-2")[0]
    assert delrepo.decision == "BLOCK"
