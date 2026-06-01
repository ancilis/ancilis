"""Tests for the Kubernetes apiserver audit-event importer."""

from __future__ import annotations

import json
from typing import Any

from ancilis.importers.kubernetes import KubernetesAuditImporter


# ---------------------------------------------------------------------------
# Fixtures — inline kube-apiserver audit-event records
# ---------------------------------------------------------------------------


def _event(
    *,
    audit_id: str = "audit-001",
    level: str = "RequestResponse",
    stage: str = "ResponseComplete",
    verb: str = "get",
    request_uri: str = "/api/v1/namespaces/default/pods/agent-pod-abcd",
    user_username: str = "system:serviceaccount:default:agent-sa",
    user_uid: str | None = "11111111-2222-3333-4444-555566667777",
    user_groups: list[str] | None = None,
    impersonated_username: str | None = None,
    source_ips: list[str] | None = None,
    user_agent: str = "kubectl/v1.30.0 (darwin/arm64) kubernetes/abcdef0",
    resource: str = "pods",
    namespace: str | None = "default",
    name: str | None = "agent-pod-abcd",
    api_group: str = "",
    api_version: str = "v1",
    subresource: str | None = None,
    response_code: int = 200,
    annotations: dict[str, str] | None = None,
    request_object: dict[str, Any] | None = None,
    response_object: dict[str, Any] | None = None,
    request_received: str = "2026-04-01T12:00:00.000000Z",
    stage_timestamp: str = "2026-04-01T12:00:00.123456Z",
) -> dict[str, Any]:
    if user_groups is None:
        user_groups = ["system:serviceaccounts", "system:authenticated"]
    if source_ips is None:
        source_ips = ["10.0.0.1"]
    if annotations is None:
        annotations = {"authorization.k8s.io/decision": "allow"}
    obj_ref: dict[str, Any] = {
        "resource": resource,
        "apiGroup": api_group,
        "apiVersion": api_version,
    }
    if namespace is not None:
        obj_ref["namespace"] = namespace
    if name is not None:
        obj_ref["name"] = name
    if subresource is not None:
        obj_ref["subresource"] = subresource
    user_dict: dict[str, Any] = {
        "username": user_username,
        "groups": user_groups,
    }
    if user_uid is not None:
        user_dict["uid"] = user_uid
    ev: dict[str, Any] = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": level,
        "auditID": audit_id,
        "stage": stage,
        "requestURI": request_uri,
        "verb": verb,
        "user": user_dict,
        "sourceIPs": source_ips,
        "userAgent": user_agent,
        "objectRef": obj_ref,
        "responseStatus": {"code": response_code},
        "requestReceivedTimestamp": request_received,
        "stageTimestamp": stage_timestamp,
        "annotations": annotations,
    }
    if impersonated_username is not None:
        ev["impersonatedUser"] = {
            "username": impersonated_username,
            "groups": ["system:authenticated"],
        }
    if request_object is not None:
        ev["requestObject"] = request_object
    if response_object is not None:
        ev["responseObject"] = response_object
    return ev


def _findings_for_event(results: list, audit_id: str) -> list:
    return [r for r in results if r.action_id == f"k8s-audit-{audit_id}"]


def _all_signals(eval_result: Any) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in eval_result.control_results]


# ---------------------------------------------------------------------------
# Read access
# ---------------------------------------------------------------------------


def test_parse_pod_get_passes() -> None:
    """verb=get on resource=pods + 200 → PR-04 PASS, ALLOW."""
    doc = json.dumps({"items": [_event(audit_id="evt-pod-get", verb="get", resource="pods")]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "kubernetes_audit_import"
    assert result.action_id == "k8s-audit-evt-pod-get"
    [cr] = result.control_results
    assert cr.control_id == "PR-04"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "pod_read"
    assert cr.evidence_data["verb"] == "get"
    assert cr.evidence_data["resource"] == "pods"


def test_secret_get_flags() -> None:
    """verb=get on secrets → PR-04 FLAG (single-secret read for review)."""
    doc = json.dumps({"items": [_event(audit_id="evt-secret-get", verb="get", resource="secrets", name="db-creds")]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    assert result.decision == "FLAG"
    assert "secret_read" in _all_signals(result)
    secret_cr = next(cr for cr in result.control_results if cr.evidence_data.get("signal") == "secret_read")
    assert secret_cr.control_id == "PR-04"
    assert secret_cr.result == "FLAG"


def test_secret_list_fails_mass_enum() -> None:
    """verb=list on secrets → PR-04 FAIL (mass-secret enumeration)."""
    doc = json.dumps({"items": [_event(audit_id="evt-secret-list", verb="list", resource="secrets", name=None)]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "secret_mass_enumeration")
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Pod creation overlays
# ---------------------------------------------------------------------------


def test_privileged_pod_fails() -> None:
    """verb=create on pods + privileged=true / hostNetwork=true → PR-02 FAIL."""
    pod_obj = {
        "kind": "Pod",
        "spec": {
            "hostNetwork": True,
            "containers": [
                {
                    "name": "main",
                    "image": "gcr.io/proj/app:1.2.3",
                    "securityContext": {"privileged": True},
                }
            ],
        },
    }
    doc = json.dumps({"items": [_event(
        audit_id="evt-priv-pod",
        verb="create",
        resource="pods",
        request_object=pod_obj,
        response_code=201,
    )]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "privileged_pod")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["pod_privileged"] is True
    assert cr.evidence_data["pod_host_network"] is True
    # Extracted features only — no requestObject body.
    assert "spec" not in cr.evidence_data
    assert "requestObject" not in cr.evidence_data


def test_latest_image_tag_flags() -> None:
    """verb=create on pods + image :latest tag → PR-05 FLAG (un-pinned)."""
    pod_obj = {
        "kind": "Pod",
        "spec": {
            "containers": [{"name": "main", "image": "gcr.io/proj/app:latest"}],
        },
    }
    doc = json.dumps({"items": [_event(
        audit_id="evt-latest",
        verb="create",
        resource="pods",
        request_object=pod_obj,
        response_code=201,
    )]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "unpinned_image_tag")
    assert cr.control_id == "PR-05"
    assert cr.result == "FLAG"
    assert cr.evidence_data["image_tag"] == "latest"


def test_untrusted_registry_flags() -> None:
    """verb=create on pods + image from non-allowlisted registry → PR-04 FLAG."""
    pod_obj = {
        "kind": "Pod",
        "spec": {
            "containers": [{"name": "main", "image": "evil-registry.example.com/foo/app:1.0"}],
        },
    }
    doc = json.dumps({"items": [_event(
        audit_id="evt-untrusted",
        verb="create",
        resource="pods",
        request_object=pod_obj,
        response_code=201,
    )]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "untrusted_registry")
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["image_registry"] == "evil-registry.example.com"


# ---------------------------------------------------------------------------
# Bulk-impact and prod-namespace deletes
# ---------------------------------------------------------------------------


def test_namespace_delete_fails() -> None:
    """verb=delete on namespaces → PR-02 FAIL."""
    doc = json.dumps({"items": [_event(
        audit_id="evt-ns-delete",
        verb="delete",
        resource="namespaces",
        namespace=None,
        name="staging",
        api_version="v1",
    )]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "namespace_delete")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


def test_deployment_delete_in_prod_fails() -> None:
    """verb=delete on deployments in production namespace → PR-02 FAIL."""
    doc = json.dumps({"items": [_event(
        audit_id="evt-deploy-delete",
        verb="delete",
        resource="deployments",
        namespace="production",
        api_group="apps",
        name="api-server",
    )]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "production_workload_delete")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# exec / portforward
# ---------------------------------------------------------------------------


def test_exec_into_pod_fails() -> None:
    """subresource=exec on pods → PR-02 FAIL."""
    doc = json.dumps({"items": [_event(
        audit_id="evt-exec",
        verb="create",
        resource="pods",
        subresource="exec",
        request_uri="/api/v1/namespaces/default/pods/agent-pod-abcd/exec?command=sh",
    )]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "pod_exec")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


def test_portforward_fails() -> None:
    """verb=portforward (or subresource=portforward) → PR-02 FAIL."""
    doc = json.dumps({"items": [_event(
        audit_id="evt-pf",
        verb="create",
        resource="pods",
        subresource="portforward",
    )]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "pod_portforward")
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


def test_clusterrolebinding_create_fails() -> None:
    """verb=create on clusterrolebindings → PR-02 FAIL (RBAC grant)."""
    crb_obj = {
        "kind": "ClusterRoleBinding",
        "subjects": [{"kind": "ServiceAccount", "name": "agent-sa", "namespace": "default"}],
        "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
    }
    doc = json.dumps({"items": [_event(
        audit_id="evt-crb",
        verb="create",
        resource="clusterrolebindings",
        api_group="rbac.authorization.k8s.io",
        api_version="v1",
        namespace=None,
        name="grant-cluster-admin",
        request_object=crb_obj,
        response_code=201,
    )]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "rbac_grant")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    # rbac_subjects summary stored, raw requestObject is NOT.
    assert cr.evidence_data["rbac_subjects"] == [
        {"kind": "ServiceAccount", "name": "agent-sa", "namespace": "default"}
    ]


def test_rbac_grant_to_authenticated_group_fails() -> None:
    """RBAC binding subjects include kind=Group system:authenticated → PR-02 FAIL."""
    crb_obj = {
        "kind": "ClusterRoleBinding",
        "subjects": [{"kind": "Group", "name": "system:authenticated"}],
        "roleRef": {"kind": "ClusterRole", "name": "edit"},
    }
    doc = json.dumps({"items": [_event(
        audit_id="evt-crb-everyone",
        verb="create",
        resource="clusterrolebindings",
        api_group="rbac.authorization.k8s.io",
        namespace=None,
        request_object=crb_obj,
        response_code=201,
    )]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    signals = _all_signals(result)
    assert "rbac_grant_to_authenticated" in signals
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "rbac_grant_to_authenticated")
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"


# ---------------------------------------------------------------------------
# Identity edge cases
# ---------------------------------------------------------------------------


def test_impersonation_flags() -> None:
    """impersonatedUser non-null → PR-01 FLAG."""
    doc = json.dumps({"items": [_event(
        audit_id="evt-impers",
        verb="get",
        resource="pods",
        user_username="alice@example.com",
        impersonated_username="system:serviceaccount:kube-system:cluster-admin",
    )]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "impersonation")
    assert cr.control_id == "PR-01"
    assert cr.result == "FLAG"
    assert cr.evidence_data["impersonated_username"] == "system:serviceaccount:kube-system:cluster-admin"


def test_anonymous_request_fails() -> None:
    """user.username starts with system:anonymous → PR-01 FAIL."""
    doc = json.dumps({"items": [_event(
        audit_id="evt-anon",
        verb="get",
        resource="pods",
        user_username="system:anonymous",
    )]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "anonymous_request")
    assert cr.control_id == "PR-01"
    assert cr.result == "FAIL"


def test_403_correctly_denied_audit_pass() -> None:
    """responseStatus.code=403 + decision=forbid → PR-02 PASS (RBAC denial audit-trail)."""
    doc = json.dumps({"items": [_event(
        audit_id="evt-403",
        verb="get",
        resource="secrets",
        response_code=403,
        annotations={
            "authorization.k8s.io/decision": "forbid",
            "authorization.k8s.io/reason": "RBAC: no permission",
        },
    )]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    cr = next(c for c in result.control_results if c.evidence_data.get("signal") == "rbac_denied")
    assert cr.control_id == "PR-02"
    assert cr.result == "PASS"
    assert result.decision == "ALLOW"


# ---------------------------------------------------------------------------
# Synthetic findings
# ---------------------------------------------------------------------------


def test_cross_namespace_synthetic() -> None:
    """One user touching > N namespaces → synthetic PR-02 FLAG."""
    items = [
        _event(audit_id=f"evt-cn-{i}", verb="get", resource="pods",
               namespace=f"ns-{i}", user_username="agent@ops.example.com")
        for i in range(7)
    ]
    doc = json.dumps({"items": items})
    results = KubernetesAuditImporter(cross_namespace_threshold=5).parse_string(doc)
    # Synthetic action_id is k8s-cross-namespace-<username>.
    synth = next(r for r in results if r.action_id == "k8s-cross-namespace-agent@ops.example.com")
    assert synth.decision == "FLAG"
    [cr] = synth.control_results
    assert cr.control_id == "PR-02"
    assert cr.evidence_data["synthetic"] is True
    assert cr.evidence_data["cross_namespace_count"] == 7
    assert cr.evidence_data["cross_namespace_threshold"] == 5
    # Per-event marker also present on each event.
    per_event = [r for r in results if r.action_id.startswith("k8s-audit-evt-cn-")]
    assert all(any(c.evidence_data.get("signal") == "cross_namespace_pattern" for c in r.control_results)
               for r in per_event)


def test_delete_burst_synthetic() -> None:
    """One user with > N delete verbs → synthetic PR-02 FLAG."""
    items = [
        _event(audit_id=f"evt-del-{i}", verb="delete", resource="configmaps",
               namespace="default", user_username="cleanup-bot",
               api_version="v1", api_group="")
        for i in range(12)
    ]
    doc = json.dumps({"items": items})
    results = KubernetesAuditImporter(delete_burst_threshold=10).parse_string(doc)
    synth = next(r for r in results if r.action_id == "k8s-delete-burst-cleanup-bot")
    assert synth.decision == "FLAG"
    [cr] = synth.control_results
    assert cr.control_id == "PR-02"
    assert cr.evidence_data["synthetic"] is True
    assert cr.evidence_data["delete_count"] == 12
    assert cr.evidence_data["delete_burst_threshold"] == 10


# ---------------------------------------------------------------------------
# Sanitization — only extracted features stored from requestObject
# ---------------------------------------------------------------------------


def test_request_object_only_features_extracted() -> None:
    """requestObject body MUST NOT be stored — only privileged/host* booleans + image strings + RBAC subjects."""
    pod_obj = {
        "kind": "Pod",
        "metadata": {"annotations": {"injected-secret": "shhh-do-not-store"}},
        "spec": {
            "hostPID": True,
            "containers": [
                {
                    "name": "main",
                    "image": "gcr.io/proj/app:1.2.3",
                    "env": [{"name": "DB_PASSWORD", "value": "p@ssw0rd-do-not-store"}],
                }
            ],
        },
    }
    doc = json.dumps({"items": [_event(
        audit_id="evt-sanitize",
        verb="create",
        resource="pods",
        request_object=pod_obj,
        response_code=201,
    )]})
    [result] = KubernetesAuditImporter().parse_string(doc)
    # No control-result evidence_data should mention raw secret values.
    serialized = json.dumps([cr.evidence_data for cr in result.control_results])
    assert "shhh-do-not-store" not in serialized
    assert "p@ssw0rd-do-not-store" not in serialized
    # But the security-relevant features ARE captured.
    primary = result.control_results[0]
    assert primary.evidence_data["pod_host_pid"] is True
    assert primary.evidence_data["pod_container_images"] == ["gcr.io/proj/app:1.2.3"]
    # uid is reduced to last-8 only.
    assert primary.evidence_data["user_uid_redacted"].startswith("***")
    # userAgent is reduced.
    ua = primary.evidence_data["user_agent_redacted"]
    assert ua is not None
    assert "#" in ua  # sha256 fingerprint suffix
    # Source IPs normalized.
    assert primary.evidence_data["source_ips_redacted"] == ["10.0.0.1"]
