"""Tests for the W&B Models runs / registry / audit-log importer."""

from __future__ import annotations

import hashlib
import json

from ancilis.importers.wandb_models import WandbModelsImporter


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _run(**overrides):
    base = {
        "id": "run-abc",
        "name": "agent-eval-2026q2",
        "user_id": "u-1",
        "username": "kbauer",
        "project": {"name": "agent-rag", "entity": "ancilis"},
        "state": "finished",
        "started_at": "2026-04-01T00:00:00Z",
        "ended_at": "2026-04-01T01:00:00Z",
        "duration_ms": 3_600_000,
        "config": {"model_name": "gpt-4o", "temperature": 0.7},
        "summary_metrics": {
            "accuracy": 0.95,
            "loss": 0.05,
            "hallucination_rate": 0.02,
            "toxicity": 0.01,
            "f1": 0.93,
        },
        "artifact_count": 5,
        "tags": ["baseline"],
        "git": {
            "commit": "abc123def456ghi789",
            "branch": "main",
            "remote": "origin",
            "is_dirty": False,
        },
        "host": "host-1",
        "compute_type": "gpu",
        "compute_config": {"gpu_type": "A100", "gpu_count": 4},
        "is_sweep": False,
        "sweep_id": None,
    }
    base.update(overrides)
    return base


def _registered_model(**overrides):
    base = {
        "name": "agent-rag-prod",
        "entity": "ancilis",
        "registered_at": "2026-01-01T00:00:00Z",
        "latest_alias": "production",
        "aliases": [
            {
                "alias": "production",
                "version": "v3",
                "created_at": "2026-03-01T00:00:00Z",
                "created_by": "kbauer",
            }
        ],
        "version_count": 5,
        "ml_task_type": "text-generation",
        "is_protected": True,
    }
    base.update(overrides)
    return base


def _audit(**overrides):
    base = {
        "id": "log-1",
        "timestamp": "2026-04-01T12:00:00Z",
        "user_id": "u-1",
        "action": "run.delete",
        "target_type": "run",
        "target_id": "run-abc",
        "details": {},
    }
    base.update(overrides)
    return base


def _control_ids(result):
    return [c.control_id for c in result.control_results]


def _control_by_kind(result, kind):
    for c in result.control_results:
        if c.evidence_data.get("evidence_kind") == kind:
            return c
    return None


# ---------------------------------------------------------------------------
# Run-level tests
# ---------------------------------------------------------------------------


def test_run_finished_high_metrics_passes():
    importer = WandbModelsImporter()
    payload = json.dumps({"runs": [_run()]})
    results = importer.parse_string(payload)
    assert len(results) == 1
    res = results[0]
    # Every metric ControlResult should be PASS.
    metric_results = [
        c for c in res.control_results if c.evidence_data.get("evidence_kind") == "metric"
    ]
    assert len(metric_results) >= 3
    assert all(c.result == "PASS" for c in metric_results)
    assert res.decision == "ALLOW"
    assert res.source_type == "wandb_models_import"


def test_run_failed_fails():
    importer = WandbModelsImporter()
    run = _run(state="failed", summary_metrics={})
    results = importer.parse_string(json.dumps({"runs": [run]}))
    res = results[0]
    fail_ctrl = _control_by_kind(res, "state_failed")
    assert fail_ctrl is not None
    assert fail_ctrl.control_id == "DE-01"
    assert fail_ctrl.result == "FAIL"
    assert res.decision == "BLOCK"


def test_run_crashed_fails():
    importer = WandbModelsImporter()
    run = _run(state="crashed", summary_metrics={})
    results = importer.parse_string(json.dumps({"runs": [run]}))
    res = results[0]
    crashed_ctrl = _control_by_kind(res, "state_crashed")
    assert crashed_ctrl is not None
    assert crashed_ctrl.control_id == "DE-01"
    assert crashed_ctrl.result == "FAIL"
    assert "host issue" in crashed_ctrl.detail
    assert res.decision == "BLOCK"


def test_dirty_git_with_production_tag_flags():
    importer = WandbModelsImporter()
    run = _run(
        tags=["production", "baseline"],
        git={
            "commit": "abc123def456ghi789",
            "branch": "main",
            "remote": "origin",
            "is_dirty": True,
        },
        # Avoid bad-state FAIL by leaving state=finished.
        state="finished",
    )
    results = importer.parse_string(json.dumps({"runs": [run]}))
    res = results[0]
    dirty_ctrl = _control_by_kind(res, "dirty_git_with_production_tag")
    assert dirty_ctrl is not None
    assert dirty_ctrl.control_id == "PR-05"
    assert dirty_ctrl.result == "FLAG"


def test_missing_git_commit_fails_unreproducible():
    importer = WandbModelsImporter()
    run = _run(git={"branch": "main", "is_dirty": False})  # no commit
    results = importer.parse_string(json.dumps({"runs": [run]}))
    res = results[0]
    missing_ctrl = _control_by_kind(res, "missing_git_commit")
    assert missing_ctrl is not None
    assert missing_ctrl.control_id == "PR-05"
    assert missing_ctrl.result == "FAIL"
    assert res.decision == "BLOCK"


def test_production_run_in_bad_state_fails():
    importer = WandbModelsImporter()
    run = _run(tags=["production"], state="crashed", summary_metrics={})
    results = importer.parse_string(json.dumps({"runs": [run]}))
    res = results[0]
    bad_ctrl = _control_by_kind(res, "production_run_in_bad_state")
    assert bad_ctrl is not None
    assert bad_ctrl.control_id == "PR-05"
    assert bad_ctrl.result == "FAIL"
    # And the crashed state still fires DE-01 FAIL.
    assert _control_by_kind(res, "state_crashed") is not None
    assert res.decision == "BLOCK"


def test_high_gpu_count_flags():
    importer = WandbModelsImporter()
    run = _run(compute_config={"gpu_type": "H100", "gpu_count": 16})
    results = importer.parse_string(json.dumps({"runs": [run]}))
    res = results[0]
    gpu_ctrl = _control_by_kind(res, "high_gpu_count")
    assert gpu_ctrl is not None
    assert gpu_ctrl.control_id == "PR-04"
    assert gpu_ctrl.result == "FLAG"
    assert gpu_ctrl.evidence_data["gpu_count"] == 16
    assert gpu_ctrl.evidence_data["gpu_count_threshold"] == 8


# ---------------------------------------------------------------------------
# Registered-model tests
# ---------------------------------------------------------------------------


def test_unprotected_production_model_fails():
    importer = WandbModelsImporter()
    model = _registered_model(is_protected=False)
    results = importer.parse_string(
        json.dumps({"registered_models": [model]})
    )
    res = results[0]
    fail_ctrl = _control_by_kind(res, "unprotected_production_alias")
    assert fail_ctrl is not None
    assert fail_ctrl.control_id == "PR-02"
    assert fail_ctrl.result == "FAIL"
    assert res.decision == "BLOCK"


# ---------------------------------------------------------------------------
# Audit-log tests
# ---------------------------------------------------------------------------


def test_artifact_delete_referenced_by_prod_fails():
    importer = WandbModelsImporter()
    # Build a registered model pinning artifact-99 in production, and an audit
    # log deleting that exact artifact.
    model = _registered_model(
        name="agent-rag-prod",
        production_artifact_ids=["artifact-99"],
    )
    audit = _audit(
        id="log-art-del",
        action="artifact.delete",
        target_type="artifact",
        target_id="artifact-99",
    )
    payload = json.dumps({
        "registered_models": [model],
        "audit_logs": [audit],
    })
    results = importer.parse_string(payload)
    # First result is the model, second is the audit log.
    audit_res = next(
        r for r in results if r.source_type == "wandb_models_import"
        and r.action_id.startswith("wandb-models-audit-")
    )
    ctrl = audit_res.control_results[0]
    assert ctrl.control_id == "PR-02"
    assert ctrl.result == "FAIL"
    assert (
        ctrl.evidence_data.get("referenced_production_model")
        == "agent-rag-prod"
    )
    assert audit_res.decision == "BLOCK"


def test_auto_promote_to_protected_alias_fails():
    importer = WandbModelsImporter()
    model = _registered_model(name="agent-rag-prod", is_protected=True)
    audit = _audit(
        id="log-promote",
        action="model.alias.set",
        target_type="model",
        target_id="agent-rag-prod",
        details={"new_alias": "production", "approved_by": None},
    )
    payload = json.dumps({
        "registered_models": [model],
        "audit_logs": [audit],
    })
    results = importer.parse_string(payload)
    audit_res = next(
        r for r in results
        if r.action_id.startswith("wandb-models-audit-")
    )
    ctrl = audit_res.control_results[0]
    assert ctrl.control_id == "PR-02"
    assert ctrl.result == "FAIL"
    assert "auto-promotion" in ctrl.detail
    assert audit_res.decision == "BLOCK"


def test_report_shared_publicly_fails():
    importer = WandbModelsImporter()
    audit = _audit(
        id="log-share",
        action="report.shared_publicly",
        target_type="report",
        target_id="report-1",
        details={"sharing_visibility": "public"},
    )
    results = importer.parse_string(json.dumps({"audit_logs": [audit]}))
    res = results[0]
    ctrl = res.control_results[0]
    assert ctrl.control_id == "PR-04"
    assert ctrl.result == "FAIL"
    assert "public report" in ctrl.detail.lower()
    assert res.decision == "BLOCK"


def test_api_key_created_flags():
    importer = WandbModelsImporter()
    audit = _audit(
        id="log-key",
        action="api_key.created",
        target_type="api_key",
        target_id="key-1",
    )
    results = importer.parse_string(json.dumps({"audit_logs": [audit]}))
    res = results[0]
    ctrl = res.control_results[0]
    assert ctrl.control_id == "PR-01"
    assert ctrl.result == "FLAG"
    assert res.decision == "FLAG"


def test_team_admin_role_change_flags():
    importer = WandbModelsImporter()
    audit = _audit(
        id="log-role",
        action="team.member.role.changed",
        target_type="team",
        target_id="team-1",
        details={"new_role": "admin"},
    )
    results = importer.parse_string(json.dumps({"audit_logs": [audit]}))
    res = results[0]
    ctrl = res.control_results[0]
    assert ctrl.control_id == "PR-02"
    assert ctrl.result == "FLAG"


# ---------------------------------------------------------------------------
# Sanitization tests
# ---------------------------------------------------------------------------


def test_run_name_redacted():
    importer = WandbModelsImporter()
    run = _run(name="alice-pii-customer-experiment-2026q2")
    results = importer.parse_string(json.dumps({"runs": [run]}))
    res = results[0]
    # Pull any ControlResult — they all share the same run-level evidence_base.
    ev = res.control_results[0].evidence_data
    redacted = ev["run_name_redacted"]
    assert redacted["present"] is True
    expected_sha = hashlib.sha256(
        "alice-pii-customer-experiment-2026q2".encode("utf-8")
    ).hexdigest()
    assert redacted["sha256"] == expected_sha
    assert redacted["length"] == len("alice-pii-customer-experiment-2026q2")
    # The raw run name must not appear anywhere in the evidence payload.
    payload_str = json.dumps(ev, default=str)
    assert "alice-pii-customer-experiment-2026q2" not in payload_str


def test_config_values_redacted():
    importer = WandbModelsImporter()
    secret_value = "sk-super-secret-api-key-2026"
    run = _run(
        config={
            "model_name": "gpt-4o",
            "api_key": secret_value,
            "temperature": 0.7,
        }
    )
    results = importer.parse_string(json.dumps({"runs": [run]}))
    res = results[0]
    ev = res.control_results[0].evidence_data
    summary = ev["config_summary"]
    assert summary["present"] is True
    # Key names are kept (they're schema, not secrets).
    assert "api_key" in summary["keys"]
    assert "model_name" in summary["keys"]
    # But the secret value must be hashed, not stored.
    payload_str = json.dumps(ev, default=str)
    assert secret_value not in payload_str
    # And the sha256 must match for the api_key entry.
    expected = hashlib.sha256(
        json.dumps(secret_value, default=str, sort_keys=True).encode("utf-8")
    ).hexdigest()
    assert summary["value_sha256_by_key"]["api_key"] == expected


# ---------------------------------------------------------------------------
# Auxiliary tests (envelope + JSONL handling — not required but kept lean)
# ---------------------------------------------------------------------------


def test_jsonl_dispatch_by_shape():
    importer = WandbModelsImporter()
    lines = [
        json.dumps(_run()),
        json.dumps(_registered_model()),
        json.dumps(_audit()),
    ]
    results = importer.parse_string("\n".join(lines))
    kinds = sorted(
        r.control_results[0].evidence_data["source_provenance"]["record_kind"]
        for r in results
    )
    assert kinds == ["audit_log", "registered_model", "run"]


def test_data_envelope_dispatch():
    importer = WandbModelsImporter()
    payload = json.dumps({"data": [_run(), _registered_model(), _audit()]})
    results = importer.parse_string(payload)
    assert len(results) == 3


def test_sweep_run_passes():
    importer = WandbModelsImporter()
    run = _run(is_sweep=True, sweep_id="sweep-77")
    results = importer.parse_string(json.dumps({"runs": [run]}))
    res = results[0]
    sweep_ctrl = _control_by_kind(res, "sweep_run")
    assert sweep_ctrl is not None
    assert sweep_ctrl.control_id == "PR-05"
    assert sweep_ctrl.result == "PASS"


def test_bot_run_without_automated_tag_flags():
    importer = WandbModelsImporter()
    run = _run(username="ci-runner-bot", tags=["baseline"])
    results = importer.parse_string(json.dumps({"runs": [run]}))
    res = results[0]
    bot_ctrl = _control_by_kind(res, "bot_run_without_automated_tag")
    assert bot_ctrl is not None
    assert bot_ctrl.control_id == "PR-05"
    assert bot_ctrl.result == "FLAG"


def test_model_version_count_sprawl_flags():
    importer = WandbModelsImporter()
    model = _registered_model(version_count=75)
    results = importer.parse_string(json.dumps({"registered_models": [model]}))
    res = results[0]
    sprawl = _control_by_kind(res, "version_count_sprawl")
    assert sprawl is not None
    assert sprawl.control_id == "PR-04"
    assert sprawl.result == "FLAG"


def test_control_ids_helper_smoke():
    """Sanity check that all 6 AKSI control IDs can be produced across kinds."""
    importer = WandbModelsImporter()
    payload = {
        "runs": [
            _run(state="failed", summary_metrics={}),  # DE-01 FAIL
            _run(  # PR-04 FLAG (gpu) + PR-03 metrics PASS
                id="run-2",
                compute_config={"gpu_type": "H100", "gpu_count": 32},
            ),
        ],
        "registered_models": [_registered_model(is_protected=False)],  # PR-02 FAIL
        "audit_logs": [
            _audit(action="api_key.created"),  # PR-01 FLAG
            _audit(  # PR-05 PASS
                action="model.alias.set",
                target_id="agent-rag-prod",
                details={"new_alias": "production", "approved_by": "lead-eng"},
            ),
        ],
    }
    results = importer.parse_string(json.dumps(payload))
    all_ids: set[str] = set()
    for r in results:
        all_ids.update(_control_ids(r))
    # Every Ancilis control family should appear at least once.
    assert {"PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"} <= all_ids
