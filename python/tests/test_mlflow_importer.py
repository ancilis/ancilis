"""Tests for the MLflow runs / registry / audit-log importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ancilis.importers import MLflowImporter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _run(
    *,
    run_id: str = "run-001",
    experiment_id: str = "exp-1",
    user_id: str = "alice",
    status: str = "FINISHED",
    lifecycle_stage: str = "active",
    start_time: int = 1730000000000,
    end_time: int = 1730000300000,
    artifact_uri: str = "s3://bucket/path/runs/abc/artifacts",
    run_name: str = "agent-eval-2026q2",
    metrics: list[dict] | None = None,
    params: list[dict] | None = None,
    tags: list[dict] | None = None,
    inputs: list[dict] | None = None,
    outputs: dict | None = None,
) -> dict:
    return {
        "info": {
            "run_id": run_id,
            "experiment_id": experiment_id,
            "user_id": user_id,
            "status": status,
            "start_time": start_time,
            "end_time": end_time,
            "artifact_uri": artifact_uri,
            "lifecycle_stage": lifecycle_stage,
            "run_name": run_name,
        },
        "data": {
            "metrics": metrics
            if metrics is not None
            else [
                {"key": "accuracy", "value": 0.95, "step": 0},
                {"key": "f1", "value": 0.91, "step": 0},
                {"key": "hallucination_rate", "value": 0.02, "step": 0},
                {"key": "toxicity_score", "value": 0.01, "step": 0},
            ],
            "params": params
            if params is not None
            else [
                {"key": "model_name", "value": "gpt-4o"},
                {"key": "temperature", "value": "0.7"},
                {"key": "prompt_template_id", "value": "v3"},
            ],
            "tags": tags
            if tags is not None
            else [
                {"key": "mlflow.source.type", "value": "JOB"},
                {"key": "mlflow.source.git.commit", "value": "abc123"},
                {"key": "mlflow.runName", "value": "agent-eval-2026q2"},
                {"key": "team", "value": "agent-team"},
            ],
        },
        "inputs": inputs
        if inputs is not None
        else [
            {
                "dataset": {
                    "name": "train_v2",
                    "digest": "sha256:1234567890abcdef",
                    "source_type": "s3",
                },
                "tags": [{"key": "context", "value": "training"}],
            }
        ],
        "outputs": outputs
        if outputs is not None
        else {
            "model_uri": "models:/agent-rag/3",
            "model_version": "3",
            "registered_model_name": "agent-rag",
        },
    }


def _audit(
    *,
    log_id: str = "log-1",
    timestamp: str = "2026-04-01T12:00:00Z",
    user_id: str = "ops-svc",
    action: str = "run.delete",
    target_type: str = "run",
    target_id: str = "run-xyz",
    details: dict | None = None,
) -> dict:
    return {
        "id": log_id,
        "timestamp": timestamp,
        "user_id": user_id,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "details": details or {},
    }


def _registered_model(
    *,
    name: str = "agent-rag",
    creation_timestamp: int = 1730000000000,
    latest_versions: list[dict] | None = None,
) -> dict:
    return {
        "name": name,
        "creation_timestamp": creation_timestamp,
        "latest_versions": latest_versions
        if latest_versions is not None
        else [
            {
                "name": name,
                "version": "3",
                "current_stage": "Production",
                "run_id": "run-001",
                "status": "READY",
                "status_message": "",
            }
        ],
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_parse_run_finished_high_metrics_passes():
    """A FINISHED run with strong metrics produces PASS evidence on PR-03 / DE-01."""
    payload = {"runs": [_run()]}
    importer = MLflowImporter()
    results = importer.parse_string(json.dumps(payload))

    assert len(results) == 1
    res = results[0]
    assert res.source_type == "mlflow_import"
    assert res.action_id.startswith("mlflow-run-run-001")
    # All four metric controls should fire as PASS.
    metric_results = [
        cr for cr in res.control_results if cr.evidence_data.get("evidence_kind") == "metric"
    ]
    assert len(metric_results) == 4
    assert all(cr.result == "PASS" for cr in metric_results)
    # Decision is ALLOW since worst is PASS (no reproducibility flags fired).
    assert res.decision == "ALLOW"


def test_parse_run_finished_low_metrics_fails():
    """A FINISHED run with poor metrics produces FAIL evidence."""
    bad = _run(
        metrics=[
            {"key": "accuracy", "value": 0.5, "step": 0},
            {"key": "hallucination_rate", "value": 0.45, "step": 0},
            {"key": "toxicity_score", "value": 0.4, "step": 0},
        ],
    )
    importer = MLflowImporter()
    results = importer.parse_string(json.dumps({"runs": [bad]}))
    res = results[0]
    metric_results = [
        cr for cr in res.control_results if cr.evidence_data.get("evidence_kind") == "metric"
    ]
    assert {cr.result for cr in metric_results} == {"FAIL"}
    assert res.decision == "BLOCK"


def test_run_failed_marks_de01_fail():
    """info.status=FAILED produces DE-01 FAIL with run-id captured."""
    payload = {"runs": [_run(status="FAILED")]}
    importer = MLflowImporter()
    res = importer.parse_string(json.dumps(payload))[0]
    fail = [
        cr
        for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "status_failed"
    ]
    assert len(fail) == 1
    assert fail[0].control_id == "DE-01"
    assert fail[0].result == "FAIL"
    assert "run-001" in fail[0].detail
    assert res.decision == "BLOCK"


def test_run_killed_flags():
    """info.status=KILLED → PR-05 FLAG (manual termination)."""
    payload = {"runs": [_run(status="KILLED")]}
    importer = MLflowImporter()
    res = importer.parse_string(json.dumps(payload))[0]
    killed = [
        cr
        for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "status_killed"
    ]
    assert len(killed) == 1
    assert killed[0].control_id == "PR-05"
    assert killed[0].result == "FLAG"


def test_run_no_git_commit_flags_unreproducible():
    """A run missing mlflow.source.git.commit → PR-05 FLAG."""
    no_commit_tags = [
        {"key": "mlflow.source.type", "value": "JOB"},
        {"key": "team", "value": "agent-team"},
    ]
    payload = {"runs": [_run(tags=no_commit_tags)]}
    importer = MLflowImporter()
    res = importer.parse_string(json.dumps(payload))[0]
    flags = [
        cr
        for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "missing_git_commit"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-05"
    assert flags[0].result == "FLAG"


def test_run_no_dataset_digest_flags():
    """A run with input dataset missing digest → PR-05 FLAG."""
    bad_inputs = [
        {
            "dataset": {"name": "train_v2", "source_type": "s3"},
            "tags": [{"key": "context", "value": "training"}],
        }
    ]
    payload = {"runs": [_run(inputs=bad_inputs)]}
    importer = MLflowImporter()
    res = importer.parse_string(json.dumps(payload))[0]
    flags = [
        cr
        for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "missing_dataset_digest"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-05"
    assert flags[0].result == "FLAG"


def test_deploy_to_production_tag_flags():
    """tags deploy_to_production=true on FINISHED run → PR-05 FLAG."""
    tags = [
        {"key": "mlflow.source.type", "value": "JOB"},
        {"key": "mlflow.source.git.commit", "value": "abc123"},
        {"key": "deploy_to_production", "value": "true"},
    ]
    payload = {"runs": [_run(tags=tags)]}
    importer = MLflowImporter()
    res = importer.parse_string(json.dumps(payload))[0]
    flags = [
        cr
        for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "deploy_to_production"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-05"
    assert flags[0].result == "FLAG"


def test_run_local_source_by_bot_flags():
    """user_id matches bot pattern + source.type=LOCAL → PR-05 FLAG."""
    tags = [
        {"key": "mlflow.source.type", "value": "LOCAL"},
        {"key": "mlflow.source.git.commit", "value": "abc123"},
    ]
    payload = {"runs": [_run(user_id="agent-svc", tags=tags)]}
    importer = MLflowImporter()
    res = importer.parse_string(json.dumps(payload))[0]
    flags = [
        cr
        for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "bot_local_source"
    ]
    assert len(flags) == 1
    assert flags[0].control_id == "PR-05"
    assert flags[0].result == "FLAG"
    assert flags[0].evidence_data["bot_user_id"] == "agent-svc"


def test_audit_experiment_delete_fails():
    """action=experiment.delete → PR-02 FAIL (audit destruction)."""
    payload = {
        "audit_logs": [
            _audit(
                action="experiment.delete",
                target_type="experiment",
                target_id="exp-old",
            )
        ]
    }
    importer = MLflowImporter()
    res = importer.parse_string(json.dumps(payload))[0]
    assert len(res.control_results) == 1
    cr = res.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert "audit destruction" in cr.detail
    assert res.decision == "BLOCK"


def test_audit_promote_to_prod_no_approval_fails():
    """transition_stage to Production with approved_by=null → PR-02 FAIL."""
    payload = {
        "audit_logs": [
            _audit(
                action="model_version.transition_stage",
                target_type="model_version",
                target_id="agent-rag/3",
                details={
                    "new_stage": "Production",
                    "previous_stage": "Staging",
                    "approved_by": None,
                },
            )
        ]
    }
    importer = MLflowImporter()
    res = importer.parse_string(json.dumps(payload))[0]
    cr = res.control_results[0]
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert "auto-promotion" in cr.detail
    assert res.decision == "BLOCK"


def test_audit_promote_to_prod_with_approval_passes():
    """transition_stage to Production with approved_by set → PR-05 PASS."""
    payload = {
        "audit_logs": [
            _audit(
                action="model_version.transition_stage",
                target_type="model_version",
                target_id="agent-rag/3",
                details={
                    "new_stage": "Production",
                    "previous_stage": "Staging",
                    "approved_by": "kevin@ancilis.io",
                },
            )
        ]
    }
    importer = MLflowImporter()
    res = importer.parse_string(json.dumps(payload))[0]
    cr = res.control_results[0]
    assert cr.control_id == "PR-05"
    assert cr.result == "PASS"
    assert "kevin@ancilis.io" in cr.detail
    assert res.decision == "ALLOW"


def test_registered_model_multiple_production_versions_fails():
    """Multiple Production versions for one registered model → PR-05 FAIL."""
    model = _registered_model(
        latest_versions=[
            {
                "name": "agent-rag",
                "version": "3",
                "current_stage": "Production",
                "run_id": "run-1",
                "status": "READY",
                "status_message": "",
            },
            {
                "name": "agent-rag",
                "version": "5",
                "current_stage": "Production",
                "run_id": "run-2",
                "status": "READY",
                "status_message": "",
            },
        ]
    )
    payload = {"registered_models": [model]}
    importer = MLflowImporter()
    res = importer.parse_string(json.dumps(payload))[0]
    fails = [
        cr
        for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "multiple_production_versions"
    ]
    assert len(fails) == 1
    assert fails[0].control_id == "PR-05"
    assert fails[0].result == "FAIL"
    assert res.decision == "BLOCK"


def test_artifact_uri_truncated():
    """artifact_uri host + first 2 path components only — never full path."""
    full_uri = "s3://my-bucket/team-alice/users/secret-id/runs/abc/artifacts/model.pkl"
    payload = {"runs": [_run(artifact_uri=full_uri)]}
    importer = MLflowImporter()
    res = importer.parse_string(json.dumps(payload))[0]
    truncated = res.control_results[0].evidence_data["source_provenance"][
        "artifact_uri_truncated"
    ]
    assert truncated is not None
    assert "secret-id" not in truncated
    assert "model.pkl" not in truncated
    # Should keep host + 2 path segments, plus "..." suffix.
    assert truncated.startswith("s3://my-bucket/team-alice/users")
    assert truncated.endswith("/...")


def test_param_values_redacted():
    """params values are replaced with {length, sha256} — raw values never stored."""
    sensitive_params = [
        {"key": "model_name", "value": "gpt-4o"},
        {"key": "prompt_template_id", "value": "v3"},
        {"key": "openai_api_key", "value": "sk-proj-supersecretvalueXYZ"},
    ]
    payload = {"runs": [_run(params=sensitive_params)]}
    importer = MLflowImporter()
    res = importer.parse_string(json.dumps(payload))[0]
    base = next(
        cr.evidence_data
        for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "metric"
    )
    params_view = base["params"]
    api_key = params_view["openai_api_key"]
    assert "sk-proj" not in json.dumps(params_view)
    assert "supersecret" not in json.dumps(params_view)
    assert api_key["present"] is True
    assert api_key["length"] == len("sk-proj-supersecretvalueXYZ")
    assert api_key["sha256"] == hashlib.sha256(
        b"sk-proj-supersecretvalueXYZ"
    ).hexdigest()


def test_dataset_name_redacted():
    """inputs[].dataset.name → {length, sha256}; digest prefix kept."""
    inputs = [
        {
            "dataset": {
                "name": "customer_pii_v3_alice",
                "digest": "sha256:abcdef1234567890aabbcc",
                "source_type": "s3",
            },
            "tags": [],
        }
    ]
    payload = {"runs": [_run(inputs=inputs)]}
    importer = MLflowImporter()
    res = importer.parse_string(json.dumps(payload))[0]
    base = next(
        cr.evidence_data
        for cr in res.control_results
        if cr.evidence_data.get("evidence_kind") == "metric"
    )
    assert "customer_pii_v3_alice" not in json.dumps(base["inputs"])
    ds_view = base["inputs"][0]
    assert ds_view["dataset_name_redacted"]["present"] is True
    assert ds_view["dataset_name_redacted"]["length"] == len(
        "customer_pii_v3_alice"
    )
    assert ds_view["dataset_name_redacted"]["sha256"] == hashlib.sha256(
        b"customer_pii_v3_alice"
    ).hexdigest()
    # Digest tail (last 8 chars) is non-identifying and kept verbatim.
    assert ds_view["dataset_digest_prefix"] == "0aabbcc"[-8:] or ds_view[
        "dataset_digest_prefix"
    ].endswith("aabbcc")


# ---------------------------------------------------------------------------
# Extra coverage — multi-kind dispatch + file hashing
# ---------------------------------------------------------------------------


def test_mixed_data_envelope_dispatches_by_shape():
    """Generic {data:[...]} envelope dispatches each record by its shape."""
    payload = {
        "data": [
            _run(),
            _registered_model(),
            _audit(),
        ]
    }
    importer = MLflowImporter()
    results = importer.parse_string(json.dumps(payload))
    kinds = {
        cr.evidence_data["source_provenance"]["record_kind"]
        for r in results
        for cr in r.control_results
    }
    assert kinds == {"run", "registered_model", "audit_log"}


def test_jsonl_input_supported():
    """JSONL with one record per line is auto-detected."""
    lines = [
        json.dumps(_run()),
        json.dumps(_registered_model()),
        json.dumps(_audit()),
    ]
    importer = MLflowImporter()
    results = importer.parse_string("\n".join(lines))
    assert len(results) == 3


def test_parse_from_file_hashes_source(tmp_path: Path):
    """parse() captures original_file_sha256 in source_provenance."""
    payload = {"runs": [_run()]}
    fp = tmp_path / "mlflow.json"
    fp.write_text(json.dumps(payload))
    expected_sha = hashlib.sha256(fp.read_bytes()).hexdigest()
    importer = MLflowImporter()
    res = importer.parse(fp)[0]
    sha = res.control_results[0].evidence_data["source_provenance"][
        "original_file_sha256"
    ]
    assert sha == expected_sha


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
