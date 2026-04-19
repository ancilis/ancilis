"""CLI tests for manual evidence sync commands."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore


def make_config_file(tmp_path: Path, sync_mode: str = "auto") -> Path:
    path = tmp_path / "ancilis.yaml"
    path.write_text(
        yaml.dump(
            {
                "agent": {
                    "name": "sync-agent",
                    "agent_id": "agent-123",
                },
                "platform": {
                    "url": "https://platform.example",
                    "api_key_env": "ANCILIS_TEST_TOKEN",
                },
                "sync": {
                    "offline_mode": sync_mode,
                    "batch_size": 2,
                    "backoff_base_seconds": 5,
                },
            }
        )
    )
    return path


def load_test_config(sync_mode: str = "auto") -> ResolvedConfig:
    return load_config(
        raw={
            "agent": {
                "name": "sync-agent",
                "agent_id": "agent-123",
            },
            "platform": {
                "url": "https://platform.example",
                "api_key_env": "ANCILIS_TEST_TOKEN",
            },
            "sync": {
                "offline_mode": sync_mode,
                "batch_size": 2,
                "backoff_base_seconds": 5,
            },
        }
    )


def make_evaluation(evaluation_id: str) -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=evaluation_id,
        action_id=f"action-{evaluation_id}",
        timestamp="2025-01-01T00:00:00Z",
        agent_id="sync-agent",
        mode="audit",
        control_results=[
            ControlResult(
                control_id="PR-01",
                control_name="Agent Identity",
                result="PASS",
                detail="Agent identity verified",
                evidence_data={},
            )
        ],
        decision="ALLOW",
        decision_reason="All controls passed",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=1.0,
    )


def populate_store(config: ResolvedConfig, db_path: Path, count: int = 1) -> None:
    store = EvidenceStore(config, db_path=db_path)
    try:
        for index in range(count):
            store.store(make_evaluation(f"eval-{index}"), tool_name=f"tool-{index}")
    finally:
        store.close()


def test_sync_dry_run_json_reports_pending_without_mutating(tmp_path: Path) -> None:
    config_path = make_config_file(tmp_path)
    config = load_test_config()
    db_path = tmp_path / "evidence.duckdb"
    populate_store(config, db_path, count=2)

    result = CliRunner().invoke(
        cli,
        [
            "sync",
            "--config",
            str(config_path),
            "--db",
            str(db_path),
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "dry_run"
    assert payload["pending"] == 2
    assert payload["would_send"] == 2
    store = EvidenceStore(config, db_path=db_path)
    try:
        assert len(store.get_pending_sync_records()) == 2
    finally:
        store.close()


def test_sync_human_dry_run_output_reports_limit(tmp_path: Path) -> None:
    config_path = make_config_file(tmp_path)
    config = load_test_config()
    db_path = tmp_path / "evidence.duckdb"
    populate_store(config, db_path, count=2)

    result = CliRunner().invoke(
        cli,
        [
            "sync",
            "--config",
            str(config_path),
            "--db",
            str(db_path),
            "--limit",
            "1",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert "Would sync 1 pending evidence record" in result.output
    assert "2 pending locally" in result.output


def test_sync_always_online_network_failure_exits_nonzero_and_hides_token(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    config_path = make_config_file(tmp_path, sync_mode="always_online")
    config = load_test_config(sync_mode="always_online")
    db_path = tmp_path / "evidence.duckdb"
    populate_store(config, db_path)
    monkeypatch.setenv("ANCILIS_TEST_TOKEN", "super-secret-token")

    def fake_urlopen(*_args: object, **_kwargs: object) -> object:
        raise urllib.error.URLError("refused")

    monkeypatch.setattr("ancilis.platform.client.urllib.request.urlopen", fake_urlopen)

    result = CliRunner().invoke(
        cli,
        [
            "sync",
            "--config",
            str(config_path),
            "--db",
            str(db_path),
        ],
    )

    assert result.exit_code == 1
    assert "Sync failed" in result.output
    assert "super-secret-token" not in result.output


def test_sync_always_online_missing_api_key_exits_nonzero(tmp_path: Path) -> None:
    config_path = make_config_file(tmp_path, sync_mode="always_online")
    config = load_test_config(sync_mode="always_online")
    db_path = tmp_path / "evidence.duckdb"
    populate_store(config, db_path)

    result = CliRunner().invoke(
        cli,
        [
            "sync",
            "--config",
            str(config_path),
            "--db",
            str(db_path),
        ],
    )

    assert result.exit_code == 1
    assert "platform sync is not configured" in result.output


def test_status_displays_sync_state_without_platform_call(tmp_path: Path) -> None:
    config_path = make_config_file(tmp_path)
    config = load_test_config()
    db_path = tmp_path / "evidence.duckdb"
    populate_store(config, db_path, count=2)
    store = EvidenceStore(config, db_path=db_path)
    try:
        failed_record = store.get_pending_sync_records()[1]
        store.mark_sync_failed(
            failed_record.record_id,
            error="platform unavailable",
            attempted_at="2025-01-01T00:01:00Z",
            next_retry_at="2025-01-01T00:06:00Z",
        )
    finally:
        store.close()

    result = CliRunner().invoke(
        cli,
        [
            "status",
            "--config",
            str(config_path),
            "--db",
            str(db_path),
        ],
    )

    assert result.exit_code == 0
    assert "Sync: 1 pending, 1 failed" in result.output
    assert "Last sync error: platform unavailable" in result.output
