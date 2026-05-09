"""Tests for remediation guidance."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.config import load_config
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore
from ancilis.remediation import (
    build_remediation_recommendations,
    load_remediation_guides,
    render_remediation_recommendations,
)


def _make_config_file(tmp_path: Path) -> Path:
    path = tmp_path / "ancilis.yaml"
    path.write_text(yaml.safe_dump({"agent": {"name": "demo-agent"}}), encoding="utf-8")
    return path


def _store_failing_pr01(config_path: Path, db_path: Path) -> None:
    config = load_config(path=str(config_path))
    store = EvidenceStore(config, db_path=str(db_path))
    try:
        store.store(
            EvaluationResult(
                evaluation_id="eval-1",
                action_id="action-1",
                timestamp=datetime.now(timezone.utc).isoformat(),
                agent_id="demo-agent",
                mode="audit",
                control_results=[
                    ControlResult(
                        control_id="PR-01",
                        control_name="Identity",
                        result="FAIL",
                        detail="Missing agent identity",
                    )
                ],
                decision="FLAG",
                decision_reason="Identity gap",
                total_duration_ms=1,
            ),
            "read_file",
        )
    finally:
        store.close()


def test_loads_remediation_guides() -> None:
    guides = load_remediation_guides()

    assert {"PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"} <= set(guides)
    assert guides["PR-01"].time_estimate == "5 minutes"
    assert "agent:" in guides["PR-01"].code_example


def test_builds_current_gap_recommendations() -> None:
    config = load_config(raw={"agent": {"name": "demo-agent"}})
    summary: dict[str, Any] = {
        "control_pass_rates": {
            "PR-01": {"PASS": 0, "FAIL": 1, "ERROR": 0, "FLAG": 0, "SKIP": 0},
            "PR-02": {"PASS": 3, "FAIL": 0, "ERROR": 0, "FLAG": 0, "SKIP": 0},
            "PR-03": {"PASS": 1, "FAIL": 0, "ERROR": 0, "FLAG": 1, "SKIP": 0},
        }
    }

    recommendations = build_remediation_recommendations(config, summary)
    output = render_remediation_recommendations(recommendations)

    assert [item.guide.control_id for item in recommendations] == ["PR-01", "PR-03"]
    assert "PR-01 (Identity verification) — GAP" in output
    assert "agent:" in output
    assert "demo-agent" in output
    assert "PR-03 (Data exposure prevention) — PARTIAL" in output


def test_remediate_cli_shows_guidance_for_current_gap(tmp_path: Path) -> None:
    config_path = _make_config_file(tmp_path)
    db_path = tmp_path / "evidence.duckdb"
    _store_failing_pr01(config_path, db_path)

    result = CliRunner().invoke(
        cli,
        [
            "--no-update-check",
            "remediate",
            "--config",
            str(config_path),
            "--db",
            str(db_path),
            "--all",
        ],
    )

    assert result.exit_code == 0
    assert "PR-01 (Identity verification) — GAP" in result.output
    assert "How to fix:" in result.output
    assert "agent.name" in result.output
