"""Regression tests for `ancilis evidence prune` (audit finding F7).

retention_met was reported against an unenforced number and purge_before had no
caller. `ancilis evidence prune` wires purge_before to the retention window so
the documented prune command (referenced by doctor and the cache-size warning)
exists and actually enforces retention.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from ancilis.cli.evidence import evidence
from ancilis.cli.main import cli
from ancilis.config import load_config
from ancilis.engine.engine import Engine
from ancilis.engine.action import Action, ActionParameters, ToolInfo
from ancilis.evidence.store import EvidenceStore


def _seed(store: EvidenceStore, engine: Engine, timestamp: str) -> None:
    action = Action(
        action_id="a", timestamp=timestamp, agent_id="test-agent",
        action_type="tool_call", tool=ToolInfo(name="lookup"),
        parameters=ActionParameters(raw={"query": "x"}),
    )
    evaluation = engine.evaluate(action)
    # force the stored evidence timestamp to the desired value
    evaluation.timestamp = timestamp
    store.store(evaluation, tool_name="lookup")


def test_prune_command_is_registered() -> None:
    assert "prune" in evidence.commands


def test_prune_removes_records_older_than_window(tmp_path) -> None:
    db = tmp_path / "evidence.duckdb"
    cfg_path = tmp_path / "ancilis.yaml"
    cfg_path.write_text("agent:\n  name: test-agent\n")
    config = load_config(path=str(cfg_path))
    engine = Engine(config)
    store = EvidenceStore(config, db_path=str(db))

    old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    _seed(store, engine, old)
    _seed(store, engine, recent)
    assert store.count() == 2
    store.close()

    result = CliRunner().invoke(
        cli,
        ["evidence", "prune", "--config", str(cfg_path), "--db", str(db), "--days", "30", "--yes"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "1 record(s)" in result.output

    store = EvidenceStore(config, db_path=str(db))
    try:
        remaining = store.get_records(limit=None)
        assert len(remaining) == 1
        assert remaining[0].timestamp == recent
    finally:
        store.close()
