"""Tests for evidence session isolation — ANC-159.

Covers:
1. Multi-session isolation (get_summary scoping)
2. Session listing (list_sessions)
3. Scoped count (count with session_id filter)
4. Reset (clears records, chain restarts clean)
5. CLI integration (--session flag on status; evidence sessions/reset commands)
"""

from __future__ import annotations

import uuid

import pytest
from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.config import load_config, ResolvedConfig
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_config(**overrides) -> ResolvedConfig:
    raw = {"agent": {"name": "test-agent"}, **overrides}
    return load_config(raw=raw)


def make_evaluation(
    decision: str = "ALLOW",
    mode: str = "audit",
    session_id: str | None = None,
    timestamp: str = "2025-01-15T10:30:00Z",
) -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=str(uuid.uuid4()),
        action_id="action-001",
        timestamp=timestamp,
        agent_id="test-agent",
        mode=mode,
        session_id=session_id,
        control_results=[
            ControlResult(
                control_id="PR-01",
                control_name="Agent Identity",
                result="PASS",
                detail="Agent identity verified",
                evidence_data={"agent_id": "test-agent"},
                duration_ms=1.5,
            ),
        ],
        decision=decision,
        decision_reason="All controls passed",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=5.0,
    )


# ---------------------------------------------------------------------------
# 1. Multi-session isolation
# ---------------------------------------------------------------------------


class TestMultiSessionIsolation:
    def test_get_summary_session_a_excludes_session_b(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        session_a = "session-aaa"
        session_b = "session-bbb"

        for _ in range(3):
            store.store(make_evaluation(decision="ALLOW", session_id=session_a), tool_name="tool")
        for _ in range(2):
            store.store(make_evaluation(decision="BLOCK", session_id=session_b), tool_name="tool")

        summary_a = store.get_summary(session_id=session_a)
        summary_b = store.get_summary(session_id=session_b)

        assert summary_a["total_evaluations"] == 3
        assert summary_b["total_evaluations"] == 2

        assert summary_a["decisions"]["ALLOW"] == 3
        assert summary_a["decisions"].get("BLOCK", 0) == 0

        assert summary_b["decisions"]["BLOCK"] == 2
        assert summary_b["decisions"].get("ALLOW", 0) == 0

        store.close()

    def test_get_records_session_filter_excludes_other_session(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        session_a = "session-xxx"
        session_b = "session-yyy"

        store.store(make_evaluation(session_id=session_a), tool_name="tool-a")
        store.store(make_evaluation(session_id=session_b), tool_name="tool-b")

        records_a = store.get_records(session_id=session_a)
        records_b = store.get_records(session_id=session_b)

        assert len(records_a) == 1
        assert records_a[0].tool_name == "tool-a"

        assert len(records_b) == 1
        assert records_b[0].tool_name == "tool-b"

        store.close()


# ---------------------------------------------------------------------------
# 2. Session listing
# ---------------------------------------------------------------------------


class TestListSessions:
    def test_list_sessions_returns_all_known_sessions(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        sessions = ["sess-1", "sess-2", "sess-3"]
        for i, sid in enumerate(sessions):
            for _ in range(i + 1):  # 1, 2, 3 records respectively
                store.store(make_evaluation(session_id=sid), tool_name="tool")

        listed = store.list_sessions()
        assert len(listed) == 3

        counts = {s["session_id"]: s["count"] for s in listed}
        assert counts["sess-1"] == 1
        assert counts["sess-2"] == 2
        assert counts["sess-3"] == 3

        for entry in listed:
            assert "session_id" in entry
            assert "count" in entry
            assert "first_seen" in entry
            assert "last_seen" in entry

        store.close()

    def test_list_sessions_empty_store(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)
        assert store.list_sessions() == []
        store.close()

    def test_list_sessions_excludes_null_session_ids(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        store.store(make_evaluation(), tool_name="tool")  # no session_id
        store.store(make_evaluation(session_id="real-session"), tool_name="tool")

        listed = store.list_sessions()
        assert len(listed) == 1
        assert listed[0]["session_id"] == "real-session"

        store.close()


# ---------------------------------------------------------------------------
# 3. Scoped count
# ---------------------------------------------------------------------------


class TestScopedCount:
    def test_count_no_args_returns_total(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        store.store(make_evaluation(session_id="s1"), tool_name="t")
        store.store(make_evaluation(session_id="s1"), tool_name="t")
        store.store(make_evaluation(session_id="s2"), tool_name="t")

        assert store.count() == 3
        store.close()

    def test_count_with_session_id_returns_scoped_count(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        for _ in range(4):
            store.store(make_evaluation(session_id="session-a"), tool_name="t")
        for _ in range(2):
            store.store(make_evaluation(session_id="session-b"), tool_name="t")

        assert store.count(session_id="session-a") == 4
        assert store.count(session_id="session-b") == 2
        assert store.count() == 6

        store.close()

    def test_count_unknown_session_returns_zero(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)
        store.store(make_evaluation(session_id="known"), tool_name="t")
        assert store.count(session_id="unknown") == 0
        store.close()


# ---------------------------------------------------------------------------
# 4. Reset + chain integrity
# ---------------------------------------------------------------------------


class TestReset:
    def test_reset_clears_all_records(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        for _ in range(5):
            store.store(make_evaluation(session_id="s1"), tool_name="tool")

        assert store.count() == 5
        deleted = store.reset()
        assert deleted == 5
        assert store.count() == 0

        store.close()

    def test_reset_new_writes_pass_verify_chain(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        for _ in range(3):
            store.store(make_evaluation(session_id="pre-reset"), tool_name="old")

        store.reset()

        for _ in range(2):
            store.store(make_evaluation(session_id="post-reset"), tool_name="new")

        valid, errors = store.verify_chain()
        assert valid, f"Chain invalid after reset: {errors}"

        store.close()

    def test_reset_empty_store_returns_zero(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)
        assert store.reset() == 0
        store.close()

    def test_reset_list_sessions_empty_after(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        store.store(make_evaluation(session_id="s"), tool_name="t")
        store.reset()

        assert store.list_sessions() == []
        store.close()


# ---------------------------------------------------------------------------
# 5. CLI integration — --session flag and evidence subcommands
# ---------------------------------------------------------------------------


class TestCLISessionFlag:
    def test_status_session_flag_scopes_output(self, tmp_path):
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text("agent:\n  name: test-agent\n")

        config = make_config()
        store = EvidenceStore(config, db_path=db)
        store.store(make_evaluation(decision="ALLOW", session_id="run-1"), tool_name="tool")
        store.store(make_evaluation(decision="BLOCK", session_id="run-2"), tool_name="tool")
        store.close()

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["status", "--config", config_path, "--db", db, "--session", "run-1"],
        )
        assert result.exit_code == 0, result.output
        # run-1 has exactly 1 evaluation
        assert "1" in result.output

    def test_evidence_sessions_command(self, tmp_path):
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text("agent:\n  name: test-agent\n")

        config = make_config()
        store = EvidenceStore(config, db_path=db)
        store.store(make_evaluation(session_id="alpha"), tool_name="tool")
        store.store(make_evaluation(session_id="beta"), tool_name="tool")
        store.close()

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["evidence", "sessions", "--config", config_path, "--db", db],
        )
        assert result.exit_code == 0, result.output
        assert "alpha" in result.output
        assert "beta" in result.output

    def test_evidence_reset_command_with_yes_flag(self, tmp_path):
        db = str(tmp_path / "ev.duckdb")
        config_path = str(tmp_path / "ancilis.yaml")
        (tmp_path / "ancilis.yaml").write_text("agent:\n  name: test-agent\n")

        config = make_config()
        store = EvidenceStore(config, db_path=db)
        for _ in range(3):
            store.store(make_evaluation(session_id="s"), tool_name="tool")
        store.close()

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["evidence", "reset", "--config", config_path, "--db", db, "-y"],
        )
        assert result.exit_code == 0, result.output
        assert "3" in result.output
        assert "reset" in result.output.lower()


# ---------------------------------------------------------------------------
# 6. latest_session_id
# ---------------------------------------------------------------------------


class TestLatestSessionId:
    def test_latest_session_id_returns_most_recent(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)

        store.store(
            make_evaluation(session_id="first-session", timestamp="2025-01-15T10:00:00Z"),
            tool_name="tool",
        )
        store.store(
            make_evaluation(session_id="second-session", timestamp="2025-01-15T11:00:00Z"),
            tool_name="tool",
        )

        assert store.latest_session_id() == "second-session"
        store.close()

    def test_latest_session_id_empty_store(self):
        config = make_config()
        store = EvidenceStore(config, in_memory=True)
        assert store.latest_session_id() is None
        store.close()
