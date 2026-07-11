"""Tests for ancilis.cli.watch — WatchRunner, debounce, producer affinity."""

from __future__ import annotations

import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ancilis.cli.watch import (
    WatchRunner,
    _DebounceHandler,
    get_producers_for_paths,
)
from ancilis.cli.watch_display import (
    format_delta,
    format_header,
    print_scan_result,
    print_session_summary,
)
from ancilis.ignore import IgnoreFilter


# ---------------------------------------------------------------------------
# get_producers_for_paths
# ---------------------------------------------------------------------------

class TestGetProducersForPaths:
    def test_requirements_txt_maps_to_dependency(self) -> None:
        result = get_producers_for_paths([Path("requirements.txt")])
        assert "dependency" in result

    def test_pyproject_toml_maps_to_dependency(self) -> None:
        result = get_producers_for_paths([Path("pyproject.toml")])
        assert "dependency" in result

    def test_pipfile_maps_to_dependency(self) -> None:
        result = get_producers_for_paths([Path("Pipfile")])
        assert "dependency" in result

    def test_pipfile_lock_maps_to_dependency(self) -> None:
        result = get_producers_for_paths([Path("Pipfile.lock")])
        assert "dependency" in result

    def test_duckdb_file_maps_to_evidence(self) -> None:
        result = get_producers_for_paths([Path("evidence.duckdb")])
        assert "evidence" in result

    def test_db_file_maps_to_evidence(self) -> None:
        result = get_producers_for_paths([Path("store.db")])
        assert "evidence" in result

    def test_python_file_maps_to_all(self) -> None:
        result = get_producers_for_paths([Path("ancilis/cli/scan.py")])
        assert "all" in result

    def test_yaml_file_maps_to_all(self) -> None:
        result = get_producers_for_paths([Path("ancilis.yaml")])
        assert "all" in result

    def test_mixed_files_returns_multiple_producers(self) -> None:
        paths = [Path("requirements.txt"), Path("main.py")]
        result = get_producers_for_paths(paths)
        assert "dependency" in result
        assert "all" in result

    def test_empty_list_returns_all(self) -> None:
        result = get_producers_for_paths([])
        assert result == ["all"]

    def test_multiple_dep_manifests_deduplicated(self) -> None:
        paths = [Path("requirements.txt"), Path("pyproject.toml")]
        result = get_producers_for_paths(paths)
        assert result.count("dependency") == 1


# ---------------------------------------------------------------------------
# _DebounceHandler
# ---------------------------------------------------------------------------

class TestDebounceHandler:
    def test_collects_non_ignored_paths(self, tmp_path: Path) -> None:
        ignore = IgnoreFilter()
        handler = _DebounceHandler(ignore, tmp_path)

        event = MagicMock()
        event.is_directory = False
        event.src_path = str(tmp_path / "main.py")
        handler.on_any_event(event)

        drained = handler.drain()
        assert Path(str(tmp_path / "main.py")) in drained

    def test_ignores_pycache_paths(self, tmp_path: Path) -> None:
        ignore = IgnoreFilter()
        handler = _DebounceHandler(ignore, tmp_path)

        event = MagicMock()
        event.is_directory = False
        event.src_path = str(tmp_path / "__pycache__" / "foo.pyc")
        handler.on_any_event(event)

        drained = handler.drain()
        assert drained == []

    def test_ignores_directory_events(self, tmp_path: Path) -> None:
        ignore = IgnoreFilter()
        handler = _DebounceHandler(ignore, tmp_path)

        event = MagicMock()
        event.is_directory = True
        event.src_path = str(tmp_path / "somedir")
        handler.on_any_event(event)

        drained = handler.drain()
        assert drained == []

    def test_drain_clears_pending(self, tmp_path: Path) -> None:
        ignore = IgnoreFilter()
        handler = _DebounceHandler(ignore, tmp_path)

        event = MagicMock()
        event.is_directory = False
        event.src_path = str(tmp_path / "app.py")
        handler.on_any_event(event)

        first_drain = handler.drain()
        second_drain = handler.drain()
        assert len(first_drain) == 1
        assert second_drain == []

    def test_deduplicates_same_path(self, tmp_path: Path) -> None:
        ignore = IgnoreFilter()
        handler = _DebounceHandler(ignore, tmp_path)

        event = MagicMock()
        event.is_directory = False
        event.src_path = str(tmp_path / "app.py")

        handler.on_any_event(event)
        handler.on_any_event(event)

        drained = handler.drain()
        assert len(drained) == 1

    def test_custom_ignore_pattern_respected(self, tmp_path: Path) -> None:
        ignore = IgnoreFilter(patterns=["*.log"])
        handler = _DebounceHandler(ignore, tmp_path)

        event = MagicMock()
        event.is_directory = False
        event.src_path = str(tmp_path / "debug.log")
        handler.on_any_event(event)

        drained = handler.drain()
        assert drained == []


# ---------------------------------------------------------------------------
# watch_display helpers
# ---------------------------------------------------------------------------

class TestFormatHeader:
    def test_compliant_posture(self) -> None:
        header = format_header("my-agent", "compliant", 42)
        assert "compliant" in header
        assert "my-agent" in header
        assert "42" in header

    def test_non_compliant_posture(self) -> None:
        header = format_header("my-agent", "non_compliant", 10)
        assert "non_compliant" in header


class TestFormatDelta:
    def test_no_prev_returns_empty(self) -> None:
        new = [{"id": "PR-01", "name": "Identity", "status": "pass"}]
        assert format_delta(None, new) == []

    def test_no_changes_returns_empty(self) -> None:
        results = [{"id": "PR-01", "name": "Identity", "status": "pass"}]
        assert format_delta(results, results) == []

    def test_status_change_detected(self) -> None:
        prev = [{"id": "PR-01", "name": "Identity", "status": "pass"}]
        new = [{"id": "PR-01", "name": "Identity", "status": "fail"}]
        lines = format_delta(prev, new)
        assert len(lines) == 1
        assert "Identity" in lines[0]

    def test_new_control_no_prev_entry_skipped(self) -> None:
        prev: list[dict[str, Any]] = []
        new = [{"id": "PR-01", "name": "Identity", "status": "pass"}]
        lines = format_delta(prev, new)
        assert lines == []

    def test_multiple_changes(self) -> None:
        prev = [
            {"id": "PR-01", "name": "Identity", "status": "pass"},
            {"id": "PR-02", "name": "Scope", "status": "pass"},
        ]
        new = [
            {"id": "PR-01", "name": "Identity", "status": "fail"},
            {"id": "PR-02", "name": "Scope", "status": "skip"},
        ]
        lines = format_delta(prev, new)
        assert len(lines) == 2


class TestPrintScanResult:
    """Smoke tests — just confirm no exceptions raised."""

    def test_initial_scan_no_prev(self) -> None:
        results = [
            {"id": "PR-01", "name": "Identity", "status": "pass", "evaluations": 5, "failures": 0, "flags": 0},
        ]
        # Should not raise
        print_scan_result("agent", results, "compliant", 5, prev_results=None)

    def test_with_changed_paths(self) -> None:
        results = [
            {"id": "PR-01", "name": "Identity", "status": "fail", "evaluations": 5, "failures": 1, "flags": 0},
        ]
        print_scan_result("agent", results, "non_compliant", 5, prev_results=None, changed_paths=["a.py", "b.py"])

    def test_many_changed_paths_truncated(self) -> None:
        results: list[dict[str, Any]] = []
        paths = ["a.py", "b.py", "c.py", "d.py", "e.py"]
        # Should not raise even with many paths
        print_scan_result("agent", results, "compliant", 0, prev_results=None, changed_paths=paths)


class TestPrintSessionSummary:
    def test_smoke_no_results(self) -> None:
        print_session_summary(datetime.now(), 0, None, None)

    def test_smoke_with_results(self) -> None:
        results = [
            {"id": "PR-01", "name": "Identity", "status": "pass"},
        ]
        print_session_summary(datetime.now(), 3, results, "compliant")


# ---------------------------------------------------------------------------
# WatchRunner integration
# ---------------------------------------------------------------------------

class TestWatchRunnerIntegration:
    """Integration test: WatchRunner does initial scan then exits on Ctrl+C."""

    def _make_config(self, tmp_path: Path):
        from ancilis.config import load_config
        return load_config(raw={"agent": {"name": "test-agent"}, "security": {"mode": "audit"}})

    def test_initial_scan_runs_and_ctrl_c_exits(self, tmp_path: Path) -> None:
        """WatchRunner starts, completes initial scan, then stops on interrupt."""
        config = self._make_config(tmp_path)

        scan_calls: list[tuple] = []

        def fake_run_evaluation(cfg, store, since, session_id, run_dep_scan):
            scan_calls.append((since, run_dep_scan))
            return [], "compliant", 0

        interrupt_event = threading.Event()

        def fake_sleep(duration: float) -> None:
            # Block until we signal interrupt, then raise KeyboardInterrupt
            interrupt_event.wait(timeout=3.0)
            raise KeyboardInterrupt

        with (
            patch("ancilis.cli.watch._run_evaluation", side_effect=fake_run_evaluation),
            patch("time.sleep", side_effect=fake_sleep),
            patch("ancilis.cli.watch_display.print_scan_result"),
            patch("ancilis.cli.watch_display.print_session_summary"),
        ):
            interrupt_event.set()
            runner = WatchRunner(
                config=config,
                db_path=":memory:",
                debounce=0.05,
                clear=False,
                watch_dir=tmp_path,
                producers=None,
                since="2000-01-01T00:00:00+00:00",
                session_id=None,
            )
            runner.run()

        # Initial scan must have fired
        assert len(scan_calls) >= 1
        # First scan must include dep scan
        assert scan_calls[0][1] is True

    def test_file_change_triggers_rescan(self, tmp_path: Path) -> None:
        """Simulated file-change event triggers a second evaluation pass."""
        config = self._make_config(tmp_path)

        scan_calls: list[bool] = []
        call_count = 0

        def fake_run_evaluation(cfg, store, since, session_id, run_dep_scan):
            scan_calls.append(run_dep_scan)
            return [], "compliant", 0

        changed_file = tmp_path / "app.py"
        changed_file.touch()

        call_count_lock = threading.Lock()
        sleep_count = 0

        def fake_sleep(duration: float) -> None:
            nonlocal sleep_count
            with call_count_lock:
                sleep_count += 1
                n = sleep_count
            if n == 1:
                # Simulate a file change during the second sleep iteration
                return
            raise KeyboardInterrupt

        ignore = IgnoreFilter()

        def fake_drain() -> list[Path]:
            if len(scan_calls) == 1:
                return [changed_file]
            return []

        with (
            patch("ancilis.cli.watch._run_evaluation", side_effect=fake_run_evaluation),
            patch("time.sleep", side_effect=fake_sleep),
            patch("ancilis.cli.watch_display.print_scan_result"),
            patch("ancilis.cli.watch_display.print_session_summary"),
        ):
            runner = WatchRunner(
                config=config,
                db_path=":memory:",
                debounce=0.05,
                clear=False,
                watch_dir=tmp_path,
                producers=None,
                since="2000-01-01T00:00:00+00:00",
                session_id=None,
            )
            # Replace handler drain to inject a simulated change
            runner._handler.drain = fake_drain  # type: ignore[assignment]
            runner.run()

        # Should have at least 2 scans: initial + change-triggered
        assert len(scan_calls) >= 2

    def test_producer_filter_skips_non_matching_change(self, tmp_path: Path) -> None:
        """When --producers=dependency, non-dep file changes are ignored."""
        config = self._make_config(tmp_path)

        scan_calls: list[bool] = []
        sleep_count = 0

        def fake_run_evaluation(cfg, store, since, session_id, run_dep_scan):
            scan_calls.append(run_dep_scan)
            return [], "compliant", 0

        def fake_sleep(duration: float) -> None:
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count >= 2:
                raise KeyboardInterrupt

        def fake_drain() -> list[Path]:
            # Always return a Python source change — NOT a dep manifest
            if len(scan_calls) == 1:
                return [tmp_path / "app.py"]
            return []

        with (
            patch("ancilis.cli.watch._run_evaluation", side_effect=fake_run_evaluation),
            patch("time.sleep", side_effect=fake_sleep),
            patch("ancilis.cli.watch_display.print_scan_result"),
            patch("ancilis.cli.watch_display.print_session_summary"),
        ):
            runner = WatchRunner(
                config=config,
                db_path=":memory:",
                debounce=0.05,
                clear=False,
                watch_dir=tmp_path,
                producers=["dependency"],  # only re-scan on dep changes
                since="2000-01-01T00:00:00+00:00",
                session_id=None,
            )
            runner._handler.drain = fake_drain  # type: ignore[assignment]
            runner.run()

        # Only the initial scan should have run; the app.py change is filtered out
        assert len(scan_calls) == 1

    def test_session_summary_printed_on_exit(self, tmp_path: Path) -> None:
        """print_session_summary is called once when WatchRunner exits."""
        config = self._make_config(tmp_path)

        summary_calls: list[tuple] = []

        def fake_summary(start, scans, results, posture):
            summary_calls.append((scans, posture))

        def fake_run_evaluation(cfg, store, since, session_id, run_dep_scan):
            return [], "compliant", 0

        def fake_sleep(duration: float) -> None:
            raise KeyboardInterrupt

        with (
            patch("ancilis.cli.watch._run_evaluation", side_effect=fake_run_evaluation),
            patch("time.sleep", side_effect=fake_sleep),
            patch("ancilis.cli.watch_display.print_scan_result"),
            patch("ancilis.cli.watch_display.print_session_summary", side_effect=fake_summary),
        ):
            runner = WatchRunner(
                config=config,
                db_path=":memory:",
                debounce=0.05,
                clear=False,
                watch_dir=tmp_path,
                producers=None,
                since="2000-01-01T00:00:00+00:00",
                session_id=None,
            )
            runner.run()

        assert len(summary_calls) == 1
        # 1 scan completed (initial)
        assert summary_calls[0][0] == 1
