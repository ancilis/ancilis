"""ancilis.cli.watch — WatchRunner for live posture feedback during development."""

from __future__ import annotations

import threading
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from ancilis.config import ResolvedConfig, load_control_definitions
from ancilis.deps.scanner import DependencyScanner
from ancilis.evidence.store import EvidenceStore
from ancilis.ignore import IgnoreFilter

try:
    from watchdog.events import FileSystemEvent, FileSystemEventHandler as _FileSystemEventHandler
    from watchdog.observers import Observer as _Observer
except ImportError as e:
    raise ImportError(
        "watchdog is required for watch mode. "
        "Install it with: pip install ancilis[watch]"
    ) from e

Observer = cast(Any, _Observer)

if TYPE_CHECKING:
    class _FileSystemEventHandlerBase:
        def __init__(self) -> None:
            pass
else:
    _FileSystemEventHandlerBase = _FileSystemEventHandler

# Dependency manifest filenames — changes here trigger a dep re-scan
_DEP_MANIFEST_NAMES = frozenset({
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "pipfile",
    "pipfile.lock",
})


def get_producers_for_paths(changed_paths: list[Path]) -> list[str]:
    """Map changed file paths to affected producer names.

    Returns list of producer names: 'dependency', 'evidence', or 'all'.
    """
    producers: set[str] = set()
    for p in changed_paths:
        name = p.name.lower()
        if name in _DEP_MANIFEST_NAMES:
            producers.add("dependency")
        elif p.suffix in {".duckdb", ".db"}:
            producers.add("evidence")
        else:
            producers.add("all")
    return list(producers) if producers else ["all"]


def _run_evaluation(
    config: ResolvedConfig,
    store: EvidenceStore,
    since: str,
    session_id: str | None,
    run_dep_scan: bool,
) -> tuple[list[dict[str, Any]], str, int]:
    """Run one posture pass; returns (control_results, posture, total_evals)."""
    summary = store.get_summary(since=since, session_id=session_id)
    control_defs = load_control_definitions()
    enabled = [c for c in config.controls.values() if c.enabled]
    control_stats = summary.get("control_pass_rates", {})
    total_evaluations = summary.get("total_evaluations", 0)

    control_results: list[dict[str, Any]] = []
    any_failing = False

    for cs in sorted(enabled, key=lambda c: c.control_id):
        cdef = control_defs.get(cs.control_id, {})
        display_name = cdef.get("display_name", cs.name)
        stats = control_stats.get(cs.control_id, {})
        failures = stats.get("FAIL", 0) + stats.get("ERROR", 0)
        flags = stats.get("FLAG", 0)
        total_evals = sum(stats.values()) if stats else 0

        if total_evals == 0:
            ctrl_status = "skip"
        elif failures > 0:
            ctrl_status = "fail"
            any_failing = True
        else:
            ctrl_status = "pass"

        control_results.append({
            "id": cs.control_id,
            "name": display_name,
            "status": ctrl_status,
            "evaluations": total_evals,
            "failures": failures,
            "flags": flags,
        })

    decisions = summary.get("decisions", {})
    normalized: dict[str, int] = {str(k).strip().upper(): int(v) for k, v in decisions.items()}
    if normalized.get("BLOCK", 0) > 0:
        any_failing = True

    if run_dep_scan and config.scan_dependencies_enabled:
        _ignore_set = set(config.scan_dependencies_ignore)
        _severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        _threshold = config.scan_dependencies_severity_threshold
        _threshold_rank = _severity_order.get(_threshold, 1)
        for eval_result in DependencyScanner(config).scan():
            store.store(eval_result, "dependency-scanner")
            for cr in eval_result.control_results:
                vuln_id = (cr.evidence_data or {}).get("vuln_id", "")
                if vuln_id and vuln_id in _ignore_set:
                    continue
                if cr.result == "FAIL":
                    sev = ((cr.evidence_data or {}).get("severity") or "high").lower()
                    if _severity_order.get(sev, 1) <= _threshold_rank:
                        any_failing = True

    posture = "non_compliant" if any_failing else "compliant"
    return control_results, posture, total_evaluations


class _DebounceHandler(_FileSystemEventHandlerBase):
    """Collects filesystem events; caller drains them after debounce window."""

    def __init__(self, ignore_filter: IgnoreFilter, project_root: Path) -> None:
        super().__init__()
        self._ignore = ignore_filter
        self._root = project_root
        self._lock = threading.Lock()
        self._pending: list[Path] = []

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = Path(str(event.src_path))
        if self._ignore.is_ignored(path, relative_to=self._root):
            return
        with self._lock:
            if path not in self._pending:
                self._pending.append(path)

    def drain(self) -> list[Path]:
        with self._lock:
            paths = list(self._pending)
            self._pending.clear()
            return paths


class WatchRunner:
    """Runs incremental posture re-evaluations on filesystem changes."""

    def __init__(
        self,
        config: ResolvedConfig,
        db_path: str | None,
        debounce: float,
        clear: bool,
        watch_dir: Path,
        producers: list[str] | None,
        since: str,
        session_id: str | None,
    ) -> None:
        self._config = config
        self._db_path = db_path
        self._debounce = debounce
        self._clear = clear
        self._watch_dir = watch_dir
        self._filter_producers: set[str] | None = set(producers) if producers else None
        self._since = since
        self._session_id = session_id

        self._ignore = IgnoreFilter.from_file(watch_dir)
        self._handler = _DebounceHandler(self._ignore, watch_dir)
        self._observer = Observer()
        self._observer.schedule(self._handler, str(watch_dir), recursive=True)

        self._prev_results: list[dict[str, Any]] | None = None
        self._prev_posture: str | None = None
        self._total_scans = 0
        self._start_time = datetime.now()

    def run(self) -> None:
        from ancilis.cli.watch_display import print_scan_result, print_session_summary

        self._observer.start()
        try:
            # Initial scan always includes dep scan
            self._do_scan(changed_paths=None, run_dep=True)

            while True:
                time.sleep(self._debounce)
                changed = self._handler.drain()
                if not changed:
                    continue

                producers = get_producers_for_paths(changed)

                # Apply caller-specified producer filter.
                # "all" in filter means user wants every change type to trigger re-scan.
                if self._filter_producers is not None:
                    effective = [
                        p for p in producers
                        if p in self._filter_producers or "all" in self._filter_producers
                    ]
                    if not effective:
                        continue
                    producers = effective

                run_dep = "dependency" in producers or "all" in producers
                self._do_scan(changed_paths=changed, run_dep=run_dep)

        except KeyboardInterrupt:
            pass
        finally:
            self._observer.stop()
            self._observer.join()
            print_session_summary(
                self._start_time, self._total_scans, self._prev_results, self._prev_posture
            )

    def _do_scan(self, changed_paths: list[Path] | None, run_dep: bool) -> None:
        from ancilis.cli.watch_display import print_scan_result

        store = EvidenceStore(self._config, db_path=self._db_path)
        try:
            control_results, posture, total_evals = _run_evaluation(
                self._config, store, self._since, self._session_id, run_dep_scan=run_dep
            )
        finally:
            store.close()

        self._total_scans += 1
        print_scan_result(
            agent_name=self._config.agent_name,
            control_results=control_results,
            posture=posture,
            total_evals=total_evals,
            prev_results=self._prev_results,
            changed_paths=[str(p) for p in changed_paths] if changed_paths else None,
            clear=self._clear,
        )
        self._prev_results = control_results
        self._prev_posture = posture
