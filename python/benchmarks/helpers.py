from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.ignore import IgnoreFilter
from ancilis.report.generator import ReportData

BENCHMARK_AGENT_NAME = "benchmark-agent"
BENCHMARK_SESSION_ID = "bench-session"


@dataclass(frozen=True)
class SyntheticRepo:
    root: Path
    config_path: Path
    db_path: Path
    files: tuple[Path, ...]
    session_id: str


def make_benchmark_config() -> ResolvedConfig:
    return load_config(
        raw={
            "agent": {"name": BENCHMARK_AGENT_NAME},
            "scan": {"dependencies": {"enabled": False}},
        }
    )


def make_report_json(report_data: ReportData) -> str:
    import json

    return json.dumps(asdict(report_data), sort_keys=True)


def make_store_evaluation(
    file_path: Path,
    file_index: int,
    *,
    agent_name: str = BENCHMARK_AGENT_NAME,
    session_id: str = BENCHMARK_SESSION_ID,
) -> EvaluationResult:
    timestamp = (
        datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=file_index)
    ).isoformat()
    file_label = file_path.relative_to(file_path.parents[1]) if len(file_path.parents) > 1 else file_path
    return EvaluationResult(
        evaluation_id=f"bench-eval-{file_index:04d}",
        action_id=f"bench-action-{file_index:04d}",
        timestamp=timestamp,
        agent_id=agent_name,
        session_id=session_id,
        mode="audit",
        control_results=[
            ControlResult(
                control_id="PR-05",
                control_name="Audit Logging",
                result="PASS",
                detail="Synthetic benchmark evidence recorded.",
                evidence_data={
                    "path": str(file_label),
                    "file_index": file_index,
                },
                duration_ms=0.365,
            )
        ],
        decision="ALLOW",
        decision_reason="Synthetic benchmark pass.",
        active_overlays=[],
        data_classifications=[],
        total_duration_ms=1.25,
    )


def scan_path_candidates(repo_root: Path) -> list[Path]:
    ignore_filter = IgnoreFilter.from_file(repo_root)
    candidates: list[Path] = []
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if ignore_filter.is_ignored(path, relative_to=repo_root):
            continue
        candidates.append(path)
    return sorted(candidates)
