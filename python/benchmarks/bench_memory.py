from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from .helpers import SyntheticRepo


def _measure_peak_rss_subprocess(repo: SyntheticRepo) -> tuple[int, int, int]:
    script = """
import json
import resource
import sys
from pathlib import Path

from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore
from ancilis.report.generator import ReportGenerator
from ancilis.report.renderer import render_terminal
from helpers import make_store_evaluation, scan_path_candidates

repo_root = Path(sys.argv[1])
config_path = Path(sys.argv[2])
db_path = Path(sys.argv[3])
session_id = sys.argv[4]

db_path.unlink(missing_ok=True)
config = load_config(path=config_path)
candidates = scan_path_candidates(repo_root)
with EvidenceStore(config, db_path=db_path) as store:
    for index, path in enumerate(candidates, start=1):
        store.store(
            make_store_evaluation(
                path,
                index,
                agent_name=config.agent_name,
                session_id=session_id,
            ),
            tool_name="bench-memory",
        )
    report_data = ReportGenerator(config, store).generate(
        period="365d",
        report_format="terminal",
        session_id=session_id,
    )
    rendered = render_terminal(report_data)

print(
    json.dumps(
        {
            "peak_rss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "total_evaluations": report_data.total_evaluations,
            "rendered_length": len(rendered),
        }
    )
)
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(Path.cwd() / "python" / "src"), str(Path.cwd() / "python" / "benchmarks")]
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(repo.root),
            str(repo.config_path),
            str(repo.db_path),
            repo.session_id,
        ],
        check=True,
        capture_output=True,
        env=env,
        text=True,
    )
    payload = json.loads(result.stdout)
    return (
        int(payload["peak_rss_kb"]),
        int(payload["total_evaluations"]),
        int(payload["rendered_length"]),
    )


def test_peak_rss_during_scan_and_report_generation(
    benchmark,
    synthetic_repo_1000_files: SyntheticRepo,
) -> None:
    peak_rss, total_evaluations, rendered_length = benchmark.pedantic(
        _measure_peak_rss_subprocess,
        args=(synthetic_repo_1000_files,),
        rounds=3,
        iterations=1,
    )
    assert peak_rss > 0
    assert total_evaluations >= len(synthetic_repo_1000_files.files)
    assert rendered_length > 0
