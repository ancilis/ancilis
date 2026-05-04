from __future__ import annotations

import resource

from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore
from ancilis.report.generator import ReportGenerator
from ancilis.report.renderer import render_terminal

from .helpers import SyntheticRepo, make_store_evaluation, scan_path_candidates


def _measure_peak_rss(repo: SyntheticRepo) -> tuple[int, int, int]:
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    repo.db_path.unlink(missing_ok=True)
    config = load_config(path=repo.config_path)
    candidates = scan_path_candidates(repo.root)
    with EvidenceStore(config, db_path=repo.db_path) as store:
        for index, path in enumerate(candidates, start=1):
            store.store(
                make_store_evaluation(
                    path,
                    index,
                    agent_name=config.agent_name,
                    session_id=repo.session_id,
                ),
                tool_name="bench-memory",
            )
        report_data = ReportGenerator(config, store).generate(
            period="365d",
            report_format="terminal",
            session_id=repo.session_id,
        )
        rendered = render_terminal(report_data)
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return after, report_data.total_evaluations, len(rendered)


def test_peak_rss_during_scan_and_report_generation(
    benchmark,
    synthetic_repo_1000_files: SyntheticRepo,
) -> None:
    peak_rss, total_evaluations, rendered_length = benchmark.pedantic(
        _measure_peak_rss,
        args=(synthetic_repo_1000_files,),
        rounds=3,
        iterations=1,
    )
    assert peak_rss > 0
    assert total_evaluations >= len(synthetic_repo_1000_files.files)
    assert rendered_length > 0
