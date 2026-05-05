from __future__ import annotations

from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore
from ancilis.report.generator import ReportGenerator
from ancilis.report.renderer import render_terminal

from .helpers import SyntheticRepo, make_report_json, make_store_evaluation, scan_path_candidates


def _seed_repo(repo: SyntheticRepo) -> tuple[object, int]:
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
                tool_name="bench-report",
            )
        return config, len(candidates)


def _render_terminal_report(repo: SyntheticRepo) -> tuple[int, int]:
    config, expected_count = _seed_repo(repo)
    with EvidenceStore(config, db_path=repo.db_path) as store:
        report_data = ReportGenerator(config, store).generate(
            period="365d",
            report_format="terminal",
            session_id=repo.session_id,
        )
        rendered = render_terminal(report_data)
        return report_data.total_evaluations, len(rendered)


def _render_json_report(repo: SyntheticRepo) -> tuple[int, int]:
    config, _expected_count = _seed_repo(repo)
    with EvidenceStore(config, db_path=repo.db_path) as store:
        report_data = ReportGenerator(config, store).generate(
            period="365d",
            report_format="terminal",
            session_id=repo.session_id,
        )
        rendered = make_report_json(report_data)
        return report_data.total_evaluations, len(rendered)


def test_terminal_report_render_generation(benchmark, synthetic_repo_100_files: SyntheticRepo) -> None:
    total_evaluations, output_length = benchmark.pedantic(
        _render_terminal_report,
        args=(synthetic_repo_100_files,),
        rounds=3,
        iterations=1,
    )
    assert total_evaluations >= len(synthetic_repo_100_files.files)
    assert output_length > 0


def test_json_report_render_generation(benchmark, synthetic_repo_100_files: SyntheticRepo) -> None:
    total_evaluations, output_length = benchmark.pedantic(
        _render_json_report,
        args=(synthetic_repo_100_files,),
        rounds=3,
        iterations=1,
    )
    assert total_evaluations >= len(synthetic_repo_100_files.files)
    assert output_length > 0
