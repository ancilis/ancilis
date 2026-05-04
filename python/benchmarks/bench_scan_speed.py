from __future__ import annotations

import json

from click.testing import CliRunner

from ancilis.cli.main import cli

from .helpers import SyntheticRepo


def _benchmark_scan(benchmark, repo: SyntheticRepo) -> None:
    runner = CliRunner()

    def run_scan() -> tuple[int, int]:
        result = runner.invoke(
            cli,
            [
                "--no-update-check",
                "scan",
                "--ci",
                "--config",
                str(repo.config_path),
                "--db",
                str(repo.db_path),
                "--session",
                repo.session_id,
            ],
            catch_exceptions=False,
        )
        payload = json.loads(result.output)
        return result.exit_code, int(payload["summary"]["total_evaluations"])

    exit_code, total_evaluations = benchmark.pedantic(run_scan, rounds=3, iterations=1)
    assert exit_code == 0
    assert total_evaluations >= len(repo.files)


def test_scan_speed_small_repo(benchmark, synthetic_repo_10_files: SyntheticRepo) -> None:
    _benchmark_scan(benchmark, synthetic_repo_10_files)


def test_scan_speed_medium_repo(benchmark, synthetic_repo_100_files: SyntheticRepo) -> None:
    _benchmark_scan(benchmark, synthetic_repo_100_files)


def test_scan_speed_large_repo(benchmark, synthetic_repo_1000_files: SyntheticRepo) -> None:
    _benchmark_scan(benchmark, synthetic_repo_1000_files)
