from __future__ import annotations

from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore

from .helpers import SyntheticRepo, make_store_evaluation, scan_path_candidates


def _scan_repo(repo: SyntheticRepo) -> tuple[int, int]:
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
                tool_name="bench-scan",
            )
        return len(candidates), store.count(session_id=repo.session_id)


def _benchmark_scan(benchmark, repo: SyntheticRepo) -> None:
    scanned_count, stored_count = benchmark.pedantic(_scan_repo, args=(repo,), rounds=3, iterations=1)
    assert stored_count == scanned_count
    assert stored_count >= len(repo.files)


def test_scan_speed_small_repo(benchmark, synthetic_repo_10_files: SyntheticRepo) -> None:
    _benchmark_scan(benchmark, synthetic_repo_10_files)


def test_scan_speed_medium_repo(benchmark, synthetic_repo_100_files: SyntheticRepo) -> None:
    _benchmark_scan(benchmark, synthetic_repo_100_files)


def test_scan_speed_large_repo(benchmark, synthetic_repo_1000_files: SyntheticRepo) -> None:
    _benchmark_scan(benchmark, synthetic_repo_1000_files)
