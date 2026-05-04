from __future__ import annotations

from pathlib import Path

import pytest

from ancilis.config import ResolvedConfig

from .helpers import (
    BENCHMARK_AGENT_NAME,
    BENCHMARK_SESSION_ID,
    SyntheticRepo,
    make_benchmark_config,
)


@pytest.fixture(scope="session")
def benchmark_config() -> ResolvedConfig:
    return make_benchmark_config()


def _write_config(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "agent:",
                f"  name: {BENCHMARK_AGENT_NAME}",
                "scan:",
                "  dependencies:",
                "    enabled: false",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _build_synthetic_repo(base: Path, file_count: int) -> SyntheticRepo:
    root = base / f"repo-{file_count}"
    package_root = root / "package"
    package_root.mkdir(parents=True, exist_ok=True)
    (root / ".cache").mkdir(parents=True, exist_ok=True)

    config_path = root / "ancilis.yaml"
    _write_config(config_path)

    files: list[Path] = []
    for index in range(file_count):
        module_path = package_root / f"module_{index:04d}.py"
        module_path.write_text(
            "\n".join(
                [
                    '"""Synthetic module for benchmark runs."""',
                    f"VALUE_{index:04d} = {index}",
                    "",
                    "def function() -> int:",
                    f"    return VALUE_{index:04d}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        files.append(module_path)

    (root / ".ancilisignore").write_text(".cache/\n", encoding="utf-8")
    (root / ".cache" / "ignored.py").write_text("IGNORED = True\n", encoding="utf-8")

    return SyntheticRepo(
        root=root,
        config_path=config_path,
        db_path=root / ".ancilis" / "benchmark-evidence.duckdb",
        files=tuple(files),
        session_id=BENCHMARK_SESSION_ID,
    )


@pytest.fixture
def synthetic_repo_factory(tmp_path_factory: pytest.TempPathFactory):
    base = tmp_path_factory.mktemp("ancilis-benchmark-repos")

    def factory(file_count: int) -> SyntheticRepo:
        return _build_synthetic_repo(base, file_count)

    return factory


@pytest.fixture
def synthetic_repo_10_files(synthetic_repo_factory) -> SyntheticRepo:
    return synthetic_repo_factory(10)


@pytest.fixture
def synthetic_repo_100_files(synthetic_repo_factory) -> SyntheticRepo:
    return synthetic_repo_factory(100)


@pytest.fixture
def synthetic_repo_1000_files(synthetic_repo_factory) -> SyntheticRepo:
    return synthetic_repo_factory(1000)
