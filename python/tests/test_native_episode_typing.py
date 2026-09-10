"""Static-regression coverage for the native episode public type contract."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "python/tests/typecheck"


def _mypy(fixture: str) -> subprocess.CompletedProcess[str]:
    source = str(ROOT / "python/src")
    environment = os.environ | {"PYTHONPATH": source, "MYPYPATH": source}
    return subprocess.run(
        [sys.executable, "-m", "mypy", "--no-incremental", "--strict", str(FIXTURES / fixture)],
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        capture_output=True,
    )


def test_native_episode_public_api_typechecks() -> None:
    result = _mypy("native_episode_public_api.py")
    assert result.returncode == 0, result.stdout + result.stderr


def test_native_episode_public_dict_values_are_not_any() -> None:
    result = _mypy("native_episode_invalid_api.py")
    assert result.returncode != 0
    assert "Incompatible types in assignment" in result.stdout
