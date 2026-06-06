"""Regression tests for the CI doc guards (audit findings F8, F12).

These run the lint scripts so the guards are exercised by the Python suite too,
not only in CI. The doc-count lint fails on stale control/overlay counts; the
hype lint fails on unsubstantiated marketing claims.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_doc_count_lint_passes() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_doc_counts.py")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_hype_lint_passes() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_hype.py")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
