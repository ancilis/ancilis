"""Regression tests for generated scan-script templates (audit finding F2).

Every framework template must render to valid, runnable Python that uses the
real SDK API: it must NOT import a nonexistent top-level ``ancilis.Engine``,
call ``engine.evaluate()`` with no args, or read ``results.score/.total/.passed``.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from ancilis.cli.templates.scan_scripts import _FRAMEWORK_COMMENTS, get_scan_script

FRAMEWORKS = list(_FRAMEWORK_COMMENTS)
BAD_SYMBOLS = ("from ancilis import Engine", ".score", ".passed", ".total", "record_action")


@pytest.mark.parametrize("framework", FRAMEWORKS + ["unknown-falls-back-to-generic"])
def test_template_parses_and_avoids_broken_symbols(framework: str) -> None:
    src = get_scan_script(framework)
    ast.parse(src)  # raises SyntaxError on invalid Python
    for bad in BAD_SYMBOLS:
        assert bad not in src, f"{framework} template still references {bad!r}"
    # It must use the known-good submodule import.
    assert "from ancilis.engine import Engine" in src
    assert "ToolActionProducer" in src
    assert "get_summary" in src


def test_generated_script_runs_end_to_end(tmp_path: Path) -> None:
    """`ancilis init`-style generated script must run and exit 0 (no ImportError)."""
    (tmp_path / "ancilis.yaml").write_text(
        "agent:\n  name: smoke-agent\nsecurity:\n  tools:\n    allowed:\n      - lookup\n"
    )
    (tmp_path / "ancilis_scan.py").write_text(get_scan_script("langchain"))
    home = tmp_path / "home"
    home.mkdir()
    proc = subprocess.run(
        [sys.executable, "ancilis_scan.py"],
        cwd=tmp_path,
        env={"HOME": str(home), "PATH": __import__("os").environ.get("PATH", "")},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ImportError" not in proc.stderr
    assert "Evidence:" in proc.stdout
