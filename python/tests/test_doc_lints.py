"""Regression tests for the CI doc guards (audit findings F8, F12).

These run the lint scripts so the guards are exercised by the Python suite too,
not only in CI. The doc-count lint fails on stale control/overlay counts; the
hype lint fails on unsubstantiated marketing claims.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(script: str):
    spec = importlib.util.spec_from_file_location(f"_lint_{script}", ROOT / "scripts" / f"{script}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write(tmp_path: Path, rel: str, text: str) -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


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


# --- exemption boundaries (overlay reference pages cite framework subsets) ---


def test_doc_count_exempts_overlay_subset_but_not_general_docs(tmp_path: Path) -> None:
    lint = _load("check_doc_counts")
    # An overlay page legitimately maps a 26-control subset -> allowed.
    overlay = _write(tmp_path, "docs/overlays/soc2.mdx", "The overlay maps 26 AKSI controls.")
    assert lint.main([overlay]) == 0
    # The same phrasing in a general doc is the stale total -> flagged.
    general = _write(tmp_path, "docs/quickstart.mdx", "All 26 controls are active.")
    assert lint.main([general]) == 1


def test_hype_exempts_overlay_tamper_evident_but_not_general_docs(tmp_path: Path) -> None:
    lint = _load("check_hype")
    # Overlay page quoting a framework requirement, no mechanism -> allowed.
    overlay = _write(tmp_path, "docs/overlays/mas-trm.mdx", "MAS TRM requires tamper-evident logging.")
    assert lint.main([overlay]) == 0
    # General doc claiming tamper-evidence without the mechanism -> flagged.
    general = _write(tmp_path, "docs/evidence.mdx", "Ancilis evidence is tamper-evident.")
    assert lint.main([general]) == 1


def test_hype_bans_absolutes_even_on_overlay_pages(tmp_path: Path) -> None:
    lint = _load("check_hype")
    # The hard-banned absolutes are never exempt, including on overlay pages.
    overlay = _write(tmp_path, "docs/overlays/x.mdx", "Produces audit-grade, tamper-proof records.")
    assert lint.main([overlay]) == 1
