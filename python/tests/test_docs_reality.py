"""Regression tests for docs-vs-reality fixes (audit findings F9, F10, F11)."""

from __future__ import annotations

import re
from pathlib import Path

from ancilis import ToolActionProducer, load_config
from ancilis.cli.status import _format_status
from ancilis.engine.engine import Engine
from ancilis.evidence.store import EvidenceStore

ROOT = Path(__file__).resolve().parents[2]
_EXCLUDE = {".venv", ".worktrees", "node_modules", "dist", ".demo-venv"}


# --- F9: README 30-second quickstart status sample matches real output --------


def _quickstart_status(tmp_path) -> str:
    config = load_config(
        raw={
            "agent": {"name": "my-agent"},
            "security": {"tools": {"allowed": ["search_docs", "send_reply"]}},
        }
    )
    engine = Engine(config)
    evidence = EvidenceStore(config, db_path=str(tmp_path / "q.duckdb"))
    producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)

    def search_docs(query: str) -> dict:
        return {"query": query}

    search_docs = producer.wrap_tool(search_docs, tool_name="search_docs")
    search_docs("account billing")
    try:
        return _format_status(config, evidence, verbose=False, session_id=producer.session_id)
    finally:
        evidence.close()


def _readme_quickstart_sample_lines() -> list[str]:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    # The 30-second quickstart status sample is the ```text block right after
    # the "Check posture:" / `ancilis status` heading.
    block = re.search(r"ancilis status\s*```\s*```text\n(.*?)```", text, re.S)
    assert block, "Could not find the quickstart status sample block in README"
    return [ln.rstrip() for ln in block.group(1).splitlines() if ln.strip()]


def test_readme_quickstart_status_sample_matches_real_output(tmp_path) -> None:
    real = _quickstart_status(tmp_path)
    sample = _readme_quickstart_sample_lines()
    # The documented Controls/Tool-calls/Sync lines must be exact substrings of
    # the real status output — no fabrication.
    for prefix in ("Controls:", "Tool calls:", "Sync:"):
        line = next(ln for ln in sample if ln.strip().startswith(prefix))
        assert line.strip() in real, f"README {prefix} line not in real output:\n{real}"
    # And the headline can never read "all passing" given pending/flagged controls.
    controls_line = next(ln for ln in sample if ln.strip().startswith("Controls:"))
    assert "all passing" not in controls_line


def _payment_status(tmp_path) -> str:
    config = load_config(
        raw={
            "agent": {"name": "payment-agent"},
            "certification_targets": ["aiuc-1"],
            "my_agent_handles": ["credit_cards", "personal_info"],
        }
    )
    engine = Engine(config)
    evidence = EvidenceStore(config, db_path=str(tmp_path / "p.duckdb"))
    producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)

    def charge(amount: str) -> dict:
        return {"ok": amount}

    charge = producer.wrap_tool(charge, tool_name="charge")
    charge("10.00")
    try:
        return _format_status(config, evidence, verbose=False, session_id=producer.session_id)
    finally:
        evidence.close()


def test_readme_payment_agent_status_sample_matches_real_output(tmp_path) -> None:
    real = _payment_status(tmp_path)
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    block = re.search(r"```text\nAncilis — payment-agent\n(.*?)```", text, re.S)
    assert block, "Could not find the payment-agent status sample in README"
    sample = [ln.rstrip() for ln in block.group(1).splitlines() if ln.strip()]
    controls_line = next(ln for ln in sample if ln.strip().startswith("Controls:"))
    assert controls_line.strip() in real, f"README payment Controls line not in real output:\n{real}"
    assert "all passing" not in controls_line
    # Overlays are triggered by data declarations, not the certification target.
    assert "SOC 2 Type II: active — triggered by personal_info declaration" in real


# --- F10: single documentation domain ----------------------------------------


def test_no_stale_docs_domain_remains() -> None:
    roots = [
        ROOT / "README.md",
        ROOT / "docs",
        ROOT / "python" / "src",
        ROOT / "typescript" / "src",
        ROOT / "examples",
    ]
    offenders: list[str] = []
    for root in roots:
        files = [root] if root.is_file() else list(root.rglob("*"))
        for f in files:
            if not f.is_file() or _EXCLUDE & set(f.parts):
                continue
            if f.suffix not in {".md", ".mdx", ".py", ".ts", ".yaml", ".yml"}:
                continue
            if "docs.ancilis.dev" in f.read_text(encoding="utf-8", errors="ignore"):
                offenders.append(str(f.relative_to(ROOT)))
    assert not offenders, f"stale docs.ancilis.dev domain remains in: {offenders}"


# --- F11: limitations.md reconciles the optional platform ---------------------


def test_limitations_reconciles_platform() -> None:
    text = (ROOT / "docs" / "limitations.md").read_text(encoding="utf-8")
    # The optional platform path must be acknowledged...
    assert "ancilis connect" in text
    assert "ancilis sync" in text
    # ...and the doc must no longer claim an unqualified absence of cloud sync.
    assert "no cloud sync" not in text.lower()
