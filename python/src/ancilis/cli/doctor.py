"""ancilis doctor — lightweight local installation/runtime checks."""

from __future__ import annotations

from importlib import import_module
from importlib.metadata import version
from pathlib import Path
import shutil

import click

from ancilis._shared import shared_path
from ancilis.config import load_config, load_control_definitions, load_taxonomy
from ancilis.evidence.store import EvidenceStore


def _check_config(config_path: str | None) -> tuple[bool, str, object | None]:
    try:
        config = load_config(path=config_path) if config_path else load_config()
        return True, f"loaded for agent '{config.agent_name}' in {config.mode} mode", config
    except Exception as exc:  # pragma: no cover - exercised by CLI tests
        return False, str(exc), None


@click.command()
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
def doctor(config_path: str | None, db_path: str | None) -> None:
    """Run a practical local setup check for the Ancilis CLI and runtime assets."""
    lines: list[str] = []
    failures = 0

    try:
        pkg_version = version("ancilis")
    except Exception:
        pkg_version = "0.1.0"
    lines.append(f"Ancilis doctor — version {pkg_version}")

    ok, detail, config = _check_config(config_path)
    lines.append(f"[{'OK' if ok else 'FAIL'}] config: {detail}")
    if not ok:
        failures += 1

    try:
        taxonomy = load_taxonomy()
        controls = load_control_definitions()
        lines.append(f"[OK] assets: taxonomy {taxonomy.get('version', 'unknown')}, {len(controls)} controls available")
    except Exception as exc:
        failures += 1
        lines.append(f"[FAIL] assets: {exc}")

    if config is not None:
        store = EvidenceStore(config, db_path=db_path)
        try:
            db_target = Path(store.db_path if store.db_path != ':memory:' else '.').expanduser()
            db_dir = db_target.parent if db_target.name else db_target
            db_dir.mkdir(parents=True, exist_ok=True)
            probe = db_dir / '.ancilis-write-test'
            probe.write_text('ok')
            probe.unlink()
            summary = store.get_summary()
            lines.append(f"[OK] evidence: path {store.db_path} usable, {summary.get('total_evaluations', 0)} records present")
        except Exception as exc:
            failures += 1
            lines.append(f"[FAIL] evidence: {exc}")
        finally:
            store.close()

    try:
        import_module('mcp')
        lines.append('[OK] optional mcp extra: installed')
    except ImportError:
        lines.append('[WARN] optional mcp extra: not installed (install with pip install ancilis[mcp] for MCP middleware)')

    if shutil.which("pandoc"):
        lines.append('[OK] pdf reporting dependency: pandoc executable detected')
    else:
        lines.append('[WARN] pdf reporting dependency: PDF export falls back to markdown when pandoc/xelatex are unavailable')

    click.echo("\n".join(lines))
    if failures:
        raise SystemExit(1)
