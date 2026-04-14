"""ancilis evidence — evidence store management commands."""

from __future__ import annotations

import json
import sys

import click

from ancilis.config import load_config
from ancilis.evidence.store import EvidenceStore


@click.group()
def evidence() -> None:
    """Evidence store management commands."""


@evidence.command(name="verify")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option("--session-id", default=None, help="Scope verification output to a session")
@click.option("--json", "json_output", is_flag=True, help="Emit machine-readable JSON")
def evidence_verify(
    config_path: str | None,
    db_path: str | None,
    session_id: str | None,
    json_output: bool,
) -> None:
    """Verify evidence hash chain integrity."""
    try:
        config = load_config(path=config_path) if config_path else load_config()
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        click.echo("Suggested fix: pass --config path/to/ancilis.yaml", err=True)
        raise SystemExit(1) from None

    store = EvidenceStore(config, db_path=db_path)
    try:
        valid, errors = store.verify_chain(session_id=session_id)
        record_count = store.count(session_id=session_id)
    finally:
        store.close()

    if json_output:
        click.echo(
            json.dumps(
                {
                    "valid": valid,
                    "record_count": record_count,
                    "session_id": session_id,
                    "errors": errors,
                },
                sort_keys=True,
            )
        )
    elif valid:
        scope = f" for session {session_id}" if session_id else ""
        click.echo(f"Evidence chain valid{scope}: {record_count} record(s) verified.")
    else:
        scope = f" for session {session_id}" if session_id else ""
        click.echo(f"Evidence chain broken{scope}: {record_count} record(s) checked.", err=True)
        for error in errors:
            click.echo(f"- {error}", err=True)

    if not valid:
        raise SystemExit(1)


@evidence.command(name="sessions")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
def evidence_sessions(config_path: str | None, db_path: str | None) -> None:
    """List known evidence sessions with record counts and time ranges."""
    try:
        config = load_config(path=config_path) if config_path else load_config()
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        click.echo("Suggested fix: Run your agent with Ancilis middleware to collect evidence", err=True)
        raise SystemExit(1) from None

    store = EvidenceStore(config, db_path=db_path)
    try:
        sessions = store.list_sessions()
        if not sessions:
            click.echo("No sessions recorded yet.")
            return
        click.echo(f"{'SESSION ID':<40}  {'RECORDS':>7}  {'FIRST SEEN':<24}  {'LAST SEEN':<24}")
        click.echo("-" * 100)
        for s in sessions:
            click.echo(
                f"{s['session_id']:<40}  {s['count']:>7}  "
                f"{s['first_seen']:<24}  {s['last_seen']:<24}"
            )
    finally:
        store.close()


@evidence.command(name="reset")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def evidence_reset(config_path: str | None, db_path: str | None, yes: bool) -> None:
    """Clear ALL evidence records and restart the hash chain from genesis."""
    try:
        config = load_config(path=config_path) if config_path else load_config()
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        click.echo("Suggested fix: Run your agent with Ancilis middleware to collect evidence", err=True)
        raise SystemExit(1) from None

    if not yes:
        click.confirm(
            "This will permanently delete ALL evidence records and restart the hash chain. Continue?",
            abort=True,
        )

    store = EvidenceStore(config, db_path=db_path)
    try:
        n = store.reset()
        click.echo(f"Evidence store reset: {n} record(s) deleted. Hash chain restarted from genesis.")
    finally:
        store.close()


@evidence.command(name="import")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "fmt", type=click.Choice(["sarif", "cyclonedx", "auto"]), default="auto", show_default=True, help="Input format")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option("--agent-id", default="import", show_default=True, help="Agent ID to tag imported records")
def evidence_import(
    file: str,
    fmt: str,
    config_path: str | None,
    db_path: str | None,
    agent_id: str,
) -> None:
    """Import SARIF or CycloneDX findings into the evidence store."""
    import json as _json

    from ancilis.importers.sarif import SarifImporter
    from ancilis.importers.cyclonedx import CycloneDxImporter

    # Auto-detect format from extension
    if fmt == "auto":
        lower = file.lower()
        if lower.endswith(".sarif") or lower.endswith(".sarif.json"):
            fmt = "sarif"
        elif lower.endswith(".cdx.json") or lower.endswith(".bom.json") or "cyclonedx" in lower or "sbom" in lower:
            fmt = "cyclonedx"
        else:
            try:
                with open(file) as _f:
                    _sniff = _json.load(_f)
                if "runs" in _sniff:
                    fmt = "sarif"
                elif "bomFormat" in _sniff or "components" in _sniff:
                    fmt = "cyclonedx"
                else:
                    click.echo("Error: Cannot detect format. Use --format sarif|cyclonedx.", err=True)
                    sys.exit(1)
            except Exception as e:
                click.echo(f"Error reading file: {e}", err=True)
                sys.exit(1)

    try:
        if fmt == "sarif":
            importer: SarifImporter | CycloneDxImporter = SarifImporter(agent_id=agent_id)
        else:
            importer = CycloneDxImporter(agent_id=agent_id)
        evaluations = importer.parse(file)
    except Exception as e:
        click.echo(f"Error parsing {fmt} file: {e}", err=True)
        sys.exit(1)

    try:
        config = load_config(path=config_path) if config_path else load_config()
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        click.echo("Tip: pass --config path/to/ancilis.yaml or run from a directory with ancilis.yaml", err=True)
        sys.exit(1)

    store = EvidenceStore(config, db_path=db_path)
    try:
        stored = 0
        for evaluation in evaluations:
            store.store(evaluation, tool_name=file)
            stored += 1
        click.echo(f"Imported {stored} evidence record(s) from {fmt.upper()} file: {file}")
    finally:
        store.close()
