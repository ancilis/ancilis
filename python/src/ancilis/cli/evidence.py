"""ancilis evidence — evidence store management commands."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
import sys
from typing import Any

import click

from ancilis.config import load_config
from ancilis.evidence.query import (
    find_record,
    framework_mappings_for_record,
    list_rows_for_records,
    query_records,
)
from ancilis.evidence.store import EvidenceStore


@click.group()
def evidence() -> None:
    """Evidence store management commands."""


def _load_evidence_cli_config(
    config_path: str | None,
    db_path: str | None,
    *,
    fallback_agent_name: str = "evidence-cli",
) -> Any:
    try:
        if config_path is not None:
            return load_config(path=config_path)
        return load_config()
    except FileNotFoundError as e:
        if db_path is None or config_path is not None:
            click.echo(f"Error: {e}", err=True)
            click.echo("Suggested fix: pass --config path/to/ancilis.yaml", err=True)
            raise SystemExit(1) from None
        return load_config(raw={"agent": {"name": fallback_agent_name}})
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        click.echo("Suggested fix: pass --config path/to/ancilis.yaml", err=True)
        raise SystemExit(1) from None


def _json_dump(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def _format_record_pretty(record: Any) -> str:
    lines = [
        "Evidence Record",
        "---------------",
        f"Record ID: {record.record_id}",
        f"Evaluation ID: {record.evaluation_id}",
        f"Timestamp: {record.timestamp}",
        f"Agent ID: {record.agent_id}",
        f"Session ID: {record.session_id or '-'}",
        f"Source Type: {record.source_type}",
        f"Tool Name: {record.tool_name}",
        f"Decision: {record.decision}",
        f"Mode: {record.mode}",
        f"Record Hash: {record.record_hash}",
        f"Previous Hash: {record.previous_hash}",
        f"Total Duration (ms): {record.total_duration_ms}",
        f"Output Summary: {record.output_summary or '-'}",
        f"Tenant ID: {record.tenant_id or '-'}",
        f"SDK Version: {record.sdk_version or '-'}",
        f"Active Overlays: {', '.join(record.active_overlays) or '-'}",
        f"Active Certifications: {', '.join(record.active_certifications) or '-'}",
        f"Data Classifications: {', '.join(record.data_classifications) or '-'}",
        f"Detected Data Types: {', '.join(record.detected_data_types) or '-'}",
    ]
    if record.classification_context:
        lines.extend([
            "",
            "Classification Context:",
            _json_dump(record.classification_context),
        ])

    mappings = framework_mappings_for_record(record)
    lines.extend(["", "Control Results:"])
    for result in record.control_results:
        control_id = result.get("control_id", "")
        lines.append(
            f"- {control_id} {result.get('result', 'UNKNOWN')} "
            f"({result.get('control_name', control_id)})"
        )
        lines.append(f"  Detail: {result.get('detail', '-')}")
        lines.append("  Evidence:")
        for line in _json_dump(result.get("evidence_data", {})).splitlines():
            lines.append(f"    {line}")

        control_mappings = mappings.get(str(control_id), [])
        if control_mappings:
            lines.append("  Framework Mappings:")
            for mapping in control_mappings:
                refs = ", ".join(mapping.references)
                lines.append(f"    - {mapping.source_id} ({mapping.source_name}): {refs}")

    return "\n".join(lines)


@evidence.command(name="list")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option("--limit", default=20, show_default=True, type=click.IntRange(min=1))
@click.option("--since", default=None, help="Only include records at or after this ISO8601 timestamp")
@click.option("--agent-id", default=None, help="Filter to a single agent ID")
@click.option("--classification", default=None, help="Filter by data classification code")
@click.option("--control-id", default=None, help="Filter by AKSI control ID")
@click.option(
    "--format",
    "output_format",
    default="table",
    show_default=True,
    type=click.Choice(["json", "table"]),
)
def evidence_list(
    config_path: str | None,
    db_path: str | None,
    limit: int,
    since: str | None,
    agent_id: str | None,
    classification: str | None,
    control_id: str | None,
    output_format: str,
) -> None:
    """List evidence records from the configured evidence store."""
    config = _load_evidence_cli_config(config_path, db_path)
    store = EvidenceStore(config, db_path=db_path)
    try:
        records = query_records(
            store,
            agent_id=agent_id,
            since=since,
            classification=classification,
            control_id=control_id,
            limit=limit,
        )
    finally:
        store.close()

    if not records:
        click.echo("No evidence records found.")
        return

    if output_format == "json":
        click.echo(_json_dump([asdict(record) for record in records]))
        return

    rows = list_rows_for_records(records, control_id=control_id)
    if not rows:
        click.echo("No evidence records found.")
        return

    click.echo(
        f"{'timestamp':<25}  {'evidence_id':<11}  {'agent_id':<20}  "
        f"{'source_type':<11}  {'classification':<20}  {'control_id':<10}  {'status':<6}"
    )
    click.echo("-" * 110)
    for row in rows:
        click.echo(
            f"{row.timestamp:<25}  {row.evidence_id[:7]:<11}  {row.agent_id:<20}  "
            f"{row.source_type:<11}  {row.classification:<20}  "
            f"{row.control_id:<10}  {row.status:<6}"
        )


@evidence.command(name="show")
@click.argument("evidence_id")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option(
    "--format",
    "output_format",
    default="pretty",
    show_default=True,
    type=click.Choice(["json", "pretty"]),
)
def evidence_show(
    evidence_id: str,
    config_path: str | None,
    db_path: str | None,
    output_format: str,
) -> None:
    """Show a full evidence record by exact ID or short prefix."""
    config = _load_evidence_cli_config(config_path, db_path)
    store = EvidenceStore(config, db_path=db_path)
    try:
        try:
            record = find_record(store, evidence_id)
        except LookupError as e:
            click.echo(f"Error: {e}", err=True)
            raise SystemExit(1) from None
        except ValueError as e:
            click.echo(f"Error: {e}", err=True)
            raise SystemExit(1) from None
    finally:
        store.close()

    if output_format == "json":
        click.echo(_json_dump(asdict(record)))
        return

    click.echo(_format_record_pretty(record))


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
    except FileNotFoundError as e:
        if config_path is not None or db_path is None:
            click.echo(f"Error: {e}", err=True)
            click.echo("Suggested fix: pass --config path/to/ancilis.yaml", err=True)
            raise SystemExit(1) from None
        config = load_config(raw={"agent": {"name": "evidence-verify"}})
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        click.echo("Suggested fix: pass --config path/to/ancilis.yaml", err=True)
        raise SystemExit(1) from None

    store = EvidenceStore(config, db_path=db_path)
    try:
        report = store.verify_chain_report(session_id=session_id)
        record_count = store.count(session_id=session_id)
    finally:
        store.close()

    valid = report.valid
    errors = report.errors

    if json_output:
        click.echo(
            json.dumps(
                {
                    "valid": valid,
                    "status": report.status,
                    "record_count": record_count,
                    "verified": report.verified_count,
                    "legacy_unverified": report.legacy_unverified_count,
                    "reset_events": report.reset_events,
                    "purge_events": report.purge_events,
                    "session_id": session_id,
                    "errors": errors,
                },
                sort_keys=True,
            )
        )
    elif valid:
        scope = f" for session {session_id}" if session_id else ""
        # Be explicit: keyed (v2) records are cryptographically verified; legacy
        # (v1, pre-key) records are reported as legacy-unverified, never as a
        # silent pass.
        parts: list[str] = []
        if report.verified_count:
            parts.append(f"{report.verified_count} cryptographically verified (HMAC)")
        if report.legacy_unverified_count:
            parts.append(
                f"{report.legacy_unverified_count} legacy-unverified "
                f"(pre-migration v1, not key-attestable)"
            )
        detail = "; ".join(parts) if parts else f"{record_count} record(s)"
        click.echo(f"Evidence chain intact{scope}: {detail}.")
        if report.reset_events or report.purge_events:
            click.echo(
                f"  Audit log: {report.reset_events} reset, "
                f"{report.purge_events} purge checkpoint(s) recorded."
            )
        if report.legacy_unverified_count:
            click.echo(
                "  Set ANCILIS_CHAIN_KEY to write keyed (v2) records; existing "
                "legacy records remain reported as legacy-unverified."
            )
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


@evidence.command(name="prune")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option(
    "--days",
    "days",
    type=int,
    default=None,
    help="Override retention window in days (default: config evidence_retention_days).",
)
@click.option(
    "--before",
    "before",
    default=None,
    help="Explicit ISO timestamp cutoff; delete records strictly older than this. Overrides --days.",
)
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def evidence_prune(
    config_path: str | None,
    db_path: str | None,
    days: int | None,
    before: str | None,
    yes: bool,
) -> None:
    """Delete evidence records older than the retention window.

    Enforces the retention policy reported by ``ancilis report`` (the
    ``retention_met`` line). By default it removes records older than the
    resolved ``evidence_retention_days``; use ``--days`` to override or
    ``--before`` for an explicit ISO cutoff. This is the command referenced by
    the evidence-cache size warning and ``ancilis doctor``.
    """
    config = _load_evidence_cli_config(config_path, db_path)

    if before is not None:
        cutoff = before
        window_desc = f"older than {before}"
    else:
        retention_days = (
            days if days is not None else getattr(config, "evidence_retention_days", 365)
        )
        if not retention_days or retention_days <= 0:
            click.echo(
                "No positive retention window is configured "
                "(evidence_retention_days). Pass --days N or --before <iso> to prune.",
                err=True,
            )
            raise SystemExit(1)
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        window_desc = f"older than {retention_days} days (before {cutoff})"

    if not yes:
        click.confirm(
            f"This will permanently delete evidence records {window_desc}. Continue?",
            abort=True,
        )

    store = EvidenceStore(config, db_path=db_path)
    try:
        n = store.purge_before(cutoff)
        click.echo(f"Evidence pruned: {n} record(s) {window_desc} deleted.")
        if n:
            click.echo(
                "Note: a partial prune removes the oldest records, so `ancilis evidence "
                "verify` will report a chain gap at the new earliest record until the "
                "surviving chain is re-anchored. Run it to confirm the remaining state."
            )
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
