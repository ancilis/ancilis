"""ancilis attest — manual attestation evidence commands."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from typing import Any

import click

from ancilis.config import load_config
from ancilis.engine.evaluators.attestation import (
    ATTESTATION_CONTROL_SPECS,
    AttestationSpec,
    get_attestation_state,
    latest_attestation_event,
    record_attestation,
)
from ancilis.evidence.store import EvidenceStore


@click.group()
def attest() -> None:
    """Manual attestation evidence commands."""


def _load_attest_config(
    config_path: str | None,
    db_path: str | None,
    *,
    fallback_agent_name: str = "attest-cli",
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


def _require_spec(control_id: str) -> AttestationSpec:
    normalized = control_id.upper()
    spec = ATTESTATION_CONTROL_SPECS.get(normalized)
    if spec is None:
        click.echo(f"No attestation evaluator registered for {normalized}.", err=True)
        raise SystemExit(1) from None
    return spec


def _parse_fields(raw_fields: tuple[str, ...]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for raw in raw_fields:
        if "=" not in raw:
            click.echo("Fields must use key=value syntax.", err=True)
            raise SystemExit(1) from None
        key, value = raw.split("=", 1)
        key = key.strip()
        if not key:
            click.echo("Fields must use key=value syntax.", err=True)
            raise SystemExit(1) from None
        fields[key] = value.strip()
    return fields


def _agent_id(config: Any, explicit_agent_id: str | None) -> str:
    return explicit_agent_id or getattr(config, "agent_id", None) or getattr(config, "agent_name", "") or "org"


def _attested_by(config: Any, explicit_by: str | None) -> str:
    return explicit_by or getattr(config, "agent_owner", "") or os.environ.get("USER") or "unknown"


def _validate_required_fields(spec: AttestationSpec, fields: dict[str, str]) -> list[str]:
    return [
        field
        for field in spec.required_evidence_fields
        if not str(fields.get(field, "")).strip()
    ]


@attest.command(name="list")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option(
    "--format",
    "output_format",
    default="table",
    show_default=True,
    type=click.Choice(["json", "table"]),
)
def attest_list(
    config_path: str | None,
    db_path: str | None,
    output_format: str,
) -> None:
    """List AKSI controls that require manual attestation."""
    config = _load_attest_config(config_path, db_path)
    store = EvidenceStore(config, db_path=db_path)
    try:
        states = [
            get_attestation_state(
                store,
                spec,
                agent_id=getattr(config, "agent_id", None) or getattr(config, "agent_name", None)
                if spec.per_agent
                else None,
            )
            for spec in ATTESTATION_CONTROL_SPECS.values()
        ]
    finally:
        store.close()

    if output_format == "json":
        click.echo(_json_dump([asdict(state) for state in states]))
        return

    click.echo(
        f"{'control_id':<10}  {'status':<15}  {'last_attested_at':<32}  "
        f"{'attested_by':<24}  {'required_fields'}"
    )
    click.echo("-" * 118)
    for state in states:
        click.echo(
            f"{state.control_id:<10}  {state.status:<15}  "
            f"{state.attested_at or '-':<32}  {state.attested_by or '-':<24}  "
            f"{', '.join(state.required_fields)}"
        )


@attest.command(name="show")
@click.argument("control_id")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option(
    "--format",
    "output_format",
    default="pretty",
    show_default=True,
    type=click.Choice(["json", "pretty"]),
)
def attest_show(
    control_id: str,
    config_path: str | None,
    db_path: str | None,
    output_format: str,
) -> None:
    """Show the latest manual attestation for an AKSI control."""
    spec = _require_spec(control_id)
    config = _load_attest_config(config_path, db_path)
    store = EvidenceStore(config, db_path=db_path)
    try:
        state = get_attestation_state(
            store,
            spec,
            agent_id=getattr(config, "agent_id", None) or getattr(config, "agent_name", None)
            if spec.per_agent
            else None,
        )
    finally:
        store.close()

    if output_format == "json":
        click.echo(_json_dump(asdict(state)))
        return

    click.echo(f"Attestation: {spec.control_id} ({spec.control_name})")
    click.echo("-" * 72)
    click.echo("Required Fields:")
    for field in spec.required_evidence_fields:
        click.echo(f"- {field}")
    if spec.optional_evidence_fields:
        click.echo("Optional Fields:")
        for field in spec.optional_evidence_fields:
            click.echo(f"- {field}")

    if state.record_id is None or state.revoked:
        click.echo("")
        click.echo("No attestation recorded.")
        return

    click.echo("")
    click.echo("Latest Attestation")
    click.echo(f"Record ID: {state.record_id}")
    click.echo(f"Status: {state.status}")
    click.echo(f"Attested At: {state.attested_at}")
    click.echo(f"Attested By: {state.attested_by or '-'}")
    if state.missing_fields:
        click.echo(f"Missing Fields: {', '.join(state.missing_fields)}")
    click.echo("Fields:")
    for key, value in sorted((state.fields or {}).items()):
        click.echo(f"  {key}: {value}")


@attest.command(name="record")
@click.argument("control_id")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option("--field", "raw_fields", multiple=True, help="Attestation field as key=value")
@click.option("--by", "attested_by", default=None, help="Identity recording the attestation")
@click.option("--agent-id", default=None, help="Agent or organization identity for the evidence")
def attest_record(
    control_id: str,
    config_path: str | None,
    db_path: str | None,
    raw_fields: tuple[str, ...],
    attested_by: str | None,
    agent_id: str | None,
) -> None:
    """Record manual attestation evidence for an AKSI control."""
    spec = _require_spec(control_id)
    config = _load_attest_config(config_path, db_path)
    fields = _parse_fields(raw_fields)
    effective_agent_id = _agent_id(config, agent_id)
    if spec.per_agent:
        fields.setdefault("agent_id", effective_agent_id)
    missing = _validate_required_fields(spec, fields)
    if missing:
        click.echo(
            "Missing required attestation fields: " + ", ".join(missing),
            err=True,
        )
        raise SystemExit(1) from None

    store = EvidenceStore(config, db_path=db_path)
    try:
        record = record_attestation(
            store,
            config,
            spec,
            fields=fields,
            attested_by=_attested_by(config, attested_by),
            agent_id=effective_agent_id,
        )
    finally:
        store.close()

    click.echo(f"Attestation recorded for {spec.control_id}: {record.record_id}")


@attest.command(name="revoke")
@click.argument("control_id")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option("--by", "attested_by", default=None, help="Identity revoking the attestation")
@click.option("--agent-id", default=None, help="Agent or organization identity for the evidence")
def attest_revoke(
    control_id: str,
    config_path: str | None,
    db_path: str | None,
    attested_by: str | None,
    agent_id: str | None,
) -> None:
    """Revoke the latest manual attestation for an AKSI control."""
    spec = _require_spec(control_id)
    config = _load_attest_config(config_path, db_path)
    effective_agent_id = _agent_id(config, agent_id)
    store = EvidenceStore(config, db_path=db_path)
    try:
        latest = latest_attestation_event(
            store,
            spec.control_id,
            agent_id=effective_agent_id if spec.per_agent else None,
            per_agent=spec.per_agent,
        )
        if latest is None or latest.data.get("revoked"):
            click.echo(f"No active attestation found for {spec.control_id}.", err=True)
            raise SystemExit(1) from None
        fields = latest.data.get("fields", {})
        if not isinstance(fields, dict):
            fields = {}
        record = record_attestation(
            store,
            config,
            spec,
            fields={str(key): str(value) for key, value in fields.items()},
            attested_by=_attested_by(config, attested_by),
            agent_id=effective_agent_id,
            revoked=True,
            revoked_record_id=latest.record.record_id,
        )
    finally:
        store.close()

    click.echo(
        f"Attestation revoked for {spec.control_id}: {latest.record.record_id} "
        f"(revocation record {record.record_id})"
    )


if __name__ == "__main__":
    try:
        attest()
    except KeyboardInterrupt:
        sys.exit(130)
