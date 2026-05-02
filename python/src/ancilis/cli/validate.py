"""ancilis config validate — config validation with actionable errors."""

from __future__ import annotations

import click

from ancilis.config import (
    VALID_CONTROL_IDS,
    inspect_config_file_migration,
    load_config,
    load_taxonomy,
    migrate_config_file,
)
from ancilis.errors import ConfigError


VALID_CERT_TARGETS = ["aiuc-1"]


def _validate_and_format(config_path: str | None, *, verbose: bool = False) -> tuple[bool, str]:
    """Validate config and return (valid, message)."""
    lines: list[str] = []

    try:
        migration = inspect_config_file_migration(config_path) if config_path else None
        resolved = load_config(path=config_path) if config_path else load_config()
    except FileNotFoundError:
        return False, "\u2717 Config not found\n  No ancilis.yaml found in current directory.\n  Create one with: agent.name set to your agent's name."
    except (ValueError, ConfigError) as e:
        msg = str(e)
        lines.append("\u2717 Config invalid")
        lines.append(f"  {msg}")

        # Add actionable hints
        if "Unknown data type" in msg:
            taxonomy = load_taxonomy()
            valid_types = sorted(taxonomy["developer_type_mapping"].keys())
            lines.append(f"  Available types: {', '.join(valid_types)}")
        elif "Unknown control ID" in msg:
            lines.append(f"  Available controls: {', '.join(sorted(VALID_CONTROL_IDS))}")
        elif "agent.name" in msg:
            lines.append("  Fix: add 'agent: { name: my-agent }' to ancilis.yaml")

        return False, "\n".join(lines)
    except Exception as e:
        return False, f"\u2717 Config invalid\n  {e}"

    lines.append("\u2713 Config valid")
    lines.append(f"  Config version: {resolved.config_version}")
    lines.append(f"  Agent: {resolved.agent_name}")
    lines.append(f"  Mode: {resolved.mode}")
    if migration and migration["changed"]:
        lines.append(
            f"  Migration available: v{migration['original_version']} -> v{migration['current_version']}"
        )
        for change in migration["changes"]:
            lines.append(f"    - {change}")
        lines.append("    Run `ancilis config migrate --apply` to write the migrated config and backup.")

    # Activation summary
    activation_lines: list[str] = []
    if resolved.active_certifications:
        for cert_id in resolved.active_certifications:
            enabled_count = sum(1 for c in resolved.controls.values() if c.enabled)
            activation_lines.append(
                f"    certification_targets: [{cert_id}] \u2192 {cert_id.upper()} active, {enabled_count} controls"
            )
    if resolved.active_overlays:
        for _oid, oa in sorted(resolved.active_overlays.items()):
            trigger = ", ".join(oa.triggered_by) if oa.triggered_by else "explicit"
            activation_lines.append(f"    {oa.name} overlay active (triggered by {trigger})")

    if activation_lines:
        lines.append("  Activation:")
        lines.extend(activation_lines)

    enabled = sum(1 for c in resolved.controls.values() if c.enabled)
    strict = [
        c for c in resolved.controls.values()
        if c.enabled and c.threshold == "strict"
    ]
    controls_detail = f"  Controls: {enabled} active"
    if strict:
        strict_names = ", ".join(
            f"{c.control_id} at strict threshold"
            for c in strict
        )
        controls_detail += f" ({strict_names})"
    lines.append(controls_detail)

    # Unavailable overlays (roadmap)
    if resolved.unavailable_overlays:
        lines.append("  Roadmap overlays:")
        for uo in resolved.unavailable_overlays:
            lines.append(
                f"    ? {uo.overlay_id} would be activated by {uo.triggered_by} "
                f"via {uo.data_type} but is not yet available"
            )
        lines.append("    Baseline security controls are active for all data types.")

    if resolved.warnings:
        lines.append("  Warnings:")
        for w in resolved.warnings:
            lines.append(f"    ! {w}")

    if verbose:
        lines.append("  Schema:")
        lines.append("    shared/schemas/config.schema.json")

    return True, "\n".join(lines)


@click.command()
@click.argument("config_path_arg", required=False)
@click.option("--config", "config_path_option", default=None, help="Path to ancilis.yaml")
@click.option("--verbose", is_flag=True, default=False, help="Show schema and resolved config details")
def validate(config_path_arg: str | None, config_path_option: str | None, verbose: bool) -> None:
    """Validate ancilis.yaml configuration."""
    config_path = config_path_option if config_path_option is not None else config_path_arg
    valid, message = _validate_and_format(config_path, verbose=verbose)
    click.echo(message)
    if not valid:
        raise SystemExit(1)


@click.command()
@click.option("--config", "config_path", default="ancilis.yaml", help="Path to ancilis.yaml")
@click.option("--apply", "apply_changes", is_flag=True, default=False, help="Write migrated config and .bak backup")
def migrate(config_path: str, apply_changes: bool) -> None:
    """Preview or apply ancilis.yaml schema migration."""
    try:
        result = migrate_config_file(config_path, apply=apply_changes)
    except Exception as exc:
        click.echo(f"Config migration failed\n  {exc}")
        raise SystemExit(1) from exc

    if not result["changed"]:
        click.echo(f"Config already at version {result['current_version']}; no migration needed.")
        return

    if apply_changes:
        click.echo(
            f"Migrated {config_path} from v{result['original_version']} to v{result['current_version']}."
        )
    else:
        click.echo(
            f"Preview migration for {config_path}: v{result['original_version']} -> v{result['current_version']}."
        )
    for change in result["changes"]:
        click.echo(f"  - {change}")
    if apply_changes:
        click.echo(f"Backup written to {result.get('backup_path')}")
    else:
        click.echo("Run `ancilis config migrate --apply` to write these changes.")
