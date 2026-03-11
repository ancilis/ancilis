"""ancilis config validate — config validation with actionable errors."""

from __future__ import annotations

import click
import yaml

from ancilis.config import load_config, load_taxonomy


VALID_CERT_TARGETS = ["aiuc-1"]


def _validate_and_format(config_path: str | None) -> tuple[bool, str]:
    """Validate config and return (valid, message)."""
    lines: list[str] = []

    try:
        resolved = load_config(path=config_path) if config_path else load_config()
    except FileNotFoundError:
        return False, "\u2717 Config not found\n  No ancilis.yaml found in current directory.\n  Create one with: agent.name set to your agent's name."
    except ValueError as e:
        msg = str(e)
        lines.append(f"\u2717 Config invalid")
        lines.append(f"  {msg}")

        # Add actionable hints
        if "Unknown data type" in msg:
            taxonomy = load_taxonomy()
            valid_types = sorted(taxonomy["developer_type_mapping"].keys())
            lines.append(f"  Available types: {', '.join(valid_types)}")
        elif "Unknown control ID" in msg:
            lines.append("  Available controls: PR-01, PR-02, PR-03, PR-04, PR-05, DE-01")
        elif "agent.name" in msg:
            lines.append("  Fix: add 'agent: { name: my-agent }' to ancilis.yaml")

        return False, "\n".join(lines)
    except Exception as e:
        return False, f"\u2717 Config invalid\n  {e}"

    lines.append("\u2713 Config valid")
    lines.append(f"  Agent: {resolved.agent_name}")
    lines.append(f"  Mode: {resolved.mode}")

    # Activation summary
    activation_lines: list[str] = []
    if resolved.active_certifications:
        for cert_id in resolved.active_certifications:
            enabled_count = sum(1 for c in resolved.controls.values() if c.enabled)
            activation_lines.append(
                f"    certification_targets: [{cert_id}] \u2192 {cert_id.upper()} active, {enabled_count} controls"
            )
    if resolved.active_overlays:
        for oid, oa in sorted(resolved.active_overlays.items()):
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

    if resolved.warnings:
        lines.append("  Warnings:")
        for w in resolved.warnings:
            lines.append(f"    ! {w}")

    return True, "\n".join(lines)


@click.command()
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
def validate(config_path: str | None) -> None:
    """Validate ancilis.yaml configuration."""
    valid, message = _validate_and_format(config_path)
    click.echo(message)
    if not valid:
        raise SystemExit(1)
