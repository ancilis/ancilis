"""ancilis plugins — plugin discovery and validation commands."""

from __future__ import annotations

import sys

import click

from ancilis.plugins import PluginRecord, PluginRegistry, PluginType


@click.group(name="plugins")
def plugins() -> None:
    """Plugin discovery and validation."""


@plugins.command(name="list")
@click.option(
    "--type",
    "plugin_type",
    type=click.Choice(["producer", "overlay", "adapter"]),
    default=None,
    help="Filter by plugin type.",
)
def plugins_list(plugin_type: PluginType | None) -> None:
    """List discovered Ancilis plugin entry points."""
    registry = PluginRegistry.discover()
    records = [
        record
        for record in registry.records
        if plugin_type is None or record.plugin_type == plugin_type
    ]
    _print_records(records)


@plugins.command(name="validate")
@click.argument("package_or_module")
def plugins_validate(package_or_module: str) -> None:
    """Validate Ancilis plugin entry points for an installed package or module."""
    registry = PluginRegistry.discover(package=package_or_module)
    if not registry.records:
        click.echo(f"No Ancilis plugin entry points found for {package_or_module}.", err=True)
        sys.exit(1)

    _print_records(registry.records)
    if registry.skipped():
        sys.exit(1)
    click.echo(f"Validated {len(registry.records)} Ancilis plugin entry point(s).")


def _print_records(records: list[PluginRecord]) -> None:
    if not records:
        click.echo("No Ancilis plugins discovered.")
        return

    click.echo(f"{'TYPE':<8}  {'NAME':<24}  {'PACKAGE':<24}  {'VERSION':<10}  STATUS")
    click.echo("-" * 90)
    for record in records:
        package = record.package_name or "-"
        version = record.package_version or "-"
        status = "compatible" if record.compatible else f"skipped: {record.skip_reason}"
        click.echo(
            f"{record.plugin_type:<8}  {record.name:<24}  {package:<24}  "
            f"{version:<10}  {status}"
        )
