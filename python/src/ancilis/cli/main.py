"""Click CLI entry point and subcommand registration."""

from __future__ import annotations

import click

from ancilis.cli.status import status
from ancilis.cli.report import report
from ancilis.cli.validate import validate
from ancilis.cli.approve import approve_tool
from ancilis.cli.doctor import doctor
from ancilis.cli.evidence import evidence
from ancilis.cli.connect import connect
from ancilis.cli.scan import scan
from ancilis.cli.baseline import baseline
from ancilis.cli.init import init


@click.group()
@click.version_option(version="0.1.0", prog_name="ancilis")
def cli() -> None:
    """Ancilis — runtime policy enforcement for AI agents."""


cli.add_command(status)
cli.add_command(report)
cli.add_command(approve_tool)
cli.add_command(doctor)
cli.add_command(evidence)
cli.add_command(connect)
cli.add_command(scan)
cli.add_command(baseline)
cli.add_command(init)


@cli.group(name="config")
def config_group() -> None:
    """Configuration management commands."""


config_group.add_command(validate)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
