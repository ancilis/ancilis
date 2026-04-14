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
from ancilis.cli.plugins import plugins
from ancilis.cli.shell import shell


@click.group()
@click.version_option(version="0.1.0", prog_name="ancilis")
@click.option("--no-update-check", is_flag=True, default=False, hidden=True,
              help="Suppress update check.")
@click.pass_context
def cli(ctx: click.Context, no_update_check: bool) -> None:
    """Ancilis — runtime policy enforcement for AI agents."""
    ctx.ensure_object(dict)
    ctx.obj["no_update_check"] = no_update_check
    ctx.params["no_update_check"] = no_update_check
    from ancilis.cli.version_check import check_and_notify
    check_and_notify(ctx)


cli.add_command(status)
cli.add_command(report)
cli.add_command(approve_tool)
cli.add_command(doctor)
cli.add_command(evidence)
cli.add_command(connect)
cli.add_command(scan)
cli.add_command(baseline)
cli.add_command(init)
cli.add_command(plugins)
cli.add_command(shell)


@cli.group(name="config")
def config_group() -> None:
    """Configuration management commands."""


config_group.add_command(validate)


def main() -> None:
    import sys
    from ancilis.errors import AncilisError, print_error

    try:
        cli()
    except SystemExit:
        raise
    except AncilisError as exc:
        print_error(exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
