"""Click CLI entry point and subcommand registration."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import Any

import click

from ancilis.cli.status import status
from ancilis.cli.report import report
from ancilis.cli.remediate import remediate
from ancilis.cli.validate import migrate, validate
from ancilis.cli.approve import approve_tool
from ancilis.cli.doctor import doctor
from ancilis.cli.evidence import evidence
from ancilis.cli.export import export
from ancilis.cli.connect import connect
from ancilis.cli.scan import scan
from ancilis.cli.baseline import baseline
from ancilis.cli.init import init
from ancilis.cli.plugins import plugins
from ancilis.cli.shell import shell
from ancilis.cli.serve import serve
from ancilis.cli.sync import sync
from ancilis.cli.telemetry import telemetry


def _top_level_command(argv: list[str]) -> str:
    for token in argv:
        if token.startswith("-"):
            continue
        return token
    return "unknown"


class AncilisCLIGroup(click.Group):
    def main(
        self,
        args: Sequence[str] | None = None,
        prog_name: str | None = None,
        complete_var: str | None = None,
        standalone_mode: bool = True,
        **extra: Any,
    ) -> Any:
        tokens = list(args) if args is not None else sys.argv[1:]
        command = _top_level_command([str(token) for token in tokens])
        exit_code = 0

        try:
            return super().main(
                args=args,
                prog_name=prog_name,
                complete_var=complete_var,
                standalone_mode=standalone_mode,
                **extra,
            )
        except SystemExit as exc:
            exit_code = exc.code if isinstance(exc.code, int) else 1 if exc.code else 0
            raise
        except click.ClickException as exc:
            exit_code = exc.exit_code
            raise
        finally:
            if command != "telemetry":
                from ancilis.telemetry import record_telemetry_event

                record_telemetry_event("cli_command", {"command": command, "exit_code": exit_code})


@click.group(cls=AncilisCLIGroup)
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
    from ancilis.telemetry import maybe_prompt_for_telemetry_consent

    check_and_notify(ctx)
    if ctx.invoked_subcommand != "telemetry":
        maybe_prompt_for_telemetry_consent()

cli.add_command(status)
cli.add_command(report)
cli.add_command(remediate)
cli.add_command(approve_tool)
cli.add_command(doctor)
cli.add_command(evidence)
cli.add_command(export)
cli.add_command(connect)
cli.add_command(scan)
cli.add_command(baseline)
cli.add_command(init)
cli.add_command(plugins)
cli.add_command(shell)
cli.add_command(serve)
cli.add_command(sync)
cli.add_command(telemetry)


@cli.group(name="config")
def config_group() -> None:
    """Configuration management commands."""


config_group.add_command(validate)
config_group.add_command(migrate)


def main() -> None:
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
