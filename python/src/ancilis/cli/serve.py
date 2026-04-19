"""CLI command for running Ancilis as an MCP server."""

from __future__ import annotations

import click

from ancilis.mcp_server import create_mcp_server


@click.command()
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(dir_okay=False, path_type=str),
    default=None,
    help="Path to ancilis.yaml. Defaults to auto-discovery in the current directory.",
)
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse"]),
    default="stdio",
    show_default=True,
    help="MCP transport to run.",
)
@click.option(
    "--port",
    type=int,
    default=8765,
    show_default=True,
    help="Port for future SSE transport support.",
)
def serve(config_path: str | None, transport: str, port: int) -> None:
    """Run Ancilis as an MCP tool server."""
    if transport == "sse":
        raise NotImplementedError(
            f"SSE transport is not implemented yet; requested port {port}."
        )

    server = create_mcp_server(config_path=config_path)
    server.run(transport="stdio")
