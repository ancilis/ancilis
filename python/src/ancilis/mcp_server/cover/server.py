"""FastMCP server for deterministic Ancilis Cover onboarding tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, cast

import click
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from ancilis.mcp_server import (
    MCPServerContext,
    build_mcp_context,
    register_runtime_tools,
)
from ancilis.mcp_server.cover.classification import classify_project
from ancilis.mcp_server.cover.code_review import review_code
from ancilis.mcp_server.cover.gap_assessment import assess_gap
from ancilis.mcp_server.cover.models import ProjectClassification, ProjectInspection
from ancilis.mcp_server.cover.project import inspect_project
from ancilis.mcp_server.cover.recommendations import recommend_setup
from ancilis.mcp_server.cover.report import render_onboarding_report


def _json_response(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")


def _soc2_only_business_target(
    business_context: str | None,
    target_overlays: list[str] | None,
) -> bool:
    if target_overlays is not None or business_context is None:
        return False
    context = business_context.lower()
    if "gdpr" in context or "european union" in context or "data subject" in context:
        return False
    return "soc2" in context or "soc 2" in context


def register_cover_tools(
    server: FastMCP,
    *,
    runtime_context: MCPServerContext | None = None,
) -> None:
    """Register deterministic Cover onboarding and gap tools on an existing server."""
    @server.tool(name="ancilis_inspect_project")
    async def ancilis_inspect_project(
        root: str | None = None,
        max_files: int = 200,
        include_hidden: bool = False,
    ) -> dict[str, Any]:
        """Inspect local project metadata and likely Ancilis integration paths."""
        return _json_response(
            inspect_project(
                root,
                max_files=max_files,
                include_hidden=include_hidden,
            )
        )

    @server.tool(name="ancilis_classify_project")
    async def ancilis_classify_project(
        root: str | None = None,
        description: str | None = None,
        signals: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Classify likely data handled by a project using deterministic rules."""
        return _json_response(
            classify_project(
                root,
                description=description,
                signals=signals,
            )
        )

    @server.tool(name="ancilis_recommend_setup")
    async def ancilis_recommend_setup(
        root: str | None = None,
        project: dict[str, Any] | None = None,
        classification: dict[str, Any] | None = None,
        project_name: str | None = None,
        language: str = "auto",
    ) -> dict[str, Any]:
        """Return read-only setup guidance for adding Ancilis."""
        return _json_response(
            recommend_setup(
                root=root,
                project=project,
                classification=classification,
                project_name=project_name,
                language=language,
            )
        )

    @server.tool(name="ancilis_review_code")
    async def ancilis_review_code(
        root: str | None = None,
        paths: list[str] | None = None,
        snippets: list[dict[str, str]] | None = None,
        max_bytes_per_file: int = 60000,
    ) -> dict[str, Any]:
        """Review explicit files or snippets for onboarding-relevant Ancilis signals."""
        return _json_response(
            review_code(
                root,
                paths=paths,
                snippets=snippets,
                max_bytes_per_file=max_bytes_per_file,
            )
        )

    @server.tool(name="ancilis_onboarding_report")
    async def ancilis_onboarding_report(
        root: str | None = None,
        description: str | None = None,
        include_code_review: bool = False,
        paths: list[str] | None = None,
    ) -> dict[str, Any]:
        """Generate a concise deterministic onboarding report."""
        inspection = inspect_project(root)
        classification = classify_project(
            root,
            description=description,
            signals=inspection.signals,
        )
        setup = recommend_setup(
            project=inspection,
            classification=classification,
            language="auto",
        )
        review = (
            review_code(root, paths=paths)
            if include_code_review
            else None
        )
        summary = _report_summary(inspection, classification)
        next_steps = setup.next_steps
        if review is not None and review.findings:
            next_steps = [*next_steps, "Review code findings before enabling enforce mode."]
        report_markdown = render_onboarding_report(
            summary=summary,
            next_steps=next_steps,
            confidence=classification.confidence,
        )
        return {
            "report_markdown": report_markdown,
            "summary": summary,
            "next_steps": next_steps,
            "confidence": classification.confidence,
        }

    @server.tool(name="ancilis_assess_gap")
    async def ancilis_assess_gap(
        root: str | None = None,
        business_context: str | None = None,
        target_data_types: list[str] | None = None,
        target_overlays: list[str] | None = None,
        target_certifications: list[str] | None = None,
        session_id: str | None = None,
        include_code_review: bool = False,
        paths: list[str] | None = None,
    ) -> dict[str, Any]:
        """Assess setup and evidence gaps for a business compliance target."""
        result = assess_gap(
            root,
            business_context=business_context,
            target_data_types=target_data_types,
            target_overlays=target_overlays,
            target_certifications=target_certifications,
            session_id=session_id,
            include_code_review=include_code_review,
            paths=paths,
            runtime_context=runtime_context,
        )
        if _soc2_only_business_target(business_context, target_overlays):
            result = assess_gap(
                root,
                target_data_types=result.target.my_agent_handles,
                target_overlays=["soc2"],
                target_certifications=result.target.certification_targets,
                session_id=session_id,
                include_code_review=include_code_review,
                paths=paths,
                runtime_context=runtime_context,
            )
        return _json_response(
            result
        )


def _default_cover_config() -> dict[str, Any]:
    return {
        "agent": {"name": "ancilis-cover-preview"},
        "security": {"mode": "audit"},
    }


def create_cover_mcp_server(
    config_path: str | None = None,
    context: MCPServerContext | None = None,
) -> FastMCP:
    """Create the official Ancilis Cover local MCP server."""
    default_raw_config = _default_cover_config() if config_path is None else None
    runtime_context = build_mcp_context(
        config_path=config_path,
        context=context,
        default_raw_config=default_raw_config,
    )
    server = FastMCP(name="ancilis-cover")
    register_cover_tools(server, runtime_context=runtime_context)
    register_runtime_tools(server, runtime_context)
    return server


def _report_summary(
    inspection: ProjectInspection,
    classification: ProjectClassification,
) -> str:
    if classification.my_agent_handles:
        handles = ", ".join(classification.my_agent_handles)
        overlays = ", ".join(classification.active_overlays) or "baseline controls"
        return (
            f"Project `{Path(inspection.root).name}` likely handles {handles}. "
            f"Recommended overlays: {overlays}."
        )
    if classification.review_items:
        return (
            f"Project `{Path(inspection.root).name}` has low-confidence regulated-data "
            "signals that should be reviewed before setup."
        )
    return (
        f"Project `{Path(inspection.root).name}` has no high-confidence regulated-data "
        "signals from deterministic inspection."
    )


@click.command()
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(dir_okay=False, path_type=str),
    default=None,
    help="Path to ancilis.yaml. Defaults to auto-discovery, then a read-only preview config.",
)
@click.option(
    "--transport",
    type=click.Choice(["stdio"]),
    default="stdio",
    show_default=True,
    help="MCP transport to run.",
)
def main(config_path: str | None, transport: str) -> None:
    """Run the Ancilis Cover MCP server over stdio."""
    stdio_transport = cast(Literal["stdio"], transport)
    create_cover_mcp_server(config_path=config_path).run(transport=stdio_transport)


if __name__ == "__main__":
    main()
