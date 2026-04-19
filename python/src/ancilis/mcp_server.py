"""FastMCP server factory for Ancilis self-inspection tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp import FastMCP

from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.action import Action
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolStatus
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.tool import ToolActionProducer, ToolInvocation


@dataclass(frozen=True)
class MCPServerContext:
    config: ResolvedConfig
    engine: Engine
    evidence_store: EvidenceStore
    action_producer: ToolActionProducer


def _not_implemented(_context: MCPServerContext) -> dict[str, str]:
    return {"status": "not_implemented"}


def _synthetic_tool(**_kwargs: Any) -> None:
    return None


def _matches_tool_config(tool_name: str, configured_tools: list[str]) -> bool:
    if tool_name in configured_tools:
        return True
    if ":" in tool_name:
        bare_name = tool_name.split(":", 1)[1]
        return bare_name in configured_tools
    return False


def _synthetic_tool_status(config: ResolvedConfig, tool_name: str) -> ToolStatus:
    if _matches_tool_config(tool_name, config.tools_blocked):
        return ToolStatus.BLOCKED
    if _matches_tool_config(tool_name, config.tools_allowed):
        return ToolStatus.APPROVED
    return ToolStatus.OBSERVED


def _register_synthetic_tool(
    context: MCPServerContext,
    *,
    tool_name: str,
    description: str | None,
) -> None:
    status = _synthetic_tool_status(context.config, tool_name)
    description_hash = context.action_producer.compute_tool_hash(
        f"{tool_name}:{description or ''}"
    )
    context.engine.registry.register(
        ToolEntry(
            name=tool_name,
            description_hash=description_hash,
            status=status,
            approved_by="config" if status == ToolStatus.APPROVED else None,
        )
    )


def _build_synthetic_action(
    context: MCPServerContext,
    *,
    tool_name: str,
    parameters: dict[str, Any] | None,
    description: str | None,
) -> Action:
    _register_synthetic_tool(context, tool_name=tool_name, description=description)
    kwargs = dict(parameters or {})
    kwargs["_ancilis_dry_run"] = True
    if description is not None:
        kwargs["_ancilis_description"] = description
    return context.action_producer.translate(
        ToolInvocation(
            func=_synthetic_tool,
            agent_name=context.config.agent_name,
            args=(),
            kwargs=kwargs,
            tool_name=tool_name,
        )
    )


def _control_result_payload(result: ControlResult) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "control": result.control_id,
        "result": result.result.lower(),
        "reason": result.detail,
    }
    if result.display_name:
        payload["name"] = result.display_name
    if result.remediation_hint:
        payload["remediation_hint"] = result.remediation_hint
    return payload


def _verdict_for(evaluation: EvaluationResult) -> str:
    if evaluation.decision == "BLOCK":
        return "blocked"
    if any(result.result in {"FAIL", "ERROR", "FLAG"} for result in evaluation.control_results):
        return "warning"
    return "allowed"


def _recommendation_for(verdict: str) -> str:
    if verdict == "blocked":
        return "Do not execute"
    if verdict == "warning":
        return "Proceed with caution"
    return "Safe to proceed"


def _evaluate_action(
    context: MCPServerContext,
    *,
    tool_name: str,
    parameters: dict[str, Any] | None,
    description: str | None,
) -> dict[str, Any]:
    action = _build_synthetic_action(
        context,
        tool_name=tool_name,
        parameters=parameters,
        description=description,
    )
    evaluation = context.engine.evaluate(action)
    verdict = _verdict_for(evaluation)
    return {
        "verdict": verdict,
        "tool_name": tool_name,
        "decision": evaluation.decision,
        "mode": evaluation.mode,
        "dry_run": True,
        "evaluations": [
            _control_result_payload(result)
            for result in evaluation.control_results
        ],
        "recommendation": _recommendation_for(verdict),
    }


def create_mcp_server(config_path: str | None = None) -> FastMCP:
    """Create an Ancilis MCP server with placeholder tool registrations."""
    config = load_config(path=config_path) if config_path is not None else load_config()
    evidence_store = EvidenceStore(config)
    engine = Engine(config, evidence_store=evidence_store)
    action_producer = ToolActionProducer(
        config,
        engine,
        registry=engine.registry,
        evidence_store=evidence_store,
    )
    context = MCPServerContext(
        config=config,
        engine=engine,
        evidence_store=evidence_store,
        action_producer=action_producer,
    )

    server = FastMCP(name="ancilis")

    @server.tool(name="ancilis_check_posture")
    def ancilis_check_posture() -> dict[str, str]:
        return _not_implemented(context)

    @server.tool(name="ancilis_evaluate_action")
    async def ancilis_evaluate_action(
        tool_name: str,
        parameters: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        return _evaluate_action(
            context,
            tool_name=tool_name,
            parameters=parameters,
            description=description,
        )

    @server.tool(name="ancilis_get_evidence")
    def ancilis_get_evidence() -> dict[str, str]:
        return _not_implemented(context)

    @server.tool(name="ancilis_report")
    def ancilis_report() -> dict[str, str]:
        return _not_implemented(context)

    @server.tool(name="ancilis_list_overlays")
    def ancilis_list_overlays() -> dict[str, str]:
        return _not_implemented(context)

    return server
