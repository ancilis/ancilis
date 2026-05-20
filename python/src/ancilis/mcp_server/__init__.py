"""FastMCP server factory for Ancilis self-inspection tools."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from ancilis.activation.loader import load_overlay_profiles
from ancilis.activation.resolver import ActivationResolver
from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.action import Action
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolStatus
from ancilis.engine.result import ControlResult, EvaluationResult
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.tool import ToolActionProducer, ToolInvocation
from ancilis.report.generator import ReportGenerator
from ancilis.report.renderer import render_markdown


@dataclass(frozen=True)
class MCPServerContext:
    config: ResolvedConfig
    engine: Engine
    evidence_store: EvidenceStore
    action_producer: ToolActionProducer


class MCPControlPosture(BaseModel):
    id: str
    name: str
    status: str
    reason: str = ""
    evidence_count: int = 0
    latest_evaluated_at: str | None = None


class MCPPostureResponse(BaseModel):
    posture_score: float = 0.0
    controls: list[MCPControlPosture] = Field(default_factory=list)
    active_overlays: list[str] = Field(default_factory=list)
    session_id: str | None = None
    evaluated_at: datetime


class MCPOverlayCoverage(BaseModel):
    name: str
    controls_total: int
    controls_covered: int
    coverage_pct: float


class MCPOverlayListResponse(BaseModel):
    overlays: list[MCPOverlayCoverage] = Field(default_factory=list)


class MCPEvidenceItem(BaseModel):
    id: str
    timestamp: str
    action_type: str
    tool_name: str | None = None
    control_id: str | None = None
    result: str | None = None
    chain_hash: str


class MCPEvidenceResponse(BaseModel):
    evidence: list[MCPEvidenceItem] = Field(default_factory=list)
    total_count: int = 0
    returned_count: int = 0
    session_id: str | None = None


class MCPReportResponse(BaseModel):
    report: str
    format: str
    session_id: str | None = None
    generated_at: str


def _json_response(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")


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


def _active_runtime_evaluator_ids(context: MCPServerContext) -> set[str]:
    evaluator_ids = set(getattr(context.engine, "_evaluators", {}))
    is_policy_gated = getattr(context.engine, "_is_policy_gated", None)
    active_ids: set[str] = set()
    for control_id, control_status in context.config.controls.items():
        if not control_status.enabled or control_id not in evaluator_ids:
            continue
        if callable(is_policy_gated) and is_policy_gated(control_id):
            continue
        active_ids.add(control_id)
    return active_ids


def _evidence_store_has_materialized_data(store: EvidenceStore) -> bool:
    if store.db_path == ":memory:":
        return getattr(store, "_conn", None) is not None
    return getattr(store, "_conn", None) is not None or Path(store.db_path).exists()


def _latest_session_records(context: MCPServerContext) -> tuple[str | None, list[EvidenceRecord]]:
    if not _evidence_store_has_materialized_data(context.evidence_store):
        return None, []
    session_id = context.evidence_store.latest_session_id()
    if session_id is None:
        return None, []
    return session_id, context.evidence_store.get_records(session_id=session_id, limit=None)


def _active_overlay_ids(context: MCPServerContext) -> list[str]:
    return sorted(context.config.active_overlays)


def _build_posture_response(context: MCPServerContext) -> MCPPostureResponse:
    session_id, records = _latest_session_records(context)
    active_evaluator_ids = _active_runtime_evaluator_ids(context)
    evidence_counts: Counter[str] = Counter()
    latest_results: dict[str, dict[str, Any]] = {}

    for record in records:
        for raw_result in record.control_results:
            control_id = raw_result.get("control_id")
            if control_id not in active_evaluator_ids:
                continue
            status = str(raw_result.get("result", "SKIP")).upper()
            if status == "SKIP":
                continue
            evidence_counts[control_id] += 1
            latest_results[control_id] = {
                "id": control_id,
                "name": raw_result.get("control_name", control_id),
                "status": status,
                "reason": raw_result.get("detail", ""),
                "evidence_count": evidence_counts[control_id],
                "latest_evaluated_at": record.timestamp,
            }

    controls = [
        MCPControlPosture(**latest_results[control_id])
        for control_id in sorted(latest_results)
    ]
    passing = sum(1 for control in controls if control.status == "PASS")
    posture_score = (
        round(passing / len(active_evaluator_ids), 4)
        if active_evaluator_ids
        else 0.0
    )

    return MCPPostureResponse(
        posture_score=posture_score,
        controls=controls,
        active_overlays=_active_overlay_ids(context),
        session_id=session_id,
        evaluated_at=datetime.now(timezone.utc),
    )


def _overlay_control_ids(profile: dict[str, Any]) -> list[str]:
    controls = {
        control_id
        for control_id, control_data in profile.get("controls", {}).items()
        if control_data.get("applicable", True)
    }
    if not controls:
        controls.update(profile.get("control_adjustments", {}).keys())
        controls.update(profile.get("evidence_requirements", {}).keys())
    return sorted(controls)


def _evidenced_control_ids(records: list[EvidenceRecord]) -> set[str]:
    control_ids: set[str] = set()
    for record in records:
        for raw_result in record.control_results:
            status = str(raw_result.get("result", "SKIP")).upper()
            if status == "SKIP":
                continue
            control_id = raw_result.get("control_id")
            if isinstance(control_id, str):
                control_ids.add(control_id)
    return control_ids


def _resolved_overlay_ids(context: MCPServerContext) -> list[str]:
    configured_overlay_ids = _active_overlay_ids(context)
    resolver = ActivationResolver()
    spec = resolver.resolve(
        my_agent_handles=list(context.config.data_classifications) or None,
        certification_targets=list(context.config.active_certifications) or None,
        compliance_overlays=configured_overlay_ids or None,
    )
    active = [
        overlay_id
        for overlay_id in spec.active_overlays
        if overlay_id in configured_overlay_ids
    ]
    for overlay_id in configured_overlay_ids:
        if overlay_id not in active:
            active.append(overlay_id)
    return sorted(active)


def _build_overlay_list_response(context: MCPServerContext) -> MCPOverlayListResponse:
    _session_id, records = _latest_session_records(context)
    evidenced_controls = _evidenced_control_ids(records)
    overlay_profiles = load_overlay_profiles()
    overlays: list[MCPOverlayCoverage] = []

    for overlay_id in _resolved_overlay_ids(context):
        profile = overlay_profiles.get(overlay_id)
        if profile is None:
            continue
        active_controls = _overlay_control_ids(profile)
        total_controls = len(active_controls)
        controls_covered = len(set(active_controls) & evidenced_controls)
        coverage_pct = (
            round((controls_covered / total_controls) * 100, 2)
            if total_controls
            else 0.0
        )
        overlays.append(
            MCPOverlayCoverage(
                name=overlay_id,
                controls_total=total_controls,
                controls_covered=controls_covered,
                coverage_pct=coverage_pct,
            )
        )

    return MCPOverlayListResponse(overlays=overlays)


def _selected_session_id(context: MCPServerContext, session_id: str | None) -> str | None:
    if session_id is not None:
        return session_id
    if not _evidence_store_has_materialized_data(context.evidence_store):
        return None
    return context.evidence_store.latest_session_id()


def _evidence_items_for(
    records: list[EvidenceRecord],
    *,
    control_id: str | None,
) -> list[MCPEvidenceItem]:
    items: list[MCPEvidenceItem] = []
    for record in sorted(records, key=lambda item: item.timestamp, reverse=True):
        control_results = record.control_results or []
        if not control_results and control_id is None:
            items.append(
                MCPEvidenceItem(
                    id=record.record_id,
                    timestamp=record.timestamp,
                    action_type=record.source_type,
                    tool_name=record.tool_name,
                    chain_hash=record.record_hash,
                )
            )
            continue

        for result in control_results:
            result_control_id = result.get("control_id")
            if control_id is not None and result_control_id != control_id:
                continue
            raw_result = result.get("result")
            items.append(
                MCPEvidenceItem(
                    id=record.record_id,
                    timestamp=record.timestamp,
                    action_type=record.source_type,
                    tool_name=record.tool_name,
                    control_id=result_control_id if isinstance(result_control_id, str) else None,
                    result=str(raw_result).lower() if raw_result is not None else None,
                    chain_hash=record.record_hash,
                )
            )
    return items


def _build_evidence_response(
    context: MCPServerContext,
    *,
    limit: int,
    control_id: str | None,
    session_id: str | None,
) -> MCPEvidenceResponse:
    selected_session_id = _selected_session_id(context, session_id)
    if selected_session_id is None:
        return MCPEvidenceResponse()

    records = context.evidence_store.get_records(session_id=selected_session_id, limit=None)
    items = _evidence_items_for(records, control_id=control_id)
    bounded_limit = max(limit, 0)
    returned = items[:bounded_limit]
    return MCPEvidenceResponse(
        evidence=returned,
        total_count=len(items),
        returned_count=len(returned),
        session_id=selected_session_id,
    )


def _build_report_response(
    context: MCPServerContext,
    *,
    session_id: str | None,
    report_format: str,
) -> dict[str, Any]:
    if report_format != "markdown":
        return {
            "error": "unsupported_format",
            "format": report_format,
            "supported_formats": ["markdown"],
        }

    selected_session_id = _selected_session_id(context, session_id)
    generator = ReportGenerator(context.config, context.evidence_store)
    report_data = generator.generate(
        period="365d",
        report_format="markdown",
        session_id=selected_session_id,
    )
    return _json_response(
        MCPReportResponse(
            report=render_markdown(report_data),
            format="markdown",
            session_id=selected_session_id,
            generated_at=report_data.generated_at,
        )
    )


def build_mcp_context(
    config_path: str | None = None,
    context: MCPServerContext | None = None,
    *,
    default_raw_config: dict[str, Any] | None = None,
) -> MCPServerContext:
    """Build a runtime MCP context, optionally falling back to a default config."""
    if context is not None:
        return context

    try:
        config = load_config(path=config_path) if config_path is not None else load_config()
    except FileNotFoundError:
        if default_raw_config is None:
            raise
        config = load_config(raw=default_raw_config)

    evidence_store = EvidenceStore(config)
    engine = Engine(config, evidence_store=evidence_store)
    action_producer = ToolActionProducer(
        config,
        engine,
        registry=engine.registry,
        evidence_store=evidence_store,
    )
    return MCPServerContext(
        config=config,
        engine=engine,
        evidence_store=evidence_store,
        action_producer=action_producer,
    )


def register_runtime_tools(server: FastMCP, context: MCPServerContext) -> None:
    """Register runtime posture and evidence MCP tools on an existing server."""

    @server.tool(name="ancilis_check_posture")
    async def ancilis_check_posture() -> dict[str, Any]:
        """Return current session posture, active control status, and overlays."""
        return _json_response(_build_posture_response(context))

    @server.tool(name="ancilis_evaluate_action")
    async def ancilis_evaluate_action(
        tool_name: str,
        parameters: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        """Evaluate a proposed tool action without writing evidence."""
        return _evaluate_action(
            context,
            tool_name=tool_name,
            parameters=parameters,
            description=description,
        )

    @server.tool(name="ancilis_get_evidence")
    async def ancilis_get_evidence(
        limit: int = 50,
        control_id: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Return recent evidence records for the selected or latest session."""
        return _json_response(
            _build_evidence_response(
                context,
                limit=limit,
                control_id=control_id,
                session_id=session_id,
            )
        )

    @server.tool(name="ancilis_report")
    async def ancilis_report(
        session_id: str | None = None,
        format: str = "markdown",
    ) -> dict[str, Any]:
        """Generate a posture report for the selected or latest session."""
        return _build_report_response(
            context,
            session_id=session_id,
            report_format=format,
        )

    @server.tool(name="ancilis_list_overlays")
    async def ancilis_list_overlays() -> dict[str, Any]:
        """List active overlays and evidence coverage percentages."""
        return _json_response(_build_overlay_list_response(context))


def create_mcp_server(
    config_path: str | None = None,
    context: MCPServerContext | None = None,
) -> FastMCP:
    """Create the legacy Ancilis MCP server with the unified tool set."""
    resolved_context = build_mcp_context(config_path=config_path, context=context)
    server = FastMCP(name="ancilis")
    register_runtime_tools(server, resolved_context)

    from ancilis.mcp_server.cover.server import register_cover_tools

    register_cover_tools(server, runtime_context=resolved_context)
    return server
