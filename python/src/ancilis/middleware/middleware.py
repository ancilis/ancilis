"""MCP middleware — intercepts tool calls, evaluates via engine, enforces decisions."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp import ClientSession
    from mcp.types import CallToolResult
else:
    ClientSession = Any
    CallToolResult = Any

try:
    from mcp.types import TextContent
except ImportError:
    class TextContent:  # type: ignore[no-redef]
        """Fallback type when MCP is not installed."""

        pass

from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.engine.result import EvaluationResult
from ancilis.middleware.action_builder import build_action
from ancilis.middleware.discovery import DriftEvent, register_tools_from_list
from ancilis.evidence.store import EvidenceStore
from ancilis.middleware.response_scanner import ScanResult, scan_response

logger = logging.getLogger("ancilis.middleware")


class BlockedToolCallError(Exception):
    """Raised when a tool call is blocked by policy enforcement."""

    def __init__(self, tool_name: str, evaluation: EvaluationResult):
        self.tool_name = tool_name
        self.evaluation = evaluation
        # Build developer-facing message using display names
        reasons: list[str] = []
        for r in evaluation.control_results:
            if r.result in ("FAIL", "ERROR"):
                display = r.display_name or r.control_name
                reasons.append(display.lower())
        reason_str = ", ".join(reasons) if reasons else "policy violation"
        self.display_message = (
            f"Ancilis [blocked]: Tool '{tool_name}' blocked — {reason_str}.\n"
            f"  To approve: ancilis approve-tool {tool_name}\n"
            f"  To review: ancilis status"
        )
        super().__init__(
            f"Tool call '{tool_name}' blocked by policy. "
            f"Failed controls: {', '.join(r.control_id for r in evaluation.control_results if r.result in ('FAIL', 'ERROR'))}"
        )


class AncilisMiddleware:
    """Wraps an MCP ClientSession to intercept and evaluate tool calls."""

    def __init__(
        self,
        session: ClientSession,
        config_path: str | Path | None = None,
        config: ResolvedConfig | None = None,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        if config is not None:
            self._config = config
        elif config_path is not None:
            self._config = load_config(path=config_path)
        else:
            self._config = load_config(raw={"agent": {"name": "ancilis-agent"}})

        self._session = session
        self._registry = ToolRegistry()

        # Pre-seed registry with config-approved tools so PR-03 passes
        # even before list_tools() / discovery runs.
        for tool_name in self._config.tools_allowed:
            self._registry.register(ToolEntry(
                name=tool_name,
                status=ToolStatus.APPROVED,
            ))

        self._engine = Engine(self._config, registry=self._registry)

        self._evaluation_log: list[EvaluationResult] = []
        self._scan_results: list[ScanResult] = []
        self._drift_events: list[DriftEvent] = []
        self._evidence_store = evidence_store if evidence_store is not None else EvidenceStore(self._config)
        self._issue_count: int = 0
        self._closed: bool = False

    @property
    def evidence_store(self) -> EvidenceStore:
        return self._evidence_store

    @property
    def config(self) -> ResolvedConfig:
        return self._config

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    @property
    def evaluation_log(self) -> list[EvaluationResult]:
        return list(self._evaluation_log)

    @property
    def scan_results(self) -> list[ScanResult]:
        return list(self._scan_results)

    @property
    def drift_events(self) -> list[DriftEvent]:
        return list(self._drift_events)

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> CallToolResult:
        """Intercept a tool call, evaluate, enforce, forward or block."""
        # 1. Build Action object
        action = build_action(name, arguments, self._config, self._registry)

        # 2. Evaluate via engine
        evaluation = self._engine.evaluate(action)
        self._evaluation_log.append(evaluation)

        # 3. Store evidence
        self._evidence_store.store(evaluation, tool_name=name)

        # Track issues for summary line
        has_issues = any(r.result in ("FAIL", "ERROR") for r in evaluation.control_results)
        if has_issues:
            self._issue_count += 1

        # 4. Enforce decision
        if evaluation.decision == "BLOCK":
            error = BlockedToolCallError(name, evaluation)
            logger.warning("%s", error.display_message)
            raise error

        # 5. Forward to MCP server
        try:
            result = await self._session.call_tool(name, arguments)
        except Exception:
            logger.exception("MCP server error calling tool '%s'", name)
            raise

        # 6. Scan response
        response_text = self._extract_response_text(result)
        if response_text:
            scan = scan_response(name, response_text)
            if scan.patterns or scan.encryption_findings:
                self._scan_results.append(scan)
                # Alert-level: sensitive data detected
                if scan.patterns:
                    pattern_names = [p.pattern_type for p in scan.patterns]
                    logger.warning(
                        "Ancilis [alert]: Sensitive data pattern (%s) detected in "
                        "outbound parameters for tool '%s'.\n"
                        "  Recommended: review data handling declarations in ancilis.yaml\n"
                        "  Details: ancilis status",
                        ", ".join(pattern_names), name,
                    )
                for finding in scan.encryption_findings:
                    logger.info("Positive finding: %s", finding.detail)

        # 7. Return result to agent
        return result

    async def list_tools(self) -> Any:
        """Forward list_tools to MCP server and auto-register discovered tools."""
        result = await self._session.list_tools()
        tools = result.tools if hasattr(result, "tools") else []

        drift = register_tools_from_list(
            tools, self._registry, pre_approved=self._config.tools_allowed
        )
        self._drift_events.extend(drift)

        registered_count = len(tools)
        logger.info("Auto-discovered %d tools", registered_count)

        return result

    def get_recommendations(self) -> list[str]:
        """Get all accumulated classification recommendations."""
        recs: list[str] = []
        for scan in self._scan_results:
            recs.extend(scan.recommendations)
        return recs

    def get_summary_line(self) -> str:
        """Get the single-line summary of middleware activity.

        This is the default console output — one line, periodic.
        """
        total = len(self._evaluation_log)
        issues = self._issue_count
        return f"Ancilis: {total} tool calls evaluated. {issues} issues. Run `ancilis status` for details."

    def get_last_evaluation(self) -> EvaluationResult | None:
        """Get the most recent evaluation result."""
        return self._evaluation_log[-1] if self._evaluation_log else None

    def close(self) -> None:
        """Flush and close the evidence store. Safe to call multiple times."""
        if not self._closed:
            self._evidence_store.close()
            self._closed = True

    async def __aenter__(self) -> AncilisMiddleware:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        self.close()

    @staticmethod
    def _extract_response_text(result: CallToolResult) -> str:
        """Extract text content from an MCP CallToolResult."""
        parts: list[str] = []
        for content in result.content:
            if isinstance(content, TextContent):
                parts.append(content.text)
            elif hasattr(content, "text"):
                parts.append(str(content.text))
        return "\n".join(parts)
