"""MCP middleware — intercepts tool calls, evaluates via engine, enforces decisions."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.types import CallToolResult, TextContent

from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolRegistry
from ancilis.engine.result import EvaluationResult
from ancilis.middleware.action_builder import build_action
from ancilis.middleware.discovery import DriftEvent, register_tools_from_list
from ancilis.middleware.response_scanner import ScanResult, scan_response

logger = logging.getLogger("ancilis.middleware")


class BlockedToolCallError(Exception):
    """Raised when a tool call is blocked by policy enforcement."""

    def __init__(self, tool_name: str, evaluation: EvaluationResult):
        self.tool_name = tool_name
        self.evaluation = evaluation
        failed = [r.control_id for r in evaluation.control_results if r.result in ("FAIL", "ERROR")]
        super().__init__(
            f"Tool call '{tool_name}' blocked by policy. "
            f"Failed controls: {', '.join(failed)}"
        )


class AncilisMiddleware:
    """Wraps an MCP ClientSession to intercept and evaluate tool calls."""

    def __init__(
        self,
        session: ClientSession,
        config_path: str | Path | None = None,
        config: ResolvedConfig | None = None,
    ) -> None:
        if config is not None:
            self._config = config
        elif config_path is not None:
            self._config = load_config(path=config_path)
        else:
            self._config = load_config(raw={"agent": {"name": "ancilis-agent"}})

        self._session = session
        self._registry = ToolRegistry()
        self._engine = Engine(self._config, registry=self._registry)

        self._evaluation_log: list[EvaluationResult] = []
        self._scan_results: list[ScanResult] = []
        self._drift_events: list[DriftEvent] = []

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

        logger.info(
            "Evaluated tool call '%s': decision=%s, mode=%s",
            name, evaluation.decision, evaluation.mode,
        )

        # 3. Enforce decision
        if evaluation.decision == "BLOCK":
            logger.warning("BLOCKED tool call '%s': %s", name, evaluation.decision_reason)
            raise BlockedToolCallError(name, evaluation)

        # 4. Forward to MCP server
        try:
            result = await self._session.call_tool(name, arguments)
        except Exception:
            logger.exception("MCP server error calling tool '%s'", name)
            raise

        # 5. Scan response
        response_text = self._extract_response_text(result)
        if response_text:
            scan = scan_response(name, response_text)
            if scan.patterns or scan.encryption_findings:
                self._scan_results.append(scan)
                for rec in scan.recommendations:
                    logger.info("Recommendation: %s", rec)
                for finding in scan.encryption_findings:
                    logger.info("Positive finding: %s", finding.detail)

        # 6. Return result to agent
        return result

    async def list_tools(self) -> Any:
        """Forward list_tools to MCP server and auto-register discovered tools."""
        result = await self._session.list_tools()
        tools = result.tools if hasattr(result, "tools") else []

        drift = register_tools_from_list(tools, self._registry)
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

    def get_last_evaluation(self) -> EvaluationResult | None:
        """Get the most recent evaluation result."""
        return self._evaluation_log[-1] if self._evaluation_log else None

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
