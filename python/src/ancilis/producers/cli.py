"""CLIActionProducer — intercepts CLI/subprocess tool calls for evaluation.

Usage:
    from ancilis import CLIActionProducer
    from ancilis.engine import Engine
    from ancilis.config import load_config
    from ancilis.evidence import EvidenceStore

    config = load_config()
    engine = Engine(config)
    evidence_store = EvidenceStore(config)
    producer = CLIActionProducer(config=config, engine=engine, evidence_store=evidence_store)

    # Wrap a subprocess call
    result = producer.execute(
        command=["aws", "s3", "ls", "s3://patient-records/"],
        agent_name="my-agent",
    )
    # result.blocked -> True if enforce mode blocked execution

    # Evaluate without executing (dry run)
    action = producer.translate(CLIInvocation(
        command=["aws", "s3", "ls", "s3://patient-records/"],
        agent_name="my-agent",
    ))
    evaluation = engine.evaluate(action)
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.engine.result import EvaluationResult
from ancilis.evidence.store import EvidenceStore
from ancilis.middleware.response_scanner import ScanResult, scan_response
from ancilis.producers.protocol import ProducerType


@dataclass
class CLIInvocation:
    """Raw CLI invocation before translation to Action."""

    command: list[str]
    agent_name: str
    working_directory: str | None = None
    environment: dict[str, str] | None = None


@dataclass
class CLIExecutionResult:
    """Result of a CLI execution through the producer."""

    action: Action
    evaluation: EvaluationResult
    blocked: bool
    stdout: str | None = None
    stderr: str | None = None
    return_code: int | None = None
    scan_result: ScanResult | None = None


class CLIActionProducer:
    """Produces Action objects from CLI/subprocess invocations.

    Implements the ActionProducer protocol.
    """

    def __init__(
        self,
        config: ResolvedConfig,
        engine: Engine,
        registry: ToolRegistry | None = None,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        self._config = config
        self._engine = engine
        self._registry = registry or engine.registry
        # Create default evidence store if not provided (same as middleware).
        # Lazy init means this doesn't touch the filesystem at construction.
        self._evidence_store = evidence_store if evidence_store is not None else EvidenceStore(config)

    @property
    def producer_type(self) -> ProducerType:
        return ProducerType.CLI

    @property
    def producer_version(self) -> str:
        return "0.1.0"

    def translate(self, raw_invocation: CLIInvocation) -> Action:
        """Convert a CLI invocation to an Action object."""
        tool_name = self._resolve_tool_name(raw_invocation.command)

        args = raw_invocation.command[1:] if len(raw_invocation.command) > 1 else []
        raw_params: dict[str, Any] = {
            "command": raw_invocation.command,
            "args": args,
        }
        if raw_invocation.working_directory:
            raw_params["working_directory"] = raw_invocation.working_directory

        param_hash = hashlib.sha256(
            str(raw_invocation.command).encode()
        ).hexdigest()

        # Look up tool in registry for provenance
        entry = self._registry.lookup(tool_name)
        description_hash = entry.description_hash if entry else None

        # Collect DC codes from config
        dc_codes: list[str] = []
        for codes in self._config.data_classifications.values():
            for code in codes:
                if code not in dc_codes:
                    dc_codes.append(code)

        overlay_ids = list(self._config.active_overlays.keys())

        return Action(
            action_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=raw_invocation.agent_name,
            source_type=self.producer_type.value,
            agent_owner=self._config.agent_owner or None,
            action_type="tool_call",
            tool=ToolInfo(
                name=tool_name,
                description_hash=description_hash,
            ),
            parameters=ActionParameters(
                raw=raw_params,
                parameter_hash=param_hash,
            ),
            context=ActionContext(
                data_classifications=dc_codes,
                active_overlays=overlay_ids,
            ),
            producer_type=self.producer_type.value,
            producer_version=self.producer_version,
        )

    def compute_tool_hash(self, tool_identifier: str) -> str:
        """Compute provenance hash for a CLI tool.

        Uses the tool's resolved path + version output.
        Detects both binary swaps (path change) and updates (version bump).
        """
        tool_path = shutil.which(tool_identifier)
        version_output = self._get_version_output(tool_identifier)

        hash_input = f"{tool_path or tool_identifier}:{version_output or 'no-version'}"
        return hashlib.sha256(hash_input.encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        """Register CLI tools from config allowlist.

        Tools in config.tools_allowed register as APPROVED (mirrors MCP
        middleware pre-seeding). Other tools discovered at runtime enter
        as OBSERVED via _auto_register().
        Strips existing cli: prefix to prevent double-prefix.
        """
        registered: list[str] = []

        for tool_spec in self._config.tools_allowed:
            bare_name = tool_spec if isinstance(tool_spec, str) else ""
            if not bare_name:
                continue

            # Strip cli: prefix if developer already included it
            if bare_name.startswith("cli:"):
                bare_name = bare_name[4:]

            cli_name = f"cli:{bare_name}"
            tool_hash = self.compute_tool_hash(bare_name)
            registry.register(
                ToolEntry(
                    name=cli_name,
                    description_hash=tool_hash,
                    status=ToolStatus.APPROVED,
                    approved_by="config",
                )
            )
            registered.append(cli_name)

        return registered

    def _auto_register(self, tool_name: str, command: list[str]) -> None:
        """Auto-register a tool on first encounter if not in registry.

        Tools matching config.tools_allowed register as APPROVED (same
        as register_tools). Unknown tools enter as OBSERVED.
        """
        if self._registry.lookup(tool_name) is not None:
            return
        bare_name = command[0] if command else "unknown"
        tool_hash = self.compute_tool_hash(os.path.basename(bare_name))
        status = self._resolve_initial_status(tool_name)
        self._registry.register(
            ToolEntry(
                name=tool_name,
                description_hash=tool_hash,
                status=status,
                approved_by="config" if status == ToolStatus.APPROVED else None,
            )
        )

    def _resolve_initial_status(self, tool_name: str) -> ToolStatus:
        """Determine initial trust status based on config allowlist."""
        from ancilis.engine.evaluators.pr02_scope import PR02ScopeEvaluator

        if self._config.tools_allowed and PR02ScopeEvaluator._matches_tool_list(
            tool_name, self._config.tools_allowed
        ):
            return ToolStatus.APPROVED
        return ToolStatus.OBSERVED

    def execute(
        self,
        command: list[str],
        agent_name: str,
        working_directory: str | None = None,
        timeout: int = 30,
    ) -> CLIExecutionResult:
        """Execute a CLI command through the Ancilis security engine.

        1. Auto-register tool if not in registry
        2. Translate command to Action
        3. Evaluate against controls
        4. Store evidence record
        5. If audit mode or PASS: execute and return result
        6. If enforce mode and FAIL: block execution, return blocked result
        7. Scan stdout for sensitive patterns
        """
        # Auto-register on first encounter (same as MCP auto-discovery)
        tool_name = self._resolve_tool_name(command)
        self._auto_register(tool_name, command)

        invocation = CLIInvocation(
            command=command,
            agent_name=agent_name,
            working_directory=working_directory,
        )

        action = self.translate(invocation)
        evaluation = self._engine.evaluate(action)

        # Persist evidence record (same as MCP middleware)
        self._evidence_store.store(evaluation, tool_name=tool_name)

        blocked = evaluation.decision == "BLOCK"

        stdout, stderr, return_code = None, None, None
        scan_result = None

        if not blocked:
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=working_directory,
                )
                stdout = result.stdout
                stderr = result.stderr
                return_code = result.returncode
            except subprocess.TimeoutExpired:
                stderr = f"Command timed out after {timeout}s"
                return_code = -1
            except FileNotFoundError:
                stderr = f"Command not found: {command[0]}"
                return_code = -1

            # Scan stdout only (not stderr) for sensitive patterns
            if stdout:
                scan = scan_response(tool_name, stdout)
                if scan.patterns or scan.encryption_findings:
                    scan_result = scan

        return CLIExecutionResult(
            action=action,
            evaluation=evaluation,
            blocked=blocked,
            stdout=stdout,
            stderr=stderr,
            return_code=return_code,
            scan_result=scan_result,
        )

    def _resolve_tool_name(self, command: list[str]) -> str:
        """Extract the tool name from a command.

        'aws s3 ls' -> 'cli:aws'
        '/usr/bin/python script.py' -> 'cli:python'
        """
        if not command:
            return "cli:unknown"
        base = os.path.basename(command[0])
        return f"cli:{base}"

    @staticmethod
    def _get_version_output(tool_name: str) -> str | None:
        """Attempt to get version output from a CLI tool."""
        for flag in ["--version", "-V", "version"]:
            try:
                result = subprocess.run(
                    [tool_name, flag],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                continue
        return None
