"""Read-only interactive shell for inspecting Ancilis SDK state."""

from __future__ import annotations

import cmd
import json
import shlex
import sys
from dataclasses import asdict
from pathlib import Path
from typing import TextIO

import click

from ancilis.cli.status import _format_status
from ancilis.config import ResolvedConfig, load_config
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.store import EvidenceStore

PROMPT = "ancilis> "
HISTORY_PATH = Path.home() / ".ancilis" / "repl_history"


class AncilisShell(cmd.Cmd):
    """Small read-only REPL over config, posture, overlays, and evidence."""

    prompt = PROMPT

    def __init__(
        self,
        *,
        config: ResolvedConfig,
        store: EvidenceStore,
        session_id: str | None = None,
        stdout: TextIO | None = None,
        stdin: TextIO | None = None,
        enable_history: bool = False,
    ) -> None:
        super().__init__(stdin=stdin or sys.stdin, stdout=stdout or sys.stdout)
        self.config = config
        self.store = store
        self.session_id = session_id
        self.enable_history = enable_history

    def preloop(self) -> None:
        if not self.enable_history:
            return
        try:
            import readline  # type: ignore[import-not-found]

            HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
            if HISTORY_PATH.exists():
                readline.read_history_file(str(HISTORY_PATH))
        except Exception:
            return

    def postloop(self) -> None:
        if not self.enable_history:
            return
        try:
            import readline  # type: ignore[import-not-found]

            HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
            readline.write_history_file(str(HISTORY_PATH))
        except Exception:
            return

    def emptyline(self) -> None:
        return None

    def do_help(self, arg: str) -> None:
        """List available shell commands."""
        self._write(
            "\n".join(
                [
                    "Available commands:",
                    "  help",
                    "  posture",
                    "  config show",
                    "  overlay list",
                    "  evidence list [--limit N] [--tool NAME] [--decision ALLOW|BLOCK|FLAG] [--session ID]",
                    "  evidence show <record_id>",
                    "  evaluate <control_id>",
                    "  exit",
                    "  quit",
                ]
            )
        )

    def do_exit(self, arg: str) -> bool:
        """Exit the shell."""
        return True

    def do_quit(self, arg: str) -> bool:
        """Exit the shell."""
        return True

    def do_posture(self, arg: str) -> None:
        """Render the same posture summary as `ancilis status`."""
        self._write(_format_status(self.config, self.store, verbose=False, session_id=self.session_id))

    def do_config(self, arg: str) -> None:
        """Show resolved config details."""
        if arg.strip() != "show":
            self._write("Usage: config show")
            return
        enabled_controls = [c for c in self.config.controls.values() if c.enabled]
        lines = [
            f"Agent: {self.config.agent_name}",
            f"Mode: {self.config.mode}",
            f"Active controls: {len(enabled_controls)}",
            "Active overlays: " + _join_or_none([oa.name for _oid, oa in sorted(self.config.active_overlays.items())]),
            "Active certifications: " + _join_or_none([c.upper() for c in self.config.active_certifications]),
            "Allowed tools: " + _join_or_none(self.config.tools_allowed),
            "Blocked tools: " + _join_or_none(self.config.tools_blocked),
            f"Evidence retention: {self.config.evidence_retention_days} days",
        ]
        self._write("\n".join(lines))

    def do_overlay(self, arg: str) -> None:
        """List active overlays and certifications."""
        if arg.strip() != "list":
            self._write("Usage: overlay list")
            return
        enabled_controls = [c for c in self.config.controls.values() if c.enabled]
        lines = [f"Enabled controls: {len(enabled_controls)}"]
        if not self.config.active_overlays and not self.config.active_certifications:
            lines.append("No active overlays or certifications.")
        for _oid, overlay in sorted(self.config.active_overlays.items()):
            lines.append(f"Overlay: {overlay.name} ({overlay.overlay_id})")
        for cert_id in self.config.active_certifications:
            lines.append(f"Certification: {cert_id.upper()}")
        self._write("\n".join(lines))

    def do_evidence(self, arg: str) -> None:
        """Inspect persisted evidence records."""
        try:
            parts = shlex.split(arg)
        except ValueError as exc:
            self._write(f"Invalid evidence command: {exc}")
            return
        if not parts:
            self._write("Usage: evidence list|show ...")
            return
        command, rest = parts[0], parts[1:]
        if command == "list":
            self._evidence_list(rest)
        elif command == "show":
            self._evidence_show(rest)
        else:
            self._write("Usage: evidence list|show ...")

    def do_evaluate(self, arg: str) -> None:
        """Show the latest persisted control result for a control id."""
        control_id = arg.strip()
        if not control_id:
            self._write("Usage: evaluate <control_id>")
            return
        records = self._records_or_empty(limit=None)
        for record in reversed(records):
            for result in reversed(record.control_results):
                if result.get("control_id") == control_id:
                    self._write(json.dumps(result, indent=2, sort_keys=True))
                    return
        self._write(f"No persisted evidence for this control yet: {control_id}")

    def _evidence_list(self, args: list[str]) -> None:
        limit = 20
        tool_name: str | None = None
        decision: str | None = None
        session_id = self.session_id
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "--limit" and i + 1 < len(args):
                try:
                    limit = max(1, int(args[i + 1]))
                except ValueError:
                    self._write("Invalid --limit value")
                    return
                i += 2
            elif arg == "--tool" and i + 1 < len(args):
                tool_name = args[i + 1]
                i += 2
            elif arg == "--decision" and i + 1 < len(args):
                decision = args[i + 1].upper()
                i += 2
            elif arg == "--session" and i + 1 < len(args):
                session_id = args[i + 1]
                i += 2
            else:
                self._write("Usage: evidence list [--limit N] [--tool NAME] [--decision ALLOW|BLOCK|FLAG] [--session ID]")
                return
        records = self._records_or_empty(
            limit=limit,
            tool_name=tool_name,
            decision=decision,
            session_id=session_id,
        )
        if not records:
            self._write("No evidence records found.")
            return
        lines = ["Record ID | Timestamp | Tool | Source | Decision | Session | Active overlays"]
        for record in records:
            lines.append(
                " | ".join(
                    [
                        record.record_id,
                        record.timestamp,
                        record.tool_name,
                        record.source_type,
                        record.decision,
                        record.session_id or "",
                        ", ".join(record.active_overlays) if record.active_overlays else "",
                    ]
                )
            )
        self._write("\n".join(lines))

    def _evidence_show(self, args: list[str]) -> None:
        if len(args) != 1:
            self._write("Usage: evidence show <record_id>")
            return
        record_id = args[0]
        for record in self._records_or_empty(limit=None):
            if record.record_id == record_id:
                self._write(json.dumps(asdict(record), indent=2, sort_keys=True))
                return
        self._write(f"No evidence record found: {record_id}")

    def _records_or_empty(
        self,
        *,
        limit: int | None,
        tool_name: str | None = None,
        decision: str | None = None,
        session_id: str | None = None,
    ) -> list[EvidenceRecord]:
        summary = self.store.get_summary(session_id=session_id)
        if int(summary.get("total_evaluations", 0)) == 0:
            return []
        return self.store.get_records(
            session_id=session_id,
            tool_name=tool_name,
            decision=decision,
            limit=limit,
        )

    def _write(self, text: str) -> None:
        self.stdout.write(text)
        self.stdout.write("\n")


def _join_or_none(values: list[str]) -> str:
    return ", ".join(values) if values else "none"


@click.command(name="shell")
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option("--session", "session_id", default=None, help="Scope to a specific session ID")
@click.option("--latest/--all", "use_latest", default=True, help="Show latest session (default) or all sessions")
def shell(config_path: str | None, db_path: str | None, session_id: str | None, use_latest: bool) -> None:
    """Start the read-only Ancilis interactive shell."""
    try:
        config = load_config(path=config_path) if config_path else load_config()
    except (FileNotFoundError, ValueError) as exc:
        click.echo(f"Error loading config: {exc}", err=True)
        raise SystemExit(1) from None

    store = EvidenceStore(config, db_path=db_path)
    try:
        if session_id is None and use_latest:
            summary = store.get_summary()
            if int(summary.get("total_evaluations", 0)) > 0:
                session_id = store.latest_session_id()
        repl = AncilisShell(
            config=config,
            store=store,
            session_id=session_id,
            enable_history=sys.stdin.isatty(),
        )
        repl.cmdloop()
    finally:
        store.close()
