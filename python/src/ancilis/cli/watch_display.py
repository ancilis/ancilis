"""ancilis.cli.watch_display — terminal rendering for watch mode."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from rich.console import Console

console = Console(highlight=False)

_STATUS_MARKS = {
    "pass": "[green]\u2713[/]",
    "fail": "[red]\u2717[/]",
    "skip": "[dim]\u2013[/]",
}
_STATUS_COLORS = {"pass": "green", "fail": "red", "skip": "dim"}


def format_header(agent_name: str, posture: str, total_evals: int) -> str:
    color = "green" if posture == "compliant" else "red"
    ts = datetime.now().strftime("%H:%M:%S")
    return f"[dim]{ts}[/] [{color}]{posture}[/] \u2014 {agent_name} ({total_evals} evals)"


def format_delta(
    prev_results: list[dict[str, Any]] | None,
    new_results: list[dict[str, Any]],
) -> list[str]:
    """Return markup lines describing control status changes between scans."""
    if prev_results is None:
        return []
    prev_map = {r["id"]: r["status"] for r in prev_results}
    lines = []
    for ctrl in new_results:
        old = prev_map.get(ctrl["id"])
        new = ctrl["status"]
        if old is not None and old != new:
            old_mark = _STATUS_MARKS.get(old, "?")
            new_mark = _STATUS_MARKS.get(new, "?")
            lines.append(f"  {ctrl['name']}: {old_mark} \u2192 {new_mark}")
    return lines


def print_scan_result(
    agent_name: str,
    control_results: list[dict[str, Any]],
    posture: str,
    total_evals: int,
    prev_results: list[dict[str, Any]] | None,
    changed_paths: list[str] | None = None,
    clear: bool = False,
) -> None:
    if clear:
        console.clear()
    console.print(format_header(agent_name, posture, total_evals))
    if changed_paths:
        shown = changed_paths[:3]
        suffix = "..." if len(changed_paths) > 3 else ""
        console.print(f"  [dim]Changed: {', '.join(shown)}{suffix}[/]")
    delta = format_delta(prev_results, control_results)
    if delta:
        console.print("  [bold]Changes:[/]")
        for line in delta:
            console.print(line)
    for ctrl in control_results:
        mark = _STATUS_MARKS.get(ctrl["status"], "?")
        color = _STATUS_COLORS.get(ctrl["status"], "white")
        detail = f"{ctrl['evaluations']} evals"
        if ctrl["failures"] > 0:
            detail += f", {ctrl['failures']} failures"
        console.print(f"  {mark} [{color}]{ctrl['name']}[/] \u2014 {ctrl['status']} ({detail})")


def print_session_summary(
    start_time: datetime,
    total_scans: int,
    final_results: list[dict[str, Any]] | None,
    final_posture: str | None,
) -> None:
    elapsed = datetime.now() - start_time
    minutes = int(elapsed.total_seconds()) // 60
    seconds = int(elapsed.total_seconds()) % 60
    console.print()
    console.print(f"[bold]Watch session ended[/] \u2014 {minutes}m {seconds}s, {total_scans} scan(s)")
    if final_results and final_posture:
        color = "green" if final_posture == "compliant" else "red"
        passing = sum(1 for r in final_results if r["status"] == "pass")
        total = len(final_results)
        console.print(
            f"  Final posture: [{color}]{final_posture}[/] \u2014 {passing}/{total} controls passing"
        )
