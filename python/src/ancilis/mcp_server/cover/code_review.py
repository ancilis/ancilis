"""Bounded deterministic code review for Ancilis Cover."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import re
from pathlib import Path

from ancilis.engine.patterns import scan_for_patterns
from ancilis.mcp_server.cover.models import CodeFinding, CodeReviewResult, SkippedFile

_SHELL_PATTERN = re.compile(
    r"\bimport\s+subprocess\b|\bfrom\s+subprocess\b|\bsubprocess\.|\bos\.system\(|\bshell\s*=\s*True",
    re.I,
)
_HTTP_PATTERN = re.compile(r"\brequests\.(get|post|put|patch|delete)\(|\bhttpx\.|\bfetch\(", re.I)
_DATABASE_PATTERN = re.compile(r"\bselect\s+.+\s+from\b|\bexecute\(|\bquery\(", re.I)
_LLM_PATTERN = re.compile(r"\bopenai\.|\banthropic\.|\bChatOpenAI\b|\bmessages\.create\(", re.I)


def review_code(
    root: str | Path | None = None,
    *,
    paths: Sequence[str | Path] | None = None,
    snippets: Sequence[Mapping[str, str]] | None = None,
    max_bytes_per_file: int = 60000,
) -> CodeReviewResult:
    """Review explicit files and snippets without traversing or mutating the project."""
    root_path = (Path.cwd() if root is None else Path(root)).resolve()
    findings: list[CodeFinding] = []
    reviewed_files: list[str] = []
    skipped_files: list[SkippedFile] = []

    for raw_path in paths or []:
        path = Path(raw_path)
        resolved = path.resolve() if path.is_absolute() else (root_path / path).resolve()
        if not _is_relative_to(resolved, root_path):
            skipped_files.append(
                SkippedFile(
                    path=str(resolved),
                    reason="path_outside_root",
                    detail=f"{resolved} is outside {root_path}",
                )
            )
            continue
        try:
            size = resolved.stat().st_size
        except OSError as exc:
            skipped_files.append(SkippedFile(path=str(resolved), reason="read_error", detail=str(exc)))
            continue
        if size > max_bytes_per_file:
            skipped_files.append(
                SkippedFile(
                    path=str(resolved),
                    reason="file_too_large",
                    detail=f"{size} bytes exceeds limit {max_bytes_per_file}",
                )
            )
            continue
        text = resolved.read_text(encoding="utf-8", errors="replace")
        reviewed_files.append(str(resolved))
        findings.extend(_findings_for_text(text, path=str(resolved)))

    for snippet in snippets or []:
        name = snippet.get("name", "snippet")
        text = snippet.get("text", "")
        snippet_path = f"snippet:{name}"
        reviewed_files.append(snippet_path)
        findings.extend(_findings_for_text(text, path=snippet_path))

    producers = sorted({finding.producer for finding in findings if finding.producer})
    config_changes = [f"Review `{producer}` producer setup." for producer in producers]
    return CodeReviewResult(
        findings=findings,
        producer_recommendations=producers,
        suggested_config_changes=config_changes,
        reviewed_files=reviewed_files,
        skipped_files=skipped_files,
    )


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _findings_for_text(text: str, *, path: str) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    for pattern in scan_for_patterns(text):
        findings.append(
            CodeFinding(
                severity="medium",
                category="sensitive_data",
                message=f"Detected {pattern.pattern_type} pattern in reviewed code.",
                path=path,
                sample=pattern.redacted_sample,
            )
        )
    if _SHELL_PATTERN.search(text):
        findings.append(
            CodeFinding(
                severity="high",
                category="shell_execution",
                message="Shell or subprocess execution surface should be evaluated by Ancilis.",
                path=path,
                producer="cli",
            )
        )
    if _HTTP_PATTERN.search(text):
        findings.append(
            CodeFinding(
                severity="medium",
                category="outbound_http",
                message="Outbound HTTP call surface should be evaluated by Ancilis.",
                path=path,
                producer="http",
            )
        )
    if _DATABASE_PATTERN.search(text):
        findings.append(
            CodeFinding(
                severity="medium",
                category="database_query",
                message="Database or query surface may handle sensitive data.",
                path=path,
                producer="tool",
            )
        )
    if _LLM_PATTERN.search(text):
        findings.append(
            CodeFinding(
                severity="medium",
                category="llm_invocation",
                message="LLM invocation surface can be observed with an Ancilis SDK producer.",
                path=path,
                producer="openai",
            )
        )
    return findings
