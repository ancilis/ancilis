"""PR-08: Input Validation evaluator."""

from __future__ import annotations

import re
import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult

# Injection pattern definitions — compiled once at module load
INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    # SQL injection
    "sql_or_injection": re.compile(r"'\s*OR\s+1\s*=\s*1", re.IGNORECASE),
    "sql_drop_table": re.compile(r";\s*DROP\s+TABLE", re.IGNORECASE),
    "sql_union_select": re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE),
    "sql_comment_injection": re.compile(r"'[^']*--"),
    # Command injection
    "cmd_rm": re.compile(r";\s*rm\s+"),
    "cmd_pipe_cat": re.compile(r"\|\s*cat\s+"),
    "cmd_subshell": re.compile(r"\$\([^)]+\)"),
    "cmd_backtick": re.compile(r"`[^`]+`"),
    # Path traversal
    "path_traversal_unix": re.compile(r"\.\./"),
    "path_traversal_win": re.compile(r"\.\.[/\\\\]"),
    "path_etc_passwd": re.compile(r"/etc/passwd", re.IGNORECASE),
    "path_traversal_encoded": re.compile(r"%2e%2e", re.IGNORECASE),
}

# Patterns that are suspicious but not conclusive (→ FLAG instead of FAIL)
_SUSPICIOUS_PATTERNS = {"sql_comment_injection"}


def _flatten_values(params: dict[str, Any], depth: int = 3) -> list[str]:
    """Recursively extract string values from a parameter dict."""
    results: list[str] = []
    if depth <= 0:
        return results
    for val in params.values():
        if isinstance(val, str):
            results.append(val)
        elif isinstance(val, dict):
            results.extend(_flatten_values(val, depth - 1))
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    results.append(item)
                elif isinstance(item, dict):
                    results.extend(_flatten_values(item, depth - 1))
    return results


class PR08InputEvaluator:
    control_id = "PR-08"
    control_name = "Input Validation"

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()

        params = action.parameters.raw
        parameter_keys = list(params.keys())
        values = _flatten_values(params)

        patterns_found: list[str] = []
        is_suspicious_only = True

        for pattern_name, pattern in INJECTION_PATTERNS.items():
            for value in values:
                if pattern.search(value):
                    patterns_found.append(pattern_name)
                    if pattern_name not in _SUSPICIOUS_PATTERNS:
                        is_suspicious_only = False
                    break  # one match per pattern is enough

        evidence: dict[str, Any] = {
            "scan_result": "clean",
            "patterns_found": patterns_found,
            "parameter_keys": parameter_keys,
        }

        duration_ms = (time.perf_counter() - start) * 1000

        if not patterns_found:
            evidence["scan_result"] = "clean"
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail="No injection patterns detected in action parameters.",
                evidence_data=evidence,
                duration_ms=duration_ms,
            )

        if is_suspicious_only:
            evidence["scan_result"] = "suspicious"
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FLAG",
                detail=f"Suspicious patterns detected (may be false positive): {', '.join(patterns_found)}.",
                evidence_data=evidence,
                duration_ms=duration_ms,
            )

        evidence["scan_result"] = "injection_detected"
        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="FAIL",
            detail=f"Injection patterns detected: {', '.join(patterns_found)}.",
            evidence_data=evidence,
            duration_ms=duration_ms,
        )
