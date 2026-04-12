"""Ancilis posture gate — entry point for the GitHub Action composite step.

Runs `ancilis scan --ci`, evaluates the threshold, optionally posts a PR comment,
sets GitHub Actions outputs, and exits with code 1 when the threshold is not met.

No dependencies beyond ancilis (stdlib only for all GitHub API calls).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def set_output(name: str, value: str) -> None:
    """Write a key=value pair to GITHUB_OUTPUT (Actions v2 protocol)."""
    output_file = os.environ.get("GITHUB_OUTPUT", "")
    if output_file:
        with open(output_file, "a") as fh:
            fh.write(f"{name}={value}\n")
    else:
        # Fallback for older runners / local testing
        print(f"::set-output name={name}::{value}")


def is_pr_context() -> bool:
    return os.environ.get("GITHUB_EVENT_NAME", "") == "pull_request"


def _github_api(
    method: str,
    url: str,
    token: str,
    body: dict[str, Any] | None = None,
) -> dict[str, Any] | list[Any]:
    """Minimal stdlib GitHub API helper.  Returns parsed JSON or raises."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "ancilis-action/1",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())  # type: ignore[return-value]
    except urllib.error.HTTPError as exc:
        print(f"::warning::GitHub API {method} {url} returned {exc.code}: {exc.read()[:200]}")
        return {}


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


def run_scan(overlay: str) -> dict[str, Any]:
    """Run `ancilis scan --ci` and return a normalised result dict.

    Returns:
        {
            "score": int,          # 0-100
            "posture": str,        # "compliant" | "non_compliant"
            "overlay": str,
            "controls": [{"id", "name", "verdict", "detail"}],
            "raw": dict,           # full CI JSON when available
        }
    """
    # Try JSON output first (--ci flag)
    cmd = ["ancilis", "scan", "--ci"]
    if overlay:
        cmd.extend(["--overlay", overlay])
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )
    if result.returncode in (0, 1):
        try:
            raw = json.loads(result.stdout)
            return _normalise_ci_output(raw, overlay)
        except (json.JSONDecodeError, KeyError):
            pass

    # Fallback: parse human text output
    return _parse_text_output(result.stdout + result.stderr, overlay)


def _normalise_ci_output(raw: dict[str, Any], overlay: str) -> dict[str, Any]:
    summary = raw.get("summary", {})
    total = summary.get("total_controls", 0)
    passing = summary.get("passing", 0)
    score = int(passing / total * 100) if total > 0 else 100

    controls = [
        {
            "id": c.get("id", ""),
            "name": c.get("name", ""),
            "verdict": c.get("status", "skip").upper(),
            "detail": _format_detail(c),
        }
        for c in raw.get("controls", [])
    ]

    return {
        "score": score,
        "posture": raw.get("posture", "non_compliant"),
        "overlay": overlay,
        "controls": controls,
        "raw": raw,
    }


def _format_detail(c: dict[str, Any]) -> str:
    parts = []
    evals = c.get("evaluations", 0)
    if evals:
        parts.append(f"{evals} evals")
    failures = c.get("failures", 0)
    if failures:
        parts.append(f"{failures} failures")
    flags = c.get("flags", 0)
    if flags:
        parts.append(f"{flags} flags")
    return ", ".join(parts) if parts else "no data"


def _parse_text_output(text: str, overlay: str) -> dict[str, Any]:
    """Best-effort text parsing fallback."""
    posture = "non_compliant"
    if re.search(r"Posture:\s*compliant", text, re.IGNORECASE):
        posture = "compliant"

    controls = []
    for line in text.splitlines():
        m = re.match(r"\s*[✓✗–?]\s+(.+?)\s+—\s+(pass|fail|skip)", line, re.IGNORECASE)
        if m:
            controls.append({
                "id": "",
                "name": m.group(1).strip(),
                "verdict": m.group(2).upper(),
                "detail": "",
            })

    passing = sum(1 for c in controls if c["verdict"] == "PASS")
    total = len(controls)
    score = int(passing / total * 100) if total > 0 else (100 if posture == "compliant" else 0)

    return {
        "score": score,
        "posture": posture,
        "overlay": overlay,
        "controls": controls,
        "raw": {},
    }


# ---------------------------------------------------------------------------
# Comment
# ---------------------------------------------------------------------------

COMMENT_MARKER = "<!-- ancilis-posture-gate -->"


def format_comment(
    scan_result: dict[str, Any],
    threshold: int,
    passed: bool,
) -> str:
    score = scan_result["score"]
    overlay = scan_result.get("overlay", "default")
    pass_icon = "✅" if passed else "❌"
    status_label = "PASS" if passed else "FAIL"

    rows = "\n".join(
        f"| `{c['id']}` {c['name']} | {_verdict_icon(c['verdict'])} {c['verdict']} | {c['detail']} |"
        for c in scan_result.get("controls", [])
    )
    if not rows:
        rows = "| — | — | No control data available |"

    return (
        f"{COMMENT_MARKER}\n"
        f"## Ancilis Posture Gate\n\n"
        f"| Metric | Value |\n"
        f"|--------|-------|\n"
        f"| Overlay | `{overlay}` |\n"
        f"| Score | **{score}/100** |\n"
        f"| Threshold | {threshold} |\n"
        f"| Status | {pass_icon} **{status_label}** |\n\n"
        f"### Control Results\n"
        f"| Control | Verdict | Details |\n"
        f"|---------|---------|--------|\n"
        f"{rows}\n\n"
        f"*Scanned by [Ancilis](https://ancilis.dev) · ancilis-action v1*"
    )


def _verdict_icon(verdict: str) -> str:
    return {"PASS": "✅", "FAIL": "❌", "SKIP": "⬜", "FLAG": "⚠️"}.get(verdict.upper(), "❓")


def format_summary(scan_result: dict[str, Any], passed: bool) -> str:
    score = scan_result["score"]
    overlay = scan_result.get("overlay", "default")
    status = "PASS" if passed else "FAIL"
    return f"Ancilis posture gate: {status} ({score}/100, overlay={overlay})"


def post_posture_comment(
    scan_result: dict[str, Any],
    threshold: int,
    passed: bool,
    token: str,
) -> None:
    """Upsert a posture comment on the current PR."""
    if not token:
        print("::warning::GITHUB_TOKEN not set — skipping PR comment")
        return

    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_path:
        print("::warning::GITHUB_EVENT_PATH not set — skipping PR comment")
        return

    try:
        with open(event_path) as fh:
            event = json.load(fh)
    except Exception as exc:
        print(f"::warning::Could not read event payload: {exc}")
        return

    pr_number = event.get("pull_request", {}).get("number")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not pr_number or not repo:
        print("::warning::Missing PR number or repo — skipping comment")
        return

    api_base = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    comments_url = f"{api_base}/repos/{repo}/issues/{pr_number}/comments"

    # List existing comments to find marker
    existing: list[Any] = _github_api("GET", comments_url, token)  # type: ignore[assignment]
    marker_comment_id = None
    if isinstance(existing, list):
        for comment in existing:
            if isinstance(comment, dict) and COMMENT_MARKER in comment.get("body", ""):
                marker_comment_id = comment["id"]
                break

    body = format_comment(scan_result, threshold, passed)

    if marker_comment_id:
        update_url = f"{api_base}/repos/{repo}/issues/comments/{marker_comment_id}"
        _github_api("PATCH", update_url, token, {"body": body})
    else:
        _github_api("POST", comments_url, token, {"body": body})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    overlay = os.environ.get("INPUT_OVERLAY", "financial")
    threshold_str = os.environ.get("INPUT_THRESHOLD", "70")
    fail_on_error = os.environ.get("INPUT_FAIL_ON_ERROR", "true").lower() == "true"
    post_comment = os.environ.get("INPUT_POST_COMMENT", "true").lower() == "true"
    github_token = os.environ.get("GITHUB_TOKEN", "")

    try:
        threshold = int(threshold_str)
    except ValueError:
        print(f"::error::Invalid threshold value: {threshold_str!r} — must be an integer")
        sys.exit(1)

    # Step 1: run scan
    try:
        scan_result = run_scan(overlay)
    except Exception as exc:
        print(f"::error::ancilis scan failed: {exc}")
        if fail_on_error:
            sys.exit(1)
        # Graceful degradation — treat as 0 score
        scan_result = {
            "score": 0,
            "posture": "non_compliant",
            "overlay": overlay,
            "controls": [],
            "raw": {},
        }

    # Step 2: evaluate threshold
    score = scan_result["score"]
    passed = score >= threshold

    # Step 3: post PR comment
    if post_comment and is_pr_context():
        post_posture_comment(scan_result, threshold, passed, github_token)

    # Step 4: set outputs
    set_output("score", str(score))
    set_output("passed", str(passed).lower())
    set_output("summary", format_summary(scan_result, passed))

    # Step 5: exit code
    if not passed:
        print(f"::error::Posture score {score} is below threshold {threshold}")
        sys.exit(1)


if __name__ == "__main__":
    main()
