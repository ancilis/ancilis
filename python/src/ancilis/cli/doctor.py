"""ancilis doctor — 10-check diagnostic tool for configuration, connectivity, and environment health."""

from __future__ import annotations

import concurrent.futures
import importlib
import importlib.metadata
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from collections.abc import Callable

import click

from ancilis.cli.version_check import fetch_latest_version, read_cache
from ancilis.config import ResolvedConfig


class CheckStatus(Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    label: str
    detail: str
    fix_hint: str = ""
    verbose_detail: str = ""


@dataclass
class DoctorReport:
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.PASS)

    @property
    def warnings(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.WARN)

    @property
    def errors(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def exit_code(self) -> int:
        if self.errors > 0:
            return 2
        if self.warnings > 0:
            return 1
        return 0


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------


def check_sdk_version(config: ResolvedConfig | None, verbose: bool) -> CheckResult:
    try:
        installed = importlib.metadata.version("ancilis")
    except importlib.metadata.PackageNotFoundError:
        installed = "unknown"

    latest: str | None = None
    source = ""
    cached = read_cache()
    if cached is not None:
        latest = cached.get("latest_version")
        source = "(cached)"
    else:
        latest = fetch_latest_version()
        source = "(live)" if latest else ""

    if latest is None:
        return CheckResult(
            name="sdk_version",
            status=CheckStatus.PASS,
            label="SDK version",
            detail=f"{installed} (could not check latest)",
            verbose_detail="PyPI check failed or timed out — no network or cache available",
        )

    try:
        from packaging.version import parse as vparse

        outdated = vparse(latest) > vparse(installed)
    except Exception:
        outdated = latest != installed

    if outdated:
        return CheckResult(
            name="sdk_version",
            status=CheckStatus.WARN,
            label="SDK version",
            detail=f"{installed} (latest: {latest} {source})",
            fix_hint="Run: pip install --upgrade ancilis",
            verbose_detail=f"Installed: {installed}, Available: {latest}",
        )
    return CheckResult(
        name="sdk_version",
        status=CheckStatus.PASS,
        label="SDK version",
        detail=f"{installed} (latest {source})".strip(),
        verbose_detail=f"Installed: {installed}, PyPI latest: {latest}",
    )


def check_python_version(config: ResolvedConfig | None, verbose: bool) -> CheckResult:
    vi = sys.version_info
    version_str = f"{vi[0]}.{vi[1]}.{vi[2]}"
    if vi >= (3, 9):
        return CheckResult(
            name="python_version",
            status=CheckStatus.PASS,
            label="Python version",
            detail=f"{version_str} (>=3.9 required)",
            verbose_detail=f"Full version: {sys.version}",
        )
    return CheckResult(
        name="python_version",
        status=CheckStatus.FAIL,
        label="Python version",
        detail=f"{version_str} (>=3.9 required)",
        fix_hint="Install Python 3.9+ from https://www.python.org/downloads/",
        verbose_detail=f"Full version: {sys.version}",
    )


def check_config(
    config: ResolvedConfig | None, verbose: bool, config_path: str | None = None
) -> CheckResult:
    if config is not None:
        return CheckResult(
            name="config",
            status=CheckStatus.PASS,
            label="Configuration",
            detail=f"ancilis.yaml loaded for agent '{config.agent_name}' in {config.mode} mode",
            verbose_detail=f"Mode: {config.mode}, Agent: {config.agent_name}",
        )
    try:
        from ancilis.config import load_config

        cfg = load_config(path=config_path) if config_path else load_config()
        return CheckResult(
            name="config",
            status=CheckStatus.PASS,
            label="Configuration",
            detail=f"ancilis.yaml loaded for agent '{cfg.agent_name}' in {cfg.mode} mode",
        )
    except Exception as exc:
        return CheckResult(
            name="config",
            status=CheckStatus.FAIL,
            label="Configuration",
            detail=f"ancilis.yaml not found or invalid: {exc}",
            fix_hint=(
                "Create ancilis.yaml in your project root:\n"
                "  agent:\n"
                "    name: my-agent\n"
                "\n"
                "  Then run: ancilis doctor"
            ),
            verbose_detail=str(exc),
        )


def check_overlay(config: ResolvedConfig | None, verbose: bool) -> CheckResult:
    if config is None:
        return CheckResult(
            name="overlay",
            status=CheckStatus.WARN,
            label="Overlay",
            detail="skipped (config not loaded)",
        )
    try:
        from ancilis.overlays.loader import load_overlay_definitions

        overlays = getattr(config.compliance, "overlays", []) or []
        if not overlays:
            return CheckResult(
                name="overlay",
                status=CheckStatus.WARN,
                label="Overlay",
                detail="no overlays configured",
                fix_hint="Consider enabling an overlay (e.g. financial, hipaa) in ancilis.yaml",
            )

        all_defs = load_overlay_definitions()
        available = {d.get("id") or d.get("overlay_id", "") for d in all_defs}
        missing = [ov for ov in overlays if ov not in available]
        if missing:
            return CheckResult(
                name="overlay",
                status=CheckStatus.FAIL,
                label="Overlay",
                detail=f"overlay(s) not found: {', '.join(missing)}",
                fix_hint="Check overlay IDs in ancilis.yaml against available overlays",
                verbose_detail=f"Available overlays: {sorted(available)}",
            )

        control_count = sum(
            len(d.get("controls", []))
            for d in all_defs
            if (d.get("id") or d.get("overlay_id", "")) in set(overlays)
        )
        return CheckResult(
            name="overlay",
            status=CheckStatus.PASS,
            label="Overlay",
            detail=f"{', '.join(overlays)} (active, {control_count} controls)",
            verbose_detail=f"Overlays: {overlays}, Total controls: {control_count}",
        )
    except Exception as exc:
        return CheckResult(
            name="overlay",
            status=CheckStatus.WARN,
            label="Overlay",
            detail=f"could not validate overlays: {exc}",
            verbose_detail=str(exc),
        )


def check_platform_connectivity(config: ResolvedConfig | None, verbose: bool) -> CheckResult:
    platform_json = Path.home() / ".ancilis" / "platform.json"
    url = ""
    if not platform_json.exists():
        return CheckResult(
            name="platform_connectivity",
            status=CheckStatus.WARN,
            label="Platform API",
            detail="not connected (platform.json not found)",
            fix_hint="Run: ancilis login  to connect to the Ancilis platform",
        )
    try:
        data = json.loads(platform_json.read_text())
        url = data.get("api_url") or data.get("url", "")
        if not url:
            return CheckResult(
                name="platform_connectivity",
                status=CheckStatus.WARN,
                label="Platform API",
                detail="platform.json missing api_url field",
            )
        import time

        t0 = time.monotonic()
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=2) as resp:
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            return CheckResult(
                name="platform_connectivity",
                status=CheckStatus.PASS,
                label="Platform API",
                detail=f"{url} (connected)",
                verbose_detail=f"Response: {resp.status} in {elapsed_ms}ms",
            )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return CheckResult(
            name="platform_connectivity",
            status=CheckStatus.FAIL,
            label="Platform API",
            detail=f"could not reach {url} — check network",
            fix_hint="Check your network connection or platform URL in ~/.ancilis/platform.json",
            verbose_detail=str(exc),
        )
    except Exception as exc:
        return CheckResult(
            name="platform_connectivity",
            status=CheckStatus.WARN,
            label="Platform API",
            detail=f"unexpected error: {exc}",
            verbose_detail=str(exc),
        )


def check_api_key(config: ResolvedConfig | None, verbose: bool) -> CheckResult:
    platform_json = Path.home() / ".ancilis" / "platform.json"
    url = ""
    if not platform_json.exists():
        return CheckResult(
            name="api_key",
            status=CheckStatus.WARN,
            label="API key",
            detail="not configured (platform.json not found)",
            fix_hint="Run: ancilis login  to connect to the Ancilis platform",
        )
    try:
        data = json.loads(platform_json.read_text())
        api_key = data.get("api_key") or data.get("token", "")
        api_url = data.get("api_url") or data.get("url", "")
        if not api_key:
            return CheckResult(
                name="api_key",
                status=CheckStatus.WARN,
                label="API key",
                detail="not configured",
                fix_hint="Run: ancilis login  to set up API authentication",
            )
        if not api_url:
            return CheckResult(
                name="api_key",
                status=CheckStatus.WARN,
                label="API key",
                detail="key present but no API URL configured",
            )
        req = urllib.request.Request(
            f"{api_url.rstrip('/')}/api/me",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            body = json.loads(resp.read())
            tenant = body.get("tenant", body.get("name", "unknown"))
            return CheckResult(
                name="api_key",
                status=CheckStatus.PASS,
                label="API key",
                detail=f"valid, tenant={tenant}",
                verbose_detail=f"Response: {body}",
            )
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return CheckResult(
                name="api_key",
                status=CheckStatus.FAIL,
                label="API key",
                detail="rejected (401/403) — key may be expired or invalid",
                fix_hint="Run: ancilis login  to refresh credentials",
                verbose_detail=str(exc),
            )
        return CheckResult(
            name="api_key",
            status=CheckStatus.WARN,
            label="API key",
            detail=f"HTTP {exc.code} from platform",
            verbose_detail=str(exc),
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return CheckResult(
            name="api_key",
            status=CheckStatus.WARN,
            label="API key",
            detail="key present but platform unreachable",
            verbose_detail=str(exc),
        )
    except Exception as exc:
        return CheckResult(
            name="api_key",
            status=CheckStatus.WARN,
            label="API key",
            detail=f"could not validate: {exc}",
            verbose_detail=str(exc),
        )


def check_evidence_cache(
    config: ResolvedConfig | None,
    verbose: bool,
    db_path: str | None = None,
    fix: bool = False,
) -> CheckResult:
    cache_dir = Path.home() / ".ancilis"
    try:
        if fix and not cache_dir.exists():
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_dir.chmod(0o700)

        if not cache_dir.exists():
            return CheckResult(
                name="evidence_cache",
                status=CheckStatus.WARN,
                label="Evidence cache",
                detail=f"{cache_dir} does not exist",
                fix_hint=f"Run: mkdir -p {cache_dir}  or use: ancilis doctor --fix",
            )

        # Check writability
        probe = cache_dir / ".ancilis-write-probe"
        probe.write_text("ok")
        probe.unlink()

        # Calculate total directory size
        total_bytes = sum(f.stat().st_size for f in cache_dir.rglob("*") if f.is_file())
        total_mb = total_bytes / (1024 * 1024)

        if total_mb > 500:
            return CheckResult(
                name="evidence_cache",
                status=CheckStatus.WARN,
                label="Evidence cache",
                detail=f"{cache_dir} ({total_mb:.0f} MB — consider cleanup)",
                fix_hint="Run: ancilis evidence prune  or manually remove old .duckdb files in ~/.ancilis/",
                verbose_detail=f"Total size: {total_mb:.1f} MB",
            )
        return CheckResult(
            name="evidence_cache",
            status=CheckStatus.PASS,
            label="Evidence cache",
            detail=f"{cache_dir} ({total_mb:.1f} MB, writable)",
            verbose_detail=f"Path: {cache_dir}, Size: {total_mb:.1f} MB",
        )
    except PermissionError:
        return CheckResult(
            name="evidence_cache",
            status=CheckStatus.FAIL,
            label="Evidence cache",
            detail=f"{cache_dir} is not writable",
            fix_hint=f"Run: chmod 700 {cache_dir}",
        )
    except Exception as exc:
        return CheckResult(
            name="evidence_cache",
            status=CheckStatus.WARN,
            label="Evidence cache",
            detail=f"could not check cache: {exc}",
            verbose_detail=str(exc),
        )


def check_producers(config: ResolvedConfig | None, verbose: bool) -> CheckResult:
    if config is None:
        return CheckResult(
            name="producers",
            status=CheckStatus.WARN,
            label="Producer",
            detail="skipped (config not loaded)",
        )

    handles = getattr(config, "my_agent_handles", []) or []

    # Framework detection: handle type keyword → (import_name, install_hint)
    framework_map: dict[str, tuple[str, str]] = {
        "langchain": ("langchain", "pip install ancilis[langchain]"),
        "crewai": ("crewai", "pip install crewai"),
        "autogen": ("autogen", "pip install pyautogen"),
        "openai": ("openai", "pip install openai"),
    }

    warnings: list[str] = []
    verbose_lines: list[str] = []
    for handle in handles:
        for fw_name, (import_path, hint) in framework_map.items():
            if fw_name in str(handle).lower():
                try:
                    importlib.import_module(import_path)
                    verbose_lines.append(f"{fw_name}: importable")
                except ImportError:
                    warnings.append(f"{fw_name} not importable")
                    verbose_lines.append(f"{fw_name}: not importable — {hint}")

    if warnings:
        return CheckResult(
            name="producers",
            status=CheckStatus.WARN,
            label="Producer",
            detail=f"framework(s) missing: {', '.join(warnings)}",
            fix_hint="; ".join(
                f"pip install ancilis[{w.split()[0]}]" for w in warnings
            ),
            verbose_detail="\n".join(verbose_lines),
        )
    return CheckResult(
        name="producers",
        status=CheckStatus.PASS,
        label="Producer",
        detail="all configured producer frameworks available",
        verbose_detail=(
            "\n".join(verbose_lines)
            if verbose_lines
            else "No framework-specific producers configured"
        ),
    )


def check_gitignore(
    config: ResolvedConfig | None, verbose: bool, fix: bool = False
) -> CheckResult:
    cwd = Path.cwd()
    git_dir = cwd / ".git"
    if not git_dir.exists():
        return CheckResult(
            name="gitignore",
            status=CheckStatus.PASS,
            label="Git",
            detail="not a git repo — skipping gitignore check",
        )

    gitignore = cwd / ".gitignore"
    if not gitignore.exists():
        if fix:
            gitignore.write_text(".ancilis/\n")
            return CheckResult(
                name="gitignore",
                status=CheckStatus.PASS,
                label="Git",
                detail=".gitignore created with .ancilis/ entry",
            )
        return CheckResult(
            name="gitignore",
            status=CheckStatus.WARN,
            label="Git",
            detail=".gitignore not found — .ancilis/ may be committed accidentally",
            fix_hint="Create .gitignore and add .ancilis/ to it, or run: ancilis doctor --fix",
        )

    content = gitignore.read_text()
    lines = [line.strip() for line in content.splitlines()]
    if ".ancilis/" in lines or ".ancilis" in lines:
        return CheckResult(
            name="gitignore",
            status=CheckStatus.PASS,
            label="Git",
            detail=".ancilis/ is in .gitignore",
            verbose_detail=f"Gitignore path: {gitignore}",
        )

    if fix:
        with gitignore.open("a") as f:
            f.write("\n.ancilis/\n")
        return CheckResult(
            name="gitignore",
            status=CheckStatus.PASS,
            label="Git",
            detail=".ancilis/ added to .gitignore (auto-fixed)",
        )

    return CheckResult(
        name="gitignore",
        status=CheckStatus.WARN,
        label="Git",
        detail=".ancilis/ not in .gitignore",
        fix_hint="Add .ancilis/ to .gitignore, or run: ancilis doctor --fix",
        verbose_detail=f"Checked {gitignore}, no matching entry found",
    )


def check_dependency_conflicts(config: ResolvedConfig | None, verbose: bool) -> CheckResult:
    issues: list[str] = []
    verbose_lines: list[str] = []

    # Check pydantic v2+
    try:
        pydantic_ver = importlib.metadata.version("pydantic")
        try:
            from packaging.version import parse as vparse

            if vparse(pydantic_ver).major < 2:
                issues.append(f"pydantic {pydantic_ver} (requires v2+)")
        except Exception:
            pass
        verbose_lines.append(f"pydantic: {pydantic_ver}")
    except importlib.metadata.PackageNotFoundError:
        verbose_lines.append("pydantic: not installed")
    except Exception as exc:
        verbose_lines.append(f"pydantic check error: {exc}")

    # Check duckdb minimum version
    try:
        duckdb_ver = importlib.metadata.version("duckdb")
        try:
            from packaging.version import parse as vparse

            if vparse(duckdb_ver) < vparse("0.10.0"):
                issues.append(f"duckdb {duckdb_ver} (requires >=0.10.0)")
        except Exception:
            pass
        verbose_lines.append(f"duckdb: {duckdb_ver}")
    except importlib.metadata.PackageNotFoundError:
        verbose_lines.append("duckdb: not installed")
    except Exception as exc:
        verbose_lines.append(f"duckdb check error: {exc}")

    if issues:
        return CheckResult(
            name="dependency_conflicts",
            status=CheckStatus.WARN,
            label="Dependencies",
            detail=f"potential conflicts: {'; '.join(issues)}",
            fix_hint="Run: pip install --upgrade " + " ".join(p.split()[0] for p in issues),
            verbose_detail="\n".join(verbose_lines),
        )
    return CheckResult(
        name="dependency_conflicts",
        status=CheckStatus.PASS,
        label="Dependencies",
        detail="no known conflicts detected",
        verbose_detail="\n".join(verbose_lines),
    )


# ---------------------------------------------------------------------------
# Check runner — network checks parallelized
# ---------------------------------------------------------------------------

_NETWORK_CHECKS = {"sdk_version", "platform_connectivity", "api_key"}


def _run_checks(
    config: ResolvedConfig | None,
    verbose: bool,
    fix: bool,
    config_path: str | None,
    db_path: str | None,
) -> DoctorReport:
    report = DoctorReport()

    check_fns: list[tuple[str, Callable[[], CheckResult]]] = [
        ("sdk_version", lambda: check_sdk_version(config, verbose)),
        ("python_version", lambda: check_python_version(config, verbose)),
        ("config", lambda: check_config(config, verbose, config_path=config_path)),
        ("overlay", lambda: check_overlay(config, verbose)),
        ("platform_connectivity", lambda: check_platform_connectivity(config, verbose)),
        ("api_key", lambda: check_api_key(config, verbose)),
        (
            "evidence_cache",
            lambda: check_evidence_cache(config, verbose, db_path=db_path, fix=fix),
        ),
        ("producers", lambda: check_producers(config, verbose)),
        ("gitignore", lambda: check_gitignore(config, verbose, fix=fix)),
        ("dependency_conflicts", lambda: check_dependency_conflicts(config, verbose)),
    ]

    network_results: dict[str, CheckResult] = {}
    network_fns = [(n, fn) for n, fn in check_fns if n in _NETWORK_CHECKS]

    if network_fns:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(network_fns)) as executor:
            futures = {executor.submit(fn): name for name, fn in network_fns}
            for fut in concurrent.futures.as_completed(futures):
                name = futures[fut]
                try:
                    network_results[name] = fut.result()
                except Exception as exc:
                    network_results[name] = CheckResult(
                        name=name,
                        status=CheckStatus.WARN,
                        label=name.replace("_", " ").title(),
                        detail=f"check error: {exc}",
                    )

    for name, fn in check_fns:
        if name in _NETWORK_CHECKS:
            result = network_results.get(
                name,
                CheckResult(
                    name=name,
                    status=CheckStatus.WARN,
                    label=name.replace("_", " ").title(),
                    detail="check did not complete",
                ),
            )
            report.checks.append(result)
        else:
            try:
                report.checks.append(fn())
            except Exception as exc:
                report.checks.append(
                    CheckResult(
                        name=name,
                        status=CheckStatus.FAIL,
                        label=name.replace("_", " ").title(),
                        detail=f"check error: {exc}",
                    )
                )

    return report


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

_STATUS_ICONS = {
    CheckStatus.PASS: "[✓]",
    CheckStatus.WARN: "[!]",
    CheckStatus.FAIL: "[✗]",
}

_STATUS_COLORS = {
    CheckStatus.PASS: "green",
    CheckStatus.WARN: "yellow",
    CheckStatus.FAIL: "red",
}


def _color(text: str, color: str) -> str:
    if os.environ.get("NO_COLOR", ""):
        return text
    return click.style(text, fg=color)


def _format_human(report: DoctorReport, verbose: bool) -> str:
    lines = ["Ancilis Doctor", "==============", ""]
    for check in report.checks:
        icon = _STATUS_ICONS[check.status]
        colored_icon = _color(icon, _STATUS_COLORS[check.status])
        lines.append(f"{colored_icon} {check.label}: {check.detail}")
        if verbose and check.verbose_detail:
            for vline in check.verbose_detail.splitlines():
                lines.append(f"    {vline}")

    lines.append("")
    summary_parts = [f"{report.passed} checks passed"]
    if report.warnings:
        summary_parts.append(f"{report.warnings} warning{'s' if report.warnings != 1 else ''}")
    if report.errors:
        summary_parts.append(f"{report.errors} error{'s' if report.errors != 1 else ''}")
    lines.append(", ".join(summary_parts))

    fix_items = [
        c
        for c in report.checks
        if c.fix_hint and c.status in (CheckStatus.WARN, CheckStatus.FAIL)
    ]
    if fix_items:
        lines.append("")
        lines.append("To fix issues:")
        for c in fix_items:
            for hint_line in c.fix_hint.splitlines():
                lines.append(f"  \u2022 {hint_line}")

    return "\n".join(lines)


def _format_json(report: DoctorReport) -> str:
    try:
        installed = importlib.metadata.version("ancilis")
    except Exception:
        installed = "unknown"
    data = {
        "version": installed,
        "checks": [
            {"name": c.name, "status": c.status.value, "detail": c.detail}
            for c in report.checks
        ],
        "summary": {
            "passed": report.passed,
            "warnings": report.warnings,
            "errors": report.errors,
        },
        "exit_code": report.exit_code,
    }
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------


@click.command()
@click.option("--config", "config_path", default=None, help="Path to ancilis.yaml")
@click.option("--db", "db_path", default=None, help="Path to evidence database")
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    default=False,
    help="Machine-readable JSON output",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Show full diagnostic details per check",
)
@click.option(
    "--fix",
    is_flag=True,
    default=False,
    help="Auto-fix common issues (gitignore, cache dir)",
)
def doctor(
    config_path: str | None,
    db_path: str | None,
    json_output: bool,
    verbose: bool,
    fix: bool,
) -> None:
    """Run 10 diagnostic checks for configuration, connectivity, and environment health."""
    config: ResolvedConfig | None = None
    try:
        from ancilis.config import load_config

        config = load_config(path=config_path) if config_path else load_config()
    except Exception:
        pass

    report = _run_checks(
        config, verbose=verbose, fix=fix, config_path=config_path, db_path=db_path
    )

    if json_output:
        click.echo(_format_json(report))
    else:
        click.echo(_format_human(report, verbose=verbose))

    raise SystemExit(report.exit_code)
