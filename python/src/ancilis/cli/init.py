"""ancilis init — project scaffold with framework-aware templates."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


import click

from ancilis.cli.templates.ancilis_yaml import generate_ancilis_yaml
from ancilis.cli.templates.scan_scripts import get_scan_script
from ancilis.overlays import normalize_overlay_id

# ---------------------------------------------------------------------------
# Framework detection
# ---------------------------------------------------------------------------

_FRAMEWORK_PATTERNS: dict[str, str] = {
    "langchain": r"langchain(?:-core|-community|-openai|-anthropic)?",
    "crewai": r"crewai",
    "autogen": r"(?:pyautogen|autogen)",
    "openai": r"openai",
}

# Detection order (most specific first)
_DETECTION_ORDER = ["langchain", "crewai", "autogen", "openai"]

_AVAILABLE_OVERLAYS = [
    "soc2",
    "gdpr",
    "hipaa",
    "iso-42001",
    "eu-ai-act",
    "nist-csf",
    "pci-dss-v4",
    "cmmc-l2",
    "glba",
    "securities-mnpi",
]


class Framework(str, Enum):
    LANGCHAIN = "langchain"
    CREWAI = "crewai"
    AUTOGEN = "autogen"
    OPENAI = "openai"
    GENERIC = "generic"


@dataclass
class DetectionResult:
    framework: Framework
    confidence: str  # "high", "medium", "low"
    source: str


def _scan_text_for_framework(text: str) -> str | None:
    """Return first matching framework name found in text."""
    text_lower = text.lower()
    for fw in _DETECTION_ORDER:
        if re.search(_FRAMEWORK_PATTERNS[fw], text_lower):
            return fw
    return None


def _read_pyproject_deps(path: Path) -> str:
    """Extract dependency strings from pyproject.toml using stdlib or regex."""
    content = path.read_text(encoding="utf-8", errors="replace")
    # Try stdlib tomllib (Python 3.11+)
    if sys.version_info >= (3, 11):
        import tomllib

        try:
            data = tomllib.loads(content)
            deps: list[str] = []
            # PEP 621 / hatch
            deps += data.get("project", {}).get("dependencies", [])
            # Poetry
            tool_poetry = data.get("tool", {}).get("poetry", {})
            deps += list(tool_poetry.get("dependencies", {}).keys())
            return " ".join(deps)
        except Exception:
            pass
    # Fallback: return raw content for regex scanning
    return content


def detect_framework(project_dir: Path = Path(".")) -> DetectionResult | None:
    """Scan dependency files in *project_dir* and return a DetectionResult."""
    checks: list[tuple[str, str, str]] = []  # (source_label, content, confidence)

    req = project_dir / "requirements.txt"
    if req.is_file():
        checks.append((req.name, req.read_text(encoding="utf-8", errors="replace"), "high"))

    pyproj = project_dir / "pyproject.toml"
    if pyproj.is_file():
        checks.append((pyproj.name, _read_pyproject_deps(pyproj), "high"))

    setup_py = project_dir / "setup.py"
    if setup_py.is_file():
        checks.append((setup_py.name, setup_py.read_text(encoding="utf-8", errors="replace"), "medium"))

    pkg_json = project_dir / "package.json"
    if pkg_json.is_file():
        checks.append((pkg_json.name, pkg_json.read_text(encoding="utf-8", errors="replace"), "low"))

    for source, content, confidence in checks:
        fw = _scan_text_for_framework(content)
        if fw:
            return DetectionResult(Framework(fw), confidence, source)

    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sanitize_name(raw: str) -> str:
    """Convert a raw string into a valid agent name (lowercase, hyphens)."""
    name = raw.lower()
    name = re.sub(r"[^a-z0-9]+", "-", name)
    name = name.strip("-")
    return name or "my-agent"


def _prompt_framework_selection() -> str:
    choices = [fw.value for fw in Framework]
    click.echo("Select agent framework:")
    for i, fw in enumerate(choices, 1):
        click.echo(f"  {i}. {fw}")
    return str(click.prompt(
        "Framework",
        default="generic",
        type=click.Choice(choices, case_sensitive=False),
    ))


def _prompt_overlay_selection() -> str:
    click.echo("Available compliance overlays:")
    for i, ol in enumerate(_AVAILABLE_OVERLAYS, 1):
        click.echo(f"  {i:2d}. {ol}")
    click.echo("  [none] — skip overlay selection")
    return str(click.prompt("Select overlay", default="soc2"))


def _generate_env_example(target: Path) -> None:
    env_file = target / ".env.example"
    if not env_file.exists():
        env_file.write_text(
            "# Ancilis platform API key (optional for local-only scanning)\n"
            "# Get yours at https://ancilis.dev/settings\n"
            "# ANCILIS_API_KEY=your-api-key-here\n",
            encoding="utf-8",
        )


def _update_gitignore(target: Path) -> None:
    gitignore = target / ".gitignore"
    if not gitignore.exists():
        return  # Don't create it — user may not be using git
    content = gitignore.read_text(encoding="utf-8")
    if ".ancilis/" not in content:
        separator = "\n" if content and not content.endswith("\n") else ""
        gitignore.write_text(content + separator + ".ancilis/\n", encoding="utf-8")


def _print_next_steps(
    created_files: list[str],
    skipped_sample: bool,
) -> None:
    click.echo("")
    for f in created_files:
        click.echo(f"✓ {f}")
    click.echo("")
    click.echo("Next steps:")
    click.echo("  1. Review ancilis.yaml and adjust settings")
    if not skipped_sample:
        click.echo("  2. Run: python ancilis_scan.py — create your first evidence records")
        click.echo("  3. Run: ancilis status        — inspect local posture")
        click.echo("  4. Run: ancilis scan          — run your first compliance scan")
    else:
        click.echo("  2. Run: ancilis doctor       — verify your setup")
        click.echo("  3. Add Ancilis to your agent and run it")
        click.echo("  4. Run: ancilis scan          — run your first compliance scan")
    click.echo("  5. Visit https://docs.ancilis.dev/quickstart for the full guide")


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------


@click.command()
@click.option(
    "--framework", "-f",
    type=click.Choice(["langchain", "crewai", "autogen", "openai", "generic"], case_sensitive=False),
    default=None,
    help="Agent framework (skips detection).",
)
@click.option(
    "--overlay", "-o",
    default=None,
    help="Compliance overlay (e.g. soc2, gdpr, hipaa).",
)
@click.option(
    "--agent-name",
    default=None,
    help="Agent name for ancilis.yaml.",
)
@click.option(
    "--detect",
    is_flag=True,
    default=False,
    help="Auto-detect framework without prompting.",
)
@click.option(
    "--no-sample",
    is_flag=True,
    default=False,
    help="Skip generating sample scan script.",
)
@click.option(
    "--dir", "target_dir",
    default=".",
    type=click.Path(exists=True),
    help="Target directory.",
)
def init(
    framework: str | None,
    overlay: str | None,
    agent_name: str | None,
    detect: bool,
    no_sample: bool,
    target_dir: str,
) -> None:
    """Initialize a new Ancilis project with framework-aware configuration."""
    target = Path(target_dir).resolve()

    # 1. Check for existing ancilis.yaml
    config_file = target / "ancilis.yaml"
    if config_file.exists() and not click.confirm("ancilis.yaml already exists. Overwrite?", default=False):
        raise SystemExit(0)

    # 2. Framework detection / selection
    if framework is None:
        detected = detect_framework(target)
        if detected and detected.confidence in ("high", "medium"):
            click.echo(
                f"Detected framework: {detected.framework.value} (from {detected.source})"
            )
            if detect:
                # --detect flag: use it without confirmation
                framework = detected.framework.value
            else:
                if click.confirm(f"Use {detected.framework.value}?", default=True):
                    framework = detected.framework.value
        if framework is None:
            if detect:
                # --detect with nothing found → generic
                framework = Framework.GENERIC.value
                click.echo("No framework detected — using generic.")
            else:
                framework = _prompt_framework_selection()

    # 3. Overlay selection
    if overlay is None:
        overlay = _prompt_overlay_selection()
    overlay = normalize_overlay_id(overlay)

    # 4. Agent name
    if agent_name is None:
        default_name = sanitize_name(target.name)
        agent_name = click.prompt("Agent name", default=default_name)

    agent_name = sanitize_name(agent_name)

    # 5. Generate files
    created: list[str] = []

    yaml_content = generate_ancilis_yaml(agent_name, overlay)
    config_file.write_text(yaml_content, encoding="utf-8")
    created.append("ancilis.yaml")

    if not no_sample:
        scan_script = target / "ancilis_scan.py"
        scan_script.write_text(get_scan_script(framework), encoding="utf-8")
        created.append("ancilis_scan.py")

    _generate_env_example(target)
    created.append(".env.example")

    _update_gitignore(target)
    created.append("updated .gitignore")

    # 6. Print next steps
    _print_next_steps(created, no_sample)
