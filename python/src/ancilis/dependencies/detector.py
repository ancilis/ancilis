"""Lockfile detection and dependency parsing for Python projects.

Priority order: poetry.lock > Pipfile.lock > requirements.txt > pyproject.toml
Returns the first manifest found (highest-priority match).
"""

from __future__ import annotations

import json
import re
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ImportError:
        tomllib = None


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str = "PyPI"


@dataclass
class DetectionResult:
    manifest_path: str
    manifest_format: str  # "poetry.lock" | "Pipfile.lock" | "requirements.txt" | "pyproject.toml"
    dependencies: list[Dependency] = field(default_factory=list)


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------

_REQUIREMENTS_PINNED = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)(?:\[.*?\])?==([^\s;#]+)", re.IGNORECASE
)


def _parse_requirements_txt(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return deps
    has_unpinned = False
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQUIREMENTS_PINNED.match(line)
        if m:
            deps.append(Dependency(name=m.group(1), version=m.group(2)))
        else:
            # Check if it's a real specifier (not a URL or option)
            if re.match(r"^[A-Za-z0-9_.\-]+", line):
                has_unpinned = True
    if has_unpinned:
        warnings.warn(
            f"{path}: some dependencies lack pinned versions — OSV results may be incomplete",
            UserWarning,
            stacklevel=2,
        )
    return deps


# ---------------------------------------------------------------------------
# pyproject.toml
# ---------------------------------------------------------------------------


def _normalise_pep508(spec: str) -> tuple[str, str | None]:
    spec = re.sub(r"\[.*?\]", "", spec).split(";")[0].strip()
    m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s,]+)", spec)
    if m:
        return m.group(1), m.group(2)
    m = re.match(r"^([A-Za-z0-9_.\-]+)", spec)
    if m:
        return m.group(1), None
    return spec, None


def _parse_pyproject_toml(path: Path) -> list[Dependency]:
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    raw_deps: list[str] = []
    # [project.dependencies] (PEP 621)
    raw_deps.extend(data.get("project", {}).get("dependencies", []))
    # [tool.poetry.dependencies]
    for name, val in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
        if name.lower() == "python":
            continue
        if isinstance(val, str):
            raw_deps.append(f"{name}{val}" if val.startswith(("=", "^", "~", ">", "<")) else name)
        elif isinstance(val, dict) and "version" in val:
            raw_deps.append(f"{name}{val['version']}")
    deps: list[Dependency] = []
    for spec in raw_deps:
        name, version = _normalise_pep508(str(spec))
        if version is not None:
            deps.append(Dependency(name=name, version=version))
    return deps


# ---------------------------------------------------------------------------
# Pipfile.lock
# ---------------------------------------------------------------------------


def _parse_pipfile_lock(path: Path) -> list[Dependency]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    deps: list[Dependency] = []
    for section in ("default", "develop"):
        for pkg, info in data.get(section, {}).items():
            if isinstance(info, dict):
                version_raw = info.get("version", "")
                m = re.match(r"==(.+)", version_raw)
                if m:
                    deps.append(Dependency(name=pkg, version=m.group(1)))
    return deps


# ---------------------------------------------------------------------------
# poetry.lock
# ---------------------------------------------------------------------------


def _parse_poetry_lock(path: Path) -> list[Dependency]:
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    deps: list[Dependency] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            deps.append(Dependency(name=name, version=str(version)))
    return deps


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_CANDIDATES: list[tuple[str, str]] = [
    ("poetry.lock", "poetry.lock"),
    ("Pipfile.lock", "Pipfile.lock"),
    ("requirements.txt", "requirements.txt"),
    ("pyproject.toml", "pyproject.toml"),
]

_PARSERS = {
    "poetry.lock": _parse_poetry_lock,
    "Pipfile.lock": _parse_pipfile_lock,
    "requirements.txt": _parse_requirements_txt,
    "pyproject.toml": _parse_pyproject_toml,
}


def detect_dependencies(project_dir: Path) -> DetectionResult | None:
    """Find the highest-priority manifest in *project_dir* and parse its dependencies.

    Returns ``None`` if no supported manifest is found.
    """
    for filename, fmt in _CANDIDATES:
        candidate = project_dir / filename
        if candidate.is_file():
            deps = _PARSERS[fmt](candidate)
            return DetectionResult(
                manifest_path=str(candidate),
                manifest_format=fmt,
                dependencies=deps,
            )
    return None
