"""Manifest detection and dependency parsing for common Python manifest formats."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[import]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


@dataclass
class Dependency:
    name: str
    version: str | None
    source_file: str


@dataclass
class Manifest:
    path: str
    format: str
    dependencies: list[Dependency] = field(default_factory=list)


# Matches pinned lines like: requests==2.28.0, requests==2.28.0[security]
_REQUIREMENTS_PINNED = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)(?:\[.*?\])?==([^\s;#]+)", re.IGNORECASE
)


def _parse_requirements_txt(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-r") or line.startswith("-c"):
            continue
        m = _REQUIREMENTS_PINNED.match(line)
        if m:
            deps.append(Dependency(name=m.group(1), version=m.group(2), source_file=str(path)))
    return deps


def _normalise_pep508(spec: str) -> tuple[str, str | None]:
    """Extract (name, version) from a PEP 508 specifier, or (name, None) if unpinned."""
    # Strip extras, environment markers
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
    raw_deps = data.get("project", {}).get("dependencies", [])
    deps: list[Dependency] = []
    for spec in raw_deps:
        name, version = _normalise_pep508(spec)
        if version is not None:
            deps.append(Dependency(name=name, version=version, source_file=str(path)))
    return deps


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
                # Pipfile.lock versions look like "==2.28.0"
                m = re.match(r"==(.+)", version_raw)
                if m:
                    deps.append(Dependency(name=pkg, version=m.group(1), source_file=str(path)))
    return deps


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
            deps.append(Dependency(name=name, version=str(version), source_file=str(path)))
    return deps


class ManifestDetector:
    """Detect and parse Python dependency manifests in a project directory."""

    _HANDLERS: list[tuple[str, str, object]] = [
        ("requirements.txt", "requirements.txt", _parse_requirements_txt),
        ("pyproject.toml", "pyproject.toml", _parse_pyproject_toml),
        ("Pipfile.lock", "Pipfile.lock", _parse_pipfile_lock),
        ("poetry.lock", "poetry.lock", _parse_poetry_lock),
    ]

    def detect(self, project_dir: Path) -> list[Manifest]:
        """Find and parse all supported manifest files in *project_dir*."""
        manifests: list[Manifest] = []
        for filename, fmt, handler in self._HANDLERS:
            candidate = project_dir / filename
            if candidate.is_file():
                deps = handler(candidate)  # type: ignore[operator]
                manifests.append(Manifest(path=str(candidate), format=fmt, dependencies=deps))
        return manifests
