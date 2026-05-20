"""Deterministic local project inspection for Ancilis Cover."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib

from ancilis.mcp_server.cover.models import CoverSignal, ProjectInspection

_MANIFEST_NAMES = {
    "pyproject.toml",
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Dockerfile",
    "ancilis.yaml",
}

_LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
}

_SOURCE_EXTENSIONS = set(_LANGUAGE_EXTENSIONS)

_DEPENDENCY_FRAMEWORKS: tuple[tuple[str, str, str], ...] = (
    ("@modelcontextprotocol/sdk", "mcp", "mcp"),
    ("mcp", "mcp", "mcp"),
    ("langchain", "langchain", "langchain"),
    ("langchain-core", "langchain", "langchain"),
    ("langchain-openai", "langchain", "langchain"),
    ("openai", "openai", "openai"),
    ("anthropic", "anthropic", "anthropic"),
    ("crewai", "crewai", "crewai"),
    ("autogen", "autogen", "autogen"),
    ("pyautogen", "autogen", "autogen"),
    ("ag2", "autogen", "autogen"),
    ("llama-index", "llamaindex", "tool"),
    ("llama_index", "llamaindex", "tool"),
    ("pydantic-ai", "pydantic-ai", "tool"),
    ("pydantic_ai", "pydantic-ai", "tool"),
)

_IMPORT_FRAMEWORKS: tuple[tuple[re.Pattern[str], str, str, str], ...] = (
    (re.compile(r"\bfrom\s+langchain|\bimport\s+langchain|\blangchain_", re.I), "langchain", "langchain", "import.langchain"),
    (re.compile(r"\bfrom\s+openai\b|\bimport\s+openai\b|from\s+['\"]openai['\"]", re.I), "openai", "openai", "import.openai"),
    (re.compile(r"\bfrom\s+anthropic\b|\bimport\s+anthropic\b|from\s+['\"]anthropic['\"]", re.I), "anthropic", "anthropic", "import.anthropic"),
    (re.compile(r"\bfrom\s+mcp\b|\bimport\s+mcp\b|@modelcontextprotocol/sdk", re.I), "mcp", "mcp", "import.mcp"),
    (re.compile(r"\bfrom\s+crewai\b|\bimport\s+crewai\b", re.I), "crewai", "crewai", "import.crewai"),
    (re.compile(r"\bfrom\s+autogen\b|\bimport\s+autogen\b|\bfrom\s+ag2\b|\bimport\s+ag2\b", re.I), "autogen", "autogen", "import.autogen"),
)


def inspect_project(
    root: str | Path | None = None,
    *,
    max_files: int = 200,
    include_hidden: bool = False,
) -> ProjectInspection:
    """Inspect local project metadata without network calls or file mutation."""
    root_path = Path.cwd() if root is None else Path(root)
    root_path = root_path.resolve()
    if not root_path.exists() or not root_path.is_dir():
        raise ValueError(f"invalid_root: {root_path}")

    files, skipped = _bounded_files(root_path, max_files=max_files, include_hidden=include_hidden)
    languages: set[str] = set()
    dependencies: set[str] = set()
    frameworks: set[str] = set()
    producers: set[str] = set()
    signals: list[CoverSignal] = []
    warnings: list[str] = []

    for path in files:
        language = _LANGUAGE_EXTENSIONS.get(path.suffix.lower())
        if language:
            languages.add(language)

        if path.name in _MANIFEST_NAMES:
            if path.name == "pyproject.toml":
                languages.add("python")
            elif path.name == "package.json":
                languages.add("javascript")
            _inspect_manifest(path, dependencies, signals, warnings)

        if path.suffix.lower() in _SOURCE_EXTENSIONS:
            _inspect_source(path, frameworks, producers, signals, warnings)

    _frameworks_from_dependencies(dependencies, frameworks, producers, signals)

    config_path = root_path / "ancilis.yaml"
    ancilis_present = config_path.exists()
    if ancilis_present:
        signals.append(
            CoverSignal(
                source="config",
                value="ancilis.yaml",
                rule_id="config.ancilis_yaml",
                confidence="high",
                recommendation="ancilis_present",
                path=str(config_path.resolve()),
            )
        )

    if skipped:
        warnings.append(f"Skipped {skipped} files after reaching file limit {max_files}.")

    if "typescript" in dependencies:
        languages.add("typescript")

    return ProjectInspection(
        root=str(root_path),
        languages=sorted(languages),
        frameworks=sorted(frameworks),
        dependencies=sorted(dependencies),
        ancilis_present=ancilis_present,
        config_path=str(config_path.resolve()) if ancilis_present else None,
        recommended_producers=sorted(producers),
        signals=signals,
        warnings=warnings,
        files_scanned=len(files),
        files_skipped=skipped,
    )


def _bounded_files(
    root: Path,
    *,
    max_files: int,
    include_hidden: bool,
) -> tuple[list[Path], int]:
    files: list[Path] = []
    skipped = 0
    limit = max(max_files, 0)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(dirnames)
        if not include_hidden:
            dirnames[:] = [name for name in dirnames if not name.startswith(".")]

        current = Path(dirpath)
        for filename in sorted(filenames):
            path = current / filename
            relative = path.relative_to(root)
            if not include_hidden and any(part.startswith(".") for part in relative.parts):
                continue
            if not path.is_file():
                continue
            if len(files) >= limit:
                skipped += 1
                continue
            files.append(path)
    return files, skipped


def _inspect_manifest(
    path: Path,
    dependencies: set[str],
    signals: list[CoverSignal],
    warnings: list[str],
) -> None:
    try:
        if path.name == "pyproject.toml":
            for dependency in _pyproject_dependencies(path):
                _add_dependency(dependency, path, dependencies, signals)
        elif path.name == "requirements.txt":
            for dependency in _requirements_dependencies(path):
                _add_dependency(dependency, path, dependencies, signals)
        elif path.name == "package.json":
            for dependency in _package_json_dependencies(path):
                _add_dependency(dependency, path, dependencies, signals)
        elif path.name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
            signals.append(
                CoverSignal(
                    source="manifest",
                    value=path.name,
                    rule_id="manifest.lockfile",
                    confidence="medium",
                    path=str(path),
                )
            )
    except Exception as exc:
        warnings.append(f"manifest_parse_error:{path.name}:{exc}")


def _pyproject_dependencies(path: Path) -> list[str]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    dependencies: list[str] = []
    project = data.get("project", {})
    dependencies.extend(str(item) for item in project.get("dependencies", []))
    poetry = data.get("tool", {}).get("poetry", {})
    for name in poetry.get("dependencies", {}):
        if str(name).lower() != "python":
            dependencies.append(str(name))
    return dependencies


def _requirements_dependencies(path: Path) -> list[str]:
    out: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        out.append(line)
    return out


def _package_json_dependencies(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: list[str] = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        values = data.get(section, {})
        if isinstance(values, dict):
            out.extend(str(name) for name in values)
    return out


def _add_dependency(
    raw: str,
    path: Path,
    dependencies: set[str],
    signals: list[CoverSignal],
) -> None:
    dependency = _normalize_dependency(raw)
    if not dependency:
        return
    dependencies.add(dependency)
    signals.append(
        CoverSignal(
            source="dependency",
            value=dependency,
            rule_id="dependency.detected",
            confidence="medium",
            path=str(path),
        )
    )


def _normalize_dependency(raw: str) -> str:
    value = raw.strip().lower()
    if not value:
        return ""
    value = re.split(r"[<>=!~;,\s]", value, maxsplit=1)[0]
    value = re.sub(r"\[.*\]$", "", value)
    return value.strip()


def _frameworks_from_dependencies(
    dependencies: set[str],
    frameworks: set[str],
    producers: set[str],
    signals: list[CoverSignal],
) -> None:
    for dependency in sorted(dependencies):
        for prefix, framework, producer in _DEPENDENCY_FRAMEWORKS:
            if dependency == prefix or dependency.startswith(f"{prefix}-"):
                frameworks.add(framework)
                producers.add(producer)
                signals.append(
                    CoverSignal(
                        source="dependency",
                        value=dependency,
                        rule_id=f"dependency.{framework}",
                        confidence="high",
                        recommendation=producer,
                    )
                )


def _inspect_source(
    path: Path,
    frameworks: set[str],
    producers: set[str],
    signals: list[CoverSignal],
    warnings: list[str],
) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:60000]
    except OSError as exc:
        warnings.append(f"source_read_error:{path.name}:{exc}")
        return

    for pattern, framework, producer, rule_id in _IMPORT_FRAMEWORKS:
        if not pattern.search(text):
            continue
        frameworks.add(framework)
        producers.add(producer)
        signals.append(
            CoverSignal(
                source="import",
                value=framework,
                rule_id=rule_id,
                confidence="high",
                recommendation=producer,
                path=str(path),
            )
        )
