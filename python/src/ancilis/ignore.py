"""ancilis.ignore — .ancilisignore file parser using gitignore-compatible pathspec matching."""

from __future__ import annotations

from pathlib import Path
import contextlib

_ANCILISIGNORE = ".ancilisignore"

DEFAULT_PATTERNS = [
    "__pycache__/",
    ".git/",
    "node_modules/",
    ".venv/",
    "venv/",
    "*.pyc",
    "*.pyo",
    "build/",
    "dist/",
    ".eggs/",
    "*.egg-info/",
    ".tox/",
    ".mypy_cache/",
    ".ruff_cache/",
    ".pytest_cache/",
    "*.duckdb",
    ".ancilis/",
]


class IgnoreFilter:
    """Filter file paths using gitignore-compatible patterns.

    Combines DEFAULT_PATTERNS with any patterns from .ancilisignore.
    """

    def __init__(self, patterns: list[str] | None = None) -> None:
        try:
            import pathspec
        except ImportError as e:
            raise ImportError(
                "pathspec is required for .ancilisignore support. "
                "Install it with: pip install ancilis[watch]"
            ) from e
        combined = list(DEFAULT_PATTERNS) + (patterns or [])
        self._spec = pathspec.PathSpec.from_lines("gitignore", combined)

    @classmethod
    def from_file(cls, project_root: Path) -> IgnoreFilter:
        """Load patterns from .ancilisignore in project_root, falling back to defaults."""
        ignore_file = project_root / _ANCILISIGNORE
        extra: list[str] = []
        if ignore_file.is_file():
            for line in ignore_file.read_text().splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    extra.append(stripped)
        return cls(patterns=extra)

    def is_ignored(self, path: str | Path, relative_to: Path | None = None) -> bool:
        """Return True if *path* matches any ignore pattern."""
        p = Path(path)
        if relative_to is not None:
            with contextlib.suppress(ValueError):
                p = p.relative_to(relative_to)
        return bool(self._spec.match_file(str(p)))
