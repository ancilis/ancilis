"""Helpers for loading packaged shared runtime assets."""

from __future__ import annotations

from importlib.resources import as_file, files  # nosemgrep
from pathlib import Path
from types import TracebackType
from typing import Iterator


def _source_tree_shared_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "shared"
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError("Could not locate shared/ runtime assets")


def shared_root() -> Path:
    """Return the packaged shared/ asset directory."""
    packaged = Path(str(files("ancilis").joinpath("shared")))
    if packaged.exists():
        return packaged
    return _source_tree_shared_root()


def shared_path(*parts: str) -> Path:
    """Return a concrete path under packaged shared/ assets."""
    return shared_root().joinpath(*parts)


class shared_path_context:
    """Context manager for callers that require an on-disk path."""

    def __init__(self, *parts: str) -> None:
        self._resource = files("ancilis").joinpath("shared", *parts)
        self._ctx = as_file(self._resource)
        self.path: Path | None = None

    def __enter__(self) -> Path:
        self.path = self._ctx.__enter__()
        return self.path

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._ctx.__exit__(exc_type, exc, tb)


def iter_shared_paths(*parts: str, pattern: str) -> Iterator[Path]:
    """Iterate shared assets matching a glob pattern."""
    yield from sorted(shared_path(*parts).glob(pattern))
