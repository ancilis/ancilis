"""Tests for ancilis.ignore — .ancilisignore file parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from ancilis.ignore import DEFAULT_PATTERNS, IgnoreFilter


class TestIgnoreFilterDefaults:
    def test_pycache_ignored(self) -> None:
        f = IgnoreFilter()
        assert f.is_ignored("__pycache__/some.pyc")

    def test_git_dir_ignored(self) -> None:
        f = IgnoreFilter()
        assert f.is_ignored(".git/COMMIT_EDITMSG")

    def test_node_modules_ignored(self) -> None:
        f = IgnoreFilter()
        assert f.is_ignored("node_modules/lodash/index.js")

    def test_venv_ignored(self) -> None:
        f = IgnoreFilter()
        assert f.is_ignored(".venv/lib/python3.12/site-packages/foo.py")

    def test_pyc_extension_ignored(self) -> None:
        f = IgnoreFilter()
        assert f.is_ignored("ancilis/cli/__pycache__/main.cpython-313.pyc")

    def test_duckdb_ignored(self) -> None:
        f = IgnoreFilter()
        assert f.is_ignored("evidence.duckdb")

    def test_ancilis_dir_ignored(self) -> None:
        f = IgnoreFilter()
        assert f.is_ignored(".ancilis/some-file")

    def test_normal_python_file_not_ignored(self) -> None:
        f = IgnoreFilter()
        assert not f.is_ignored("ancilis/cli/scan.py")

    def test_requirements_txt_not_ignored(self) -> None:
        f = IgnoreFilter()
        assert not f.is_ignored("requirements.txt")

    def test_pyproject_toml_not_ignored(self) -> None:
        f = IgnoreFilter()
        assert not f.is_ignored("pyproject.toml")

    def test_yaml_not_ignored(self) -> None:
        f = IgnoreFilter()
        assert not f.is_ignored("ancilis.yaml")


class TestIgnoreFilterCustomPatterns:
    def test_custom_pattern_respected(self) -> None:
        f = IgnoreFilter(patterns=["*.log", "tmp/"])
        assert f.is_ignored("debug.log")
        assert f.is_ignored("tmp/scratch.txt")
        # Normal files still pass
        assert not f.is_ignored("main.py")

    def test_custom_pattern_negation(self) -> None:
        # pathspec supports negation with !
        f = IgnoreFilter(patterns=["logs/", "!logs/important.log"])
        assert f.is_ignored("logs/debug.log")
        # Note: pathspec negation un-ignores the file
        assert not f.is_ignored("logs/important.log")

    def test_double_star_glob(self) -> None:
        f = IgnoreFilter(patterns=["**/fixtures/**"])
        assert f.is_ignored("tests/fixtures/data.json")
        assert not f.is_ignored("tests/unit/test_foo.py")


class TestIgnoreFilterRelativeTo:
    def test_absolute_path_relative_to_root(self, tmp_path: Path) -> None:
        f = IgnoreFilter()
        abs_path = tmp_path / "__pycache__" / "foo.pyc"
        # Without relative_to, absolute path won't match simple pattern
        # With relative_to, it strips the prefix first
        assert f.is_ignored(abs_path, relative_to=tmp_path)

    def test_path_outside_root_still_works(self, tmp_path: Path) -> None:
        """If path can't be made relative, is_ignored still functions (uses full path)."""
        f = IgnoreFilter(patterns=["*.log"])
        outside = Path("/some/other/dir/debug.log")
        # Should not raise; pathspec will try to match against full path string
        result = f.is_ignored(outside, relative_to=tmp_path)
        assert isinstance(result, bool)


class TestIgnoreFilterFromFile:
    def test_loads_ancilisignore(self, tmp_path: Path) -> None:
        ignore_file = tmp_path / ".ancilisignore"
        ignore_file.write_text("*.log\ntmp/\n# this is a comment\n\nbuild/\n")

        f = IgnoreFilter.from_file(tmp_path)
        assert f.is_ignored("debug.log")
        assert f.is_ignored("tmp/scratch.txt")
        assert not f.is_ignored("main.py")

    def test_no_ancilisignore_uses_defaults_only(self, tmp_path: Path) -> None:
        f = IgnoreFilter.from_file(tmp_path)
        # Defaults still apply
        assert f.is_ignored("__pycache__/foo.pyc")
        assert not f.is_ignored("main.py")

    def test_comments_and_blank_lines_skipped(self, tmp_path: Path) -> None:
        ignore_file = tmp_path / ".ancilisignore"
        ignore_file.write_text("# ignore logs\n*.log\n\n  # another comment\n*.tmp\n")

        f = IgnoreFilter.from_file(tmp_path)
        assert f.is_ignored("app.log")
        assert f.is_ignored("scratch.tmp")
        assert not f.is_ignored("app.py")

    def test_default_patterns_list_not_empty(self) -> None:
        assert len(DEFAULT_PATTERNS) > 0
        assert "__pycache__/" in DEFAULT_PATTERNS
        assert ".git/" in DEFAULT_PATTERNS
