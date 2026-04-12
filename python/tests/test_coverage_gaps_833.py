"""Tests filling coverage gaps for ANC-833."""

from __future__ import annotations

import builtins
import importlib.util
import json
import sys
import urllib.request
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from ancilis.cli.init import Framework, _read_pyproject_deps, detect_framework
from ancilis.cli.main import cli
from ancilis.config import load_config
from ancilis.controls.de01_baseline import BaselineWindow, DE01BaselineEvaluator
from ancilis.dependencies.detector import Dependency as OsvDependency
from ancilis.dependencies import osv as dependencies_osv
from ancilis.dependencies import detector as dependencies_detector
from ancilis.deps import manifest as deps_manifest
from ancilis.engine.action import Action, ActionParameters, ToolInfo


def _osv_response(vulns_per_query: list[list[dict]]) -> bytes:
    return json.dumps({"results": [{"vulns": vs} for vs in vulns_per_query]}).encode()


def _mock_urlopen(response_bytes: bytes) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.read.return_value = response_bytes
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _make_action(tool_name: str = "tool-a") -> Action:
    return Action(
        action_id="act-833",
        timestamp="2026-04-12T00:00:00Z",
        agent_id="test-agent",
        action_type="tool_call",
        tool=ToolInfo(name=tool_name),
        parameters=ActionParameters(raw={}),
    )


def _load_manifest_without_tomllib(monkeypatch) -> ModuleType:
    path = Path(deps_manifest.__file__).resolve()
    spec = importlib.util.spec_from_file_location(
        "ancilis.deps._manifest_without_tomllib_test",
        path,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)

    real_import = builtins.__import__

    def fake_import(name: str, *args, **kwargs):
        if name in {"tomllib", "tomli"}:
            raise ImportError("tomllib unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(sys, "version_info", (3, 10))
    monkeypatch.setattr(builtins, "__import__", fake_import)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def _load_module_with_tomli_fallback(
    monkeypatch,
    source_path: Path,
    module_name: str,
) -> ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, source_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)

    real_import = builtins.__import__

    def fake_import(name: str, *args, **kwargs):
        if name == "tomllib":
            raise ImportError("tomllib unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(sys, "version_info", (3, 10))
    monkeypatch.setattr(builtins, "__import__", fake_import)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


class TestDepsManifestCoverage833:
    def test_import_fallback_sets_tomllib_none(self, monkeypatch, tmp_path: Path) -> None:
        module = _load_manifest_without_tomllib(monkeypatch)
        assert module.tomllib is None

        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\ndependencies = ["requests==2.28.0"]\n')
        poetry = tmp_path / "poetry.lock"
        poetry.write_text('[[package]]\nname = "requests"\nversion = "2.28.0"\n')

        assert module._parse_pyproject_toml(pyproject) == []
        assert module._parse_poetry_lock(poetry) == []

    def test_manifest_uses_tomli_fallback_on_python_310(
        self,
        monkeypatch,
        tmp_path: Path,
    ) -> None:
        module = _load_module_with_tomli_fallback(
            monkeypatch,
            Path(deps_manifest.__file__).resolve(),
            "ancilis.deps._manifest_with_tomli_test",
        )
        assert module.tomllib is not None

        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\ndependencies = ["requests==2.28.0"]\n')
        poetry = tmp_path / "poetry.lock"
        poetry.write_text('[[package]]\nname = "flask"\nversion = "2.3.0"\n')

        assert [dep.name for dep in module._parse_pyproject_toml(pyproject)] == ["requests"]
        assert [dep.name for dep in module._parse_poetry_lock(poetry)] == ["flask"]

    def test_dependency_detector_uses_tomli_fallback_on_python_310(
        self,
        monkeypatch,
        tmp_path: Path,
    ) -> None:
        module = _load_module_with_tomli_fallback(
            monkeypatch,
            Path(dependencies_detector.__file__).resolve(),
            "ancilis.dependencies._detector_with_tomli_test",
        )
        assert module.tomllib is not None

        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\ndependencies = ["requests==2.28.0"]\n')
        poetry = tmp_path / "poetry.lock"
        poetry.write_text('[[package]]\nname = "flask"\nversion = "2.3.0"\n')

        assert [dep.name for dep in module._parse_pyproject_toml(pyproject)] == ["requests"]
        assert [dep.name for dep in module._parse_poetry_lock(poetry)] == ["flask"]

    def test_normalise_pep508_returns_original_for_unparseable_spec(self) -> None:
        name, version = deps_manifest._normalise_pep508("!not-pep508!")
        assert name == "!not-pep508!"
        assert version is None

    def test_toml_parse_exceptions_return_empty_dependencies(self, monkeypatch, tmp_path: Path) -> None:
        class BrokenToml:
            @staticmethod
            def loads(_content: str) -> dict:
                raise RuntimeError("invalid toml")

        monkeypatch.setattr(deps_manifest, "tomllib", BrokenToml)
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[project]\n")
        poetry = tmp_path / "poetry.lock"
        poetry.write_text("[[package]]\n")

        assert deps_manifest._parse_pyproject_toml(pyproject) == []
        assert deps_manifest._parse_poetry_lock(poetry) == []


class TestDependenciesOsvCoverage833:
    def test_bad_cvss_score_falls_back_to_database_specific_severity(self) -> None:
        vuln_data = {
            "id": "GHSA-bad-cvss",
            "summary": "Bad score",
            "severity": [{"type": "CVSS_V3", "score": "not-a-number"}],
            "database_specific": {"severity": "HIGH"},
            "affected": [],
        }

        with patch("urllib.request.urlopen", return_value=_mock_urlopen(_osv_response([[vuln_data]]))):
            findings, err = dependencies_osv.query_osv_batch([OsvDependency("requests", "2.27.0")])

        assert err is None
        assert findings[0].severity == "high"
        assert findings[0].cvss_score is None

    def test_unknown_database_specific_severity_defaults_low(self) -> None:
        vuln_data = {
            "id": "GHSA-unknown-severity",
            "summary": "Unknown severity",
            "severity": [],
            "database_specific": {"severity": "MODERATE"},
            "affected": [],
        }

        with patch("urllib.request.urlopen", return_value=_mock_urlopen(_osv_response([[vuln_data]]))):
            findings, err = dependencies_osv.query_osv_batch([OsvDependency("requests", "2.27.0")])

        assert err is None
        assert findings[0].severity == "low"
        assert findings[0].cvss_score is None

    def test_invalid_osv_json_returns_error(self) -> None:
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(b"not json")):
            findings, err = dependencies_osv.query_osv_batch([OsvDependency("requests", "2.27.0")])

        assert findings == []
        assert err is not None
        assert "Invalid JSON from OSV.dev" in err

    def test_query_chunk_for_else_returns_last_exception_when_retries_disabled(self, monkeypatch) -> None:
        monkeypatch.setattr(dependencies_osv, "_MAX_RETRIES", 0)

        findings, err = dependencies_osv._query_chunk([OsvDependency("requests", "2.27.0")])

        assert findings == []
        assert err is None


class TestDE01Coverage833:
    def test_calls_per_minute_is_zero_for_empty_window(self) -> None:
        assert BaselineWindow(call_count=10, window_minutes=0).calls_per_minute == 0.0

    def test_baseline_property_and_setter(self) -> None:
        evaluator = DE01BaselineEvaluator()
        baseline = BaselineWindow(tool_calls=["tool-a"], call_count=1, window_minutes=1)

        evaluator.set_baseline(baseline)

        assert evaluator.baseline is baseline

    def test_evaluate_with_rate_passes_when_baseline_missing(self) -> None:
        result = DE01BaselineEvaluator().evaluate_with_rate(
            _make_action(),
            load_config(raw={"agent": {"name": "test-agent"}}),
            current_rate=10,
        )

        assert result.result == "PASS"
        assert result.evidence_data["baseline_established"] is False

    def test_evaluate_with_rate_flags_new_tool(self) -> None:
        baseline = BaselineWindow(tool_calls=["tool-a"], call_count=10, window_minutes=5)
        result = DE01BaselineEvaluator(baseline).evaluate_with_rate(
            _make_action("tool-b"),
            load_config(raw={"agent": {"name": "test-agent"}}),
            current_rate=1,
        )

        assert result.result == "FLAG"
        assert result.evidence_data["new_tools_detected"] == ["tool-b"]

    def test_evaluate_with_rate_passes_for_known_tool_at_normal_rate(self) -> None:
        baseline = BaselineWindow(tool_calls=["tool-a"], call_count=10, window_minutes=5)
        result = DE01BaselineEvaluator(baseline).evaluate_with_rate(
            _make_action("tool-a"),
            load_config(raw={"agent": {"name": "test-agent"}}),
            current_rate=2,
        )

        assert result.result == "PASS"
        assert result.evidence_data["current_rate_vs_baseline"] == 1.0


class TestCliInitCoverage833:
    def test_read_pyproject_deps_falls_back_to_raw_content_on_invalid_toml(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[not valid toml\n# openai")

        assert "openai" in _read_pyproject_deps(pyproject)
        detected = detect_framework(tmp_path)
        assert detected is not None
        assert detected.framework == Framework.OPENAI

    def test_detect_framework_reads_setup_py_with_medium_confidence(self, tmp_path: Path) -> None:
        (tmp_path / "setup.py").write_text('install_requires=["crewai"]')

        detected = detect_framework(tmp_path)

        assert detected is not None
        assert detected.framework == Framework.CREWAI
        assert detected.source == "setup.py"
        assert detected.confidence == "medium"

    def test_detect_framework_reads_package_json_with_low_confidence(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text('{"dependencies": {"openai": "latest"}}')

        detected = detect_framework(tmp_path)

        assert detected is not None
        assert detected.framework == Framework.OPENAI
        assert detected.source == "package.json"
        assert detected.confidence == "low"

    def test_init_detect_uses_detected_framework_without_confirmation(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            td_path = Path(td)
            (td_path / "requirements.txt").write_text("langchain==0.1.0\n")

            result = runner.invoke(
                cli,
                [
                    "init",
                    "--detect",
                    "--overlay",
                    "soc2",
                    "--agent-name",
                    "agent",
                    "--dir",
                    str(td_path),
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        assert "Detected framework: langchain" in result.output

    def test_init_accepts_detected_framework_confirmation(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            td_path = Path(td)
            (td_path / "requirements.txt").write_text("openai==1.0.0\n")

            result = runner.invoke(
                cli,
                [
                    "init",
                    "--overlay",
                    "soc2",
                    "--agent-name",
                    "agent",
                    "--dir",
                    str(td_path),
                ],
                input="\n",
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        assert "Detected framework: openai" in result.output

    def test_init_detect_uses_generic_when_nothing_detected(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            td_path = Path(td)

            result = runner.invoke(
                cli,
                [
                    "init",
                    "--detect",
                    "--overlay",
                    "soc2",
                    "--agent-name",
                    "agent",
                    "--dir",
                    str(td_path),
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        assert "No framework detected" in result.output
