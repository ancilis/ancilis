from __future__ import annotations

import importlib
import importlib.util
import sys
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None
from pathlib import Path

from click.testing import CliRunner
import pytest
import yaml

from ancilis.cli.main import cli
from ancilis.config import load_config, load_control_definitions, load_taxonomy
from ancilis.engine.action import Action, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.evidence.store import EvidenceStore


ROOT = Path(__file__).resolve().parents[2]
RELEASE_CHECK_PATH = ROOT / "scripts" / "release_check.py"
RELEASE_CHECK_SPEC = importlib.util.spec_from_file_location("ancilis_release_check", RELEASE_CHECK_PATH)
assert RELEASE_CHECK_SPEC is not None and RELEASE_CHECK_SPEC.loader is not None
release_check = importlib.util.module_from_spec(RELEASE_CHECK_SPEC)
RELEASE_CHECK_SPEC.loader.exec_module(release_check)


def _config(**overrides):
    raw = {"agent": {"name": "test-agent"}}
    raw.update(overrides)
    return load_config(raw=raw)


def _action(*, tool_name: str = "read_file", source_type: str = "tool") -> Action:
    return Action(
        action_id="act-001",
        timestamp="2026-03-20T00:00:00Z",
        agent_id="test-agent",
        source_type=source_type,
        action_type="tool_call",
        tool=ToolInfo(name=tool_name),
        parameters=ActionParameters(raw={"path": "/tmp/demo"}),
    )


def test_shared_assets_load_from_runtime_tree():
    taxonomy = load_taxonomy()
    controls = load_control_definitions()
    assert taxonomy["version"]
    assert controls["PR-01"]["id"] == "PR-01"


def test_optional_mcp_import_remains_lazy(monkeypatch):
    sys.modules.pop("ancilis.producers", None)
    original_import = importlib.import_module

    def guarded_import(name: str, package: str | None = None):
        if name == "mcp":
            raise ImportError("simulated missing optional dependency")
        return original_import(name, package)

    monkeypatch.setattr(importlib, "import_module", guarded_import)
    producers = importlib.import_module("ancilis.producers")
    assert producers.CLIActionProducer is not None
    assert producers.HTTPActionProducer is not None


def test_source_type_flows_into_evidence_record():
    config = _config()
    registry = ToolRegistry()
    registry.register(ToolEntry(name="read_file", status=ToolStatus.APPROVED))
    engine = Engine(config, registry=registry)
    evaluation = engine.evaluate(_action(source_type="http"))
    store = EvidenceStore(config, in_memory=True)
    try:
        record = store.store(evaluation, tool_name="read_file")
        assert record.agent_id == "test-agent"
        assert record.source_type == "http"
        assert store.get_records()[0].source_type == "http"
    finally:
        store.close()


def test_status_and_report_handle_empty_store(tmp_path: Path):
    cfg = tmp_path / "ancilis.yaml"
    cfg.write_text("agent:\n  name: empty-agent\n")
    db = tmp_path / "empty.duckdb"
    runner = CliRunner()

    status_result = runner.invoke(cli, ["status", "--config", str(cfg), "--db", str(db)])
    report_result = runner.invoke(cli, ["report", "--config", str(cfg), "--db", str(db)])

    assert status_result.exit_code == 0
    assert "No evaluations recorded yet" in status_result.output
    assert report_result.exit_code == 0
    assert "0 total" in report_result.output or "0 records" in report_result.output


def test_evidence_store_repeated_writes_are_stable():
    config = _config()
    registry = ToolRegistry()
    registry.register(ToolEntry(name="read_file", status=ToolStatus.APPROVED))
    engine = Engine(config, registry=registry)
    store = EvidenceStore(config, in_memory=True)
    try:
        for idx in range(10):
            action = _action(tool_name="read_file", source_type="tool")
            action.action_id = f"act-{idx}"
            evaluation = engine.evaluate(action)
            store.store(evaluation, tool_name="read_file")
        valid, errors = store.verify_chain()
        assert valid is True
        assert errors == []
        assert store.count() == 10
    finally:
        store.close()


@pytest.mark.skipif(tomllib is None, reason="tomllib requires Python >=3.11 or tomli package")
def test_pyproject_has_required_pypi_metadata():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    project = pyproject["project"]

    assert project["name"] == "ancilis"
    assert project["version"] == "0.1.0"
    assert project["readme"] == "README.md"
    assert project["requires-python"] == ">=3.10"
    assert project["authors"] == [{"name": "Kevin Bauer", "email": "kevin@ancilis.ai"}]
    assert project["urls"]["Repository"] == "https://github.com/ancilis/ancilis"
    assert "Programming Language :: Python :: 3.13" in project["classifiers"]


@pytest.mark.skipif(tomllib is None, reason="tomllib requires Python >=3.11 or tomli package")
def test_dev_extra_includes_watch_dependencies_exercised_by_tests():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    extras = pyproject["project"]["optional-dependencies"]

    assert set(extras["watch"]).issubset(set(extras["dev"]))


def test_ci_typescript_examples_keeps_deterministic_tarball_name():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())

    build_step = next(
        step
        for step in workflow["jobs"]["typescript-examples"]["steps"]
        if step.get("name") == "Build SDK tarball"
    )
    assert "mv ancilis-*.tgz ancilis-0.1.0.tgz" not in build_step["run"]
    assert "npm ci --include=dev" in build_step["run"]
    assert "test -f ancilis-0.1.0.tgz" in build_step["run"]


def test_ci_typescript_example_score_steps_tolerate_non_compliant_scan_exit():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())

    score_steps = [
        step
        for step in workflow["jobs"]["typescript-examples"]["steps"]
        if step.get("name", "").endswith("scan score")
    ]
    assert score_steps
    for step in score_steps:
        assert "npx ancilis scan --ci --config ancilis.yaml 2>&1 || true" in step["run"]


def test_ci_typescript_example_setup_steps_include_dev_dependencies():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())

    setup_steps = [
        step
        for step in workflow["jobs"]["typescript-examples"]["steps"]
        if step.get("name", "").endswith("setup")
    ]
    assert setup_steps
    for step in setup_steps:
        assert step["run"] == "npm install --include=dev"


def test_ci_typescript_example_fixtures_exist():
    for example in ["minimal-quickstart-ts", "langchain-ts-chatbot"]:
        example_dir = ROOT / "examples" / "typescript" / example

        assert (example_dir / "package.json").exists()
        assert (example_dir / "index.ts").exists()
        assert (example_dir / "ancilis.yaml").exists()
        assert not (example_dir / "package-lock.json").exists()


def test_publish_script_cleans_dist_and_uploads_selected_artifacts():
    script = ROOT / "scripts" / "publish.sh"

    assert script.exists()

    contents = script.read_text()
    assert contents.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in contents
    assert "rm -rf dist" in contents
    assert "python -m build" in contents
    assert 'twine check "${artifacts[@]}"' in contents
    assert 'twine upload "${artifacts[@]}"' in contents
    assert "dist/*" not in contents


def test_release_python_workflow_uses_release_check_and_trusted_publishing():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "release-python.yml").read_text())
    workflow_on = workflow.get("on", workflow.get(True))

    assert workflow["name"] == "Release Python"
    assert "v*" in workflow_on["push"]["tags"]
    assert workflow["permissions"] == {"contents": "read", "id-token": "write"}

    verify_job = workflow["jobs"]["verify_python_release"]
    verify_runs = [step["run"] for step in verify_job["steps"] if "run" in step]
    assert "python scripts/release_check.py" in verify_runs

    publish_job = workflow["jobs"]["publish_python"]
    assert publish_job["needs"] == "verify_python_release"
    publish_uses = [step["uses"] for step in publish_job["steps"] if "uses" in step]
    assert "pypa/gh-action-pypi-publish@release/v1" in publish_uses


def test_release_check_expands_twine_artifact_paths(monkeypatch, tmp_path: Path):
    dist = tmp_path / "dist"
    commands: list[list[str]] = []

    def fake_run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
        commands.append(cmd)
        if cmd == ["python", "-m", "build", "--sdist", "--wheel"]:
            dist.mkdir(parents=True, exist_ok=True)
            (dist / "ancilis-0.1.0-py3-none-any.whl").write_text("wheel")
            (dist / "ancilis-0.1.0.tar.gz").write_text("sdist")

    monkeypatch.setattr(release_check, "DIST", dist)
    monkeypatch.setattr(release_check, "run", fake_run)

    wheel, sdist = release_check.build_python_artifacts("python")
    twine_check = next(cmd for cmd in commands if cmd[:3] == ["python", "-m", "twine"])

    assert "dist/*" not in twine_check
    assert str(wheel) in twine_check
    assert str(sdist) in twine_check


def test_release_check_sanitizes_node_env_for_typescript_smoke(monkeypatch):
    commands: list[tuple[list[str], dict[str, str] | None]] = []

    def fake_run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
        commands.append((cmd, env))

    monkeypatch.setattr(release_check.shutil, "which", lambda _: "/usr/bin/npm")
    monkeypatch.setattr(release_check, "run", fake_run)
    monkeypatch.setenv("NODE_ENV", "production")
    monkeypatch.setenv("NPM_CONFIG_PRODUCTION", "true")
    monkeypatch.setenv("npm_config_omit", "dev")

    release_check.smoke_typescript()

    assert [cmd for cmd, _env in commands] == [
        ["npm", "ci"],
        ["npm", "run", "build"],
        ["npm", "pack", "--dry-run"],
        ["node", "scripts/ts_package_smoke.mjs"],
    ]
    for _cmd, env in commands:
        assert env is not None
        assert "NODE_ENV" not in env
        assert "NPM_CONFIG_PRODUCTION" not in env
        assert "npm_config_omit" not in env
