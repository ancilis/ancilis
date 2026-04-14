"""Tests for ancilis.dependencies — detector, SBOM builder, OSV client, and public API."""

from __future__ import annotations

import json
import textwrap
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ancilis.dependencies import (
    DependencyScanResult,
    scan_dependencies,
)
from ancilis.dependencies.detector import (
    Dependency,
    DetectionResult,
    _normalise_pep508,
    _parse_pipfile_lock,
    _parse_poetry_lock,
    _parse_pyproject_toml,
    _parse_requirements_txt,
    detect_dependencies,
)
from ancilis.dependencies.osv import VulnerabilityFinding, query_osv_batch
from ancilis.dependencies.sbom import CycloneDxBom, build_sbom


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _osv_response(vulns_per_query: list[list[dict]]) -> bytes:
    """Build a fake OSV /v1/querybatch response."""
    results = [{"vulns": vs} for vs in vulns_per_query]
    return json.dumps({"results": results}).encode()


def _mock_urlopen(response_bytes: bytes) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.read.return_value = response_bytes
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _fake_vuln(
    vid: str = "GHSA-0000-0000-0001",
    summary: str = "Test vuln",
    cvss: float = 7.5,
    fixed: str | None = "2.0.0",
) -> dict:
    return {
        "id": vid,
        "summary": summary,
        "aliases": [f"CVE-2024-{vid[-4:]}"],
        "severity": [{"type": "CVSS_V3", "score": str(cvss)}],
        "affected": [
            {
                "package": {"name": "requests"},
                "ranges": [
                    {"events": [{"introduced": "0"}, {"fixed": fixed}] if fixed else [{"introduced": "0"}]}
                ],
            }
        ],
    }


# ---------------------------------------------------------------------------
# detector tests
# ---------------------------------------------------------------------------


class TestDetectDependencies:
    def test_returns_none_when_no_manifest(self, tmp_path: Path) -> None:
        result = detect_dependencies(tmp_path)
        assert result is None

    def test_detects_requirements_txt(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\nflask==2.3.0\n")
        result = detect_dependencies(tmp_path)
        assert result is not None
        assert result.manifest_format == "requirements.txt"
        names = [d.name for d in result.dependencies]
        assert "requests" in names
        assert "flask" in names

    def test_detects_pipfile_lock(self, tmp_path: Path) -> None:
        data = {
            "default": {"requests": {"version": "==2.28.0"}},
            "develop": {"pytest": {"version": "==7.4.0"}},
        }
        (tmp_path / "Pipfile.lock").write_text(json.dumps(data))
        result = detect_dependencies(tmp_path)
        assert result is not None
        assert result.manifest_format == "Pipfile.lock"
        names = [d.name for d in result.dependencies]
        assert "requests" in names
        assert "pytest" in names

    def test_detects_poetry_lock(self, tmp_path: Path) -> None:
        content = textwrap.dedent(
            """\
            [[package]]
            name = "requests"
            version = "2.31.0"

            [[package]]
            name = "certifi"
            version = "2024.2.2"
            """
        )
        (tmp_path / "poetry.lock").write_text(content)
        result = detect_dependencies(tmp_path)
        assert result is not None
        assert result.manifest_format == "poetry.lock"
        names = [d.name for d in result.dependencies]
        assert "requests" in names

    def test_priority_poetry_over_requirements(self, tmp_path: Path) -> None:
        """poetry.lock should take priority over requirements.txt."""
        (tmp_path / "requirements.txt").write_text("flask==2.3.0\n")
        content = "[[package]]\nname = 'requests'\nversion = '2.31.0'\n"
        (tmp_path / "poetry.lock").write_text(content)
        result = detect_dependencies(tmp_path)
        assert result is not None
        assert result.manifest_format == "poetry.lock"

    def test_priority_pipfile_over_requirements(self, tmp_path: Path) -> None:
        """Pipfile.lock should take priority over requirements.txt."""
        (tmp_path / "requirements.txt").write_text("flask==2.3.0\n")
        data = {"default": {"requests": {"version": "==2.28.0"}}, "develop": {}}
        (tmp_path / "Pipfile.lock").write_text(json.dumps(data))
        result = detect_dependencies(tmp_path)
        assert result is not None
        assert result.manifest_format == "Pipfile.lock"

    def test_unpinned_requirements_warns(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests\nflask>=2.0\n")
        with pytest.warns(UserWarning, match="lack pinned versions"):
            detect_dependencies(tmp_path)

    def test_all_deps_have_pypi_ecosystem(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        result = detect_dependencies(tmp_path)
        assert result is not None
        assert all(d.ecosystem == "PyPI" for d in result.dependencies)


# ---------------------------------------------------------------------------
# SBOM builder tests
# ---------------------------------------------------------------------------


class TestBuildSbom:
    def test_returns_cyclonedx_bom(self) -> None:
        deps = [Dependency("requests", "2.28.0"), Dependency("flask", "2.3.0")]
        bom = build_sbom(deps)
        assert isinstance(bom, CycloneDxBom)
        assert bom.bom_format == "CycloneDX"
        assert bom.spec_version == "1.5"
        assert bom.version == 1

    def test_serial_number_is_urn_uuid(self) -> None:
        bom = build_sbom([Dependency("requests", "2.28.0")])
        assert bom.serial_number.startswith("urn:uuid:")

    def test_component_count_matches_deps(self) -> None:
        deps = [Dependency("a", "1.0"), Dependency("b", "2.0"), Dependency("c", "3.0")]
        bom = build_sbom(deps)
        assert len(bom.components) == 3

    def test_purl_format(self) -> None:
        bom = build_sbom([Dependency("My_Package", "1.2.3")])
        assert bom.components[0].purl == "pkg:pypi/my-package@1.2.3"

    def test_empty_deps_produces_empty_components(self) -> None:
        bom = build_sbom([])
        assert bom.components == []

    def test_to_dict_serializes_correctly(self) -> None:
        deps = [Dependency("requests", "2.28.0")]
        bom = build_sbom(deps)
        d = bom.to_dict()
        assert d["bomFormat"] == "CycloneDX"
        assert d["specVersion"] == "1.5"
        assert len(d["components"]) == 1
        assert d["components"][0]["purl"].startswith("pkg:pypi/")


# ---------------------------------------------------------------------------
# OSV client tests
# ---------------------------------------------------------------------------


class TestQueryOsvBatch:
    def test_returns_empty_when_no_versioned_deps(self) -> None:
        findings, err = query_osv_batch([])
        assert findings == []
        assert err is None

    def test_returns_vulnerability_findings(self) -> None:
        deps = [Dependency("requests", "2.27.0")]
        vuln_data = _fake_vuln("GHSA-0001-0001-0001", "RCE in requests", cvss=9.1, fixed="2.28.0")
        response = _osv_response([[vuln_data]])

        with patch("urllib.request.urlopen", return_value=_mock_urlopen(response)):
            findings, err = query_osv_batch(deps)

        assert err is None
        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, VulnerabilityFinding)
        assert f.package_name == "requests"
        assert f.installed_version == "2.27.0"
        assert f.severity == "critical"
        assert f.cvss_score == 9.1
        assert f.fixed_version == "2.28.0"

    def test_severity_mapping_high(self) -> None:
        deps = [Dependency("flask", "2.0.0")]
        vuln_data = _fake_vuln(cvss=7.5)
        response = _osv_response([[vuln_data]])
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(response)):
            findings, _ = query_osv_batch(deps)
        assert findings[0].severity == "high"

    def test_severity_mapping_medium(self) -> None:
        deps = [Dependency("flask", "2.0.0")]
        vuln_data = _fake_vuln(cvss=5.3)
        response = _osv_response([[vuln_data]])
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(response)):
            findings, _ = query_osv_batch(deps)
        assert findings[0].severity == "medium"

    def test_severity_mapping_low(self) -> None:
        deps = [Dependency("flask", "2.0.0")]
        vuln_data = _fake_vuln(cvss=2.1)
        response = _osv_response([[vuln_data]])
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(response)):
            findings, _ = query_osv_batch(deps)
        assert findings[0].severity == "low"

    def test_network_error_returns_error_string(self) -> None:
        deps = [Dependency("requests", "2.27.0")]
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("Connection refused"),
        ):
            findings, err = query_osv_batch(deps)
        assert findings == []
        assert err is not None
        assert "Connection refused" in err

    def test_no_vulns_returns_empty_findings(self) -> None:
        deps = [Dependency("requests", "2.31.0")]
        response = _osv_response([[]])
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(response)):
            findings, err = query_osv_batch(deps)
        assert findings == []
        assert err is None

    def test_skips_deps_without_version(self) -> None:
        # Dependency with empty version should be skipped (no API call needed for it)
        deps = [Dependency("requests", "")]
        with patch("urllib.request.urlopen") as mock_urlopen:
            findings, err = query_osv_batch(deps)
        mock_urlopen.assert_not_called()
        assert findings == []


# ---------------------------------------------------------------------------
# Public API: scan_dependencies
# ---------------------------------------------------------------------------


class TestScanDependencies:
    def test_no_manifest_returns_empty_result(self, tmp_path: Path) -> None:
        result = scan_dependencies(tmp_path)
        assert isinstance(result, DependencyScanResult)
        assert result.manifest_path is None
        assert result.dependencies == []
        assert result.sbom is None
        assert result.vulnerabilities == []
        assert result.osv_error is None

    def test_returns_sbom_and_vulns(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.27.0\n")
        vuln_data = _fake_vuln("GHSA-9999-9999-9999", "Test vuln", cvss=8.0, fixed="2.28.0")
        response = _osv_response([[vuln_data]])

        with patch("urllib.request.urlopen", return_value=_mock_urlopen(response)):
            result = scan_dependencies(tmp_path)

        assert result.manifest_path is not None
        assert "requirements.txt" in result.manifest_path
        assert len(result.dependencies) == 1
        assert isinstance(result.sbom, CycloneDxBom)
        assert len(result.vulnerabilities) == 1
        assert result.osv_error is None

    def test_osv_failure_sets_error_not_raises(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.27.0\n")
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("timeout"),
        ):
            result = scan_dependencies(tmp_path)

        assert result.osv_error is not None
        assert result.vulnerabilities == []
        assert result.sbom is not None  # SBOM was built before OSV call
        assert len(result.dependencies) == 1

    def test_defaults_to_cwd(self) -> None:
        """scan_dependencies() with no arg should not crash (just needs to run)."""
        # We mock detect_dependencies to return None so no FS operations needed
        with patch(
            "ancilis.dependencies.detect_dependencies", return_value=None
        ):
            result = scan_dependencies()
        assert result.manifest_path is None

    def test_metadata_includes_dep_count_and_format(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\nflask==2.3.0\n")
        response = _osv_response([[], []])
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(response)):
            result = scan_dependencies(tmp_path)
        assert result.metadata["dep_count"] == 2
        assert result.metadata["manifest_format"] == "requirements.txt"


# ---------------------------------------------------------------------------
# Branch coverage: detector internals (ANC-827)
# ---------------------------------------------------------------------------


class TestNormalisePep508:
    """Unit tests for _normalise_pep508 — covers lines 81-88 in detector.py."""

    def test_pinned_dep_returns_name_and_version(self) -> None:
        name, ver = _normalise_pep508("requests==2.28.0")
        assert name == "requests"
        assert ver == "2.28.0"

    def test_extras_are_stripped_before_parsing(self) -> None:
        name, ver = _normalise_pep508("requests[security]==2.28.0")
        assert name == "requests"
        assert ver == "2.28.0"

    def test_env_marker_is_stripped(self) -> None:
        name, ver = _normalise_pep508("requests==2.28.0; python_version>='3.7'")
        assert name == "requests"
        assert ver == "2.28.0"

    def test_unpinned_dep_returns_name_with_none_version(self) -> None:
        name, ver = _normalise_pep508("requests>=2.0")
        assert name == "requests"
        assert ver is None

    def test_bare_name_returns_name_with_none_version(self) -> None:
        name, ver = _normalise_pep508("requests")
        assert name == "requests"
        assert ver is None

    def test_non_matching_spec_returns_spec_with_none_version(self) -> None:
        # A spec that starts with a non-identifier char hits the final fallback (line 88)
        name, ver = _normalise_pep508("!invalid-spec!")
        assert ver is None
        assert name == "!invalid-spec!"


class TestParseRequirementsTxtBranches:
    """Covers OSError handler and comment/empty line skip in _parse_requirements_txt."""

    def test_oserror_returns_empty_list(self, tmp_path: Path) -> None:
        path = tmp_path / "requirements.txt"
        path.write_text("requests==2.28.0\n")
        with patch.object(path.__class__, "read_text", side_effect=OSError("perm denied")):
            deps = _parse_requirements_txt(path)
        assert deps == []

    def test_comment_lines_are_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "requirements.txt"
        path.write_text("# This is a comment\nrequests==2.28.0\n\n")
        deps = _parse_requirements_txt(path)
        assert len(deps) == 1
        assert deps[0].name == "requests"

    def test_dash_option_lines_are_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "requirements.txt"
        path.write_text("-r other.txt\nflask==2.3.0\n")
        deps = _parse_requirements_txt(path)
        assert len(deps) == 1
        assert deps[0].name == "flask"

    def test_empty_lines_are_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "requirements.txt"
        path.write_text("\n\nrequests==2.28.0\n\n")
        deps = _parse_requirements_txt(path)
        assert len(deps) == 1


class TestParsePipfileLockBranches:
    """Covers JSONDecodeError and OSError in _parse_pipfile_lock."""

    def test_invalid_json_returns_empty_list(self, tmp_path: Path) -> None:
        path = tmp_path / "Pipfile.lock"
        path.write_text("{not valid json{{")
        deps = _parse_pipfile_lock(path)
        assert deps == []

    def test_oserror_returns_empty_list(self, tmp_path: Path) -> None:
        path = tmp_path / "Pipfile.lock"
        path.write_text('{"default": {}}')
        with patch.object(path.__class__, "read_text", side_effect=OSError("no access")):
            deps = _parse_pipfile_lock(path)
        assert deps == []

    def test_entry_without_version_key_is_skipped(self, tmp_path: Path) -> None:
        data = {"default": {"requests": {"hash": "sha256:abc"}}, "develop": {}}
        path = tmp_path / "Pipfile.lock"
        path.write_text(json.dumps(data))
        deps = _parse_pipfile_lock(path)
        assert deps == []

    def test_entry_with_non_pinned_version_is_skipped(self, tmp_path: Path) -> None:
        data = {"default": {"requests": {"version": "2.28.0"}}, "develop": {}}
        path = tmp_path / "Pipfile.lock"
        path.write_text(json.dumps(data))
        deps = _parse_pipfile_lock(path)
        # version doesn't match ==X.Y.Z format → skipped
        assert deps == []


class TestParsePoetryLockBranches:
    """Covers exception path in _parse_poetry_lock."""

    def test_invalid_toml_returns_empty_list(self, tmp_path: Path) -> None:
        path = tmp_path / "poetry.lock"
        path.write_text("{{{ definitely not toml }}}")
        deps = _parse_poetry_lock(path)
        assert deps == []

    def test_package_without_name_or_version_is_skipped(self, tmp_path: Path) -> None:
        content = "[[package]]\ndescription = 'no name or version'\n"
        path = tmp_path / "poetry.lock"
        path.write_text(content)
        deps = _parse_poetry_lock(path)
        assert deps == []


class TestParsePyprojectToml:
    """Covers all branches of _parse_pyproject_toml — lines 92-114."""

    def test_pep621_pinned_deps(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            [project]
            name = "myapp"
            dependencies = ["requests==2.28.0", "flask==2.3.0"]
        """)
        path = tmp_path / "pyproject.toml"
        path.write_text(content)
        deps = _parse_pyproject_toml(path)
        names = [d.name for d in deps]
        assert "requests" in names
        assert "flask" in names
        versions = {d.name: d.version for d in deps}
        assert versions["requests"] == "2.28.0"

    def test_pep621_unpinned_deps_excluded(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            [project]
            dependencies = ["requests>=2.0", "flask"]
        """)
        path = tmp_path / "pyproject.toml"
        path.write_text(content)
        deps = _parse_pyproject_toml(path)
        # unpinned → no exact version → excluded
        assert deps == []

    def test_pep621_dep_with_extras_and_marker(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            [project]
            dependencies = ["requests[security]==2.28.0; python_version>='3.7'"]
        """)
        path = tmp_path / "pyproject.toml"
        path.write_text(content)
        deps = _parse_pyproject_toml(path)
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.28.0"

    def test_poetry_string_version_with_specifier(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            [tool.poetry.dependencies]
            python = ">=3.8"
            requests = "==2.28.0"
        """)
        path = tmp_path / "pyproject.toml"
        path.write_text(content)
        deps = _parse_pyproject_toml(path)
        # python is skipped; requests==2.28.0 is pinned
        names = [d.name for d in deps]
        assert "requests" in names
        assert "python" not in names

    def test_poetry_string_version_without_specifier_excluded(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            [tool.poetry.dependencies]
            requests = "latest"
        """)
        path = tmp_path / "pyproject.toml"
        path.write_text(content)
        deps = _parse_pyproject_toml(path)
        # "latest" doesn't start with a specifier char → no version → excluded
        assert deps == []

    def test_poetry_dict_version(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            [tool.poetry.dependencies]
            requests = {version = "==2.28.0", optional = false}
        """)
        path = tmp_path / "pyproject.toml"
        path.write_text(content)
        deps = _parse_pyproject_toml(path)
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.28.0"

    def test_invalid_toml_returns_empty_list(self, tmp_path: Path) -> None:
        path = tmp_path / "pyproject.toml"
        path.write_text("{{{ not valid toml }}}")
        deps = _parse_pyproject_toml(path)
        assert deps == []

    def test_pyproject_toml_detected_via_detect_dependencies(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            [project]
            name = "myapp"
            dependencies = ["requests==2.28.0"]
        """)
        (tmp_path / "pyproject.toml").write_text(content)
        result = detect_dependencies(tmp_path)
        assert result is not None
        assert result.manifest_format == "pyproject.toml"
        assert any(d.name == "requests" for d in result.dependencies)
