"""Tests for dependency vulnerability scanning — ManifestDetector, OSVClient, DependencyScanner."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ancilis.config import ControlStatus, ResolvedConfig
from ancilis.deps.manifest import Dependency, Manifest, ManifestDetector
from ancilis.deps.osv import OSVClient, Vuln, _cvss_to_severity
from ancilis.deps.scanner import DependencyScanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(de01_enabled: bool = True, mode: str = "audit") -> ResolvedConfig:
    cfg = ResolvedConfig()
    cfg.agent_name = "test-agent"
    cfg.mode = mode
    cfg.controls["DE-01"] = ControlStatus("DE-01", "Dependency Evaluation", de01_enabled)
    return cfg


def _osv_response(vulns_per_query: list[list[dict]]) -> bytes:
    """Build a fake OSV batch response body."""
    results = [{"vulns": vs} for vs in vulns_per_query]
    return json.dumps({"results": results}).encode()


def _mock_urlopen(response_bytes: bytes):
    """Return a context-manager mock that yields a readable response."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = response_bytes
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# ---------------------------------------------------------------------------
# ManifestDetector tests
# ---------------------------------------------------------------------------

class TestManifestDetector:
    def test_requirements_txt_pinned(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\nflask==2.3.0\n")
        manifests = ManifestDetector().detect(tmp_path)
        assert len(manifests) == 1
        deps = manifests[0].dependencies
        names = {d.name for d in deps}
        assert "requests" in names
        assert "flask" in names
        assert all(d.version is not None for d in deps)

    def test_requirements_txt_skips_unpinned(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "requests>=2.28.0\nflask\nnumpy~=1.24\n"
        )
        manifests = ManifestDetector().detect(tmp_path)
        assert manifests[0].dependencies == []

    def test_requirements_txt_skips_comments_and_includes(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "# a comment\n-r other.txt\n-c constraints.txt\nrequests==2.28.0\n"
        )
        deps = ManifestDetector().detect(tmp_path)[0].dependencies
        assert len(deps) == 1
        assert deps[0].name == "requests"

    def test_requirements_txt_handles_extras(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests[security]==2.28.0\n")
        deps = ManifestDetector().detect(tmp_path)[0].dependencies
        assert len(deps) == 1
        assert deps[0].version == "2.28.0"

    def test_pyproject_toml_pinned(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests==2.28.0", "flask==2.3.0"]\n'
        )
        manifests = ManifestDetector().detect(tmp_path)
        assert len(manifests) == 1
        names = {d.name for d in manifests[0].dependencies}
        assert "requests" in names
        assert "flask" in names

    def test_pyproject_toml_unpinned_skipped(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests>=2.0", "flask"]\n'
        )
        manifests = ManifestDetector().detect(tmp_path)
        assert manifests[0].dependencies == []

    def test_pipfile_lock_parsed(self, tmp_path):
        data = {
            "default": {
                "requests": {"version": "==2.28.0"},
                "flask": {"version": "==2.3.0"},
            }
        }
        (tmp_path / "Pipfile.lock").write_text(json.dumps(data))
        manifests = ManifestDetector().detect(tmp_path)
        # Only Pipfile.lock manifest found
        pipfile_manifests = [m for m in manifests if m.format == "Pipfile.lock"]
        assert len(pipfile_manifests) == 1
        names = {d.name for d in pipfile_manifests[0].dependencies}
        assert "requests" in names
        assert "flask" in names

    def test_poetry_lock_parsed(self, tmp_path):
        toml = (
            '[[package]]\nname = "requests"\nversion = "2.28.0"\n\n'
            '[[package]]\nname = "flask"\nversion = "2.3.0"\n'
        )
        (tmp_path / "poetry.lock").write_text(toml)
        manifests = ManifestDetector().detect(tmp_path)
        poetry_manifests = [m for m in manifests if m.format == "poetry.lock"]
        assert len(poetry_manifests) == 1
        names = {d.name for d in poetry_manifests[0].dependencies}
        assert "requests" in names

    def test_no_manifest_files_returns_empty(self, tmp_path):
        manifests = ManifestDetector().detect(tmp_path)
        assert manifests == []

    def test_multiple_manifests_detected(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        (tmp_path / "Pipfile.lock").write_text(
            json.dumps({"default": {"flask": {"version": "==2.3.0"}}})
        )
        manifests = ManifestDetector().detect(tmp_path)
        assert len(manifests) == 2
        formats = {m.format for m in manifests}
        assert "requirements.txt" in formats
        assert "Pipfile.lock" in formats

    def test_malformed_pipfile_lock_returns_empty_deps(self, tmp_path):
        (tmp_path / "Pipfile.lock").write_text("not valid json{")
        manifests = ManifestDetector().detect(tmp_path)
        pipfile_manifests = [m for m in manifests if m.format == "Pipfile.lock"]
        assert pipfile_manifests[0].dependencies == []


# ---------------------------------------------------------------------------
# CVSS mapping tests
# ---------------------------------------------------------------------------

class TestCvssMapping:
    def test_critical(self):
        assert _cvss_to_severity(9.0) == "CRITICAL"
        assert _cvss_to_severity(10.0) == "CRITICAL"

    def test_high(self):
        assert _cvss_to_severity(7.0) == "HIGH"
        assert _cvss_to_severity(8.9) == "HIGH"

    def test_medium(self):
        assert _cvss_to_severity(4.0) == "MEDIUM"
        assert _cvss_to_severity(6.9) == "MEDIUM"

    def test_low(self):
        assert _cvss_to_severity(0.0) == "LOW"
        assert _cvss_to_severity(3.9) == "LOW"


# ---------------------------------------------------------------------------
# OSVClient tests
# ---------------------------------------------------------------------------

class TestOSVClient:
    def _dep(self, name: str, version: str) -> Dependency:
        return Dependency(name=name, version=version, source_file="requirements.txt")

    def test_query_returns_vulns_for_affected_package(self):
        vuln_payload = [
            [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "summary": "Remote code execution",
                    "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                    "aliases": ["CVE-2023-12345"],
                    "affected": [
                        {
                            "package": {"name": "requests", "ecosystem": "PyPI"},
                            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.28.2"}]}],
                        }
                    ],
                }
            ]
        ]
        mock_resp = _mock_urlopen(_osv_response(vuln_payload))
        client = OSVClient()
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = client.query_batch([self._dep("requests", "2.28.0")])
        assert "requests" in result
        assert result["requests"][0].id == "GHSA-xxxx-yyyy-zzzz"
        assert result["requests"][0].severity == "CRITICAL"
        assert result["requests"][0].fixed_version == "2.28.2"

    def test_empty_vulns_returns_empty_dict(self):
        mock_resp = _mock_urlopen(_osv_response([[]]))
        client = OSVClient()
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = client.query_batch([self._dep("requests", "2.28.0")])
        assert result == {}
        assert client.last_error is None

    def test_network_timeout_sets_error_returns_empty(self):
        client = OSVClient()
        with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            result = client.query_batch([self._dep("requests", "2.28.0")])
        assert result == {}
        assert client.last_error is not None
        assert "timed out" in client.last_error

    def test_urlerror_sets_error_returns_empty(self):
        client = OSVClient()
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("Name or service not known"),
        ):
            result = client.query_batch([self._dep("requests", "2.28.0")])
        assert result == {}
        assert client.last_error is not None

    def test_deps_without_version_skipped(self):
        client = OSVClient()
        dep_no_version = Dependency(name="requests", version=None, source_file="req.txt")
        with patch("urllib.request.urlopen") as mock_url:
            result = client.query_batch([dep_no_version])
        mock_url.assert_not_called()
        assert result == {}

    def test_batch_splits_large_batches(self):
        """More than 1000 deps should trigger two separate HTTP requests."""
        deps = [self._dep(f"pkg{i}", "1.0.0") for i in range(1001)]
        # Both batches return no vulns
        mock_resp = _mock_urlopen(_osv_response([[]] * 1000))
        mock_resp2 = _mock_urlopen(_osv_response([[]] * 1))
        client = OSVClient()
        call_count = 0

        def fake_urlopen(req, timeout=None):
            nonlocal call_count
            call_count += 1
            return mock_resp if call_count == 1 else mock_resp2

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = client.query_batch(deps)
        assert call_count == 2
        assert result == {}

    def test_database_specific_severity_fallback(self):
        """When CVSS score missing, fall back to database_specific.severity."""
        vuln_payload = [
            [
                {
                    "id": "GHSA-test",
                    "summary": "Test vuln",
                    "severity": [],
                    "database_specific": {"severity": "HIGH"},
                    "affected": [],
                }
            ]
        ]
        mock_resp = _mock_urlopen(_osv_response(vuln_payload))
        client = OSVClient()
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = client.query_batch([self._dep("somepkg", "1.0.0")])
        assert "somepkg" in result
        assert result["somepkg"][0].severity == "HIGH"


# ---------------------------------------------------------------------------
# DependencyScanner tests
# ---------------------------------------------------------------------------

class TestDependencyScanner:
    def _dep(self, name: str, version: str) -> Dependency:
        return Dependency(name=name, version=version, source_file="requirements.txt")

    def test_de01_disabled_returns_empty_list(self, tmp_path):
        cfg = _make_config(de01_enabled=False)
        results = DependencyScanner(cfg).scan(tmp_path)
        assert results == []

    def test_no_manifests_returns_skip_result(self, tmp_path):
        cfg = _make_config()
        results = DependencyScanner(cfg).scan(tmp_path)
        assert len(results) == 1
        crs = results[0].control_results
        assert len(crs) == 1
        assert crs[0].result == "SKIP"
        assert crs[0].control_id == "DE-01"

    def test_no_vulns_returns_pass_result(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        cfg = _make_config()
        mock_resp = _mock_urlopen(_osv_response([[]]))
        with patch("urllib.request.urlopen", return_value=mock_resp):
            results = DependencyScanner(cfg).scan(tmp_path)
        assert len(results) == 1
        crs = results[0].control_results
        assert len(crs) == 1
        assert crs[0].result == "PASS"
        assert crs[0].control_id == "DE-01"

    def test_critical_vuln_produces_fail(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        cfg = _make_config()
        vuln_payload = [
            [
                {
                    "id": "GHSA-crit",
                    "summary": "Critical bug",
                    "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                    "aliases": [],
                    "affected": [
                        {
                            "package": {"name": "requests", "ecosystem": "PyPI"},
                            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.28.2"}]}],
                        }
                    ],
                }
            ]
        ]
        mock_resp = _mock_urlopen(_osv_response(vuln_payload))
        with patch("urllib.request.urlopen", return_value=mock_resp):
            results = DependencyScanner(cfg).scan(tmp_path)
        fail_results = [cr for cr in results[0].control_results if cr.result == "FAIL"]
        assert len(fail_results) >= 1

    def test_medium_vuln_produces_flag(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        cfg = _make_config()
        vuln_payload = [
            [
                {
                    "id": "GHSA-med",
                    "summary": "Medium severity",
                    "severity": [{"type": "CVSS_V3", "score": "5.0"}],
                    "aliases": [],
                    "affected": [],
                }
            ]
        ]
        mock_resp = _mock_urlopen(_osv_response(vuln_payload))
        with patch("urllib.request.urlopen", return_value=mock_resp):
            results = DependencyScanner(cfg).scan(tmp_path)
        flag_results = [cr for cr in results[0].control_results if cr.result == "FLAG"]
        assert len(flag_results) >= 1

    def test_network_failure_returns_flag_not_crash(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        cfg = _make_config()
        with patch("urllib.request.urlopen", side_effect=TimeoutError("timeout")):
            results = DependencyScanner(cfg).scan(tmp_path)
        assert len(results) == 1
        crs = results[0].control_results
        assert len(crs) == 1
        assert crs[0].result == "FLAG"
        assert "OSV.dev" in crs[0].detail

    def test_source_type_is_dependency_scan(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        cfg = _make_config()
        mock_resp = _mock_urlopen(_osv_response([[]]))
        with patch("urllib.request.urlopen", return_value=mock_resp):
            results = DependencyScanner(cfg).scan(tmp_path)
        assert results[0].source_type == "dependency_scan"

    def test_evidence_data_fields_populated(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        cfg = _make_config()
        vuln_payload = [
            [
                {
                    "id": "GHSA-ev01",
                    "summary": "Test vuln",
                    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                    "aliases": ["CVE-2023-99999"],
                    "affected": [
                        {
                            "package": {"name": "requests", "ecosystem": "PyPI"},
                            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.28.2"}]}],
                        }
                    ],
                }
            ]
        ]
        mock_resp = _mock_urlopen(_osv_response(vuln_payload))
        with patch("urllib.request.urlopen", return_value=mock_resp):
            results = DependencyScanner(cfg).scan(tmp_path)
        cr = results[0].control_results[0]
        ev = cr.evidence_data
        assert ev["package"] == "requests"
        assert ev["version"] == "2.28.0"
        assert ev["vuln_id"] == "GHSA-ev01"
        assert ev["severity"] == "HIGH"
        assert ev["fixed_version"] == "2.28.2"
        assert ev["source_file"].endswith("requirements.txt")

    def test_remediation_hint_with_fixed_version(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        cfg = _make_config()
        vuln_payload = [
            [
                {
                    "id": "GHSA-fix",
                    "summary": "Fixed vuln",
                    "severity": [{"type": "CVSS_V3", "score": "9.0"}],
                    "aliases": [],
                    "affected": [
                        {
                            "package": {"name": "requests", "ecosystem": "PyPI"},
                            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.29.0"}]}],
                        }
                    ],
                }
            ]
        ]
        mock_resp = _mock_urlopen(_osv_response(vuln_payload))
        with patch("urllib.request.urlopen", return_value=mock_resp):
            results = DependencyScanner(cfg).scan(tmp_path)
        cr = results[0].control_results[0]
        assert "2.29.0" in cr.remediation_hint
        assert "requests" in cr.remediation_hint

    def test_sorted_critical_before_high_before_medium(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "aaaa==1.0.0\nbbbb==1.0.0\ncccc==1.0.0\n"
        )
        cfg = _make_config()
        vuln_payload = [
            # aaaa → MEDIUM
            [{"id": "G-med", "summary": "m", "severity": [{"type": "CVSS_V3", "score": "5.0"}], "aliases": [], "affected": []}],
            # bbbb → CRITICAL
            [{"id": "G-crit", "summary": "c", "severity": [{"type": "CVSS_V3", "score": "9.5"}], "aliases": [], "affected": []}],
            # cccc → HIGH
            [{"id": "G-high", "summary": "h", "severity": [{"type": "CVSS_V3", "score": "7.5"}], "aliases": [], "affected": []}],
        ]
        mock_resp = _mock_urlopen(_osv_response(vuln_payload))
        with patch("urllib.request.urlopen", return_value=mock_resp):
            results = DependencyScanner(cfg).scan(tmp_path)
        severities = [cr.evidence_data["severity"] for cr in results[0].control_results]
        # CRITICAL must come before HIGH which must come before MEDIUM
        crit_idx = severities.index("CRITICAL")
        high_idx = severities.index("HIGH")
        med_idx = severities.index("MEDIUM")
        assert crit_idx < high_idx < med_idx

    def test_de01_absent_from_config_still_scans(self, tmp_path):
        """If DE-01 is not in config at all, scanner should still run (default enabled)."""
        cfg = ResolvedConfig()
        cfg.agent_name = "test"
        cfg.mode = "audit"
        # No controls set at all
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        mock_resp = _mock_urlopen(_osv_response([[]]))
        with patch("urllib.request.urlopen", return_value=mock_resp):
            results = DependencyScanner(cfg).scan(tmp_path)
        # Should get a PASS (not skip due to disabled)
        assert results[0].control_results[0].result == "PASS"

    def test_multiple_manifests_deps_all_queried(self, tmp_path):
        """Deps from both requirements.txt and Pipfile.lock are queried together."""
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        (tmp_path / "Pipfile.lock").write_text(
            json.dumps({"default": {"flask": {"version": "==2.3.0"}}})
        )
        cfg = _make_config()
        captured_queries = []

        def fake_urlopen(req, timeout=None):
            body = json.loads(req.data.decode())
            captured_queries.extend(body["queries"])
            # Return no vulns for all
            n = len(body["queries"])
            return _mock_urlopen(_osv_response([[]] * n))

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            DependencyScanner(cfg).scan(tmp_path)

        queried_names = {q["package"]["name"] for q in captured_queries}
        assert "requests" in queried_names
        assert "flask" in queried_names
