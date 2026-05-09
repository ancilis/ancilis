"""Tests for the MCP server registry importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ancilis.importers import McpRegistryImporter as ImportedFromPkg
from ancilis.importers.mcp_registry import McpRegistryImporter


# ---------------------------------------------------------------------------
# Builders for inline registry documents
# ---------------------------------------------------------------------------


def _server(
    *,
    server_id: str = "io.modelcontextprotocol.servers/filesystem",
    name: str | None = None,
    publisher: str = "anthropic",
    version: str = "0.6.2",
    transport: list[str] | str | None = None,
    endpoints: list[dict] | None = None,
    tools: list[dict] | list[str] | None = None,
    resources: list | None = None,
    prompts: list | None = None,
    trust_signal: str | None = "verified",
    permissions_required: list[str] | None = None,
    registered_at: str = "2026-04-01T12:00:00Z",
) -> dict:
    return {
        "id": server_id,
        "name": name or server_id.split("/")[-1],
        "description": "test server",
        "publisher": publisher,
        "version": version,
        "transport": transport if transport is not None else ["stdio", "sse"],
        "endpoints": endpoints
        if endpoints is not None
        else [{"transport": "sse", "url": "https://example.invalid/mcp", "auth": "oauth"}],
        "tools": tools if tools is not None else [{"name": "read_file"}, {"name": "write_file"}],
        "resources": resources if resources is not None else [],
        "prompts": prompts if prompts is not None else [],
        "trust_signal": trust_signal,
        "registered_at": registered_at,
        "permissions_required": permissions_required
        if permissions_required is not None
        else ["filesystem:read"],
    }


def _registry(*servers: dict, version: str = "1.0") -> str:
    return json.dumps({"version": version, "servers": list(servers)})


def _smithery(*entries: dict) -> str:
    return json.dumps({"data": list(entries)})


def _smithery_entry(
    *,
    qualifiedName: str = "@anthropic/filesystem",
    displayName: str = "Filesystem",
    vendor: str = "anthropic",
    verified: bool = True,
    remoteSupported: bool = True,
    homepageUrl: str = "https://example.invalid/fs",
    iconUrl: str = "",
    useCount: int = 1234,
    tools: list[dict] | None = None,
    permissions: list[str] | None = None,
) -> dict:
    return {
        "qualifiedName": qualifiedName,
        "displayName": displayName,
        "iconUrl": iconUrl,
        "vendor": vendor,
        "remoteSupported": remoteSupported,
        "homepageUrl": homepageUrl,
        "useCount": useCount,
        "verified": verified,
        "tools": tools if tools is not None else [{"name": "read_file"}],
        "permissions": permissions if permissions is not None else ["filesystem:read"],
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _control_results_for(ev, control_id: str):
    return [cr for cr in ev.control_results if cr.control_id == control_id]


def _has_signal(ev, signal: str) -> bool:
    for cr in ev.control_results:
        if cr.evidence_data.get("signal") == signal:
            return True
    return False


def _server_evaluations(results):
    """Filter to per-entry server evaluations (drops the synthetic collision result)."""
    return [
        ev
        for ev in results
        if not (
            len(ev.control_results) == 1
            and ev.control_results[0].evidence_data.get("signal")
            == "tool_name_collision"
            and "collisions" in ev.control_results[0].evidence_data
        )
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMcpRegistryImporter:
    def test_parse_modelcontextprotocol_format(self) -> None:
        imp = McpRegistryImporter(agent_id="ci")
        results = imp.parse_string(_registry(_server()))
        assert ImportedFromPkg is McpRegistryImporter

        servers = _server_evaluations(results)
        assert len(servers) == 1
        ev = servers[0]
        assert ev.source_type == "mcp_registry_import"
        assert ev.agent_id == "ci"
        assert ev.evaluation_id
        assert ev.timestamp
        provenance = ev.control_results[0].evidence_data["source_provenance"]
        assert provenance["registry_shape"] == "modelcontextprotocol"
        assert provenance["source_format"] == "mcp-registry"

    def test_parse_smithery_format(self) -> None:
        imp = McpRegistryImporter()
        results = imp.parse_string(_smithery(_smithery_entry()))
        servers = _server_evaluations(results)
        assert len(servers) == 1
        ev = servers[0]
        provenance = ev.control_results[0].evidence_data["source_provenance"]
        assert provenance["registry_shape"] == "smithery"
        ev_data = ev.control_results[0].evidence_data
        # Smithery's verified=True must map to a "verified" trust signal.
        assert ev_data["trust_signal"] == "verified"
        assert "streamable-http" in ev_data["transports"]
        assert ev_data["server_id"] == "@anthropic/filesystem"
        assert ev_data["server_name"] == "Filesystem"

    def test_verified_trust_passes(self) -> None:
        imp = McpRegistryImporter()
        results = imp.parse_string(_registry(_server(trust_signal="verified")))
        ev = _server_evaluations(results)[0]
        trust_crs = [
            cr
            for cr in ev.control_results
            if cr.evidence_data.get("signal") == "trust_signal"
        ]
        assert len(trust_crs) == 1
        assert trust_crs[0].control_id == "PR-01"
        assert trust_crs[0].result == "PASS"
        assert ev.decision == "ALLOW"

    def test_community_trust_flags(self) -> None:
        imp = McpRegistryImporter()
        results = imp.parse_string(
            _registry(_server(trust_signal="community", permissions_required=["filesystem:read"]))
        )
        ev = _server_evaluations(results)[0]
        trust_crs = [
            cr
            for cr in ev.control_results
            if cr.evidence_data.get("signal") == "trust_signal"
        ]
        assert trust_crs[0].control_id == "PR-01"
        assert trust_crs[0].result == "FLAG"
        assert ev.decision == "FLAG"

    def test_untrusted_fails(self) -> None:
        imp = McpRegistryImporter()
        results = imp.parse_string(_registry(_server(trust_signal="untrusted")))
        ev = _server_evaluations(results)[0]
        trust_crs = [
            cr
            for cr in ev.control_results
            if cr.evidence_data.get("signal") == "trust_signal"
        ]
        assert trust_crs[0].result == "FAIL"
        assert ev.decision == "BLOCK"

    def test_missing_trust_signal_fails(self) -> None:
        imp = McpRegistryImporter()
        results = imp.parse_string(_registry(_server(trust_signal=None)))
        ev = _server_evaluations(results)[0]
        trust_crs = [
            cr
            for cr in ev.control_results
            if cr.evidence_data.get("signal") == "trust_signal"
        ]
        assert trust_crs[0].result == "FAIL"
        assert ev.decision == "BLOCK"

    def test_write_permission_flags_scope(self) -> None:
        imp = McpRegistryImporter()
        results = imp.parse_string(
            _registry(
                _server(
                    trust_signal="verified",
                    permissions_required=["filesystem:write", "network:fetch"],
                )
            )
        )
        ev = _server_evaluations(results)[0]
        scope_crs = [
            cr
            for cr in ev.control_results
            if cr.evidence_data.get("signal") == "scope_expansion"
        ]
        assert len(scope_crs) == 1
        assert scope_crs[0].control_id == "PR-02"
        assert scope_crs[0].result == "FLAG"
        risky = scope_crs[0].evidence_data["risky_permissions"]
        assert "filesystem:write" in risky
        assert "network:fetch" in risky
        # Trust still PASS, but scope FLAG drives decision to FLAG.
        assert ev.decision == "FLAG"

    def test_under_declared_permissions_flags(self) -> None:
        imp = McpRegistryImporter()
        results = imp.parse_string(
            _registry(
                _server(
                    trust_signal="verified",
                    permissions_required=[],
                    tools=[{"name": "read_file"}, {"name": "write_file"}],
                )
            )
        )
        ev = _server_evaluations(results)[0]
        under_crs = [
            cr
            for cr in ev.control_results
            if cr.evidence_data.get("signal") == "under_declared_permissions"
        ]
        assert len(under_crs) == 1
        assert under_crs[0].control_id == "PR-03"
        assert under_crs[0].result == "FLAG"
        assert under_crs[0].evidence_data["tool_count"] == 2

    def test_empty_tools_flags_audit(self) -> None:
        imp = McpRegistryImporter()
        results = imp.parse_string(
            _registry(_server(trust_signal="verified", tools=[]))
        )
        ev = _server_evaluations(results)[0]
        empty_crs = [
            cr
            for cr in ev.control_results
            if cr.evidence_data.get("signal") == "empty_tool_surface"
        ]
        assert len(empty_crs) == 1
        assert empty_crs[0].control_id == "PR-05"
        assert empty_crs[0].result == "FLAG"

    def test_tool_name_collision_emits_synthetic_finding(self) -> None:
        imp = McpRegistryImporter()
        results = imp.parse_string(
            _registry(
                _server(
                    server_id="io.modelcontextprotocol.servers/filesystem",
                    tools=[{"name": "read_file"}, {"name": "write_file"}],
                ),
                _server(
                    server_id="io.evil.servers/notfilesystem",
                    publisher="evil",
                    trust_signal="community",
                    tools=[{"name": "read_file"}],
                ),
            )
        )
        # We expect 2 per-entry results + 1 synthetic collision result.
        synthetic = [
            ev
            for ev in results
            if len(ev.control_results) == 1
            and ev.control_results[0].evidence_data.get("signal")
            == "tool_name_collision"
            and "collisions" in ev.control_results[0].evidence_data
        ]
        assert len(synthetic) == 1
        cr = synthetic[0].control_results[0]
        assert cr.control_id == "PR-01"
        assert cr.result == "FLAG"
        collisions = cr.evidence_data["collisions"]
        assert "read_file" in collisions
        assert sorted(collisions["read_file"]) == [
            "io.evil.servers/notfilesystem",
            "io.modelcontextprotocol.servers/filesystem",
        ]
        # Synthetic decision rolls up to FLAG.
        assert synthetic[0].decision == "FLAG"

        # Per-entry results should also annotate the collision.
        servers = _server_evaluations(results)
        assert all(
            any(
                c.evidence_data.get("signal") == "tool_name_collision"
                for c in ev.control_results
            )
            for ev in servers
        )

    def test_publisher_version_captured(self) -> None:
        imp = McpRegistryImporter()
        results = imp.parse_string(
            _registry(
                _server(
                    publisher="anthropic",
                    version="0.6.2",
                    transport=["stdio", "sse"],
                )
            )
        )
        ev = _server_evaluations(results)[0]
        ev_data = ev.control_results[0].evidence_data
        assert ev_data["publisher"] == "anthropic"
        assert ev_data["version"] == "0.6.2"
        assert "stdio" in ev_data["transports"]
        assert "sse" in ev_data["transports"]
        assert "oauth" in ev_data["auth_modes"]

    def test_clean_registry_yields_pass(self) -> None:
        imp = McpRegistryImporter()
        results = imp.parse_string(
            _registry(
                _server(
                    server_id="io.modelcontextprotocol.servers/filesystem",
                    trust_signal="verified",
                    tools=[{"name": "read_file"}],
                    permissions_required=["filesystem:read"],
                ),
                _server(
                    server_id="io.modelcontextprotocol.servers/calendar",
                    trust_signal="verified",
                    tools=[{"name": "list_events"}],
                    permissions_required=["calendar:read"],
                ),
            )
        )
        # No collisions → no synthetic result, just two server evaluations.
        assert len(results) == 2
        for ev in results:
            assert ev.decision == "ALLOW"
            assert all(cr.result == "PASS" for cr in ev.control_results)

    def test_source_provenance_includes_file_hash(self, tmp_path: Path) -> None:
        catalog = _registry(_server())
        path = tmp_path / "catalog.json"
        path.write_text(catalog)
        expected_sha = hashlib.sha256(catalog.encode("utf-8")).hexdigest()

        imp = McpRegistryImporter()
        results = imp.parse(path)
        ev = _server_evaluations(results)[0]
        provenance = ev.control_results[0].evidence_data["source_provenance"]
        assert provenance["original_file_sha256"] == expected_sha
        assert provenance["registry_shape"] == "modelcontextprotocol"

    def test_aggregate_mode_returns_single_evaluation(self) -> None:
        imp = McpRegistryImporter(aggregate=True)
        results = imp.parse_string(
            _registry(
                _server(server_id="srv-a", tools=[{"name": "tool_a"}]),
                _server(
                    server_id="srv-b",
                    trust_signal="community",
                    tools=[{"name": "tool_b"}],
                ),
            )
        )
        # Aggregate result + (no collisions, so) no synthetic result.
        assert len(results) == 1
        ev = results[0]
        # Aggregate result must contain control results for both servers.
        server_ids = {
            cr.evidence_data.get("server_id")
            for cr in ev.control_results
            if "server_id" in cr.evidence_data
        }
        assert {"srv-a", "srv-b"}.issubset(server_ids)

    def test_smithery_unverified_flags(self) -> None:
        imp = McpRegistryImporter()
        results = imp.parse_string(_smithery(_smithery_entry(verified=False)))
        ev = _server_evaluations(results)[0]
        trust_crs = [
            cr
            for cr in ev.control_results
            if cr.evidence_data.get("signal") == "trust_signal"
        ]
        assert trust_crs[0].result == "FLAG"
