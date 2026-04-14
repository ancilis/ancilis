"""Tests for Python SDK plugin contracts, discovery, and CLI commands."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from click.testing import CliRunner

from ancilis.cli.main import cli
from ancilis.plugins import PluginContext, PluginMetadata, PluginRegistry


@dataclass(frozen=True)
class FakeDist:
    name: str

    @property
    def metadata(self) -> dict[str, str]:
        return {"Name": self.name}


@dataclass(frozen=True)
class FakeEntryPoint:
    name: str
    group: str
    value: str
    loaded: Any = None
    error: Exception | None = None
    dist: FakeDist = FakeDist("fake-plugin")

    @property
    def module(self) -> str:
        return self.value.split(":", 1)[0]

    def load(self) -> Any:
        if self.error is not None:
            raise self.error
        return self.loaded


class FakeEntryPoints(list[FakeEntryPoint]):
    def select(self, *, group: str) -> list[FakeEntryPoint]:
        return [entry for entry in self if entry.group == group]


class FakeProducerPlugin:
    metadata = PluginMetadata(
        name="fake-producer",
        plugin_type="producer",
        package_name="fake-plugin",
        package_version="1.2.3",
        min_sdk_version="0.1.0",
    )


class FakeOverlayPlugin:
    metadata = PluginMetadata(
        name="fake-overlay",
        plugin_type="overlay",
        package_name="fake-plugin",
        package_version="1.2.3",
        min_sdk_version="0.1.0",
    )


class FakeAdapterPlugin:
    metadata = PluginMetadata(
        name="fake-adapter",
        plugin_type="adapter",
        package_name="fake-plugin",
        package_version="1.2.3",
        min_sdk_version="0.1.0",
    )


def _patch_entry_points(monkeypatch: Any, entries: list[FakeEntryPoint]) -> None:
    import importlib.metadata

    monkeypatch.setattr(importlib.metadata, "entry_points", lambda: FakeEntryPoints(entries))


def test_plugin_context_defaults_to_immutable_empty_config() -> None:
    context = PluginContext(sdk_version="0.1.0")

    assert dict(context.config) == {}
    assert type(context.config).__name__ == "mappingproxy"


def test_registry_discovers_good_plugins_for_all_entry_point_groups(monkeypatch: Any) -> None:
    _patch_entry_points(
        monkeypatch,
        [
            FakeEntryPoint("producer", "ancilis.producers", "fake_plugin:producer", FakeProducerPlugin),
            FakeEntryPoint("overlay", "ancilis.overlays", "fake_plugin:overlay", FakeOverlayPlugin),
            FakeEntryPoint("adapter", "ancilis.adapters", "fake_plugin:adapter", FakeAdapterPlugin),
        ],
    )

    registry = PluginRegistry.discover(sdk_version="0.1.0")

    assert [(record.plugin_type, record.metadata.name, record.compatible) for record in registry.records] == [
        ("producer", "fake-producer", True),
        ("overlay", "fake-overlay", True),
        ("adapter", "fake-adapter", True),
    ]
    assert registry.compatible("producer")[0].metadata.name == "fake-producer"


def test_registry_skips_broken_missing_metadata_and_incompatible_plugins(
    monkeypatch: Any,
    caplog: Any,
) -> None:
    class MissingMetadataPlugin:
        pass

    class FuturePlugin:
        metadata = PluginMetadata(
            name="future-producer",
            plugin_type="producer",
            package_name="future-plugin",
            package_version="9.0.0",
            min_sdk_version="99.0.0",
        )

    caplog.set_level(logging.WARNING)
    _patch_entry_points(
        monkeypatch,
        [
            FakeEntryPoint(
                "broken",
                "ancilis.producers",
                "fake_plugin:broken",
                error=RuntimeError("boom"),
            ),
            FakeEntryPoint(
                "missing",
                "ancilis.producers",
                "fake_plugin:missing",
                loaded=MissingMetadataPlugin,
            ),
            FakeEntryPoint(
                "future",
                "ancilis.producers",
                "fake_plugin:future",
                loaded=FuturePlugin,
                dist=FakeDist("future-plugin"),
            ),
        ],
    )

    registry = PluginRegistry.discover(sdk_version="0.1.0")

    assert [record.name for record in registry.skipped()] == ["broken", "missing", "future-producer"]
    assert [record.skip_reason for record in registry.skipped()] == [
        "failed to load entry point: boom",
        "missing PluginMetadata",
        "requires Ancilis SDK >=99.0.0",
    ]
    assert "Skipping Ancilis plugin broken" in caplog.text
    assert "Skipping Ancilis plugin missing" in caplog.text
    assert "Skipping Ancilis plugin future-producer" in caplog.text


def test_registry_skips_metadata_accessor_and_factory_failures(
    monkeypatch: Any,
    caplog: Any,
) -> None:
    class MetadataRaisesPlugin:
        @property
        def metadata(self) -> PluginMetadata:
            raise RuntimeError("metadata boom")

    def factory_raises() -> Any:
        raise RuntimeError("factory boom")

    caplog.set_level(logging.WARNING)
    _patch_entry_points(
        monkeypatch,
        [
            FakeEntryPoint(
                "metadata-raises",
                "ancilis.producers",
                "fake_plugin:metadata_raises",
                loaded=MetadataRaisesPlugin,
            ),
            FakeEntryPoint(
                "factory-raises",
                "ancilis.producers",
                "fake_plugin:factory_raises",
                loaded=factory_raises,
            ),
        ],
    )

    registry = PluginRegistry.discover(sdk_version="0.1.0")

    assert [record.name for record in registry.skipped()] == [
        "metadata-raises",
        "factory-raises",
    ]
    assert [record.skip_reason for record in registry.skipped()] == [
        "failed to read plugin metadata: metadata boom",
        "failed to load entry point: factory boom",
    ]
    assert "Skipping Ancilis plugin metadata-raises" in caplog.text
    assert "Skipping Ancilis plugin factory-raises" in caplog.text


def test_plugins_list_cli_shows_compatibility_and_skip_reason(monkeypatch: Any) -> None:
    class FuturePlugin:
        metadata = PluginMetadata(
            name="future-producer",
            plugin_type="producer",
            package_name="future-plugin",
            package_version="9.0.0",
            min_sdk_version="99.0.0",
        )

    _patch_entry_points(
        monkeypatch,
        [
            FakeEntryPoint("producer", "ancilis.producers", "fake_plugin:producer", FakeProducerPlugin),
            FakeEntryPoint(
                "future",
                "ancilis.producers",
                "future_plugin:producer",
                FuturePlugin,
                dist=FakeDist("future-plugin"),
            ),
        ],
    )

    result = CliRunner().invoke(cli, ["--no-update-check", "plugins", "list"])

    assert result.exit_code == 0, result.output
    assert "fake-producer" in result.output
    assert "compatible" in result.output
    assert "future-producer" in result.output
    assert "requires Ancilis SDK >=99.0.0" in result.output


def test_plugins_validate_filters_package_and_exits_nonzero_for_invalid(
    monkeypatch: Any,
) -> None:
    class FuturePlugin:
        metadata = PluginMetadata(
            name="future-producer",
            plugin_type="producer",
            package_name="future-plugin",
            package_version="9.0.0",
            min_sdk_version="99.0.0",
        )

    _patch_entry_points(
        monkeypatch,
        [
            FakeEntryPoint("producer", "ancilis.producers", "fake_plugin:producer", FakeProducerPlugin),
            FakeEntryPoint(
                "future",
                "ancilis.producers",
                "future_plugin:producer",
                FuturePlugin,
                dist=FakeDist("future-plugin"),
            ),
        ],
    )

    valid = CliRunner().invoke(cli, ["--no-update-check", "plugins", "validate", "fake-plugin"])
    invalid = CliRunner().invoke(cli, ["--no-update-check", "plugins", "validate", "future-plugin"])

    assert valid.exit_code == 0, valid.output
    assert "fake-producer" in valid.output
    assert invalid.exit_code == 1, invalid.output
    assert "future-producer" in invalid.output
    assert "requires Ancilis SDK >=99.0.0" in invalid.output
