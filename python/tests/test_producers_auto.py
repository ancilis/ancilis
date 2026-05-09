"""Tests for ancilis.producers.auto (SDK detection + auto-instantiation)."""

from __future__ import annotations

import pytest

from ancilis.config import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers import auto
from ancilis.producers.auto import (
    _DETECTORS,
    _module_present,
    auto_register,
    detect_installed_sdks,
    installed_provider_slugs,
)


def _config() -> object:
    raw = {"agent": {"name": "auto-agent", "owner": "test-owner"}}
    return load_config(raw=raw)


class TestModulePresent:
    def test_returns_true_for_real_module(self) -> None:
        # ``os`` is always importable.
        assert _module_present(("os",)) is True

    def test_returns_true_for_alias(self) -> None:
        # First name missing, second name resolvable.
        assert _module_present(("ancilis_definitely_missing_xyz", "json")) is True

    def test_returns_false_when_no_module(self) -> None:
        assert _module_present(("ancilis_definitely_not_installed_module",)) is False

    def test_returns_false_for_empty_tuple(self) -> None:
        assert _module_present(()) is False


class TestDetectInstalledSdks:
    def test_returns_dict_keyed_by_provider(self) -> None:
        result = detect_installed_sdks()
        assert set(result.keys()) == {d.provider for d in _DETECTORS}
        for value in result.values():
            assert isinstance(value, bool)

    def test_installed_provider_slugs_subset_of_detect_keys(self) -> None:
        installed = installed_provider_slugs()
        detected = detect_installed_sdks()
        for slug in installed:
            assert detected[slug] is True


class TestAutoRegister:
    def test_returns_empty_when_nothing_installed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Force every SDK to look absent.
        monkeypatch.setattr(auto, "_module_present", lambda names: False)
        producers = auto_register(_config(), Engine(_config()))
        assert producers == {}

    def test_instantiates_one_producer_per_detected_sdk(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Pretend only anthropic + openai are installed.
        present_modules = {"anthropic", "openai"}

        def fake_present(names):
            return any(n in present_modules for n in names)

        monkeypatch.setattr(auto, "_module_present", fake_present)

        config = _config()
        engine = Engine(config)
        store = EvidenceStore(config, in_memory=True)
        producers = auto_register(config, engine, evidence_store=store)
        assert set(producers.keys()) == {"anthropic", "openai"}
        anthropic_producer = producers["anthropic"]
        assert anthropic_producer.provider == "anthropic"
        # Producer must use the engine, registry, and provided evidence store.
        observation = anthropic_producer.observe(
            __import__(
                "ancilis.producers.llm", fromlist=("LLMInvocation",)
            ).LLMInvocation(model="claude-sonnet-4-6", agent_name="auto-agent")
        )
        assert observation.action.tool.server == "anthropic"
        assert store.get_summary()["total_evaluations"] == 1

    def test_include_filter_narrows_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(auto, "_module_present", lambda names: True)
        producers = auto_register(_config(), Engine(_config()), include={"anthropic", "groq"})
        assert set(producers.keys()) == {"anthropic", "groq"}

    def test_exclude_filter_removes_provider(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(auto, "_module_present", lambda names: True)
        producers = auto_register(
            _config(),
            Engine(_config()),
            exclude={"openai", "fireworks"},
        )
        assert "openai" not in producers
        assert "fireworks" not in producers
        # Other providers still wired
        assert "anthropic" in producers

    def test_include_only_yields_installed_subset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # include set is ANDed with detection — providers not installed are
        # still excluded even if listed in include.
        monkeypatch.setattr(auto, "_module_present", lambda names: "openai" in names)
        producers = auto_register(
            _config(), Engine(_config()), include={"anthropic", "openai"}
        )
        assert set(producers.keys()) == {"openai"}

    def test_dispatch_table_covers_each_known_producer_attr(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Sanity: every detector's producer_attr must resolve via the
        ancilis.producers package — protects against typos in the table."""
        from ancilis import producers as producers_pkg

        for detector in _DETECTORS:
            cls = getattr(producers_pkg, detector.producer_attr)
            assert cls is not None


class TestLazyExports:
    def test_auto_register_re_exported_from_package(self) -> None:
        from ancilis import producers as p

        assert p.auto_register is auto_register
        assert p.detect_installed_sdks is detect_installed_sdks
        assert p.installed_provider_slugs is installed_provider_slugs
