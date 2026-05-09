"""Auto-detection of installed LLM/framework SDKs.

Removes per-SDK boilerplate from user code: call ``auto_register(config,
engine)`` and get back a dict of producers keyed by provider, one per
upstream SDK present in the current environment.

This module never *imports* the upstream SDKs — it uses
``importlib.util.find_spec`` so detection is free of side effects.

Typical wiring::

    from ancilis import Engine, load_config
    from ancilis.producers.auto import auto_register

    config = load_config("ancilis.yaml")
    engine = Engine(config)
    producers = auto_register(config, engine)
    # producers == {"anthropic": AnthropicActionProducer(...), ...}

For UI/diagnostics use ``detect_installed_sdks()`` which returns a
plain dict ``{provider_slug: True/False}`` without touching any state.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolRegistry
from ancilis.evidence.store import EvidenceStore


@dataclass(frozen=True)
class _Detector:
    """Maps a producer slug to the upstream module(s) that signal availability."""

    provider: str
    producer_attr: str  # name on ancilis.producers package
    modules: tuple[str, ...]  # any-of: if any module is importable, the SDK is present


# Each row: (provider_slug, producer_class_attr, candidate_module_names...)
# A provider is considered "available" if importlib can locate any one of
# its candidate modules. Aliased modules cover renames (e.g. google.genai vs
# google.generativeai, autogen vs autogen_agentchat vs ag2).
_DETECTORS: tuple[_Detector, ...] = (
    _Detector("anthropic", "AnthropicActionProducer", ("anthropic",)),
    _Detector("openai", "OpenAIActionProducer", ("openai",)),
    _Detector("gemini", "GeminiActionProducer", ("google.genai", "google.generativeai")),
    _Detector("mistral", "MistralActionProducer", ("mistralai",)),
    _Detector("cohere", "CohereActionProducer", ("cohere",)),
    _Detector("groq", "GroqActionProducer", ("groq",)),
    _Detector("together", "TogetherActionProducer", ("together",)),
    _Detector("fireworks", "FireworksActionProducer", ("fireworks",)),
    _Detector("aws-bedrock", "BedrockActionProducer", ("boto3",)),
    _Detector(
        "langchain",
        "LangChainActionProducer",
        ("langchain", "langchain_core"),
    ),
    _Detector("crewai", "CrewAIActionProducer", ("crewai",)),
    _Detector(
        "autogen",
        "AutoGenActionProducer",
        ("autogen", "autogen_agentchat", "ag2"),
    ),
    _Detector(
        "semantic-kernel",
        "SemanticKernelActionProducer",
        ("semantic_kernel",),
    ),
)


def _module_present(module_names: Iterable[str]) -> bool:
    """True iff any candidate module is importable (no actual import)."""
    for name in module_names:
        try:
            spec = importlib.util.find_spec(name)
        except (ImportError, ValueError):
            spec = None
        if spec is not None:
            return True
    return False


def detect_installed_sdks() -> dict[str, bool]:
    """Return a flat ``{provider_slug: present}`` dict.

    Side-effect-free; safe to call before any producer is wired up. Useful
    for CLI diagnostics ("which SDKs am I going to wrap?") and for users who
    want to make scope decisions before calling ``auto_register``.
    """
    return {d.provider: _module_present(d.modules) for d in _DETECTORS}


def installed_provider_slugs() -> list[str]:
    """Return only the provider slugs whose upstream SDK is installed."""
    return [provider for provider, present in detect_installed_sdks().items() if present]


def _instantiate_producer(
    detector: _Detector,
    *,
    config: ResolvedConfig,
    engine: Engine,
    registry: ToolRegistry | None,
    evidence_store: EvidenceStore | None,
) -> Any:
    """Resolve the producer class via the lazy ``ancilis.producers`` package
    and instantiate it with the standard producer constructor signature."""
    from ancilis import producers as producers_pkg

    cls = getattr(producers_pkg, detector.producer_attr)
    return cls(
        config=config,
        engine=engine,
        registry=registry,
        evidence_store=evidence_store,
    )


def auto_register(
    config: ResolvedConfig,
    engine: Engine,
    *,
    registry: ToolRegistry | None = None,
    evidence_store: EvidenceStore | None = None,
    include: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Instantiate one producer per detected upstream SDK.

    Returns a dict keyed by provider slug. Filters:
    - ``include``: only consider these provider slugs (still must be installed).
    - ``exclude``: skip these provider slugs even if installed.

    The producers share the engine and registry, and unless an explicit
    ``evidence_store`` is passed, each producer instantiates its own (matching
    the existing single-producer wiring patterns).
    """
    include_set = set(include) if include is not None else None
    exclude_set = set(exclude) if exclude else set()

    available = detect_installed_sdks()
    out: dict[str, Any] = {}
    for detector in _DETECTORS:
        if not available.get(detector.provider, False):
            continue
        if include_set is not None and detector.provider not in include_set:
            continue
        if detector.provider in exclude_set:
            continue
        out[detector.provider] = _instantiate_producer(
            detector,
            config=config,
            engine=engine,
            registry=registry,
            evidence_store=evidence_store,
        )
    return out
