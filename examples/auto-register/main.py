"""Ancilis ``auto_register`` — wire whatever's installed in your environment.

``auto_register(config, engine)`` removes per-SDK boilerplate. It detects
which upstream LLM and framework SDKs are installed in the current Python
environment via ``importlib.util.find_spec`` (no actual imports, no side
effects) and instantiates one Ancilis producer per detected SDK.

Drop it into your agent's startup once, and every supported SDK you import
later will already have a producer ready.

Run from this directory:

    python main.py
    ancilis status

Prerequisites:

    pip install -r requirements.txt
"""

from pathlib import Path

from ancilis import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers import (
    auto_register,
    detect_installed_sdks,
    installed_provider_slugs,
)

# --- Ancilis setup ---
config = load_config(path=Path(__file__).parent / "ancilis.yaml")
engine = Engine(config)
evidence = EvidenceStore(config)

print(f"Agent: {config.agent_name}")
print(f"Mode:  {config.mode}")
print()

# --- Detect what's installed ---

available = detect_installed_sdks()
present = installed_provider_slugs()

print("=== SDK detection (importlib.find_spec) ===")
for provider, ok in sorted(available.items()):
    flag = "✓" if ok else " "
    print(f"  [{flag}] {provider}")
print()
print(f"Detected: {present or '(none)'}")
print()

# --- Wire one producer per detected SDK ---

producers = auto_register(config, engine, evidence_store=evidence)

print(f"Wired {len(producers)} producer(s):")
for slug, prod in sorted(producers.items()):
    print(f"  - {slug:<16}  {prod.__class__.__name__}")
print()

# --- Filter via include / exclude ---

if "openai" in available and "anthropic" in available:
    only_anthropic = auto_register(config, engine, include={"anthropic"}, evidence_store=evidence)
    print(f"include={{anthropic}} → {sorted(only_anthropic.keys())}")

skip_examples = {"deepseek", "fireworks"}
filtered = auto_register(config, engine, exclude=skip_examples, evidence_store=evidence)
skipped = [s for s in skip_examples if s in present]
if skipped:
    print(f"exclude={skip_examples} → dropped {skipped}")

print()
print("Hint: drop the per-SDK wiring boilerplate from your agent code.")
print("Just call auto_register() once and import producers from the returned dict.")

evidence.close()
