"""AutoGen Group Chat + Ancilis multi-agent compliance monitoring.

Demonstrates the AutoGen-native producer. ``AutoGenActionProducer.attach()``
wires ``process_message_before_send`` and ``process_last_received_message``
hooks against a ``ConversableAgent``-shaped object — every agent-to-agent
message becomes an evaluated, evidence-recorded Action with the sender,
recipient, and message payload captured.

Works without ``autogen`` installed: the producer is duck-typed against
ConversableAgent and we use simple stand-ins here. Add ``producer.attach(my_agent)``
to a real ConversableAgent and the same observations are produced for free.

Run from this directory:

    python main.py
    ancilis status            # see SOC 2 + GLBA + AIUC-1 posture

Prerequisites:

    pip install -r requirements.txt
"""

from __future__ import annotations

from pathlib import Path

from ancilis import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore, _agent_db_path
from ancilis.producers import AutoGenActionProducer

# --- Ancilis setup ---
config = load_config(path=Path(__file__).parent / "ancilis.yaml")

# Reset evidence for a clean demo run.
_db_path = _agent_db_path(config.agent_name)
if _db_path.exists():
    _db_path.unlink()

engine = Engine(config)
evidence = EvidenceStore(config)
producer = AutoGenActionProducer(config=config, engine=engine, evidence_store=evidence)

print(f"Crew:      {config.agent_name}")
print(f"Mode:      {config.mode}")
print(f"SOC 2:     {'soc2' in (config.active_overlays or {})}")
print(f"AIUC-1:    {'aiuc-1' in (config.active_certifications or [])}")
print(f"GLBA:      {'financial_services' in (config.active_overlays or {})}")
print()


# --- Mock ConversableAgent stand-ins ---
#
# In a real deployment these would be real `autogen.ConversableAgent`
# instances. Each agent only needs a `.name` attribute and either a
# `register_hook` method, a `hook_lists` dict, or no hook surface at all
# (in which case `attach` falls back to direct attribute assignment, which
# is what we use here).


class MockAgent:
    """Minimal stand-in for autogen.ConversableAgent."""

    def __init__(self, name: str) -> None:
        self.name = name
        # Attribute-fallback hooks land here after producer.attach()
        self.process_message_before_send = None
        self.process_last_received_message = None

    def __repr__(self) -> str:
        return f"<{self.name}>"


# --- Build the crew ---
researcher = MockAgent("Researcher")
analyst = MockAgent("Analyst")
coordinator = MockAgent("Coordinator")

# One call per agent — wires send + receive hooks for each.
for agent in (researcher, analyst, coordinator):
    producer.attach(agent)

print("=== AutoGen group chat — Compliance Research Crew ===")
print("Agents: Researcher · Analyst · Coordinator")
print()


# --- Simulated conversation ---
#
# Each tuple represents one inter-agent message. With a real ConversableAgent,
# AutoGen would call the registered hooks itself; here we drive them directly
# using the same signatures.

CONVERSATION = [
    (
        researcher,
        coordinator,
        "Researched SOC 2 CC6.1 — per-agent tool attribution required for multi-agent systems.",
    ),
    (
        researcher,
        coordinator,
        "AIUC-1 mandates runtime control enforcement at the tool-call layer.",
    ),
    (
        researcher,
        coordinator,
        "GLBA §6801 + SOX §802 require audit trails for financial data access by AI agents.",
    ),
    (
        analyst,
        coordinator,
        "SOC 2 gap: missing runtime enforcement hooks. Remediation: wrap with Ancilis producers.",
    ),
    (
        analyst,
        coordinator,
        "GLBA+SOX gap: no per-agent attribution. Remediation: AutoGenActionProducer.attach(agent).",
    ),
    (
        coordinator,
        researcher,
        "Compiled gap report. 4 total gaps, 1 critical. Recommendation: deploy Ancilis with AIUC-1 target.",
    ),
    (
        coordinator,
        analyst,
        "Notifying ciso@example.com with the gap report summary.",
    ),
]

for sender, recipient, message in CONVERSATION:
    print(f"[{sender.name} → {recipient.name}]")
    print(f"  {message[:100]}")
    # Send hook: emits {kind: 'send', sender: ..., recipient: ..., message: ...}
    sender.process_message_before_send(
        sender=sender,
        message=message,
        recipient=recipient,
        silent=False,
    )
    # Receive hook: emits {kind: 'receive', sender: ..., recipient: ..., message: ...}
    recipient.process_last_received_message(
        messages=[{"role": "user", "name": sender.name, "content": message}],
    )
    print()


# --- Evidence summary ---
summary = evidence.get_summary()
print("=== Evidence summary ===")
print(f"  Records:    {summary['total_evaluations']}")
print(f"  Decisions:  {summary['decisions']}")
print(f"  Hash chain: {'intact' if summary['chain_valid'] else 'BROKEN'}")
print(f"  Tools:      {summary['tools_evaluated']}")
print()
print("Each agent message was attributed via tool name ``autogen:{kind}:{sender}->{recipient}``.")
print("Run `ancilis status` to see multi-agent compliance posture.")

evidence.close()
