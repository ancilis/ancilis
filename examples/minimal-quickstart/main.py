"""Minimal Quickstart — fastest path to first Ancilis scan.

Run from this directory:
    python main.py
    ancilis scan
"""

from pathlib import Path

from ancilis import ToolActionProducer, load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore

config = load_config(path=Path(__file__).parent / "ancilis.yaml")
engine = Engine(config)
evidence = EvidenceStore(config)
producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)


def search_web(query: str) -> dict:
    return {"results": ["NIST AI RMF", "EU AI Act", "SOC 2 Type II"]}


def send_reply(message: str) -> str:
    return f"Sent: {message}"


search_web = producer.wrap_tool(search_web, tool_name="search_web")
send_reply = producer.wrap_tool(send_reply, tool_name="send_reply")

print(f"Agent: {config.agent_name}")
print(f"Mode: {config.mode}")
print()

result = search_web("AI compliance frameworks")
print(f"search_web -> {result}")

result = send_reply("Here are the top compliance frameworks for AI agents.")
print(f"send_reply -> {result}")

summary = evidence.get_summary()
print(f"\nEvidence: {summary['total_evaluations']} records, "
      f"chain {'intact' if summary['chain_valid'] else 'BROKEN'}")
print("\nRun `ancilis scan` to see your compliance posture.")

evidence.close()
