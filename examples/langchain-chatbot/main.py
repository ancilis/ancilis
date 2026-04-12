"""LangChain Chatbot + Ancilis SOC 2 Compliance Monitoring.

Demonstrates wrapping LangChain tool calls with Ancilis ToolActionProducer
to record compliance evidence for every tool execution.

If ancilis-langchain is available, migrate the TODO blocks below to use it.

Run from this directory:
    python main.py

Prerequisites:
    pip install -r requirements.txt
    export OPENAI_API_KEY=sk-...
"""

import os
from pathlib import Path

from ancilis import ToolActionProducer, load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore

# --- Ancilis setup ---
config = load_config(path=Path(__file__).parent / "ancilis.yaml")
engine = Engine(config)
evidence = EvidenceStore(config)
producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)

print(f"Agent: {config.agent_name}")
print(f"Mode: {config.mode}")
print(f"SOC 2 active: {'soc2' in (config.active_overlays or {})}")
print()

# --- Define tools with Ancilis wrapping ---

def _search_web_impl(query: str) -> dict:
    """Simulate web search — replace with real search tool in production."""
    return {
        "query": query,
        "results": [
            "SOC 2 Type II requires continuous monitoring of security controls",
            "AI agents accessing personal data must maintain audit logs",
            "NIST AI RMF recommends runtime policy enforcement",
        ],
    }


def _calculator_impl(expression: str) -> dict:
    """Safe arithmetic evaluator."""
    allowed = set("0123456789+-*/.() ")
    if not all(c in allowed for c in expression):
        return {"error": "Expression contains disallowed characters"}
    try:
        result = eval(expression, {"__builtins__": {}})  # noqa: S307
        return {"expression": expression, "result": result}
    except Exception as e:
        return {"error": str(e)}


# Wrap with Ancilis — each call is evaluated and evidence-recorded
# TODO: replace with ancilis-langchain wrapper when ANC-568 ships
search_web = producer.wrap_tool(_search_web_impl, tool_name="search_web")
calculator = producer.wrap_tool(_calculator_impl, tool_name="calculator")


# --- Simulate LangChain agent conversation ---

CONVERSATIONS = [
    {
        "user": "What are the SOC 2 monitoring requirements for AI agents?",
        "tool": "search_web",
        "tool_input": {"query": "SOC 2 monitoring requirements AI agents"},
    },
    {
        "user": "If we need 99.9% uptime, how many minutes of downtime per year is allowed?",
        "tool": "calculator",
        "tool_input": {"expression": "365 * 24 * 60 * (1 - 0.999)"},
    },
    {
        "user": "What frameworks does NIST recommend for AI runtime policy?",
        "tool": "search_web",
        "tool_input": {"query": "NIST AI RMF runtime policy enforcement"},
    },
    {
        "user": "How many hours is 525 minutes?",
        "tool": "calculator",
        "tool_input": {"expression": "525 / 60"},
    },
    {
        "user": "What is required for SOC 2 audit log compliance?",
        "tool": "search_web",
        "tool_input": {"query": "SOC 2 audit log requirements AI personal data"},
    },
]

print("=== Simulated LangChain Agent Conversation ===")
print()

for i, turn in enumerate(CONVERSATIONS, 1):
    print(f"[Turn {i}] User: {turn['user']}")

    if turn["tool"] == "search_web":
        result = search_web(**turn["tool_input"])
        print(f"  → search_web({turn['tool_input']['query']!r})")
        if "results" in result:
            print(f"    Found {len(result['results'])} results")
    elif turn["tool"] == "calculator":
        result = calculator(**turn["tool_input"])
        print(f"  → calculator({turn['tool_input']['expression']!r})")
        if "result" in result:
            print(f"    = {result['result']:.4f}")

    print()

# --- Evidence summary ---
summary = evidence.get_summary(session_id=producer.session_id)
print("=== Evidence Summary ===")
print(f"  Records:    {summary['total_evaluations']}")
print(f"  Decisions:  {summary['decisions']}")
print(f"  Hash chain: {'intact' if summary['chain_valid'] else 'BROKEN'}")
print(f"  Tools:      {summary['tools_evaluated']}")
print()
print("Run `ancilis scan` to see SOC 2 posture.")

evidence.close()
