"""AutoGen Group Chat + Ancilis Multi-Agent Compliance Monitoring.

Demonstrates per-agent tool-call evidence in a simulated AutoGen group chat
scenario. Three agents — Researcher, Analyst, Coordinator — each wrap their
tools with a shared ToolActionProducer so every call is individually attributed
and compliance evidence is captured for the full conversation.

Works without an OpenAI API key: runs a scripted simulation of the group-chat
conversation that exercises the same Ancilis code paths a live run would use.
Set OPENAI_API_KEY in .env to enable live AutoGen completion calls.

Run from this directory:
    python main.py
    ancilis scan

Prerequisites:
    pip install -r requirements.txt
    cp .env.example .env  # optional — only needed for live AutoGen calls
"""

from __future__ import annotations

import os
from pathlib import Path

from ancilis import ToolActionProducer, load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore, _agent_db_path

# --- Ancilis setup ---
config = load_config(path=Path(__file__).parent / "ancilis.yaml")

# Reset evidence for a clean demo run
_db_path = _agent_db_path(config.agent_name)
if _db_path.exists():
    _db_path.unlink()

engine = Engine(config)
evidence = EvidenceStore(config)
producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)

print(f"Crew:      {config.agent_name}")
print(f"Mode:      {config.mode}")
print(f"SOC 2:     {'soc2' in (config.active_overlays or {})}")
print(f"AIUC-1:    {'aiuc-1' in (config.active_certifications or [])}")
print(f"GLBA:      {'financial_services' in (config.active_overlays or {})}")
print()


# ---------------------------------------------------------------------------
# Tool implementations (shared across all agents in the group)
# ---------------------------------------------------------------------------

def _search_research_impl(topic: str) -> dict:
    """Research a compliance or AI governance topic."""
    data = {
        "AutoGen multi-agent SOC 2 requirements": {
            "summary": "Multi-agent systems must attribute tool calls per agent for SOC 2 CC6.1",
            "controls": ["CC6.1 — logical access", "CC7.2 — system monitoring", "A1.2 — availability"],
        },
        "AIUC-1 certification for agentic AI": {
            "summary": "AIUC-1 requires runtime control enforcement at the tool-call layer",
            "controls": ["PR-01 identity", "PR-02 scope", "PR-03 provenance", "PR-05 audit trail"],
        },
        "financial data handling compliance": {
            "summary": "GLBA and SOX require audit trails for all financial data access by AI agents",
            "controls": ["GLBA §6801 — data protection", "SOX §802 — audit record retention"],
        },
    }
    return data.get(topic, {"summary": f"No cached data for: {topic}", "controls": []})


def _analyze_findings_impl(findings: str, framework: str) -> dict:
    """Analyze research findings against a compliance framework."""
    return {
        "framework": framework,
        "findings_digest": findings[:80] + "..." if len(findings) > 80 else findings,
        "gap_count": 2,
        "gaps": [
            f"Missing runtime enforcement hooks in {framework}",
            f"No per-agent attribution in current {framework} implementation",
        ],
        "remediation": "Wrap all tool calls with ToolActionProducer for per-call evidence",
    }


def _compile_report_impl(analyses: str, title: str) -> dict:
    """Compile a compliance gap report from multiple analyses."""
    return {
        "title": title,
        "sections": ["Executive Summary", "Gap Analysis", "Remediation Plan"],
        "total_gaps": 4,
        "critical_gaps": 1,
        "recommendation": "Deploy Ancilis SDK with AIUC-1 certification target",
        "evidence_required": True,
    }


def _notify_stakeholder_impl(recipient: str, summary: str) -> dict:
    """Notify a stakeholder with the report summary (simulated)."""
    return {
        "recipient": recipient,
        "status": "delivered",
        "channel": "email",
        "message_preview": summary[:100],
    }


# Wrap with Ancilis — each call gets evaluated and evidence-recorded
search_research = producer.wrap_tool(_search_research_impl, tool_name="search_research")
analyze_findings = producer.wrap_tool(_analyze_findings_impl, tool_name="analyze_findings")
compile_report = producer.wrap_tool(_compile_report_impl, tool_name="compile_report")
notify_stakeholder = producer.wrap_tool(_notify_stakeholder_impl, tool_name="notify_stakeholder")


# ---------------------------------------------------------------------------
# Simulated group-chat conversation
# ---------------------------------------------------------------------------
# In a real AutoGen deployment, each agent would call these same wrapped tools
# through AutoGen's function-calling interface. The Ancilis wrapping is
# framework-agnostic — it intercepts calls regardless of who initiates them.

TURNS = [
    # Researcher agent tasks
    {
        "agent": "Researcher",
        "action": "search_research",
        "kwargs": {"topic": "AutoGen multi-agent SOC 2 requirements"},
    },
    {
        "agent": "Researcher",
        "action": "search_research",
        "kwargs": {"topic": "AIUC-1 certification for agentic AI"},
    },
    {
        "agent": "Researcher",
        "action": "search_research",
        "kwargs": {"topic": "financial data handling compliance"},
    },
    # Analyst agent tasks
    {
        "agent": "Analyst",
        "action": "analyze_findings",
        "kwargs": {
            "findings": "SOC 2 CC6.1 requires per-agent tool attribution; AIUC-1 mandates runtime enforcement",
            "framework": "SOC 2 Type II",
        },
    },
    {
        "agent": "Analyst",
        "action": "analyze_findings",
        "kwargs": {
            "findings": "GLBA §6801 requires data protection; SOX §802 mandates audit trail retention",
            "framework": "GLBA + SOX",
        },
    },
    # Coordinator agent tasks
    {
        "agent": "Coordinator",
        "action": "compile_report",
        "kwargs": {
            "analyses": "SOC 2 gap: 2 gaps, GLBA+SOX gap: 2 gaps",
            "title": "AI Agent Compliance Gap Report — Q2 2026",
        },
    },
    {
        "agent": "Coordinator",
        "action": "notify_stakeholder",
        "kwargs": {
            "recipient": "ciso@example.com",
            "summary": "4 compliance gaps identified across SOC 2, GLBA, and SOX for AI agent deployment",
        },
    },
]

TOOL_MAP = {
    "search_research": search_research,
    "analyze_findings": analyze_findings,
    "compile_report": compile_report,
    "notify_stakeholder": notify_stakeholder,
}

print("=== AutoGen Group Chat — Compliance Research Crew ===")
print("Agents: Researcher · Analyst · Coordinator")
print()

for turn in TURNS:
    agent = turn["agent"]
    action = turn["action"]
    kwargs = turn["kwargs"]

    print(f"[{agent}] → {action}()")
    result = TOOL_MAP[action](**kwargs)

    # Print a concise excerpt of the result
    if isinstance(result, dict):
        first_key = next(iter(result))
        first_val = result[first_key]
        if isinstance(first_val, str):
            print(f"    {first_key}: {first_val[:70]}")
        elif isinstance(first_val, list) and first_val:
            print(f"    {first_key}[0]: {first_val[0][:70]}")
    print()

# ---------------------------------------------------------------------------
# Evidence summary
# ---------------------------------------------------------------------------
summary = evidence.get_summary(session_id=producer.session_id)
print("=== Evidence Summary ===")
print(f"  Records:    {summary['total_evaluations']}")
print(f"  Decisions:  {summary['decisions']}")
print(f"  Hash chain: {'intact' if summary['chain_valid'] else 'BROKEN'}")
print(f"  Tools:      {summary['tools_evaluated']}")
print()
print("Run `ancilis scan` to see multi-agent compliance posture.")

evidence.close()
