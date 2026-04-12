"""CrewAI Research Crew + Ancilis Multi-Agent Compliance Monitoring.

Demonstrates per-agent evidence attribution across a multi-agent research crew.
Each crew member (Researcher, Analyst, Reporter) wraps tools with its own
agent_name, so compliance evidence identifies which agent made each tool call.

If ancilis-crewai is available, migrate the TODO blocks to use it.

Run from this directory:
    python main.py

Prerequisites:
    pip install -r requirements.txt
"""

from pathlib import Path

from ancilis import ToolActionProducer, load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore, _agent_db_path

# --- Shared Ancilis setup ---
config = load_config(path=Path(__file__).parent / "ancilis.yaml")

# Reset evidence for a clean demo run each time main.py is executed
_db_path = _agent_db_path(config.agent_name)
if _db_path.exists():
    _db_path.unlink()

engine = Engine(config)
evidence = EvidenceStore(config)
producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)

print(f"Crew: {config.agent_name}")
print(f"Mode: {config.mode}")
print(f"SOC 2 overlay: {'soc2' in (config.active_overlays or {})}")
print(f"AIUC-1 active: {'aiuc-1' in (config.active_certifications or [])}")
print()


# --- Tool implementations ---

def _search_web_impl(query: str) -> dict:
    """Simulate web search tool."""
    results_map = {
        "AI governance frameworks 2024": [
            "NIST AI RMF 1.0 — voluntary risk management framework",
            "EU AI Act — mandatory for high-risk AI systems",
            "AIUC-1 — first certifiable standard for AI agents",
        ],
        "AI agent security controls best practices": [
            "Runtime policy enforcement at tool-call level",
            "Data classification-driven control activation",
            "Cryptographic audit trails for evidence integrity",
        ],
        "SOC 2 AI agent audit requirements": [
            "CC6.1: Logical access security — tool-call authorization",
            "CC7.2: System monitoring — behavioral baseline tracking",
            "A1.2: Availability monitoring — agent uptime and error rates",
        ],
    }
    return {
        "query": query,
        "results": results_map.get(query, ["No results found"]),
    }


def _analyze_findings_impl(findings: str, focus: str) -> dict:
    """Analyze research findings and extract key insights."""
    return {
        "focus": focus,
        "key_insights": [
            f"Runtime enforcement is central to {focus}",
            "Data classification drives control selection",
            "Evidence integrity requires cryptographic chaining",
        ],
        "risk_level": "medium",
        "recommendation": f"Implement {focus} controls at the tool-call layer",
    }


def _generate_report_impl(insights: str, format_type: str = "markdown") -> dict:
    """Generate final research report."""
    return {
        "format": format_type,
        "title": "AI Agent Compliance Research Report",
        "sections": ["Executive Summary", "Key Findings", "Recommendations"],
        "word_count": 847,
        "status": "complete",
    }


# Per-agent tool wrapping — pass agent_name to attribute evidence correctly
# TODO: replace with ancilis-crewai @agent_tool decorator when ANC-568 ships
search_web = producer.wrap_tool(_search_web_impl, tool_name="search_web", agent_name="researcher")
analyze_findings = producer.wrap_tool(_analyze_findings_impl, tool_name="analyze_findings", agent_name="analyst")
generate_report = producer.wrap_tool(_generate_report_impl, tool_name="generate_report", agent_name="reporter")


# --- Simulate CrewAI research crew execution ---

print("=== CrewAI Research Crew Execution ===")
print()

# --- Researcher agent ---
print("[Researcher] Gathering intelligence...")
r1 = search_web("AI governance frameworks 2024")
print(f"  search_web → {len(r1['results'])} results")

r2 = search_web("AI agent security controls best practices")
print(f"  search_web → {len(r2['results'])} results")

r3 = search_web("SOC 2 AI agent audit requirements")
print(f"  search_web → {len(r3['results'])} results")
print()

# --- Analyst agent ---
print("[Analyst] Processing findings...")
combined = "; ".join(r1["results"] + r2["results"])
a1 = analyze_findings(combined, focus="SOC 2 compliance")
print(f"  analyze_findings → risk={a1['risk_level']}, {len(a1['key_insights'])} insights")

a2 = analyze_findings("; ".join(r3["results"]), focus="audit trail requirements")
print(f"  analyze_findings → risk={a2['risk_level']}, {len(a2['key_insights'])} insights")
print()

# --- Reporter agent ---
print("[Reporter] Generating report...")
final_insights = "; ".join(a1["key_insights"] + a2["key_insights"])
rep = generate_report(final_insights, format_type="markdown")
print(f"  generate_report → {rep['word_count']} words, {len(rep['sections'])} sections")
print()

# --- Evidence summary ---
summary = evidence.get_summary(session_id=producer.session_id)
print("=== Evidence Summary ===")
print(f"  Records:    {summary['total_evaluations']}")
print(f"  Decisions:  {summary['decisions']}")
print(f"  Hash chain: {'intact' if summary['chain_valid'] else 'BROKEN'}")
print(f"  Tools:      {summary['tools_evaluated']}")
print()
print("Per-agent attribution: pass agent_name= to wrap_tool() for each crew member.")
print("Run `ancilis scan` to see compliance posture.")

evidence.close()
