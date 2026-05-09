"""CrewAI Research Crew + Ancilis multi-agent compliance monitoring.

Demonstrates the CrewAI-native producer. ``CrewAIActionProducer`` exposes
``step_callback`` / ``task_callback`` / ``crew_callback`` factories that
match the signatures CrewAI calls — drop them into any ``Agent`` /
``Task`` / ``Crew`` constructor and every step, task, and crew completion
becomes an evaluated, evidence-recorded Action with the agent's role
captured as the ``agent_name``.

Works without ``crewai`` installed: the producer is duck-typed against
CrewAI's output objects (it pulls ``tool``, ``agent_role``, etc. from
attributes or dict keys) and we drive the callbacks directly here.

Run from this directory:

    python main.py
    ancilis status            # see SOC 2 + AIUC-1 posture

Prerequisites:

    pip install -r requirements.txt
"""

from pathlib import Path

from ancilis import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore, _agent_db_path
from ancilis.producers import CrewAIActionProducer

# --- Shared Ancilis setup ---
config = load_config(path=Path(__file__).parent / "ancilis.yaml")

# Reset evidence for a clean demo run each time main.py is executed.
_db_path = _agent_db_path(config.agent_name)
if _db_path.exists():
    _db_path.unlink()

engine = Engine(config)
evidence = EvidenceStore(config)
producer = CrewAIActionProducer(config=config, engine=engine, evidence_store=evidence)

print(f"Crew:   {config.agent_name}")
print(f"Mode:   {config.mode}")
print(f"SOC 2:  {'soc2' in (config.active_overlays or {})}")
print(f"AIUC-1: {'aiuc-1' in (config.active_certifications or [])}")
print()


# --- How you'd wire this with real CrewAI ---
#
#     from crewai import Agent, Task, Crew
#
#     researcher = Agent(
#         role="researcher",
#         step_callback=producer.step_callback("researcher"),
#     )
#     research_task = Task(
#         description="Gather intelligence on AI governance",
#         agent=researcher,
#         callback=producer.task_callback("research"),
#     )
#     crew = Crew(
#         agents=[researcher, analyst, reporter],
#         tasks=[research_task, analyze_task, report_task],
#         step_callback=producer.crew_callback("compliance-crew"),
#     )
#     crew.kickoff()
#
# Below we simulate the same callbacks driving the producer directly.


# Per-agent step callbacks — captured agent_name attributes evidence
researcher_step = producer.step_callback("researcher")
analyst_step = producer.step_callback("analyst")
reporter_step = producer.step_callback("reporter")

# Per-task task callbacks — fired when CrewAI completes a Task
research_task_cb = producer.task_callback("research")
analyze_task_cb = producer.task_callback("analyze")
report_task_cb = producer.task_callback("report")

# Crew-level callback — fired by Crew.step_callback / Crew completion
crew_cb = producer.crew_callback("compliance-crew")


print("=== CrewAI research crew execution ===\n")

# --- Researcher agent — three search steps ---
print("[Researcher] Gathering intelligence...")
researcher_step({"tool": "search_web", "agent_role": "researcher", "input": {"query": "AI governance frameworks 2024"}})
researcher_step({"tool": "search_web", "agent_role": "researcher", "input": {"query": "AI agent security controls best practices"}})
researcher_step({"tool": "search_web", "agent_role": "researcher", "input": {"query": "SOC 2 AI agent audit requirements"}})
research_task_cb({"description": "research", "agent_role": "researcher", "output": "3 findings"})
print("  3 search steps + task callback → 4 records\n")

# --- Analyst agent — two analysis steps ---
print("[Analyst] Processing findings...")
analyst_step({"tool": "analyze_findings", "agent_role": "analyst", "focus": "SOC 2 compliance"})
analyst_step({"tool": "analyze_findings", "agent_role": "analyst", "focus": "audit trail requirements"})
analyze_task_cb({"description": "analyze", "agent_role": "analyst", "output": "risk=medium"})
print("  2 analysis steps + task callback → 3 records\n")

# --- Reporter agent — generate the final report ---
print("[Reporter] Generating report...")
reporter_step({"tool": "generate_report", "agent_role": "reporter", "format": "markdown"})
report_task_cb({"description": "report", "agent_role": "reporter", "output": "847 words, 3 sections"})
print("  1 generate step + task callback → 2 records\n")

# --- Crew-level: full kickoff completion ---
crew_cb({"name": "compliance-crew", "id": "crew-001"})
print("[Crew] kickoff complete → 1 record\n")


# --- Evidence summary ---
summary = evidence.get_summary()
print("=== Evidence summary ===")
print(f"  Records:    {summary['total_evaluations']}")
print(f"  Decisions:  {summary['decisions']}")
print(f"  Hash chain: {'intact' if summary['chain_valid'] else 'BROKEN'}")
print(f"  Tools:      {summary['tools_evaluated']}")
print()
print("Per-agent attribution: pass `agent_name=` to step_callback() / task_callback() for each crew member.")
print("Run `ancilis status` to see crew compliance posture.")

evidence.close()
