"""Data Classification Example — declare your data, get compliance controls.

This example demonstrates the data-classification activation path:
1. Declare what data your agent handles (health_records, personal_info)
2. HIPAA, GDPR, and SOC 2 overlays activate automatically
3. Pattern detection flags sensitive data in tool call parameters
4. Enforcement blocks unauthorized tools

Run from this directory:
    python run.py
"""

from pathlib import Path

from ancilis import BlockedActionError, ToolActionProducer, load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore

config = load_config(path=Path(__file__).parent / "ancilis.yaml")
engine = Engine(config)
evidence = EvidenceStore(config, in_memory=True)
producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)


# --- Agent tools ---

def lookup_patient(patient_id: str) -> dict:
    """Look up a patient record by ID."""
    return {
        "id": patient_id,
        "name": "Jane Smith",
        "dob": "1985-03-15",
        "diagnosis": "Type 2 diabetes",
    }


def get_diagnosis(patient_id: str) -> str:
    """Retrieve diagnosis details."""
    return "Type 2 diabetes, managed with metformin 500mg BID"


def schedule_appointment(patient_id: str, date: str) -> str:
    """Schedule a follow-up appointment."""
    return f"Appointment scheduled for {patient_id} on {date}"


def export_all_records() -> str:
    """Bulk export — this tool is NOT in the approved list."""
    return "Exported 50,000 patient records"


# Wrap approved tools
lookup_patient = producer.wrap_tool(lookup_patient, tool_name="lookup_patient")
get_diagnosis = producer.wrap_tool(get_diagnosis, tool_name="get_diagnosis")
schedule_appointment = producer.wrap_tool(schedule_appointment, tool_name="schedule_appointment")
export_all_records = producer.wrap_tool(export_all_records, tool_name="export_all_records")


# --- Show what activated ---

print("=== Data Classification Example ===")
print(f"Agent: {config.agent_name}")
print(f"Mode: {config.mode}")
print(f"Data handled: health_records, personal_info")
print()
print("Overlays activated automatically:")
for oa in config.active_overlays.values():
    triggers = [t.split(" via ")[1] for t in oa.triggered_by if " via " in t]
    print(f"  {oa.name} — triggered by {', '.join(triggers)} declaration")
print()

# --- Run approved tool calls ---

print("Running approved tool calls...")
r1 = lookup_patient("P-1234")
print(f"  lookup_patient('P-1234') -> {r1}")

r2 = get_diagnosis("P-1234")
print(f"  get_diagnosis('P-1234') -> {r2}")

r3 = schedule_appointment("P-1234", "2026-04-01")
print(f"  schedule_appointment('P-1234', '2026-04-01') -> {r3}")

# --- Try unauthorized tool (enforce mode blocks it) ---

print()
print("Attempting unauthorized tool call (enforce mode)...")
try:
    export_all_records()
    print("  ERROR: should have been blocked!")
except BlockedActionError as e:
    print(f"  {e.display_message}")

# --- Evidence and report ---

summary = evidence.get_summary()
print(f"\n=== Evidence Summary ===")
print(f"  Records: {summary['total_evaluations']}")
print(f"  Decisions: {summary['decisions']}")
print(f"  Hash chain: {'intact' if summary['chain_valid'] else 'BROKEN'}")

print(f"\n=== What `ancilis status` shows ===")
from ancilis.cli.status import _format_status
print(_format_status(config, evidence, verbose=False))

print(f"\n=== What `ancilis report` shows (HIPAA section) ===")
from ancilis.report.generator import ReportGenerator
from ancilis.report.renderer import render_terminal
generator = ReportGenerator(config, evidence)
report_data = generator.generate(period="30d", report_format="terminal")
output = render_terminal(report_data)
# Print just the HIPAA section for brevity
lines = output.split("\n")
in_hipaa = False
for line in lines:
    if "HIPAA" in line:
        in_hipaa = True
    if in_hipaa:
        print(line)
        if line.strip().startswith("Evidence retention"):
            break

evidence.close()
print("\nDone. Declare your data types, get the right compliance controls automatically.")
