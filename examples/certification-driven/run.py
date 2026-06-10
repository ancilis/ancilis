"""Certification-Driven Example — one config line to AIUC-1 readiness.

This example demonstrates the certification-intent activation path:
1. A minimal config declares only agent_name and certification_targets
2. AIUC-1 controls activate automatically
3. Tool calls are evaluated and evidence is recorded
4. `ancilis report` shows certification readiness

Run from this directory:
    python run.py
"""

from pathlib import Path

from ancilis import ToolActionProducer, load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore

# Load config from this example's ancilis.yaml
config = load_config(path=Path(__file__).parent / "ancilis.yaml")
engine = Engine(config)

# Use an in-memory evidence store for the demo (no files left behind)
evidence = EvidenceStore(config, in_memory=True)
producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)


# --- Define some agent tools ---

def get_customer(customer_id: str) -> dict:
    """Look up a customer record."""
    return {"id": customer_id, "name": "Jane Doe", "status": "active"}


def update_preferences(customer_id: str, preferences: dict) -> str:
    """Update customer notification preferences."""
    return f"Updated preferences for {customer_id}"


def send_notification(customer_id: str, message: str) -> str:
    """Send a push notification."""
    return f"Notification sent to {customer_id}: {message}"


# Wrap the tools with Ancilis evaluation
get_customer = producer.wrap_tool(get_customer, tool_name="get_customer")
update_preferences = producer.wrap_tool(update_preferences, tool_name="update_preferences")
send_notification = producer.wrap_tool(send_notification, tool_name="send_notification")


# --- Simulate agent activity ---

print("=== Certification-Driven Example ===")
print(f"Agent: {config.agent_name}")
print(f"Mode: {config.mode}")
print(f"Certification targets: {config.active_certifications}")
print(f"Active controls: {sum(1 for c in config.controls.values() if c.enabled)}")
print()

# Run some tool calls — each one is evaluated and evidence is recorded
print("Running tool calls...")
result1 = get_customer("C-001")
print(f"  get_customer('C-001') -> {result1}")

result2 = update_preferences("C-001", {"email": True, "sms": False})
print(f"  update_preferences('C-001', ...) -> {result2}")

result3 = send_notification("C-001", "Your order shipped")
print(f"  send_notification('C-001', ...) -> {result3}")

# Run a few more to build up evidence
for i in range(5):
    get_customer(f"C-{100 + i}")

print(f"\n  Total tool calls: 8")

# --- Show evidence summary ---
summary = evidence.get_summary(session_id=producer.session_id)
print(f"\n=== Evidence Summary ===")
print(f"  Records: {summary['total_evaluations']}")
print(f"  Decisions: {summary['decisions']}")
print(f"  Hash chain: {summary.get('chain_status') or ('intact' if summary['chain_valid'] else 'BROKEN')}")
print(f"  Tools: {summary['tools_evaluated']}")

# --- Show what ancilis status would display ---
print(f"\n=== What `ancilis status` shows ===")
from ancilis.cli.status import _format_status
print(_format_status(config, evidence, verbose=False))

# --- Show what ancilis report would display ---
print(f"\n=== What `ancilis report` shows (terminal) ===")
from ancilis.report.generator import ReportGenerator
from ancilis.report.renderer import render_terminal
generator = ReportGenerator(config, evidence)
report_data = generator.generate(period="30d", report_format="terminal")
print(render_terminal(report_data))

evidence.close()
print("\nDone. One config line. AIUC-1 readiness assessment from real tool call evidence.")
