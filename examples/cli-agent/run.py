"""CLI Agent Example — evaluate shell commands before execution.

This example demonstrates the CLIActionProducer:
1. Wrapping subprocess/shell commands with Ancilis evaluation
2. Allowed commands execute normally with evidence recorded
3. Blocked commands are intercepted before execution
4. Pattern detection on command output

Run from this directory:
    python run.py
"""

from pathlib import Path

from ancilis import CLIActionProducer, load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore

config = load_config(path=Path(__file__).parent / "ancilis.yaml")
engine = Engine(config)
evidence = EvidenceStore(config, in_memory=True)
producer = CLIActionProducer(config=config, engine=engine, evidence_store=evidence)

# Register tools from config allowlist
producer.register_tools(engine.registry)

print("=== CLI Agent Example ===")
print(f"Agent: {config.agent_name}")
print(f"Mode: {config.mode}")
print(f"Allowed: {config.tools_allowed}")
print(f"Blocked: {config.tools_blocked}")
print()

# 1. Allowed command
print("1. Running 'echo hello world' (allowed)...")
result = producer.execute(["echo", "hello", "world"], agent_name="ops-agent")
print(f"   stdout: {result.stdout.strip()}")
print(f"   Decision: {result.evaluation.decision}")
print(f"   Blocked: {result.blocked}")

# 2. Another allowed command
print("\n2. Running 'date' (allowed)...")
result = producer.execute(["date"], agent_name="ops-agent")
print(f"   stdout: {result.stdout.strip()}")
print(f"   Decision: {result.evaluation.decision}")

# 3. Allowed command with output
print("\n3. Running 'ls -la' (allowed)...")
result = producer.execute(["ls", "-la", str(Path(__file__).parent)], agent_name="ops-agent")
print(f"   stdout (first 3 lines):")
for line in (result.stdout or "").strip().split("\n")[:3]:
    print(f"     {line}")
print(f"   Decision: {result.evaluation.decision}")

# 4. Blocked command
print("\n4. Running 'rm -rf /tmp/test' (blocked)...")
result = producer.execute(["rm", "-rf", "/tmp/ancilis-test-nonexistent"], agent_name="ops-agent")
print(f"   Blocked: {result.blocked}")
print(f"   Decision: {result.evaluation.decision}")
print(f"   stdout: {result.stdout}")  # None because it didn't execute

# 5. Another blocked command
print("\n5. Running 'curl https://example.com' (blocked)...")
result = producer.execute(["curl", "https://example.com"], agent_name="ops-agent")
print(f"   Blocked: {result.blocked}")
print(f"   Decision: {result.evaluation.decision}")

# --- Evidence summary ---
summary = evidence.get_summary()
print(f"\n=== Evidence Summary ===")
print(f"  Records: {summary['total_evaluations']}")
print(f"  Decisions: {summary['decisions']}")
print(f"  Tools: {summary['tools_evaluated']}")
print(f"  Hash chain: {'intact' if summary['chain_valid'] else 'BROKEN'}")

evidence.close()
print("\nDone. Shell commands evaluated against policy. Blocked before execution.")
