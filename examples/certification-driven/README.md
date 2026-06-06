# Certification-Driven Example

One config line gets you AIUC-1 certification readiness assessment.

## What this demonstrates

[AIUC-1](https://aiuc.ai/) is the first certifiable standard for AI agents. Enterprise buyers are starting to ask for it. This example shows how Ancilis gets you there with minimal config.

The flow:

1. A minimal `ancilis.yaml` declares `certification_targets: [aiuc-1]` and approved tools
2. AIUC-1's 6 required controls activate automatically
3. Your agent's tool calls are evaluated against those controls
4. `ancilis report` shows certification readiness with specific evidence

You don't need to know what the controls are. You don't need to map frameworks. You just declare the target.

## Prerequisites

```bash
pip install ancilis
```

## Run

```bash
cd examples/certification-driven
python run.py
```

## Config

```yaml
agent:
  name: demo-agent
certification_targets:
  - aiuc-1
security:
  tools:
    allowed:
      - get_customer
      - update_preferences
      - send_notification
```

That's it. The `certification_targets` line activates the controls AIUC-1 requires.

## Expected output

```
=== Certification-Driven Example ===
Agent: demo-agent
Mode: audit
Certification targets: ['aiuc-1']
Active controls: 26

Running tool calls...
  get_customer('C-001') -> {'id': 'C-001', 'name': 'Jane Doe', 'status': 'active'}
  update_preferences('C-001', ...) -> Updated preferences for C-001
  send_notification('C-001', ...) -> Notification sent to C-001: Your order shipped

  Total tool calls: 8

=== Evidence Summary ===
  Records: 8
  Decisions: {'ALLOW': 8}
  Hash chain: intact
  Tools: ['get_customer', 'send_notification', 'update_preferences']

=== What `ancilis status` shows ===
Ancilis — demo-agent
  Mode: audit
  Controls: 39 active, 11 runtime-verified, 27 pending, 1 flagged
  AIUC-1: active
  Tool calls: 8 evaluated, 0 blocked
  Sync: 8 pending, 0 failed

=== What `ancilis report` shows (terminal) ===
Ancilis Posture Report — demo-agent
...
AIUC-1 AI Agent Certification Standard Readiness
  Readiness: 85% (17 of 20 requirements passing)
  Coverage: 85% (17 automated, 3 operator)
  Evidence records: 8, hash chain intact

Evidence: 8 records, hash chain ✓ intact

Done. One config line. AIUC-1 readiness assessment from real tool call evidence.
```

## What happened

- 39 common AKSI v0.6 controls activated (these are always on)
- AIUC-1 maps 6 of those controls to 20 certification requirements
- 17 requirements are automated — Ancilis evaluates them from tool call evidence
- 3 requirements need operator action (governance documentation your team writes)
- 85% readiness from tool call evidence alone
- Every evaluation is hash-chained in a local DuckDB evidence store

## What the 3 operator requirements are

These can't be automated — they require human governance:

- **A006**: Data processing agreements and privacy policies
- **E010**: Annual transparency report
- **F001**: Policy prohibiting CBRN/cyberweapon use

Ancilis generates the evidence these documents cite. Your compliance team writes the docs.
