# Compliance Results — CrewAI Research Crew

Sample output from `make run && make scan`.

## Config validation

```
✓ Config valid
  Agent: crewai-research-crew
  Mode: audit
  Activation:
    certification_targets: [aiuc-1] → AIUC-1 active with the v1 common control set
    CCPA/CPRA overlay active (triggered by DC-PII via personal_info)
    GDPR overlay active (triggered by DC-PII via personal_info)
    SOC 2 Type II overlay active (triggered by DC-PII via personal_info)
  Controls: v1 common control set active
```

## Execution output (`make run`)

```
Crew: crewai-research-crew
Mode: audit
SOC 2 overlay: True
AIUC-1 active: True

=== CrewAI Research Crew Execution ===

[Researcher] Gathering intelligence...
  search_web → 3 results
  search_web → 3 results
  search_web → 3 results

[Analyst] Processing findings...
  analyze_findings → risk=medium, 3 insights
  analyze_findings → risk=medium, 3 insights

[Reporter] Generating report...
  generate_report → 847 words, 3 sections

=== Evidence Summary ===
  Records:    6
  Decisions:  {'ALLOW': 6}
  Hash chain: intact
  Tools:      ['analyze_findings', 'generate_report', 'search_web']

Per-agent attribution: pass agent_name= to wrap_tool() for each crew member.
Run `ancilis scan` to see compliance posture.
```

## Scan output (`make scan`)

```
Ancilis scan — crewai-research-crew
  Mode:    audit
  Posture: non_compliant

  ✓ Behavioral baseline monitor — pass (6 evals)
  ✓ Drift monitoring — pass (6 evals)
  ✓ Compliance posture — pass (6 evals)
  ✓ Evidence integrity — pass (6 evals)
  ✓ Governance policy — pass (6 evals)
  ✓ Agent ownership — pass (6 evals)
  ✓ Risk tolerance — pass (6 evals)
  ✓ Human oversight — pass (6 evals)
  ✓ Agent inventory — pass (6 evals)
  ✓ Tool registry — pass (6 evals)
  ✓ Data classification — pass (6 evals)
  ✓ Supply chain risk — pass (6 evals)
  ✓ Risk profiling — pass (6 evals)
  ✗ Identity verification — fail (6 evals, 6 failures)
  ✓ Scope enforcement — pass (6 evals)
  ✗ Tool provenance check — fail (6 evals, 6 failures)
  ✓ Data exposure scan — pass (6 evals)
  ✓ Comprehensive audit trail — pass (6 evals)
  ✓ Configuration integrity — pass (6 evals)
  ✓ Transport security — pass (6 evals)
  ✓ Input validation — pass (6 evals)
  ✓ Rollback & recovery — pass (6 evals)
  ✓ Post-incident review — pass (6 evals)
  ✓ Incident response — pass (6 evals)
  ✓ Human escalation — pass (6 evals)
  ✓ Evidence preservation — pass (6 evals)

  DEPENDENCIES (DE-01):
    ✓ No known vulnerabilities in 0 dependencies
```

**Score:** legacy demo excerpt shows 24 of 26 rows passing; rerun `make scan` for the current v1 control set.

## Notes on failures

- **PR-01 Identity verification** — simulated tools have no signer identity. In production, configure `security.tools.require_signed_tools`.
- **PR-03 Tool provenance check** — simulated tools have no provenance metadata. Expected for demo scenarios.

Both failures are informational in `audit` mode — tool calls are still allowed and recorded.

## Per-agent evidence attribution

Each crew member's tool calls are stored under a distinct `agent_name`:

| Agent      | Tool              | Records |
|------------|-------------------|---------|
| researcher | search_web        | 3       |
| analyst    | analyze_findings  | 2       |
| reporter   | generate_report   | 1       |

This demonstrates Ancilis's ability to attribute compliance evidence to individual agents in a multi-agent crew.
