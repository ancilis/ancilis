# Compliance Results — CrewAI Research Crew

Sample output from `make run && make scan`.

`make scan` exits nonzero while the demo posture is `non_compliant`; that is expected for this unauthenticated simulated crew in `audit` mode.

## Config validation

```
✓ Config valid
  Agent: crewai-research-crew
  Mode: audit
  Activation:
    certification_targets: [aiuc-1] → AIUC-1 active, 39 controls
    CCPA/CPRA overlay active (triggered by DC-PII via personal_info)
    GDPR overlay active (triggered by DC-PII via personal_info)
    SOC 2 Type II overlay active (triggered by DC-PII via personal_info)
  Controls: 39 active (GOV-04 at strict threshold, PR-02 at strict threshold, PR-04 at strict threshold, PR-05 at strict threshold)
```

## Execution output (`make run`)

```
Crew:   crewai-research-crew
Mode:   audit
SOC 2:  True
AIUC-1: True

=== CrewAI research crew execution ===

[Researcher] Gathering intelligence...
  3 search steps + task callback → 4 records

[Analyst] Processing findings...
  2 analysis steps + task callback → 3 records

[Reporter] Generating report...
  1 generate step + task callback → 2 records

[Crew] kickoff complete → 1 record

=== Evidence summary ===
  Records:    10
  Decisions:  {'ALLOW': 10}
  Hash chain: intact
  Tools:      ['crewai:crew:compliance-crew', 'crewai:step:analyze_findings', 'crewai:step:generate_report', 'crewai:step:search_web', 'crewai:task:analyze', 'crewai:task:report', 'crewai:task:research']

Per-agent attribution: pass `agent_name=` to step_callback() / task_callback() for each crew member.
Run `ancilis status` to see crew compliance posture.
```

## Scan output (`make scan`)

```
Ancilis scan — crewai-research-crew
  Mode:    audit
  Posture: non_compliant

  ✓ Behavioral Anomaly Detection — pass (10 evals)
  ✓ Classification Drift and Boundary Validation — pass (10 evals)
  ✓ Configuration/Dependency Drift Monitoring — pass (10 evals)
  ✓ Evidence Integrity Monitoring — pass (10 evals)
  ✓ AI Outcome Evaluation and Harm Monitoring — pass (10 evals)
  ✓ Assurance Testing and Vulnerability Evidence Ingestion — pass (10 evals)
  ✓ Agent Identity Declaration and Match — pass (10 evals)
  ✓ Ownership Accountability — pass (10 evals)
  ✓ Risk Tolerance and Policy Baseline — pass (10 evals)
  ✓ Human Oversight and Decision Accountability — pass (10 evals)
  ✓ Purpose, Legal Basis and Data-Use Authority — pass (10 evals)
  ✓ External Obligation Registry and Posture Reporting — pass (10 evals)
  ✓ Transparency, Instructions and Affected-Party Feedback — pass (10 evals)
  ✓ Agent Inventory and Registry — pass (10 evals)
  ✓ Tool, Model and Integration Registry — pass (10 evals)
  ✓ Data Flow Mapping and Classification — pass (10 evals)
  ✓ Supply Chain and Dependency Risk — pass (10 evals)
  ✓ Agent Risk Profiling and Purpose Scoping — pass (10 evals)
  ✗ Action Authorization — fail (10 evals, 10 failures)
  ✓ Permission Scope Enforcement — pass (10 evals)
  ✗ Tool/Model Integrity and Provenance — fail (10 evals, 10 failures)
  ✓ Data Exposure Prevention — pass (10 evals)
  ✓ Context and Tenant Isolation — pass (10 evals)
  ✓ Audit Trail Completeness — pass (10 evals, 10 flags)
  ✓ Secure Communication and Agent Messaging — pass (10 evals)
  ✓ Input Validation and Injection Resistance — pass (10 evals)
  ✓ Controlled Code Execution and Sandbox Enforcement — pass (10 evals)
  ✓ Memory and Context Integrity — pass (10 evals)
  ✓ Retention, Deletion and Memory Disposal — pass (10 evals)
  ✓ Secrets, Credential and Wallet Key Custody — pass (10 evals)
  ✓ Rollback and Recovery Planning — pass (10 evals)
  ✓ Post-Incident Review and Communications — pass (10 evals)
  ✓ Resilience Exercise and Recovery Test Evidence — pass (10 evals)
  ✓ Automated Compliance Response — pass (10 evals)
  ✗ Containment, Quarantine and Kill Switch — fail (10 evals, 10 failures)
  ✓ Human Escalation and Incident Reporting — pass (10 evals)
  ✓ Cascade Containment and Blast-Radius Control — pass (10 evals)
  ✓ Regulated Notification Clock and Authority Routing — pass (10 evals)
  ✓ Coordinated Vulnerability Disclosure and Security Update Handling — pass (10 evals)

Next steps:
  ancilis report              — generate a compliance report
  ancilis status --verbose    — control-by-control breakdown
  ancilis scan --ci           — JSON output for CI/CD pipelines

  DEPENDENCIES (DE-01):
    ✓ No known vulnerabilities in 0 dependencies
```

**Score:** 36 of 39 active common controls pass in this unauthenticated demo run; `PR-06` also records review flags for audit-trail completeness.

## Notes on findings

- **PR-01 Action Authorization** — the simulated callbacks attribute work to `researcher`, `analyst`, and `reporter`, while `ancilis.yaml` authorizes only `crewai-research-crew`. In production, align the configured identities with the CrewAI agent identities.
- **PR-03 Tool/Model Integrity and Provenance** — generated CrewAI callback tools are observed but not approved. Approve expected tools with `ancilis approve-tool`.
- **RS-02 Containment, Quarantine and Kill Switch** — containment is required because `PR-01` and `PR-03` failed, but this demo does not declare containment, quarantine, kill-switch, degrade, block, or credential-revocation intent.
- **PR-06 Audit Trail Completeness** — the demo writes tamper-evident evidence records (a SHA-256 hash chain), but the per-action evaluator flags that no evidence store was attached to verify pre-completion persistence during each simulated action.

These findings are informational in `audit` mode — tool calls are still allowed and recorded.

## Per-agent evidence attribution

Each crew member's tool calls are stored under a distinct `agent_name`:

| Agent      | Records |
|------------|---------|
| researcher | 4       |
| analyst    | 3       |
| reporter   | 2       |
| crew       | 1       |

This demonstrates Ancilis's ability to attribute compliance evidence to individual agents in a multi-agent crew.
