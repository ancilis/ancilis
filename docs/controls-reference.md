# AKSI Controls Reference

Ancilis evaluates agent actions against the AI & Agent Key Security Indicators (AKSI) framework — 26 controls organized by [NIST CSF 2.0](https://www.nist.gov/cyberframework) functions. Every control activates by default as part of the baseline. Overlays and certification targets can adjust thresholds (standard → strict) but never disable baseline controls.

Nine controls have runtime evaluators in the current SDK (PR-01 through PR-08, DE-01). The remaining 17 are defined, mapped to regulations, and included in posture reports — their runtime evaluators are on the roadmap.

## How controls work

1. Your agent makes a tool call (via any [producer](producers.md))
2. The engine evaluates the action against every enabled control
3. Each control returns **PASS**, **FAIL**, **SKIP**, **FLAG**, or **ERROR**
4. The engine decides: **ALLOW** (audit mode, or all controls pass) or **BLOCK** (enforce mode + any failure)
5. The result is stored as a hash-chained [evidence record](evidence-and-reporting.md)

```
Action → Engine → [PR-01, PR-02, ..., DE-01] → Decision → Evidence
```

## Control families

| Family | Function | Controls | Focus |
|--------|----------|----------|-------|
| **PR** | PROTECT | PR-01 – PR-08 | Runtime enforcement — identity, scope, provenance, data, audit, config, encryption, input |
| **ID** | IDENTIFY | ID-01 – ID-05 | Asset management — agent inventory, tool registry, data classification, supply chain, risk |
| **DE** | DETECT | DE-01 – DE-04 | Monitoring — anomaly detection, drift, compliance posture, evidence integrity |
| **GOV** | GOVERN | GOV-01 – GOV-04 | Policy — governance, ownership, risk tolerance, human oversight |
| **RS** | RESPOND | RS-01 – RS-03 | Incident response — automated response, escalation, evidence preservation |
| **RC** | RECOVER | RC-01 – RC-02 | Recovery — rollback, post-incident review |

---

## PROTECT (PR) — 8 controls

### PR-01: Agent Identity & Authentication

**Runtime evaluator: Yes**

Verifies the agent presents valid credentials for every action. No anonymous tool calls.

**What it checks:**
- Agent ID is present and non-empty
- Agent ID matches the `agent.name` in `ancilis.yaml`
- Agent owner matches `agent.owner` (if configured)

**Pass:** Authentication verified — agent identity matches configuration.
**Fail:** Agent identity missing, empty, or mismatched.

**Config example:**
```yaml
agent:
  name: my-agent
  owner: platform-team
```

**Regulatory mappings:** NIST CSF PR.AA-01–03 · ISO 27001 A.8.5 · SOC 2 CC6.1, CC6.2 · CMMC IA.L2 · FedRAMP KSI-IAM · DORA Art.9 · NIS2 Art.21 · PCI-DSS Req 8 · OWASP MCP07

---

### PR-02: Permission Scope Enforcement

**Runtime evaluator: Yes**

Enforces machine-readable permission boundaries per agent. Every action is evaluated against declared scope.

**What it checks (in order):**
1. Tool is not in `security.tools.blocked` (blocklist takes precedence)
2. Tool is in `security.tools.allowed` (if allowlist is defined)
3. Destination is not in `security.scope.blocked_destinations`
4. Rate limit not exceeded (`security.scope.max_actions_per_minute`)

**Pass:** Action within declared scope.
**Fail:** Tool blocked, not in allowlist, destination blocked, or rate limit exceeded.

**Config example:**
```yaml
security:
  mode: enforce
  tools:
    allowed:
      - search_docs
      - send_reply
    blocked:
      - delete_database
  scope:
    max_actions_per_minute: 60
    blocked_destinations:
      - "*.internal.corp"
```

**Regulatory mappings:** NIST CSF PR.AA-05 · ISO 27001 A.8.3 · SOC 2 CC6.3 · CMMC AC.L2 · EU AI Act Art.9(4) · GDPR Art.25 · DORA Art.9 · PCI-DSS Req 7 · OWASP MCP02

---

### PR-03: Tool Provenance Verification

**Runtime evaluator: Yes**

Verifies tool registration, approval, version, and description integrity before every invocation. Detects semantic supply chain attacks where a tool's description is modified after approval.

**What it checks:**
- Tool is registered in the ToolRegistry
- Tool status is APPROVED (not OBSERVED or BLOCKED)
- Tool version matches baseline (if versions are tracked)
- Description hash matches the audited baseline

**Pass:** Provenance verified — tool is approved and unchanged.
**Fail:** Unregistered tool, unapproved tool, hash mismatch, or version mismatch.
**Flag:** Approved tool without baseline hash yet (first observation).

**How tools get approved:**
1. Listed in `security.tools.allowed` → auto-approved at config load
2. CLI: `ancilis approve-tool <tool-name>` → adds to config and approves
3. Programmatic: `registry.approve("tool-name", approved_by="operator")`

**Config example:**
```yaml
security:
  tools:
    allowed:
      - get-status        # Auto-approved at startup
      - get-transactions
```

**Regulatory mappings:** NIST CSF ID.SC-04, PR.DS-06 · ISO 27001 A.5.23 · SOC 2 CC8.1 · CMMC SI.L2 · FedRAMP KSI-3IR, KSI-SVC · DORA Art.28 · NIS2 Art.21 · PCI-DSS Req 6.3 · OWASP MCP04, Agentic AA05

---

### PR-04: Data Exposure Prevention

**Runtime evaluator: Yes**

Scans outbound tool call parameters for sensitive data patterns and blocks transmission to unauthorized destinations.

**What it checks:**
- Scans `action.parameters` for sensitive data patterns:
  - SSN (`\d{3}-\d{2}-\d{4}`)
  - Email addresses
  - US phone numbers
  - Credit card numbers (with Luhn validation)
  - API keys/tokens (`sk-*`, `pk-*`, `api-*`, etc.)
  - Medical Record Numbers (`MRN-*`)
- Checks destination against scope rules

**Pass:** No sensitive data detected, or destination is authorized.
**Fail:** Sensitive data detected going to an unauthorized destination.

**Config example:**
```yaml
my_agent_handles:
  - personal_info      # Activates GDPR overlay → strict PR-04 threshold
  - credit_cards       # Activates PCI-DSS → strict PR-04 threshold
security:
  scope:
    allowed_destinations:
      - "api.internal.com"
    blocked_destinations:
      - "*.external.io"
```

**Regulatory mappings:** NIST CSF PR.DS-01, PR.DS-02 · ISO 27001 A.8.10–12 · SOC 2 CC6.7 · CMMC MP.L2 · EU AI Act Art.10 · GDPR Art.32 · DORA Art.9 · PCI-DSS Req 3, 4 · OWASP MCP03

---

### PR-05: Comprehensive Audit Trail

**Runtime evaluator: Yes**

Every agent action generates a tamper-evident audit log entry with full context for incident investigation and compliance demonstration.

**What it checks:**
- Evidence retention is configured (> 0 days)
- Structured logging is enabled
- Required action fields are present (`action_id`, `timestamp`, `agent_id`, `action_type`)
- Log format is structured JSON

**Pass:** Complete audit entry generated with all required fields.
**Fail:** Missing or incomplete log entry.

**Config example:**
```yaml
compliance:
  evidence:
    storage: local
    retention_days: 365   # HIPAA overlay increases to 2190 (6 years)
```

**Regulatory mappings:** NIST CSF DE.AE-02, DE.AE-03 · ISO 42001 MEA 2.1 · ISO 27001 A.8.15 · SOC 2 CC7.1, CC7.2 · CMMC AU.L2 · EU AI Act Art.12 · FedRAMP KSI-MLA · GDPR Art.30 · DORA Art.10 · NIS2 Art.23 · PCI-DSS Req 10

---

### PR-06: Configuration Integrity Baseline

**Runtime evaluator: Roadmap**

Establishes and monitors configuration baselines for agents, tools, and MCP servers. Detects unauthorized configuration changes.

**Security outcome:** Monitoring covers all configuration files. Baselines current. Hash comparison continuous. Unauthorized changes trigger alerts within defined window.

**Evidence fields:** `baseline_records`, `drift_scan_results`, `unauthorized_change_logs`, `remediation_records`

**Regulatory mappings:** NIST CSF PR.PS-01, PR.PS-02 · ISO 27001 A.8.9 · SOC 2 CC8.1 · CMMC CM.L2 · FedRAMP KSI-CMT, KSI-SVC · DORA Art.9 · NIS2 Art.21 · PCI-DSS Req 2, 11.5 · OWASP MCP06

---

### PR-07: Encryption & Transport Security

**Runtime evaluator: Roadmap**

Ensures all data transmitted by agents uses strong encryption and secure transport protocols.

**Security outcome:** TLS 1.2+ verified on all connections. At-rest encryption active for sensitive data. Certificates valid. FIPS 140-2/3 compliant where required.

**Evidence fields:** `tls_configuration_records`, `certificate_chain_validation`, `at_rest_encryption_configuration`, `fips_certification`

**Regulatory mappings:** NIST CSF PR.DS-01, PR.DS-02 · ISO 27001 A.8.24 · SOC 2 CC6.7 · CMMC SC.L2 · FedRAMP KSI-SVC · GDPR Art.32 · DORA Art.9 · NIS2 Art.21 · PCI-DSS Req 4

---

### PR-08: Input Validation & Injection Prevention

**Runtime evaluator: Roadmap**

Validates and sanitizes inputs to agents and tools to prevent injection attacks — including prompt injection (direct and indirect), command injection, and parameter manipulation.

**Security outcome:** Validation active on all direct input (user/orchestrator prompts) and indirect input (tool responses, memory, retrieved context). Tool responses treated as untrusted regardless of tool approval status.

**Evidence fields:** `validation_configuration`, `blocked_injection_logs`, `tool_response_validation_records`

**Regulatory mappings:** NIST CSF PR.DS-10 · ISO 27001 A.8.28 · SOC 2 CC7.1 · EU AI Act Art.15 · FedRAMP KSI-VDR · DORA Art.9 · PCI-DSS Req 6.2 · OWASP MCP01, MCP05, MCP09, Agentic AA01

---

## IDENTIFY (ID) — 5 controls

### ID-01: Agent Inventory & Registry

**Runtime evaluator: Roadmap**

Maintains comprehensive inventory of all deployed AI agents, their capabilities, data access permissions, and operational status. Detects shadow deployments.

**Security outcome:** Registry complete — no unregistered agents in production. All required fields populated and updated within defined cycle.

**Evidence fields:** `agent_registry_export`, `discovery_scan_delta_reports`, `last_updated_timestamps`

**Regulatory mappings:** NIST CSF ID.AM-01, ID.AM-02 · ISO 42001 MAP 1.1 · ISO 27001 A.5.9 · SOC 2 CC6.1 · CMMC CM.L2 · EU AI Act Art.49 · FedRAMP KSI-PIY · DORA Art.8 · NIS2 Art.21 · PCI-DSS Req 2.4 · OWASP Agentic AA09

---

### ID-02: Tool & MCP Server Registry

**Runtime evaluator: Roadmap**

Maintains registry of all tools and MCP servers available to agents, including capabilities, trust levels, and approval status. Enforces no unregistered tool invocation at runtime.

**Security outcome:** Registry complete. No agent invokes unregistered tool. All entries have current approval status and description content hash.

**Evidence fields:** `tool_registry_export`, `blocked_unregistered_call_logs`, `approval_workflow_records`, `description_hash_records`

**Regulatory mappings:** NIST CSF ID.AM-07, ID.AM-08 · ISO 27001 A.5.23 · SOC 2 CC6.6 · CMMC SC.L2 · FedRAMP KSI-3IR · DORA Art.28 · NIS2 Art.21 · PCI-DSS Req 6.3 · OWASP MCP04

---

### ID-03: Data Classification & Validation

**Runtime evaluator: Roadmap**

Classifies and validates data handled by agents using standardized DC codes. Maps declared data types to regulatory requirements, enabling automatic overlay activation.

**Security outcome:** All data sources tagged. Runtime validation active — pattern detection (regex, Luhn, co-occurrence) compares observed data against declared classifications. Discrepancy alerts triggered.

**Evidence fields:** `data_classification_registry_export`, `overlay_activation_logs`, `unclassified_source_reports`, `validation_scan_results`, `discrepancy_alert_logs`

**Regulatory mappings:** NIST CSF ID.AM-05 · ISO 42001 MAP 1.5 · ISO 27001 A.5.12, A.5.13 · SOC 2 CC6.1 · CMMC MP.L2 · GDPR Art.30 · DORA Art.8 · PCI-DSS Req 3

---

### ID-04: Supply Chain Risk Assessment

**Runtime evaluator: Roadmap**

Assesses and tracks supply chain risk for tools, MCP servers, and third-party dependencies. Evaluates trust relationships, monitors dependency health, identifies compromise indicators.

**Security outcome:** Risk assessment completed for all registered tools. SBOMs available. No unresolved critical vulnerabilities in approved tools.

**Evidence fields:** `tool_risk_assessment_records`, `sbom_files`, `vulnerability_scan_results`, `risk_acceptance_records`

**Regulatory mappings:** NIST CSF ID.SC-01–05 · ISO 42001 MAP 5.1 · ISO 27001 A.5.19–23 · SOC 2 CC9.2 · CMMC SR.L2 · FedRAMP KSI-3IR · DORA Art.28–30 · NIS2 Art.21 · PCI-DSS Req 6.3, 12.8 · OWASP MCP04, Agentic AA05

---

### ID-05: Agent Risk Profiling

**Runtime evaluator: Roadmap**

Builds and maintains risk profiles for deployed agents based on data access, tool capabilities, operational scope, and behavioral patterns.

**Security outcome:** All agents profiled (Low/Moderate/High/Critical). Ratings current and aligned with risk tolerance. High-risk agents have enhanced controls.

**Evidence fields:** `risk_profile_records`, `rating_methodology_documentation`, `profile_review_timestamps`

**Regulatory mappings:** NIST CSF ID.RA-01–06 · ISO 42001 MAP 1.1 · SOC 2 CC3.2 · CMMC RA.L2 · EU AI Act Art.9 · GDPR Art.35 · DORA Art.6 · NIS2 Art.21 · PCI-DSS Req 12.3.1

---

## DETECT (DE) — 4 controls

### DE-01: Behavioral Anomaly Detection

**Runtime evaluator: Yes**

Detects anomalous agent behavior by comparing real-time activity against per-agent behavioral baselines.

**What it checks:**
- Whether a tool is new (not seen in the baseline window)
- Whether call frequency has spiked (current rate > 3x baseline average)

**Pass:** Behavior within established baseline.
**Flag:** New tool or frequency spike detected (DE-01 flags but never blocks).

**How baselines work:**
The `BaselineWindow` maintains a rolling window of tool call history per agent. After sufficient operational history (>7 days recommended), deviations from normal patterns generate FLAG results. Flags are recorded in evidence and surfaced in status/reports but do not cause BLOCK decisions.

**Config:** DE-01 is always enabled by default. No configuration needed.

**Regulatory mappings:** NIST CSF DE.AE-02–05 · ISO 42001 MEA 2.2 · ISO 27001 A.8.16 · SOC 2 CC7.2 · EU AI Act Art.9(2) · FedRAMP KSI-MLA · DORA Art.10 · NIS2 Art.21 · PCI-DSS Req 10.6, 11.4 · OWASP Agentic AA07

---

### DE-02: Configuration Drift Monitoring

**Runtime evaluator: Roadmap**

Continuously monitors agent, tool, and MCP server configurations for drift from established baselines. Tool description hashes are checked against audited baselines per invocation or per session.

**Security outcome:** Monitoring covers all registered tools. Hash comparison continuous or per-session. Drift triggers alerts and re-approval workflows.

**Evidence fields:** `hash_comparison_logs`, `drift_detection_alerts`, `re_approval_workflow_records`

**Regulatory mappings:** NIST CSF DE.CM-01, DE.CM-09 · ISO 27001 A.8.9 · SOC 2 CC7.1 · FedRAMP KSI-CMT · DORA Art.9 · NIS2 Art.21 · PCI-DSS Req 11.5 · OWASP MCP06, Agentic AA05

---

### DE-03: Compliance Posture Assessment

**Runtime evaluator: Roadmap**

Continuously assesses agent compliance posture against active regulatory overlays. Generates posture scores, identifies gaps, and tracks remediation.

**Security outcome:** Posture dashboard current. Deviation records include AKSI ID, agent, timestamp, failure reason, and overlay impact. Trends analyzed per defined interval.

**Evidence fields:** `compliance_posture_reports`, `deviation_records`, `trend_analysis`, `remediation_tracking`

**Regulatory mappings:** NIST CSF DE.AE-06, DE.AE-07 · ISO 42001 MEA 2.1 · SOC 2 CC4.1, CC4.2 · CMMC CA.L2 · FedRAMP KSI-AFR · DORA Art.11 · PCI-DSS Req 11

---

### DE-04: Evidence Integrity Verification

**Runtime evaluator: Roadmap**

Verifies integrity of the evidence chain — the cryptographically linked sequence of evaluation records proving continuous security control operation.

**Security outcome:** Integrity mechanism active on all evidence records. 100% chain verification on schedule. No unresolved integrity alerts.

Note: The SDK already implements hash chain verification via `evidence_store.verify_chain()` and the `ancilis status --verbose` command. DE-04 extends this to scheduled, automated verification.

**Evidence fields:** `verification_scan_results`, `chain_integrity_reports`, `alert_logs`

**Regulatory mappings:** NIST CSF DE.CM-09 · ISO 27001 A.8.15 · SOC 2 CC7.3 · CMMC AU.L2 · FedRAMP KSI-MLA · DORA Art.10 · PCI-DSS Req 10.5

---

## GOVERN (GOV) — 4 controls

### GOV-01: Agent Governance Policy

**Runtime evaluator: Roadmap**

Machine-readable governance policy defining agent behavioral boundaries, acceptable use, and operational constraints. The `ancilis.yaml` config file serves as the foundation for this policy.

**Security outcome:** Policy exists in machine-readable format, is current, and covers all deployed agents.

**Evidence fields:** `governance_policy_export`, `policy_version_history`, `review_records`

**Regulatory mappings:** NIST CSF GV.PO-01, GV.PO-02 · ISO 42001 GOV 1.1 · ISO 27001 A.5.1 · SOC 2 CC1.1 · CMMC CA.L2 · EU AI Act Art.9 · FedRAMP KSI-PIY · DORA Art.5 · NIS2 Art.21 · PCI-DSS Req 12.1

---

### GOV-02: Agent Ownership & Accountability

**Runtime evaluator: Roadmap**

Every deployed agent has a designated human owner accountable for behavior, compliance posture, and incident response. Ownership resolves to a real, contactable individual — not a team alias or role.

**Security outcome:** Every active agent has current, verified human owner. No orphaned agents.

**Config example:**
```yaml
agent:
  name: my-agent
  owner: jane.doe@company.com   # Real individual, not a team alias
```

**Evidence fields:** `agent_owner_mapping`, `ownership_confirmation_timestamps`

**Regulatory mappings:** NIST CSF GV.RR-01, GV.RR-02 · ISO 42001 GOV 1.3 · ISO 27001 A.5.2 · SOC 2 CC1.2, CC1.3 · CMMC CA.L2 · EU AI Act Art.26 · GDPR Art.22 · DORA Art.5(2) · NIS2 Art.20 · PCI-DSS Req 12.4

---

### GOV-03: Risk Tolerance Definition

**Runtime evaluator: Roadmap**

Defines and enforces organizational risk tolerance for agent operations. Establishes thresholds for acceptable risk levels, evaluated at runtime.

**Security outcome:** Risk tolerance parameters exist in machine-readable format for all agents. Thresholds current and aligned with organizational risk appetite.

**Evidence fields:** `risk_tolerance_configuration`, `threshold_evaluation_logs`, `risk_acceptance_records`

**Regulatory mappings:** NIST CSF GV.RM-01, GV.RM-02 · ISO 42001 GOV 1.1 · ISO 27001 A.5.3 · SOC 2 CC3.1 · EU AI Act Art.9 · FedRAMP KSI-AFR · DORA Art.6 · NIS2 Art.21 · PCI-DSS Req 12.3

---

### GOV-04: Human Oversight Configuration

**Runtime evaluator: Roadmap**

Configures and validates human oversight mechanisms for agent operations. Defines when human review is required and how escalation works. Required by EU AI Act Art. 14 for high-risk AI systems.

**Security outcome:** HITL policy defines action categories requiring approval. Routing functional and tested. All human decisions logged.

**Evidence fields:** `hitl_policy_configuration`, `approval_workflow_logs`, `response_time_metrics`

**Regulatory mappings:** NIST CSF GV.OV-01, GV.OV-02 · ISO 42001 GOV 1.3 · SOC 2 CC1.4 · EU AI Act Art.14 · GDPR Art.22 · OWASP Agentic AA06

---

## RESPOND (RS) — 3 controls

### RS-01: Automated Incident Response

**Runtime evaluator: Roadmap**

Pre-defined automated response per AKSI per severity level: block the action, flag for human review, log and continue, or quarantine the agent. The SDK's enforce mode is the foundation — BLOCK decisions are the first automated response mechanism.

**Security outcome:** Response configuration exists for all AKSIs at all severity levels. Responses tested. Execution latency meets threshold.

**Evidence fields:** `response_configuration_per_aksi`, `execution_logs`, `latency_measurements`, `test_records`

**Regulatory mappings:** NIST CSF RS.MA-01, RS.MA-02 · ISO 42001 MAN 4.1 · ISO 27001 A.5.24–28 · SOC 2 CC7.3, CC7.4 · CMMC IR.L2 · FedRAMP KSI-IRR · DORA Art.17 · NIS2 Art.23 · PCI-DSS Req 12.10 · OWASP Agentic AA04

---

### RS-02: Human Escalation Workflow

**Runtime evaluator: Roadmap**

Routes deviations above severity threshold to designated reviewers with full context: action, failed AKSIs, regulatory impact, recommended response.

**Security outcome:** Routing rules cover all escalation scenarios. SLAs defined and tracked.

**Evidence fields:** `escalation_configuration`, `event_logs_with_response_times`, `sla_performance_metrics`

**Regulatory mappings:** NIST CSF RS.CO-02, RS.CO-03 · ISO 42001 MAN 4.1 · SOC 2 CC7.4 · CMMC IR.L2 · EU AI Act Art.14 · FedRAMP KSI-IRR · GDPR Art.22 · DORA Art.17 · NIS2 Art.23 · PCI-DSS Req 12.10

---

### RS-03: Incident Evidence Preservation

**Runtime evaluator: Roadmap**

On any compliance incident trigger, automatically preserves all relevant evidence in tamper-evident format: full log chain, AKSI evaluations, agent state, tool call context, regulatory impact.

**Security outcome:** Preservation triggers on all incident types. Evidence tamper-evident. Accessible within retrieval SLA.

**Evidence fields:** `evidence_packages`, `trigger_configuration_records`, `retrieval_test_results`, `tamper_verification_records`

**Regulatory mappings:** NIST CSF RS.AN-03, RS.AN-06 · ISO 27001 A.5.28 · SOC 2 CC7.5 · CMMC IR.L2 · FedRAMP KSI-IRR · DORA Art.17 · NIS2 Art.23 · PCI-DSS Req 12.10

---

## RECOVER (RC) — 2 controls

### RC-01: Agent Rollback & Recovery

**Runtime evaluator: Roadmap**

Provides rollback and recovery capabilities for agent deployments. Maintains known-good configuration snapshots for all Moderate+ risk agents.

**Security outcome:** Rollback targets exist for all Moderate+ agents. Tested within defined cycle. Recovery meets RTO.

**Evidence fields:** `rollback_configuration_snapshots`, `rollback_test_results`, `recovery_time_measurements`

**Regulatory mappings:** NIST CSF RC.RP-01–04 · ISO 27001 A.8.13, A.8.14 · SOC 2 A1.2 · CMMC CP.L2 · FedRAMP KSI-IRR · DORA Art.12 · NIS2 Art.21 · PCI-DSS Req 12.10.2

---

### RC-02: Post-Incident Review & Improvement

**Runtime evaluator: Roadmap**

Structured post-incident reviews: root cause analysis, regulatory reporting assessment, policy/threshold updates, lessons learned. Findings tracked to resolution.

**Security outcome:** Review process exists and completed for all qualifying incidents. Action items tracked to closure.

**Evidence fields:** `review_records`, `root_cause_analysis`, `policy_update_records`, `action_item_tracking`

**Regulatory mappings:** NIST CSF RC.IM-01, RC.IM-02 · ISO 42001 MAN 4.2 · SOC 2 CC4.2 · CMMC CA.L2 · FedRAMP KSI-AFR · DORA Art.13 · NIS2 Art.21 · PCI-DSS Req 12.10.6

---

## Overlay threshold adjustments

When overlays activate (via `my_agent_handles` or `certification_targets`), certain controls are elevated to **strict** thresholds. Strict thresholds tighten evaluation criteria and require additional evidence.

| Overlay | Controls at strict threshold |
|---------|------------------------------|
| PCI-DSS v4.0 | PR-01, PR-02, PR-04, PR-05, PR-07, DE-01 |
| GDPR | PR-02, PR-04, PR-05, DE-01 |
| HIPAA | PR-01, PR-02, PR-04, PR-05 |
| EU AI Act | PR-01, PR-05, DE-01, GOV-04 |
| SOC 2 Type II | Standard thresholds (no strict overrides) |
| ISO 42001 | Standard thresholds (no strict overrides) |

When multiple overlays are active, the strictest threshold wins.

## Quick reference

| Control | Name | Runtime | Overlay strict |
|---------|------|---------|----------------|
| PR-01 | Agent Identity & Authentication | Yes | PCI, HIPAA, EU AI Act |
| PR-02 | Permission Scope Enforcement | Yes | PCI, GDPR, HIPAA |
| PR-03 | Tool Provenance Verification | Yes | — |
| PR-04 | Data Exposure Prevention | Yes | PCI, GDPR, HIPAA |
| PR-05 | Comprehensive Audit Trail | Yes | PCI, GDPR, HIPAA, EU AI Act |
| PR-06 | Configuration Integrity Baseline | Roadmap | — |
| PR-07 | Encryption & Transport Security | Roadmap | PCI |
| PR-08 | Input Validation & Injection Prevention | Roadmap | — |
| ID-01 | Agent Inventory & Registry | Roadmap | — |
| ID-02 | Tool & MCP Server Registry | Roadmap | — |
| ID-03 | Data Classification & Validation | Roadmap | — |
| ID-04 | Supply Chain Risk Assessment | Roadmap | — |
| ID-05 | Agent Risk Profiling | Roadmap | — |
| DE-01 | Behavioral Anomaly Detection | Yes | PCI, GDPR, EU AI Act |
| DE-02 | Configuration Drift Monitoring | Roadmap | — |
| DE-03 | Compliance Posture Assessment | Roadmap | — |
| DE-04 | Evidence Integrity Verification | Roadmap | — |
| GOV-01 | Agent Governance Policy | Roadmap | — |
| GOV-02 | Agent Ownership & Accountability | Roadmap | — |
| GOV-03 | Risk Tolerance Definition | Roadmap | — |
| GOV-04 | Human Oversight Configuration | Roadmap | EU AI Act |
| RS-01 | Automated Incident Response | Roadmap | — |
| RS-02 | Human Escalation Workflow | Roadmap | — |
| RS-03 | Incident Evidence Preservation | Roadmap | — |
| RC-01 | Agent Rollback & Recovery | Roadmap | — |
| RC-02 | Post-Incident Review & Improvement | Roadmap | — |
