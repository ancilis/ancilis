# AKSI Controls Reference

Ancilis evaluates agent actions against AKSI Framework v0.6.

- 41 controls are defined in the shared catalog.
- 39 common controls are enabled for every governed agent.
- `PAY-01` and `PAY-02` are extension controls activated by `DC-PAY`, `AGENT_PAYMENTS`, or `X402`.
- `support_level: runtime_evaluator` means the Python SDK has direct deterministic evaluator code today; it is not a cross-language parity field.
- `support_level: attestation` means the control is evidence-backed and requires attached, imported, or attested evidence when it cannot be proven from a single action alone.
- The TypeScript SDK has direct evaluators for its core runtime controls and uses catalog-backed evaluators for the remaining AKSI controls; those catalog-backed controls return `FLAG` until explicit attestation is supplied.

## Control Table

| Control | Domain | Name | Default | Support | Evidence sources |
|---------|--------|------|---------|---------|------------------|
| DE-01 | DETECT | Behavioral Anomaly Detection | common | runtime_evaluator | sdk_direct, singulr, noma, otel, arize_phoenix, attestation |
| DE-02 | DETECT | Classification Drift & Boundary Validation | common | runtime_evaluator | sdk_direct, openai, anthropic, singulr, noma, otel, attestation |
| DE-03 | DETECT | Configuration/Dependency Drift Monitoring | common | runtime_evaluator | sdk_direct, aws_cloudtrail, aws_bedrock, github, mcp_registry, singulr, noma, otel, attestation |
| DE-04 | DETECT | Evidence Integrity Monitoring | common | runtime_evaluator | sdk_direct, otel, attestation, github |
| DE-05 | DETECT | AI Outcome Evaluation & Harm Monitoring | common | attestation | sdk_direct, openai, anthropic, otel, arize_phoenix, langfuse, langsmith, attestation, jira |
| DE-06 | DETECT | Assurance Testing & Vulnerability Evidence Ingestion | common | attestation | sdk_direct, sarif_import, cyclonedx_import, github, otel, arize_phoenix, langfuse, langsmith, attestation, jira |
| GOV-01 | GOVERN | Agent Identity & Authentication | common | runtime_evaluator | sdk_direct, aws_cloudtrail, github, attestation |
| GOV-02 | GOVERN | Ownership Accountability | common | runtime_evaluator | sdk_direct, github, jira, attestation |
| GOV-03 | GOVERN | Risk Tolerance & Policy Baseline | common | runtime_evaluator | sdk_direct, github, jira, attestation |
| GOV-04 | GOVERN | Human Oversight & Decision Accountability | common | attestation | sdk_direct, github, jira, attestation |
| GOV-05 | GOVERN | Purpose, Legal Basis & Data-Use Authority | common | attestation | sdk_direct, github, jira, attestation, singulr, noma |
| GOV-06 | GOVERN | External Obligation Registry & Posture Reporting | common | attestation | sdk_direct, github, jira, attestation, servicenow_now_assist |
| GOV-07 | GOVERN | Transparency, Instructions & Affected-Party Feedback | common | attestation | sdk_direct, github, jira, attestation, servicenow_now_assist, langfuse, langsmith |
| ID-01 | IDENTIFY | Agent Inventory & Registry | common | runtime_evaluator | sdk_direct, sarif_import, cyclonedx_import, aws_cloudtrail, aws_bedrock, azure_ai_foundry, openai, anthropic, openrouter, litellm, composio, github, mcp_registry, singulr, noma, servicenow_now_assist, salesforce_agentforce, google_a2a_protocol, vertex_ai_agent_builder, otel, arize_phoenix, attestation, jira, pinecone, langfuse, langsmith, databricks_mlflow, snowflake_cortex, databricks_agent_bricks_mlflow |
| ID-02 | IDENTIFY | Tool, Model & Integration Registry | common | attestation | sdk_direct, aws_cloudtrail, aws_bedrock, openai, anthropic, github, mcp_registry, singulr, noma, otel, attestation |
| ID-03 | IDENTIFY | Data Flow Mapping & Classification | common | attestation | sdk_direct, aws_bedrock, openai, anthropic, singulr, noma, otel, attestation |
| ID-04 | IDENTIFY | Supply Chain & Dependency Risk | common | attestation | sdk_direct, github, sarif_import, cyclonedx_import, mcp_registry, attestation |
| ID-05 | IDENTIFY | Agent Risk Profiling & Purpose Scoping | common | attestation | sdk_direct, github, jira, attestation, singulr, noma |
| PAY-01 | PAYMENT | Agent Payment Authorization & Sanctions Screening | extension | attestation | sdk_direct, aws_cloudtrail, openai, anthropic, otel, attestation, jira |
| PAY-02 | PAYMENT | Payment Settlement Reconciliation & Irreversibility Control | extension | attestation | sdk_direct, aws_cloudtrail, otel, attestation, jira |
| PR-01 | PROTECT | Action Authorization | common | runtime_evaluator | sdk_direct, aws_cloudtrail, github, jira, attestation, sarif_import |
| PR-02 | PROTECT | Permission Scope Enforcement | common | runtime_evaluator | sdk_direct, aws_cloudtrail, github, attestation |
| PR-03 | PROTECT | Tool/Model Integrity & Provenance | common | runtime_evaluator | sdk_direct, aws_cloudtrail, github, mcp_registry, attestation, sarif_import, cyclonedx_import |
| PR-04 | PROTECT | Data Exposure Prevention | common | runtime_evaluator | sdk_direct, aws_bedrock, openai, anthropic, github, singulr, noma, otel, attestation |
| PR-05 | PROTECT | Context & Tenant Isolation | common | runtime_evaluator | sdk_direct, aws_bedrock, openai, anthropic, otel, attestation, cyclonedx_import |
| PR-06 | PROTECT | Audit Trail Completeness | common | runtime_evaluator | sdk_direct, aws_cloudtrail, github, otel, jira, attestation |
| PR-07 | PROTECT | Secure Communication & Agent Messaging | common | runtime_evaluator | sdk_direct, aws_cloudtrail, google_a2a_protocol, otel, attestation |
| PR-08 | PROTECT | Input Validation & Injection Resistance | common | runtime_evaluator | sdk_direct, aws_bedrock, openai, anthropic, github, singulr, noma, otel, sarif_import |
| PR-09 | PROTECT | Controlled Code Execution & Sandbox Enforcement | common | runtime_evaluator | sdk_direct, aws_cloudtrail, github, otel, attestation, sarif_import |
| PR-10 | PROTECT | Memory & Context Integrity | common | attestation | sdk_direct, aws_bedrock, openai, anthropic, github, otel, pinecone, attestation |
| PR-11 | PROTECT | Retention, Deletion & Memory Disposal | common | attestation | sdk_direct, aws_cloudtrail, github, otel, pinecone, attestation, jira |
| PR-12 | PROTECT | Secrets, Credential & Wallet Key Custody | common | attestation | sdk_direct, aws_cloudtrail, github, composio, otel, attestation, jira, sarif_import |
| RC-01 | RECOVER | Rollback & Recovery Planning | common | attestation | sdk_direct, github, jira, attestation |
| RC-02 | RECOVER | Post-Incident Review & Communications | common | attestation | sdk_direct, github, jira, attestation |
| RC-03 | RECOVER | Resilience Exercise & Recovery Test Evidence | common | attestation | sdk_direct, github, jira, otel, attestation |
| RS-01 | RESPOND | Automated Compliance Response | common | attestation | sdk_direct, otel, jira, attestation |
| RS-02 | RESPOND | Containment, Quarantine & Kill Switch | common | runtime_evaluator | sdk_direct, aws_cloudtrail, otel, jira, attestation |
| RS-03 | RESPOND | Human Escalation & Incident Reporting | common | attestation | sdk_direct, otel, jira, attestation |
| RS-04 | RESPOND | Cascade Containment & Blast-Radius Control | common | attestation | sdk_direct, otel, jira, attestation |
| RS-05 | RESPOND | Regulated Notification Clock & Authority Routing | common | attestation | sdk_direct, otel, jira, attestation, servicenow_now_assist |
| RS-06 | RESPOND | Coordinated Vulnerability Disclosure & Security Update Handling | common | attestation | sdk_direct, github, sarif_import, cyclonedx_import, jira, attestation |

## Extension Activation

| Control | Activates when |
|---------|----------------|
| PAY-01 | DC-PAY, AGENT_PAYMENTS, X402 |
| PAY-02 | DC-PAY, AGENT_PAYMENTS, X402 |

## Detailed Definitions

### DE-01 - Behavioral Anomaly Detection

Agents are monitored against expected behavioral baselines so suspicious deviations are detected quickly.

- Function: `DETECT`
- Effort level: `long`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-DE-01`
- Evidence keywords: anomaly, behavioral, monitoring, baseline

### DE-02 - Classification Drift & Boundary Validation

Observed data handling is continuously checked against declared classifications and expected processing boundaries.

- Function: `DETECT`
- Effort level: `medium`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-DE-02`
- Evidence keywords: classification, data, validation, boundary

### DE-03 - Configuration/Dependency Drift Monitoring

Meaningful drift in configuration, dependencies, tools, models, or policy baselines is detected before it normalizes.

- Function: `DETECT`
- Effort level: `long`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-DE-03`
- Evidence keywords: drift, configuration, dependency, evidence

### DE-04 - Evidence Integrity Monitoring

Evidence chains, missing telemetry, and tamper signals are monitored so posture cannot rely on corrupted records.

- Function: `DETECT`
- Effort level: `medium`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-DE-04`
- Evidence keywords: integrity, hash, tamper, missing

### DE-05 - AI Outcome Evaluation & Harm Monitoring

Agent outputs and tool outcomes are evaluated for reliability, hallucination, harmful output, bias, clinical or safety drift, and out-of-scope behavior.

- Function: `DETECT`
- Effort level: `long`
- Support level: `attestation`
- Product ID: `AKSI-DE-05`
- Evidence keywords: evaluation, hallucination, harm, reliability

### DE-06 - Assurance Testing & Vulnerability Evidence Ingestion

Agent-specific vulnerability scans, adversarial tests, red-team exercises, resilience tests, clinical/safety validations, and third-party evaluations are ingested as control evidence with remediation state.

- Function: `DETECT`
- Effort level: `long`
- Support level: `attestation`
- Product ID: `AKSI-DE-06`
- Evidence keywords: vulnerability, scan, red_team, testing

### GOV-01 - Agent Identity & Authentication

Every governed AI action is attributable to a verifiable runtime identity and authentication flow.

- Function: `GOVERN`
- Effort level: `medium`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-GOV-01`
- Evidence keywords: identity, authentication, agent, iam

### GOV-02 - Ownership Accountability

Each AI system has a named accountable owner for operation, risk decisions, and remediation.

- Function: `GOVERN`
- Effort level: `quick`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-GOV-02`
- Evidence keywords: owner, accountability, responsibility, governance

### GOV-03 - Risk Tolerance & Policy Baseline

Risk tolerance, autonomy limits, and escalation thresholds are defined in policy before autonomous actions run.

- Function: `GOVERN`
- Effort level: `medium`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-GOV-03`
- Evidence keywords: risk, tolerance, threshold, policy

### GOV-04 - Human Oversight & Decision Accountability

Human review, approval context, and decision accountability are defined for sensitive actions and exceptions.

- Function: `GOVERN`
- Effort level: `medium`
- Support level: `attestation`
- Product ID: `AKSI-GOV-04`
- Evidence keywords: human, oversight, approval, escalation

### GOV-05 - Purpose, Legal Basis & Data-Use Authority

Agent actions and data uses are bound to declared purpose, contractual limits, legal basis, consent, role allocation, and prohibited-use policy.

- Function: `GOVERN`
- Effort level: `medium`
- Support level: `attestation`
- Product ID: `AKSI-GOV-05`
- Evidence keywords: purpose, legal_basis, consent, use_restriction

### GOV-06 - External Obligation Registry & Posture Reporting

Framework, contractual, customer, and regulator-facing obligations are registered and linked to agent posture, evidence, and owner reporting.

- Function: `GOVERN`
- Effort level: `medium`
- Support level: `attestation`
- Product ID: `AKSI-GOV-06`
- Evidence keywords: obligation, contract, posture, reporting

### GOV-07 - Transparency, Instructions & Affected-Party Feedback

Agent-facing instructions, user/deployer disclosures, privacy-rights routing, affected-party feedback, and intervention channels are documented and linked to runtime evidence.

- Function: `GOVERN`
- Effort level: `medium`
- Support level: `attestation`
- Product ID: `AKSI-GOV-07`
- Evidence keywords: transparency, instruction, feedback, intervention

### ID-01 - Agent Inventory & Registry

The organization maintains a complete, current registry of governed AI systems and their operating context.

- Function: `IDENTIFY`
- Effort level: `quick`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-ID-01`
- Evidence keywords: inventory, registry, system, identity

### ID-02 - Tool, Model & Integration Registry

Tools, MCP surfaces, models, prompt packs, and integrations are registered with provenance and approval metadata.

- Function: `IDENTIFY`
- Effort level: `medium`
- Support level: `attestation`
- Product ID: `AKSI-ID-02`
- Evidence keywords: tool, model, registry, integration

### ID-03 - Data Flow Mapping & Classification

Inputs, context stores, outputs, destinations, and observed data classes are mapped for every governed system.

- Function: `IDENTIFY`
- Effort level: `long`
- Support level: `attestation`
- Product ID: `AKSI-ID-03`
- Evidence keywords: data, flow, classification, destination

### ID-04 - Supply Chain & Dependency Risk

Models, tools, dependencies, prompts, and orchestration components are assessed for supply-chain risk.

- Function: `IDENTIFY`
- Effort level: `long`
- Support level: `attestation`
- Product ID: `AKSI-ID-04`
- Evidence keywords: supply, dependency, model, sbom

### ID-05 - Agent Risk Profiling & Purpose Scoping

Agent purpose, autonomy, data sensitivity, action authority, and impact tier are profiled before use.

- Function: `IDENTIFY`
- Effort level: `medium`
- Support level: `attestation`
- Product ID: `AKSI-ID-05`
- Evidence keywords: purpose, profile, autonomy, impact

### PAY-01 - Agent Payment Authorization & Sanctions Screening

Agent-initiated payments are authorized against spend policy, recipient trust, sanctions, and approval requirements.

- Function: `PAYMENT`
- Effort level: `long`
- Support level: `attestation`
- Product ID: `AKSI-PAY-01`
- Evidence keywords: payment, authorization, sanctions, spend

### PAY-02 - Payment Settlement Reconciliation & Irreversibility Control

Agent-payment settlement is reconciled with receipts, ledger state, irreversibility risk, and reversal/escalation policy.

- Function: `PAYMENT`
- Effort level: `long`
- Support level: `attestation`
- Product ID: `AKSI-PAY-02`
- Evidence keywords: settlement, reconciliation, receipt, irreversible

### PR-01 - Action Authorization

Sensitive actions are evaluated against policy and allowed only when identity, context, and target are authorized.

- Function: `PROTECT`
- Effort level: `medium`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-PR-01`
- Evidence keywords: authorization, allow, deny, policy

### PR-02 - Permission Scope Enforcement

Each agent operates inside explicit least-privilege scopes checked per session and per action.

- Function: `PROTECT`
- Effort level: `medium`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-PR-02`
- Evidence keywords: permission, scope, least_privilege, session

### PR-03 - Tool/Model Integrity & Provenance

Tool descriptors, model artifacts, execution surfaces, and integrations are verified against trusted baselines.

- Function: `PROTECT`
- Effort level: `medium`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-PR-03`
- Evidence keywords: integrity, provenance, baseline, integration

### PR-04 - Data Exposure Prevention

Sensitive, regulated, and export-controlled data is inspected and constrained before entering context, leaving the system, or triggering actions.

- Function: `PROTECT`
- Effort level: `long`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-PR-04`
- Evidence keywords: exposure, sensitive, output, context

### PR-05 - Context & Tenant Isolation

Execution context is isolated so one system, task, tenant, user, jurisdiction, or foreign-person boundary cannot silently leak into another.

- Function: `PROTECT`
- Effort level: `long`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-PR-05`
- Evidence keywords: isolation, tenant, context, boundary

### PR-06 - Audit Trail Completeness

Every governed action records the evaluation chain needed to reconstruct who acted, why, and under which controls.

- Function: `PROTECT`
- Effort level: `quick`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-PR-06`
- Evidence keywords: audit, trail, evidence, chain

### PR-07 - Secure Communication & Agent Messaging

Agent communication uses authenticated, integrity-protected, replay-resistant channels and signed task context.

- Function: `PROTECT`
- Effort level: `medium`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-PR-07`
- Evidence keywords: communication, messaging, integrity, replay

### PR-08 - Input Validation & Injection Resistance

Direct inputs, indirect content, tool payloads, and retrieved context are validated before execution.

- Function: `PROTECT`
- Effort level: `medium`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-PR-08`
- Evidence keywords: input, validation, injection, payload

### PR-09 - Controlled Code Execution & Sandbox Enforcement

Generated code, shell commands, and dynamic execution artifacts run only inside approved sandbox execution classes.

- Function: `PROTECT`
- Effort level: `long`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-PR-09`
- Evidence keywords: sandbox, code, command, execution

### PR-10 - Memory & Context Integrity

Persistent memory, retrieved context, and shared task state carry provenance, integrity checks, and quarantine controls.

- Function: `PROTECT`
- Effort level: `medium`
- Support level: `attestation`
- Product ID: `AKSI-PR-10`
- Evidence keywords: memory, context, provenance, quarantine

### PR-11 - Retention, Deletion & Memory Disposal

Agent-held data, memory, context, and evidence are retained, deleted, evicted, or disposed according to policy and legal obligations.

- Function: `PROTECT`
- Effort level: `medium`
- Support level: `attestation`
- Product ID: `AKSI-PR-11`
- Evidence keywords: retention, deletion, disposal, memory

### PR-12 - Secrets, Credential & Wallet Key Custody

Secrets, API keys, signing keys, wallet material, access information, and payment credentials used by agents are vaulted, scoped, rotated, and never exposed to prompts or untrusted tools.

- Function: `PROTECT`
- Effort level: `long`
- Support level: `attestation`
- Product ID: `AKSI-PR-12`
- Evidence keywords: secret, credential, wallet, key

### RC-01 - Rollback & Recovery Planning

Recovery plans, rollback paths, and restoration dependencies are documented and tested for governed systems.

- Function: `RECOVER`
- Effort level: `medium`
- Support level: `attestation`
- Product ID: `AKSI-RC-01`
- Evidence keywords: recovery, rollback, restore, plan

### RC-02 - Post-Incident Review & Communications

Post-incident review, corrective action, stakeholder notification, and lessons-learned workflows are repeatable.

- Function: `RECOVER`
- Effort level: `quick`
- Support level: `attestation`
- Product ID: `AKSI-RC-02`
- Evidence keywords: review, communication, lessons, stakeholder

### RC-03 - Resilience Exercise & Recovery Test Evidence

Recovery, rollback, failover, continuity, and agent-disablement procedures are periodically exercised and captured as evidence.

- Function: `RECOVER`
- Effort level: `medium`
- Support level: `attestation`
- Product ID: `AKSI-RC-03`
- Evidence keywords: exercise, recovery, continuity, failover

### RS-01 - Automated Compliance Response

Predefined policy responses are executed when evidence crosses control, classification, or overlay thresholds.

- Function: `RESPOND`
- Effort level: `medium`
- Support level: `attestation`
- Product ID: `AKSI-RS-01`
- Evidence keywords: incident, response, threshold, action

### RS-02 - Containment, Quarantine & Kill Switch

Agents, tools, memory, credentials, and actions can be blocked, quarantined, degraded, or halted on risk conditions.

- Function: `RESPOND`
- Effort level: `long`
- Support level: `runtime_evaluator`
- Product ID: `AKSI-RS-02`
- Evidence keywords: containment, quarantine, block, kill_switch

### RS-03 - Human Escalation & Incident Reporting

Significant failures, exceptions, and regulated incidents route to the right responders with reporting context.

- Function: `RESPOND`
- Effort level: `quick`
- Support level: `attestation`
- Product ID: `AKSI-RS-03`
- Evidence keywords: escalation, reporting, responder, notification

### RS-04 - Cascade Containment & Blast-Radius Control

Multi-agent workflows enforce failure-domain isolation, circuit breakers, and coordinated kill-switch behavior.

- Function: `RESPOND`
- Effort level: `long`
- Support level: `attestation`
- Product ID: `AKSI-RS-04`
- Evidence keywords: cascade, blast_radius, circuit_breaker, kill_switch

### RS-05 - Regulated Notification Clock & Authority Routing

Potentially regulated incidents start jurisdiction-specific notification clocks, preserve decision evidence, and route authority/customer notification tasks to accountable humans.

- Function: `RESPOND`
- Effort level: `medium`
- Support level: `attestation`
- Product ID: `AKSI-RS-05`
- Evidence keywords: notification, clock, authority, regulated

### RS-06 - Coordinated Vulnerability Disclosure & Security Update Handling

Vulnerability intake, coordinated disclosure, secure-update handling, support period tracking, and remediation advisories are routed and evidenced for governed agent products.

- Function: `RESPOND`
- Effort level: `medium`
- Support level: `attestation`
- Product ID: `AKSI-RS-06`
- Evidence keywords: vulnerability, disclosure, security_update, support_period
