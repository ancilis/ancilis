# DORA-RES Overlay Control Set Specification

## 1. Scope and Activation

DORA-RES activates when an organization is in scope for Regulation (EU) 2022/2554, Digital Operational Resilience Act (DORA), and an Ancilis agent is declared to support a critical or important function through the `FunctionClassification` primitive. `FunctionClassification` does not yet exist in code; this specification defines it abstractly so a later build stage can implement it.

The overlay is function-classification-driven, not data-classification-driven. Existing overlays commonly activate from data classifications such as payment, health, or financial data. DORA-RES activates from the role the agent plays in an in-scope financial entity's operations.

### Architectural Commitment and Sequencing

This specification is the architectural commitment for DORA-RES. It defines the control set, activation semantics, evidence records, and AKSI mappings that subsequent build stages must implement. Implementation of the `FunctionClassification` primitive, gateway producer, contract metadata ingestion, equivalence evidence ingestion, and organization onboarding attribute is staged into v0.2.

### Regulatory Source Basis

Primary sources directly consulted:

- [Regulation (EU) 2022/2554](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2554), Articles 2, 3, 5-16, 17-23, 24-27, 28-31, and 44.
- [Commission Delegated Regulation (EU) 2024/1773](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1773), Articles 1-10, specifying detailed ICT third-party risk management policy content.
- European Supervisory Authorities Joint Final Report `JC 2024 29`, dated 17 July 2024, on draft RTS specifying elements related to threat-led penetration testing (TLPT).

Sources consulted with limited direct access:

- The DORA incident classification and incident reporting RTS/ITS package, including Delegated Regulation (EU) 2024/1772 and Delegated Regulation (EU) 2025/301, could not be fully retrieved as article text from the terminal environment during initial drafting. Delegated Regulation (EU) 2025/301 is the currently understood RTS source for incident report content and timing, and DORA-RES incident evidence must record the applicable RTS version. This specification maps incident controls to DORA Articles 17-20 directly and treats exact report timing as RTS-dependent evidence metadata that must be validated against the final applicable RTS/ITS text.

Local AKSI source basis:

- The requested `/Users/hellohelloalbus/projects/ancilis/aksi_framework.md` file was not present in this checkout, and repository search did not find a canonical AKSI framework Markdown file at another path. AKSI mappings in this specification are based on the live local control JSON files in `shared/controls/`, the classification taxonomy in `shared/classifications/taxonomy.json`, `docs/data-classification.md`, `docs/architecture.md`, and the existing overlay specifications in `shared/overlays/`. The missing canonical AKSI framework Markdown is a project documentation gap that should be addressed separately.
- The live taxonomy in `shared/classifications/taxonomy.json` contains 23 `DC-*` classifications: `DC-PHI`, `DC-CHD`, `DC-SAD`, `DC-CUI`, `DC-FCI`, `DC-MNPI`, `DC-PII`, `DC-FIN`, `DC-NPI`, `DC-GOV`, `DC-AI`, `DC-GEN`, `DC-ITAR`, `DC-CRIT`, `DC-MINOR`, `DC-BIO`, `DC-LEGAL`, `DC-IP`, `DC-PAY`, `DC-EDU`, `DC-CJI`, `DC-EAR`, and `DC-MEDDEV`. DORA-RES activation does not depend on the count or contents of data classifications because it uses function classification, not data classification.

### Relationship to Existing DORA Overlay

The existing `shared/overlays/dora.json` overlay and DORA-RES coexist. The existing DORA overlay is `data_classification` triggered by `DC-FIN` and covers data-handling and data-protection evidence for agents touching financial data classifications. DORA-RES is `function_classification` triggered and covers operational resilience evidence for AI workloads supporting critical or important functions.

Both overlays can activate simultaneously for the same agent when the agent both touches `DC-FIN` data and supports an `FC-CRITICAL` or `FC-IMPORTANT` function. The activation engine must support multiple concurrent DORA-family overlays. There is no suppression rule between the existing DORA overlay and DORA-RES.

### Regulated Entity Scope

DORA-RES applies only when the customer declares the organization in scope for DORA Article 2. The organization-level onboarding attribute is:

```text
organization.dora_in_scope = true
```

The overlay covers financial entities listed in DORA Article 2(1), including:

- Credit institutions.
- Payment institutions and account information service providers.
- Electronic money institutions.
- Investment firms.
- Crypto-asset service providers and issuers of asset-referenced tokens.
- Central securities depositories.
- Central counterparties.
- Trading venues.
- Trade repositories.
- Managers of alternative investment funds and management companies.
- Data reporting service providers.
- Insurance and reinsurance undertakings.
- Insurance intermediaries, reinsurance intermediaries, and ancillary insurance intermediaries.
- Institutions for occupational retirement provision.
- Credit rating agencies.
- Administrators of critical benchmarks.
- Crowdfunding service providers.
- Securitisation repositories.
- ICT third-party service providers, where the customer's DORA obligations require assessment of those providers.

The overlay does not itself determine whether a customer qualifies for an Article 2 exemption, simplified framework treatment, or Member State exclusion. That determination remains a customer-side legal and compliance declaration. Relevant Article 2 exclusions include certain small alternative investment fund managers, small insurance and reinsurance undertakings, certain small institutions for occupational retirement provision, MiFID-exempt persons, insurance intermediaries that are micro, small, or medium-sized enterprises, and other Article 2 exclusions or Member State exclusions.

### Function Criticality Scope

DORA-RES uses the following activation treatment:

| Function classification | Activation treatment |
| --- | --- |
| `FC-CRITICAL` | Full DORA-RES control set activates. |
| `FC-IMPORTANT` | Full DORA-RES control set activates. |
| `FC-SUPPORTING` | Reduced DORA-RES control set activates under Section 7 when the organization is DORA-in-scope. |
| `FC-NONE` | DORA-RES does not activate. |
| Unclassified | DORA-RES does not activate, but an elicitation prompt fires if the organization is DORA-in-scope. |

DORA Article 3(22) defines a critical or important function as a function whose disruption would materially impair financial performance, soundness or continuity of services and activities, or continued compliance with authorization conditions and financial services obligations. `FC-CRITICAL` and `FC-IMPORTANT` are Ancilis operational tiers inside that Article 3(22) concept. Both are treated as in scope for full DORA-RES evidence.

### AI Workload Scope

DORA-RES applies to AI workloads supporting in-scope functions. For this overlay, an AI workload includes:

- The foundation model provider or providers.
- The model endpoint, hosted model, or externally managed inference service.
- The gateway layer used for routing, telemetry, policy enforcement, fallback, and provider switching.
- The agent runtime and the agent's tools, prompts, context handling, memory, and workflow behavior where those elements affect resilience of the in-scope function.

DORA-RES does not cover the customer's full non-AI ICT third-party risk program. Non-AI providers, enterprise infrastructure, ordinary SaaS vendors, data centers, networks, and business applications remain inside the customer's broader DORA program unless they are direct dependencies of the AI workload being evidenced by Ancilis.

## 2. AKSI Control Mapping

This section defines the DORA-RES controls Ancilis will evidence. It does not reproduce the full DORA control framework. Controls are limited to AI workload operational resilience evidence that Ancilis can collect, structure, or package.

### ICT Risk Management, DORA Articles 5-16

| DORA-RES control | Control objective | Parent AKSI controls | Notes |
| --- | --- | --- | --- |
| `DORA-RES-001` Function and AI workload dependency inventory | Maintain a declared mapping from each in-scope agent to the function it supports, the AI providers it depends on, the gateway layer, fallback routes, and critical operational dependencies. | `ID-01`, `ID-02`, `ID-05`, `GOV-06` | Extends AKSI inventory and external obligation controls from data and agent inventory into function-based DORA scope. |
| `DORA-RES-002` Resilience objectives and impact tolerance | Record RTO, RPO, maximum tolerable disruption, degraded-mode objectives, and impact tolerance for AI workloads supporting `FC-CRITICAL` or `FC-IMPORTANT` functions. | `GOV-03`, `ID-05`, `RC-01` | Specializes AKSI risk tolerance and recovery planning for DORA operational resilience. |
| `DORA-RES-003` AI provider failover and degraded-mode design | Document the failover pattern, degraded-mode behavior, manual fallback, and provider-routing decision points for loss or degradation of a primary AI provider. | `RC-01`, `RC-03`, `RS-02`, `RS-04` | Covers provider failure as an operational disruption, not only a security incident. |
| `DORA-RES-004` Backup and restoration of AI workload state | Evidence that prompts, configuration, policies, routing rules, memory state, and other required AI workload artifacts can be restored within declared objectives. | `PR-10`, `PR-11`, `RC-01`, `RC-03` | Applies only to recoverable AI workload state; it does not require Ancilis to back up third-party model weights. |
| `DORA-RES-005` Provider performance and operational anomaly monitoring | Continuously monitor provider availability, latency, error rates, rate limits, quality degradation, gateway routing failures, and other operational anomalies affecting in-scope functions. | `DE-01`, `DE-03`, `DE-05`, `PR-06` | Extends anomaly and outcome monitoring toward resilience and service continuity. |
| `DORA-RES-006` Resilience records and tamper-evident evidence chain | Preserve resilience evidence, test results, incident records, and provider monitoring records in a traceable evidence chain. | `PR-06`, `DE-04`, `GOV-06` | Evidence integrity is necessary because DORA requires records and post-event review evidence. Confirmed against `shared/controls/`: `PR-06` covers audit trail completeness and evidence chains, `DE-04` explicitly covers evidence integrity monitoring for chains, missing telemetry, and tamper signals, and `GOV-06` covers obligation-linked posture reporting. No separate AKSI gap is flagged for this mapping. |

#### Out of Scope for ICT Risk Management

| DORA requirement | Reason out of scope |
| --- | --- |
| Management body accountability and governance under Article 5. | Ancilis can package agent evidence, but cannot evidence board competence, governance decisions, or ultimate management accountability. |
| Enterprise-wide ICT risk management framework ownership, independent review, and internal audit under Article 6. | DORA-RES is an AI workload overlay, not the customer's full ICT risk management framework. |
| General staff training and awareness under Article 13. | Training records are outside the AI workload telemetry and evidence surface. |
| General crisis communication governance under Article 14. | Ancilis may preserve incident facts, but customer communications strategy and execution remain customer-owned. |

### ICT Incident Management and Reporting, DORA Articles 17-23

| DORA-RES control | Control objective | Parent AKSI controls | Notes |
| --- | --- | --- | --- |
| `DORA-RES-007` AI provider failure incident classification | Classify AI workload incidents against DORA incident criteria, including affected clients or transactions, duration, downtime, geographic spread, data impact, criticality, and economic impact. | `RS-03`, `RS-05`, `DE-01` | Applies DORA classification criteria to AI provider outage, gateway failure, quality collapse, or failed failover. |
| `DORA-RES-008` Major incident report packet and notification clock | Generate and maintain the evidence packet and clock record needed for initial, intermediate, and final major ICT-related incident reports. | `RS-05`, `RS-03`, `PR-06`, `GOV-06` | Ancilis supports packet preparation and timing evidence. The customer remains responsible for legal reporting and submission. |
| `DORA-RES-009` Post-incident root cause and corrective action review | Preserve root cause analysis, operational timeline, lessons learned, remediation actions, and evidence of changes after AI workload incidents. | `RC-02`, `RC-01`, `RS-01`, `DE-04` | Connects DORA learning requirements to Ancilis recovery and evidence integrity controls. |

#### Out of Scope for ICT Incident Management and Reporting

| DORA requirement | Reason out of scope |
| --- | --- |
| Legal determination that an incident is reportable to a specific competent authority. | Ancilis can apply configured criteria and package evidence, but reportability is a customer legal and regulatory decision. |
| Actual submission of initial, intermediate, or final reports to competent authorities. | The customer or its reporting delegate remains responsible under Article 19, even where reporting is outsourced. |
| Client, public, market, or media communications. | Ancilis may provide supporting facts, but communications approval and delivery are customer-owned. |
| Voluntary notification of significant cyber threats under Article 19(2). | DORA-RES focuses on AI workload operational resilience and provider failure. Cyber-threat voluntary reporting is handled by the customer's security incident program. |

### Digital Operational Resilience Testing, DORA Articles 24-27

| DORA-RES control | Control objective | Parent AKSI controls | Notes |
| --- | --- | --- | --- |
| `DORA-RES-010` Annual AI resilience test program | Maintain and evidence an annual, risk-based test plan for AI workloads supporting critical or important functions, including failover, recovery, degradation, and restoration scenarios. | `RC-03`, `DE-06`, `GOV-03` | Specializes AKSI resilience exercise evidence for DORA Article 24 and 25 testing. |
| `DORA-RES-011` Provider equivalence and portability testing | Test whether an alternate model provider, model endpoint, or deployment pattern can support the same in-scope function within defined performance, quality, safety, and recovery tolerances. | `DE-05`, `RC-03`, `PR-03`, `ID-02` | AKSI gap: no clean parent covers semantic provider equivalence or portability of AI outputs. This may warrant a future AKSI framework extension. DORA does not define provider equivalence; this control is constructed from substitutability, exit, continuity, and testing obligations under Articles 24, 25, 28(8), 29, and 30(3)(f). The equivalence test standard is a forthcoming Ancilis design artifact, not a DORA statutory test. Until that standard is published, customers may use their own equivalence methodology, and the evidence record captures the methodology used. |
| `DORA-RES-012` TLPT scope inclusion and remediation evidence | Where the financial entity is subject to TLPT, preserve evidence that AI workload components supporting critical or important functions were considered for scope, tested where required, and remediated where findings affected them. | `DE-06`, `RC-03`, `RS-04` | Ancilis does not conduct TLPT. It records scope inclusion, summary findings, remediation status, and provider cooperation evidence. |

#### Out of Scope for Digital Operational Resilience Testing

| DORA requirement | Reason out of scope |
| --- | --- |
| Conducting full TLPT exercises. | TLPT must be performed by qualified testers under Article 27 and supervisory expectations; Ancilis can only ingest or package evidence. |
| Tester procurement, tester independence validation, and tester professional indemnity requirements. | These are procurement and governance obligations of the financial entity. |
| Competent authority attestation and mutual recognition processes for TLPT. | Ancilis can store attestations but cannot issue or validate supervisory attestations. |
| Non-AI operational resilience testing across all ICT systems. | DORA-RES is limited to AI workload dependencies and cascade paths. |

### ICT Third-Party Risk Management, DORA Articles 28-44

| DORA-RES control | Control objective | Parent AKSI controls | Notes |
| --- | --- | --- | --- |
| `DORA-RES-013` AI ICT third-party register entry | Maintain DORA-ready register entries for AI providers, gateway providers, hosted model providers, and material subcontractors used by in-scope AI workloads. | `ID-02`, `ID-04`, `GOV-06` | Specializes AKSI tool, model, integration, and dependency registry evidence. |
| `DORA-RES-014` AI provider due diligence and suitability assessment | Evidence pre-contract and periodic assessment of an AI provider's operational, security, continuity, data location, subcontracting, conflicts of interest, and service suitability risks. | `ID-04`, `ID-05`, `GOV-06` | Uses RTS third-party risk factors where they affect the AI workload. |
| `DORA-RES-015` AI provider concentration and substitutability analysis | Assess dependency concentration across AI providers, related providers, model families, regions, gateways, and hard-to-substitute capabilities. | `ID-04`, `ID-05` | AKSI gap: AKSI covers supply-chain risk but not concentration and substitutability as first-class operational resilience dimensions. This may warrant a future AKSI framework extension. |
| `DORA-RES-016` Contractual resilience provisions for AI providers | Evidence that contractual metadata for AI providers includes service description, locations, SLA targets, incident assistance, audit rights, testing cooperation, data return, termination, and exit provisions. | `GOV-06`, `ID-04`, `RC-01` | Ancilis records clause presence and metadata; it does not provide legal advice or negotiate contracts. |
| `DORA-RES-017` AI provider exit strategy and transition test | Maintain an exit strategy and periodically test transition from the current AI provider or gateway pattern to an alternate provider or operating mode. | `RC-01`, `RC-03`, `ID-04` | Covers DORA exit obligations for AI provider dependency and customer-defined continuity objectives. |
| `DORA-RES-018` Ongoing provider performance monitoring and corrective action | Track provider service levels, continuity reports, incident reports, unresolved deficiencies, corrective actions, and remediation verification. | `DE-03`, `DE-01`, `ID-04`, `RC-02` | Links live provider performance evidence to ongoing third-party monitoring. |

#### Out of Scope for ICT Third-Party Risk Management

| DORA requirement | Reason out of scope |
| --- | --- |
| The customer's full register of all ICT third-party contractual arrangements. | DORA-RES covers AI workload providers only. The customer's full DORA register remains outside this overlay. |
| Contract negotiation, legal enforceability, or remediation of missing contractual rights. | Ancilis can flag and evidence clause status, but cannot create contractual rights. |
| Supervisory oversight of critical ICT third-party service providers under Articles 31-44. | These articles govern ESA and Lead Overseer activity; Ancilis can preserve customer-side evidence but does not perform oversight. |
| Non-AI subcontracting chains unrelated to the AI workload. | DORA-RES tracks subcontracting only where it affects AI provider, gateway, hosted model, or agent resilience. |

## 3. DORA Article Mapping

| Control | Regulator-facing article crosswalk |
| --- | --- |
| `DORA-RES-001` | `DORA-RES-001 -> DORA Article 3(22); DORA Article 6(1); DORA Article 8(1); DORA Article 8(4); DORA Article 8(5); DORA Article 8(6)` |
| `DORA-RES-002` | `DORA-RES-002 -> DORA Article 6(8)(b); DORA Article 6(8)(c); DORA Article 11(5); DORA Article 12(6)` |
| `DORA-RES-003` | `DORA-RES-003 -> DORA Article 11(2)(a); DORA Article 11(2)(b); DORA Article 11(2)(c); DORA Article 11(4); DORA Article 11(6)(a); DORA Article 12(4); DORA Article 15(e)` |
| `DORA-RES-004` | `DORA-RES-004 -> DORA Article 12(1); DORA Article 12(2); DORA Article 12(3); DORA Article 12(7)` |
| `DORA-RES-005` | `DORA-RES-005 -> DORA Article 10(1); DORA Article 10(2); DORA Article 10(3); DORA Article 13(4); DORA Article 17(3)(a)` |
| `DORA-RES-006` | `DORA-RES-006 -> DORA Article 6(3); DORA Article 11(8); DORA Article 17(2); DORA Article 17(3)(b)` |
| `DORA-RES-007` | `DORA-RES-007 -> DORA Article 17(1); DORA Article 17(2); DORA Article 17(3)(b); DORA Article 18(1)(a); DORA Article 18(1)(b); DORA Article 18(1)(c); DORA Article 18(1)(d); DORA Article 18(1)(e); DORA Article 18(1)(f); DORA Article 18(2)` |
| `DORA-RES-008` | `DORA-RES-008 -> substantive reporting obligation: DORA Article 19(1); DORA Article 19(3); DORA Article 19(4)(a); DORA Article 19(4)(b); DORA Article 19(4)(c); DORA Article 19(5). Content and timing delegation: DORA Article 20(a)(i); DORA Article 20(a)(ii); DORA Article 20(a)(iii). RTS version for report content and timing: Delegated Regulation (EU) 2025/301 as currently understood, recorded in evidence metadata as rts_version.` |
| `DORA-RES-009` | `DORA-RES-009 -> DORA Article 13(2); DORA Article 13(3); DORA Article 17(2); DORA Article 17(3)(f); DORA Article 19(4)(c)` |
| `DORA-RES-010` | `DORA-RES-010 -> DORA Article 11(6)(a); DORA Article 24(1); DORA Article 24(3); DORA Article 24(5); DORA Article 24(6); DORA Article 25(1)` |
| `DORA-RES-011` | `DORA-RES-011 -> DORA Article 24(3); DORA Article 25(1); DORA Article 28(8); DORA Article 29(1); DORA Article 30(3)(f)` |
| `DORA-RES-012` | `DORA-RES-012 -> DORA Article 26(1); DORA Article 26(2); DORA Article 26(3); DORA Article 26(5); DORA Article 26(6); DORA Article 26(7); DORA Article 27(1); DORA Article 27(2); DORA Article 27(3)` |
| `DORA-RES-013` | `DORA-RES-013 -> DORA Article 28(3); DORA Article 28(4)(a); DORA Article 30(2)(a); DORA Article 30(2)(b); Commission Delegated Regulation (EU) 2024/1773 Article 3(2); Commission Delegated Regulation (EU) 2024/1773 Article 4(e)` |
| `DORA-RES-014` | `DORA-RES-014 -> DORA Article 28(4)(b); DORA Article 28(4)(c); DORA Article 28(4)(d); DORA Article 28(4)(e); DORA Article 28(5); Commission Delegated Regulation (EU) 2024/1773 Article 5; Commission Delegated Regulation (EU) 2024/1773 Article 6; Commission Delegated Regulation (EU) 2024/1773 Article 7` |
| `DORA-RES-015` | `DORA-RES-015 -> DORA Article 3(29); DORA Article 6(9); DORA Article 28(1)(b); DORA Article 28(4)(c); DORA Article 29(1); DORA Article 29(2); DORA Article 31(2)(c); DORA Article 31(2)(d); Commission Delegated Regulation (EU) 2024/1773 Article 1(h); Commission Delegated Regulation (EU) 2024/1773 Article 1(i); Commission Delegated Regulation (EU) 2024/1773 Article 1(j); Commission Delegated Regulation (EU) 2024/1773 Article 5(2)(i)` |
| `DORA-RES-016` | `DORA-RES-016 -> DORA Article 30(1); DORA Article 30(2)(a); DORA Article 30(2)(b); DORA Article 30(2)(c); DORA Article 30(2)(d); DORA Article 30(2)(e); DORA Article 30(2)(f); DORA Article 30(2)(g); DORA Article 30(2)(h); DORA Article 30(2)(i); DORA Article 30(3)(a); DORA Article 30(3)(b); DORA Article 30(3)(c); DORA Article 30(3)(d); DORA Article 30(3)(e); DORA Article 30(3)(f); Commission Delegated Regulation (EU) 2024/1773 Article 8` |
| `DORA-RES-017` | `DORA-RES-017 -> DORA Article 28(7); DORA Article 28(8); DORA Article 30(3)(f); Commission Delegated Regulation (EU) 2024/1773 Article 10` |
| `DORA-RES-018` | `DORA-RES-018 -> DORA Article 28(6); DORA Article 30(3)(a); DORA Article 30(3)(b); DORA Article 30(3)(e); Commission Delegated Regulation (EU) 2024/1773 Article 9` |

Inference notes:

- `DORA-RES-011` is partially inferred. DORA requires testing, exit planning, concentration risk assessment, substitutability assessment, and transition planning, but does not define an AI-specific "provider equivalence" test. The Ancilis equivalence test standard is a product design artifact; until it is published, the customer methodology must be captured in `equivalence_test_method`.
- `DORA-RES-012` uses DORA Articles 26-27 and the ESA TLPT draft RTS final report as the evidence basis. Exact implementation should be version-pinned to the final applicable TLPT RTS in the build stage.
- `DORA-RES-008` separates the Article 19 substantive reporting obligation from Article 20 RTS/ITS mechanics. Delegated Regulation (EU) 2025/301 is the currently understood RTS source for timing and content, but the effective RTS version must be stored with the incident evidence and validated during implementation.

## 4. Evidence Requirements

### Evidence Record Common Fields

Every DORA-RES evidence record must contain these common fields:

| Field | Required | Description |
| --- | --- | --- |
| `evidence_id` | Yes | Stable evidence record identifier. |
| `control_ids` | Yes | One or more `DORA-RES-*` controls satisfied by the record. |
| `parent_aksi_control_ids` | Yes | AKSI controls supported by the evidence. |
| `organization_id` | Yes | Organization to which the evidence belongs. |
| `agent_id` | Yes | Agent to which the evidence attaches. |
| `function_classification` | Yes | `FC-CRITICAL`, `FC-IMPORTANT`, `FC-SUPPORTING`, or `FC-NONE` at the time evidence was generated. |
| `function_id` | Conditional | Customer-declared function identifier when available. |
| `collected_at` | Yes | Timestamp when Ancilis collected or received the evidence. |
| `period_start` | Conditional | Beginning of the covered observation period. |
| `period_end` | Conditional | End of the covered observation period. |
| `source` | Yes | One of `gateway_telemetry`, `customer_attestation`, `customer_provided_test_harness`, `contract_metadata`, `incident_log`, or `manual_documentation`. |
| `automation_level` | Yes | `automated`, `semi_automated`, or `customer_attested`. |
| `producer_version` | Conditional | Version of the Ancilis producer, gateway, importer, or attestation schema. |
| `rts_version` | Conditional | Regulatory technical standard or implementing technical standard version used to evaluate timing, content, or cycle-specific evidence. Required for DORA-RES incident reporting evidence and any other evidence with RTS-dependent rules. |
| `artifact_hash` | Yes | Hash of the evidence payload or document artifact. |
| `related_artifacts` | Conditional | Links or identifiers for reports, logs, contracts, runbooks, or test artifacts. |
| `customer_attestation_id` | Conditional | Identifier of the customer attestation supporting manually supplied evidence. |
| `limitations` | Conditional | Known gaps, assumptions, or exclusions in the evidence. |

The Ancilis default retention period for DORA-RES evidence is 5 years, or 1825 days. DORA itself does not impose one uniform numeric retention period for every evidence type in this overlay, but the product default aligns to financial-sector recordkeeping expectations under MiFID II, CRD V, and national supervisor guidance. Customer policy can extend retention beyond 5 years but cannot reduce DORA-RES evidence retention below 5 years. Where DORA requires a recurring cycle longer than one year, specifically TLPT under Article 26's three-year cycle, evidence must remain available for the current cycle and the prior cycle, and the 5-year minimum still applies to the underlying records.

### Evidence Type Definitions

| Evidence type | Structured fields |
| --- | --- |
| `function_classification_record` | `classification`, `classification_basis`, `article_3_22_factor`, `declared_by`, `declared_at`, `confirmed_by`, `confirmed_at`, `challenge_status`, `effective_from`, `prior_classification`, `affected_functions` |
| `ai_workload_inventory` | `foundation_model_providers`, `model_ids`, `gateway_layer`, `agent_version`, `critical_path_dependencies`, `third_party_provider_ids`, `data_regions`, `fallback_routes`, `owner`, `last_reviewed_at` |
| `resilience_objectives_record` | `rto`, `rpo`, `maximum_tolerable_disruption`, `impact_tolerance`, `degraded_mode_targets`, `sla_targets`, `approval_reference`, `reviewed_at` |
| `failover_design_record` | `primary_provider`, `secondary_providers`, `trigger_conditions`, `routing_policy`, `state_sync_method`, `data_residency_constraints`, `manual_fallback`, `last_reviewed_at` |
| `resilience_runbook` | `scenario`, `steps`, `roles`, `rollback_path`, `communications_dependencies`, `kill_switch_dependency`, `degraded_mode_steps`, `approval_reference` |
| `restore_test_result` | `backup_scope`, `restore_point`, `restore_started_at`, `restore_completed_at`, `rto_measured`, `rpo_measured`, `data_integrity_checks`, `pass_fail`, `remediation_required` |
| `backup_policy_attestation` | `backup_scope`, `backup_frequency`, `encryption_status`, `segregation_status`, `retention_period`, `owner`, `attested_by`, `attested_at` |
| `provider_performance_measurement` | `provider_id`, `model_id`, `gateway_route`, `availability`, `latency_p50`, `latency_p95`, `latency_p99`, `error_rate`, `timeout_rate`, `rate_limit_events`, `sla_breach_flag`, `period_start`, `period_end` |
| `ai_quality_drift_measurement` | `benchmark_id`, `test_harness_id`, `provider_id`, `model_id`, `quality_metric`, `baseline_value`, `observed_value`, `threshold`, `drift_status`, `period_start`, `period_end` |
| `gateway_telemetry_snapshot` | `request_count`, `provider_routes`, `failover_events`, `error_events`, `rate_limit_events`, `downtime_windows`, `trace_ids`, `period_start`, `period_end` |
| `resilience_evidence_chain_record` | `evidence_hashes`, `prior_chain_hash`, `record_count`, `gap_count`, `verification_status`, `generated_at` |
| `incident_classification` | `incident_id`, `detected_at`, `started_at`, `ended_at`, `affected_function`, `affected_clients`, `affected_counterparties`, `affected_transactions`, `duration`, `downtime`, `geographical_spread`, `data_loss_impact`, `service_criticality`, `economic_impact`, `major_incident_flag`, `significant_cyber_threat_flag`, `classification_rationale`, `approved_by` |
| `incident_report` | `incident_id`, `report_type`, `report_version`, `rts_version`, `competent_authority_route`, `impact_summary`, `root_cause_summary`, `measures_taken`, `client_notification_status`, `submitted_by_customer`, `submitted_at`, `limitations` |
| `notification_clock_record` | `incident_id`, `rts_version`, `classification_time`, `initial_report_due_at`, `initial_report_submitted_at`, `intermediate_report_due_at`, `intermediate_report_submitted_at`, `final_report_due_at`, `final_report_submitted_at`, `exceptions` |
| `post_incident_review` | `incident_id`, `root_cause`, `timeline`, `procedures_followed`, `response_effectiveness`, `forensic_summary`, `lessons_learned`, `corrective_actions`, `owner`, `due_dates`, `verification_evidence` |
| `annual_resilience_test_plan` | `plan_year`, `scope`, `scenarios`, `systems`, `functions`, `test_schedule`, `independence_model`, `acceptance_criteria`, `approval_reference` |
| `failover_test_result` | `scenario`, `primary_provider`, `alternate_provider`, `trigger_method`, `started_at`, `completed_at`, `rto_achieved`, `rpo_achieved`, `output_quality_delta`, `customer_impact`, `pass_fail`, `remediation_required` |
| `recovery_time_measurement` | `function_id`, `scenario`, `outage_duration`, `restoration_timestamp`, `rto_target`, `rto_actual`, `rpo_target`, `rpo_actual`, `data_integrity_outcome`, `pass_fail` |
| `equivalence_test_result` | `primary_provider`, `alternate_provider`, `primary_model`, `alternate_model`, `test_set_id`, `equivalence_test_method`, `semantic_equivalence_method`, `quality_thresholds`, `observed_quality_delta`, `safety_differences`, `data_residency_constraints`, `pass_fail`, `limitations` |
| `portability_test_result` | `migrated_artifacts`, `target_provider`, `target_gateway_route`, `configuration_changes`, `elapsed_time`, `blockers`, `functionality_restored`, `residual_risks`, `pass_fail` |
| `tlpt_scope_attestation` | `tlpt_required_flag`, `authority_validation_status`, `critical_or_important_functions_in_scope`, `ai_components_included`, `ai_components_excluded`, `exclusion_rationale`, `attested_by`, `attested_at` |
| `tlpt_summary_record` | `test_date`, `tester_identity`, `tester_type`, `scope_summary`, `findings_summary`, `ai_workload_findings`, `remediation_plan`, `remediation_status`, `attestation_reference` |
| `third_party_register_entry` | `provider_id`, `provider_name`, `service_description`, `function_supported`, `critical_or_important_flag`, `arrangement_id`, `subcontractors`, `service_locations`, `data_processed`, `contract_start`, `contract_end`, `owner` |
| `third_party_assessment` | `provider_id`, `assessment_date`, `risk_domains`, `information_security_standard`, `financial_resources_assessment`, `operational_resources_assessment`, `business_continuity_evidence`, `audit_or_certification_references`, `subcontracting_assessment`, `third_country_assessment`, `conflicts_of_interest_assessment`, `suitability_decision`, `approver` |
| `concentration_analysis` | `provider_id`, `dependency_percentage`, `functions_affected`, `related_providers`, `model_family_concentration`, `region_concentration`, `substitutability_rating`, `migration_difficulty`, `single_points_of_failure`, `available_alternatives`, `assessment_date` |
| `contractual_clause_assessment` | `arrangement_id`, `article_30_clauses_present`, `article_30_clauses_missing`, `sla_targets`, `incident_assistance_clause`, `audit_rights_clause`, `testing_cooperation_clause`, `tlpt_cooperation_clause`, `data_return_clause`, `termination_clause`, `exit_support_clause`, `assessed_by`, `assessed_at` |
| `contract_metadata` | `provider_id`, `arrangement_id`, `effective_date`, `renewal_date`, `termination_date`, `service_description`, `locations`, `subcontracting_permissions`, `sla_summary`, `data_handling_terms` |
| `exit_strategy_document` | `provider_id`, `exit_scenarios`, `replacement_provider_options`, `in_house_option`, `transition_plan`, `data_return_plan`, `data_deletion_plan`, `transition_schedule`, `continuity_controls`, `owner`, `reviewed_at` |
| `exit_test_result` | `scenario`, `provider_id`, `target_provider`, `started_at`, `completed_at`, `elapsed_time`, `data_integrity_outcome`, `functionality_restored`, `service_disruption`, `pass_fail`, `remediation_required` |
| `provider_corrective_action_record` | `provider_id`, `issue_id`, `issue_description`, `provider_response`, `owner`, `due_date`, `remediation_status`, `verification_evidence`, `closed_at` |

### Control Evidence Matrix

| Control | Required evidence types | Evidence sources | Automation | Collection frequency | Retention | Freshness |
| --- | --- | --- | --- | --- | --- | --- |
| `DORA-RES-001` | `function_classification_record`, `ai_workload_inventory`, `third_party_register_entry` | `customer_attestation`, `manual_documentation`, `contract_metadata` | Customer-attested until `FunctionClassification` and AI inventory producers exist. | At agent onboarding, annual review, and on material function, provider, model, gateway, or routing change. | Minimum 1825 days; retain current and prior inventory versions. | Current if reviewed within 12 months and updated after the last material change. |
| `DORA-RES-002` | `resilience_objectives_record`, `recovery_time_measurement` | `customer_attestation`, `customer_provided_test_harness`, `manual_documentation` | Semi-automated when test harness emits RTO/RPO measurements; objectives remain customer-attested. | Annual, on material change, and after major incident affecting the function. | Minimum 1825 days; retain current and prior objective set. | Current if reviewed within 12 months and after the latest BIA or material change. |
| `DORA-RES-003` | `failover_design_record`, `resilience_runbook`, `failover_test_result` | `manual_documentation`, `customer_attestation`, `customer_provided_test_harness`, `gateway_telemetry` | Design is customer-attested; failover execution can be automated once gateway telemetry exists. | Annual review; test after material provider, model, or gateway routing change. | Minimum 1825 days; retain latest successful test and open remediation records. | Current if design reviewed within 12 months and last test is within 12 months or since the last material change. |
| `DORA-RES-004` | `backup_policy_attestation`, `restore_test_result` | `customer_attestation`, `customer_provided_test_harness`, `manual_documentation` | Mostly customer-attested; restore measurements can be semi-automated if test harness exists. | Annual and after material state, memory, routing, or configuration changes. | Minimum 1825 days; retain latest successful restore test. | Current if tested within 12 months and after the last material change. |
| `DORA-RES-005` | `provider_performance_measurement`, `ai_quality_drift_measurement`, `gateway_telemetry_snapshot` | `gateway_telemetry`, `customer_provided_test_harness` | Automated once gateway telemetry and benchmark ingestion exist. | Continuous monitoring with scheduled summary records. | Minimum 1825 days for summary records; raw telemetry retention follows customer configuration but cannot reduce retained DORA-RES summary evidence below 1825 days. | Current if latest telemetry summary is no older than 24 hours for active agents and quality drift summary is no older than 30 days. |
| `DORA-RES-006` | `resilience_evidence_chain_record` | `gateway_telemetry`, `incident_log`, `manual_documentation`, `contract_metadata`, `customer_attestation` | Automated once evidence-chain verification is enabled for DORA-RES record types. | Continuous or on evidence ingestion. | Minimum 1825 days; chain metadata must cover all retained evidence. | Current if verification has run within 24 hours or after the most recent evidence ingestion. |
| `DORA-RES-007` | `incident_classification`, `gateway_telemetry_snapshot` | `incident_log`, `gateway_telemetry`, `customer_attestation` | Semi-automated; telemetry can populate operational criteria, but customer confirms impact, economics, and reportability. | Event-driven, on incident detection or suspected major incident. | Minimum 1825 days; customer policy may require longer but cannot reduce DORA-RES retention below 1825 days. | Current if classification is completed or updated during the active incident workflow and reviewed after material new facts. |
| `DORA-RES-008` | `incident_report`, `notification_clock_record`, `incident_classification` | `incident_log`, `customer_attestation`, `manual_documentation` | Semi-automated packet generation; submission status is customer-attested. | On major incident and when intermediate or final report events occur. | Minimum 1825 days; retain complete packet for each major incident. | Current if packet reflects the latest report stage and RTS/ITS timing configuration. |
| `DORA-RES-009` | `post_incident_review`, `provider_corrective_action_record` | `incident_log`, `manual_documentation`, `customer_attestation`, `contract_metadata` | Customer-attested with semi-automated incident timeline support. | On incident closure and when corrective actions are updated. | Minimum 1825 days; retain until all corrective actions are closed plus one annual review cycle if longer. | Current if review is completed within the customer-defined post-incident review window and corrective action status is no older than 30 days. |
| `DORA-RES-010` | `annual_resilience_test_plan`, `failover_test_result`, `recovery_time_measurement`, `restore_test_result` | `customer_provided_test_harness`, `gateway_telemetry`, `manual_documentation`, `customer_attestation` | Semi-automated; telemetry can evidence execution, but test scope and acceptance criteria are customer-approved. | At least annual for AI workloads supporting `FC-CRITICAL` or `FC-IMPORTANT`, and after substantive changes. | Minimum 1825 days; retain current annual plan and latest test results. | Current if plan and test results are within 12 months and after the latest substantive change. |
| `DORA-RES-011` | `equivalence_test_result`, `portability_test_result`, `recovery_time_measurement` | `customer_provided_test_harness`, `gateway_telemetry`, `manual_documentation` | Semi-automated when benchmark and gateway routing data exist. | Annual, before materially increasing provider dependency, and before accepting an alternate provider as a resilience fallback. | Minimum 1825 days; retain latest accepted equivalence and portability tests. | Current if completed within 12 months or since the last provider, model, policy, or function change. |
| `DORA-RES-012` | `tlpt_scope_attestation`, `tlpt_summary_record`, `provider_corrective_action_record` | `manual_documentation`, `customer_attestation`, `contract_metadata` | Customer-attested. | At TLPT planning, execution, closure, and remediation milestones; DORA Article 26 uses a three-year TLPT cycle for identified entities. | Minimum 1825 days applies regardless of TLPT cycle; retain current TLPT cycle and prior cycle, and retain underlying records for at least 1825 days. | Current if aligned to the latest TLPT cycle or supervisory scoping decision. |
| `DORA-RES-013` | `third_party_register_entry`, `contract_metadata`, `ai_workload_inventory` | `contract_metadata`, `manual_documentation`, `customer_attestation` | Customer-attested until contract metadata ingestion exists. | Before provider use, on contract change, on provider/subcontractor/location change, and annual review. | Minimum 1825 days; retain current and prior register entry. | Current if reviewed within 12 months and after the last material arrangement change. |
| `DORA-RES-014` | `third_party_assessment`, `contract_metadata`, `provider_performance_measurement` | `contract_metadata`, `manual_documentation`, `customer_attestation`, `gateway_telemetry` | Mostly customer-attested; provider performance evidence can be automated. | Before contract, before material change, annual review for in-scope AI providers, and after material provider incident. | Minimum 1825 days; retain current assessment and supporting artifacts. | Current if assessed within 12 months and after the latest material provider change or incident. |
| `DORA-RES-015` | `concentration_analysis`, `ai_workload_inventory`, `third_party_register_entry` | `manual_documentation`, `contract_metadata`, `customer_attestation`, `gateway_telemetry` | Semi-automated when provider dependency and routing data exist; substitutability judgment remains customer-attested. | Before contract, annual, after provider consolidation, model migration, routing change, or new concentration risk. | Minimum 1825 days; retain latest assessment and prior assessment. | Current if assessed within 12 months and after latest dependency change. |
| `DORA-RES-016` | `contractual_clause_assessment`, `contract_metadata` | `contract_metadata`, `manual_documentation`, `customer_attestation` | Customer-attested until contract metadata ingestion and clause extraction exist. | Before contract execution, renewal, material amendment, and annual review for critical or important function support. | Minimum 1825 days; retain latest assessment while arrangement is active and for one review cycle after termination if longer. | Current if based on the active contract version. |
| `DORA-RES-017` | `exit_strategy_document`, `exit_test_result`, `portability_test_result` | `manual_documentation`, `customer_attestation`, `customer_provided_test_harness`, `gateway_telemetry` | Customer-attested with semi-automated transition test evidence when telemetry and test harness exist. | Annual review and test, on material provider/model/gateway change, and before planned termination. | Minimum 1825 days; retain current exit plan and latest transition test. | Current if reviewed within 12 months and after latest material provider or function change. |
| `DORA-RES-018` | `provider_performance_measurement`, `provider_corrective_action_record`, `gateway_telemetry_snapshot` | `gateway_telemetry`, `incident_log`, `contract_metadata`, `customer_attestation` | Automated for telemetry; customer-attested for provider commitments and remediation status. | Continuous monitoring with scheduled review; corrective actions event-driven. | Minimum 1825 days; retain unresolved corrective actions until closure plus one annual review cycle if longer. | Current if telemetry summary is no older than 24 hours and corrective action status is no older than 30 days. |

## 5. Function Classification Specification

`FunctionClassification` is a declared classification primitive used to determine whether an agent supports a DORA-relevant function. It is not derived from data classification, although data classifications may provide supporting context.

### Taxonomy

| Classification | Definition | DORA treatment |
| --- | --- | --- |
| `FC-CRITICAL` | A function whose disruption would materially impair the financial performance, soundness, or continuity of services and activities of the regulated entity, or materially impair continued compliance with authorization conditions and financial services obligations. | Full DORA-RES activation. This is grounded in DORA Article 3(22). |
| `FC-IMPORTANT` | A function whose disruption would substantially impair financial performance, service continuity, activity continuity, or compliance obligations, but which the customer does not classify as `FC-CRITICAL` under its internal DORA program. | Full DORA-RES activation. `FC-CRITICAL` versus `FC-IMPORTANT` is Ancilis product tiering for customer internal governance. It supports mature DORA programs that distinguish critical from important internally, but it is not a DORA Article 3(22) statutory test. DORA treats "critical or important function" as a combined concept. |
| `FC-SUPPORTING` | A function that supports an in-scope `FC-CRITICAL` or `FC-IMPORTANT` function but is not itself declared critical or important. | Reduced DORA-RES activation under Section 7. |
| `FC-NONE` | A function not in scope of DORA operational resilience classification. | No DORA-RES activation. |

### Elicitation Model

Function classification is declared by the customer. Ancilis may prompt, challenge, and preserve the rationale, but it cannot observe a function's DORA status from telemetry alone.

The platform asks:

```text
Does this agent support a business function whose disruption, defective performance,
or failed performance could materially or substantially impair financial performance,
soundness, continuity of services or activities, or compliance with authorization
conditions or financial-services obligations?
```

The platform guidance must instruct the user to consult, where available:

- The organization's DORA function inventory.
- Business impact analysis.
- ICT asset and dependency inventory.
- Outsourcing or ICT third-party register.
- Operational resilience impact tolerances.
- Incident impact criteria.
- Legal or compliance determinations of DORA scope.

The confirmation pattern follows the existing classification challenge pattern used for data classification, adapted for function classification:

- Show the proposed or declared `FunctionClassification`.
- Show the activation consequence, including whether full DORA-RES, reduced DORA-RES, or no DORA-RES controls will apply.
- Require explicit confirmation for `FC-CRITICAL`, `FC-IMPORTANT`, and any change that increases or decreases DORA-RES scope.
- Record the confirmer, timestamp, basis statement, and prior classification.
- Preserve classification history as evidence.

When classification is updated:

- Overlay activation is recalculated.
- Evidence requirements are recalculated.
- Gap analysis runs against the new control set.
- Existing evidence is re-evaluated for freshness and applicability.
- Any controls newly in scope are marked as missing, stale, or satisfied.
- Any controls leaving scope are retained historically but are no longer required for current posture.
- A classification-change audit event is generated.

### Attachment Model

Function classification attaches to agents, not to data. An agent has one current function classification at a time.

If an agent supports multiple functions, the highest criticality wins:

```text
FC-CRITICAL > FC-IMPORTANT > FC-SUPPORTING > FC-NONE
```

An agent supporting one `FC-CRITICAL` function and three `FC-SUPPORTING` functions is classified as `FC-CRITICAL`. The current classification is single-valued, but the underlying evidence record should preserve the list of supported functions and the reason the highest classification was selected.

## 6. Activation Logic

DORA-RES uses the same declarative activation style as existing overlays, but with a new `function_classification` trigger type.

```json
{
  "id": "dora-res",
  "name": "DORA Operational Resilience for AI Workloads",
  "trigger_type": "function_classification",
  "activation": {
    "all": [
      {
        "organization_attribute": "dora_in_scope",
        "equals": true
      },
      {
        "agent_attribute": "function_classification",
        "in": ["FC-CRITICAL", "FC-IMPORTANT"]
      }
    ]
  },
  "reduced_activation": {
    "all": [
      {
        "organization_attribute": "dora_in_scope",
        "equals": true
      },
      {
        "agent_attribute": "function_classification",
        "equals": "FC-SUPPORTING"
      }
    ]
  }
}
```

Boundary behavior:

| Scenario | Result |
| --- | --- |
| Organization is DORA-in-scope and agent has `FC-CRITICAL`. | Full DORA-RES activates. |
| Organization is DORA-in-scope and agent has `FC-IMPORTANT`. | Full DORA-RES activates. |
| Organization is DORA-in-scope and agent has `FC-SUPPORTING`. | Reduced DORA-RES activates under Section 7. |
| Organization is DORA-in-scope and agent has `FC-NONE`. | DORA-RES does not activate. |
| Organization is DORA-in-scope and agent has no function classification. | DORA-RES does not activate, but function classification elicitation prompt fires. |
| Organization is not DORA-in-scope and agent has `FC-CRITICAL`. | DORA-RES does not activate. Classification is retained as informational only. |
| Function classification changes from `FC-NONE` to `FC-CRITICAL`. | Full DORA-RES activates; existing evidence is re-evaluated against full DORA-RES requirements. |
| Function classification changes from `FC-CRITICAL` to `FC-SUPPORTING`. | Full control set deactivates; reduced control set remains active if the organization is DORA-in-scope. Historical evidence remains retained. |
| Organization attribute changes from `dora_in_scope = false` to `true`. | Activation is recalculated for all agents with existing function classifications. Unclassified agents receive the elicitation prompt. |

## 7. Reduced Control Set for FC-SUPPORTING

`FC-SUPPORTING` functions are not directly classified as critical or important under the customer's DORA Article 3(22) analysis. They may still create cascade risk for an in-scope function. The reduced control set captures dependency, monitoring, incident learning, concentration, and exit evidence without imposing the full DORA-RES burden.

### Required for FC-SUPPORTING

| Control | Reduced-scope requirement |
| --- | --- |
| `DORA-RES-001` | Maintain function and dependency inventory showing which `FC-CRITICAL` or `FC-IMPORTANT` function the supporting agent can affect. |
| `DORA-RES-003` | Document degraded-mode or manual fallback where the supporting agent's failure could disrupt an in-scope function. |
| `DORA-RES-005` | Monitor operational anomalies that may cascade to an in-scope function. |
| `DORA-RES-006` | Preserve evidence chain for supporting-function resilience records. |
| `DORA-RES-007` | Classify incidents for cascade potential and escalate if they affect an `FC-CRITICAL` or `FC-IMPORTANT` function. |
| `DORA-RES-009` | Complete post-incident review where a supporting-function incident affects, or could reasonably have affected, an in-scope function. |
| `DORA-RES-013` | Maintain provider register entry for AI providers used by the supporting agent when those providers also support an in-scope function or create cascade dependency. |
| `DORA-RES-015` | Assess concentration risk where the same AI provider, gateway, region, or model family supports both supporting and in-scope functions. |
| `DORA-RES-017` | Maintain an exit or transition path if loss of the supporting AI provider could cascade into an in-scope function. |
| `DORA-RES-018` | Monitor provider performance and corrective actions where provider degradation could affect the in-scope function. |

### Conditional for FC-SUPPORTING

| Control | Condition |
| --- | --- |
| `DORA-RES-010` | Required only where the customer's dependency analysis shows a credible cascade path from the supporting agent to an `FC-CRITICAL` or `FC-IMPORTANT` function. The test may be narrower than the annual test required for directly in-scope functions. |
| `DORA-RES-016` | Required only when the supporting agent uses the same contractual arrangement as an in-scope function or when contract failure could impair an in-scope function. |

### Not Required for FC-SUPPORTING Unless Reclassified

| Control | Reason |
| --- | --- |
| `DORA-RES-002` | Detailed function-level RTO, RPO, and impact tolerance are required for functions classified `FC-CRITICAL` or `FC-IMPORTANT`, not ordinary supporting functions. |
| `DORA-RES-004` | Backup and restore evidence is required only where the supporting agent's recoverable state is necessary to meet the in-scope function's continuity objective. |
| `DORA-RES-008` | Major incident report packets are required only when the incident affects a critical or important function or otherwise meets customer reportability criteria. |
| `DORA-RES-011` | Provider equivalence and portability testing is a full-scope control for directly in-scope AI workloads. |
| `DORA-RES-012` | TLPT inclusion is required only where the supporting agent or its AI components are included in the TLPT scope for critical or important functions. |
| `DORA-RES-014` | Full DORA AI provider due diligence applies when the AI provider supports a critical or important function or the customer's DORA program otherwise treats it as in scope. |

## 8. Out-of-Scope Controls

| DORA requirement | DORA article basis | Why Ancilis DORA-RES cannot evidence it |
| --- | --- | --- |
| Management body ultimate responsibility, approval, oversight, and competence. | Article 5 | Ancilis can produce AI workload evidence, but cannot evidence board-level accountability, knowledge, or governance conduct. |
| The customer's full ICT risk management framework, including enterprise policies, internal governance, internal audit, and whole-firm risk appetite. | Article 6 | DORA-RES is an overlay for AI workloads supporting in-scope functions. The entity-wide framework remains the customer's DORA program. |
| Staff training and awareness programs. | Article 13(6) | Training completion and curriculum records are not generated by agent runtime, gateway telemetry, or AI workload evidence. |
| Crisis communication strategy and public, customer, or market communications execution. | Article 14; Article 19(3) | Ancilis can preserve incident facts and report packets, but communications approvals and delivery are customer-owned. |
| Legal submission of incident reports to competent authorities. | Article 19 | Ancilis can prepare evidence packets and timing records, but the customer or its delegate remains responsible for regulatory submission. |
| Full non-AI ICT third-party risk management and the complete register of all ICT third-party contractual arrangements. | Article 28 | DORA-RES is limited to AI workload providers, gateways, hosted models, and AI-related subcontracting dependencies. |
| Contract drafting, legal negotiation, and enforceability of contractual provisions. | Article 30 | Ancilis can record clause presence or absence and supporting metadata; it cannot create legal rights. |
| TLPT execution, tester qualification, professional indemnity, and supervisory attestation. | Articles 26-27 | Ancilis can store TLPT scope and remediation evidence, but testing and attestation must be performed through qualified processes and competent authority interaction. |
| ESA and Lead Overseer oversight of critical ICT third-party service providers. | Articles 31-44 | These articles establish supervisory oversight powers and processes. They are not customer-side agent controls. |
| Payment-specific operational or security incident reporting outside AI workload resilience. | Article 23 | DORA-RES handles AI operational incidents. Payment-service-specific reporting remains in the customer's payments and DORA incident program unless the agent directly supports that payment function and is classified accordingly. |
| General cybersecurity prevention controls not tied to AI workload operational resilience evidence. | Articles 8-10 and related security provisions | AKSI already contains security controls. DORA-RES specializes resilience evidence for AI provider failure, recovery, concentration, testing, and exit. |

## 9. Evidence Source Dependencies

| Dependency | Required for | Exists in Ancilis today | Build implication |
| --- | --- | --- | --- |
| `FunctionClassification` primitive | Activation, `DORA-RES-001`, all scope decisions | No | New classification primitive, history model, confirmation flow, and activation integration are required. |
| Organization attribute `dora_in_scope` | Overlay activation | No DORA-RES-specific onboarding attribute found | Add organization-level onboarding declaration and exemption metadata. |
| Function classification elicitation and challenge flow | `DORA-RES-001`, Section 5 activation governance | No | Adapt existing data classification challenge pattern to declared function classification. |
| AI workload inventory model | `DORA-RES-001`, `DORA-RES-013`, `DORA-RES-015` | Partial through AKSI `ID-01` and `ID-02`; DORA-RES fields missing | Extend inventory records to include function, provider, gateway, fallback route, region, and subcontractor fields. |
| Gateway telemetry producer | `DORA-RES-005`, `DORA-RES-006`, `DORA-RES-010`, `DORA-RES-011`, `DORA-RES-018` | No DORA-RES gateway producer exists | Required to automate provider performance, failover, routing, and recovery evidence. |
| Customer-provided test harness ingestion | `DORA-RES-002`, `DORA-RES-003`, `DORA-RES-004`, `DORA-RES-010`, `DORA-RES-011`, `DORA-RES-017` | No DORA-RES-specific ingestion exists | Add structured import for failover, recovery, restore, equivalence, portability, and exit test results. |
| Customer attestation flow for DORA-RES | Function declarations, RTO/RPO, BIA, due diligence, contracts, TLPT, exit plans | Generic attestation concepts exist in AKSI, but DORA-RES-specific schemas do not | Implement structured attestations for each customer-supplied evidence type. |
| Contract metadata ingestion | `DORA-RES-013`, `DORA-RES-014`, `DORA-RES-016`, `DORA-RES-017`, `DORA-RES-018` | No DORA-RES contract ingestion exists | Add contract metadata schema and import path; clause extraction can be manual first. |
| Incident log and incident report packet builder | `DORA-RES-007`, `DORA-RES-008`, `DORA-RES-009`, `DORA-RES-018` | No DORA-RES incident packet builder found | Add DORA incident classification fields, notification clock records, and report packet schema. |
| Provider SLA and status connectors | `DORA-RES-005`, `DORA-RES-014`, `DORA-RES-018` | No | Optional automation path for provider status and SLA evidence; manual evidence remains possible. |
| Evidence store and tamper-evident hash chain | `DORA-RES-006` and all retained evidence | Yes, partially, through existing evidence storage and hash-chain architecture | Extend evidence schemas and verification to DORA-RES evidence types. |
| Overlay engine support for function-based triggers | Sections 1, 5, and 6 | No; existing overlays are data-classification or certification-intent driven | Add `function_classification` trigger type and reduced activation semantics. |
| Gap analysis/reporting for DORA-RES | All controls | Partial through existing overlay gap analysis patterns | Add DORA-RES control set, evidence freshness rules, and reduced-scope handling. |
| RTS version metadata | `DORA-RES-008`, `DORA-RES-012`, `DORA-RES-014` through `DORA-RES-017` | No DORA-RES-specific version field | Store regulatory source version and effective date for incident RTS, TLPT RTS, and third-party risk RTS dependencies. |

## 10. Open Questions

| Question | Why it matters |
| --- | --- |
| What default standard should Ancilis use for `equivalence_test_result`? | DORA requires substitutability, exit planning, continuity, and testing, but does not define AI provider equivalence. A default standard must define acceptable semantic, safety, latency, and operational deltas. |
| How should AI-specific degradation be mapped to DORA Article 18 incident criteria? | Provider outages map cleanly to availability and downtime, but hallucination spikes, quality collapse, tool misuse, or silent output degradation may affect clients, transactions, reputation, and economic impact in less direct ways. |
| How should Ancilis manage future RTS/ITS version changes for incident timing and content? | DORA Article 20 delegates content and timing to RTS/ITS. Delegated Regulation (EU) 2025/301 is the currently understood RTS source for DORA-RES incident reporting metadata, but the product needs a versioning and migration policy if incident RTS/ITS requirements change. |
| Which TLPT regulatory artifact should be version-pinned? | This draft directly consulted the ESA Joint Final Report `JC 2024 29` dated 17 July 2024. The build stage should pin to the final applicable TLPT RTS text and retain the source version in evidence metadata. |
| How deep should Ancilis model AI provider subcontractors and subprocessors? | DORA and the third-party risk RTS require attention to subcontracting, location, and concentration. AI provider dependency chains may include cloud regions, model hosts, safety layers, data processors, and routing vendors. |
| When is a foundation model provider always an ICT third-party service provider? | Article 3(21) broadly defines ICT services as digital and data services provided through ICT systems on an ongoing basis, and Article 3(19) defines ICT third-party service providers. Applying that to every AI deployment is a customer legal determination, although DORA-RES assumes externally provided AI services are in scope when they support `FC-CRITICAL` or `FC-IMPORTANT` functions. |
| How should `FC-SUPPORTING` cascade paths be represented? | Reduced activation depends on whether a supporting agent can impair an in-scope function. That requires a dependency graph between functions, agents, providers, and business processes that does not yet exist. |
| How should simplified framework entities under DORA Article 16 be treated? | Some entities have simplified ICT risk management obligations. The onboarding model needs a way to declare whether the organization follows the full DORA framework or simplified framework treatment. |
