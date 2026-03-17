# Ancilis SDK — Overlay Roadmap

## v0.1 — Shipped

Five complete overlay profiles with full 26-control AKSI mapping:

- **PCI-DSS v4.0** — Cardholder data (DC-CHD). Strict thresholds on identity, access control, data protection, logging, encryption, and monitoring.
- **SOC 2 Type II** — General business data (DC-GEN), PII (DC-PII). Universal enterprise compliance baseline. Standard thresholds with TSC evidence requirements.
- **EU AI Act** — AI training data (DC-AI), biometric data (DC-BIO). Human oversight mandated. Strict thresholds on logging, monitoring, and governance. 10-year evidence retention.
- **ISO/IEC 42001:2023** — AI training data (DC-AI). AI management system standard. Process-oriented evidence requirements emphasizing management system operation.
- **NIST CSF 2.0** — Always active (baseline). Direct CSF subcategory mapping for all 26 AKSIs. Alignment-based, not pass/fail.

## v0.2 — Next Priority

Overlay profiles deferred from v0.1 — these cover the next tier of buyer conversations:

- **GDPR** (standalone) — Currently partial coverage via SOC 2 privacy criteria and existing gdpr.json with 6-control mapping. v0.2 expands to full 26-control mapping with Art.25/32/30 evidence requirements and 72-hour breach notification.
- **HIPAA** — Currently has 6-control mapping in hipaa.json. v0.2 expands to full 26-control mapping with Security Rule/Privacy Rule/HITECH evidence requirements. Triggered by DC-PHI.
- **CMMC Level 2** — NIST 800-171r3 compliance for controlled unclassified information. Triggered by DC-CUI. Required for DoD contractor supply chain.
- **GLBA** — Gramm-Leach-Bliley Act for financial services data. Triggered by DC-FIN. Safeguards Rule requirements for financial institutions.
- **DORA** — Digital Operational Resilience Act for EU financial entities. ICT risk management, incident reporting, and third-party risk management.

## v0.3+ — Extended Coverage

Overlay profiles for specialized regulatory domains:

### US Federal
- **NIST 800-53** — Comprehensive federal security controls. Large effort — 1000+ controls to map.
- **FedRAMP 20x** — Cloud service provider authorization for federal agencies.
- **FISMA** — Federal Information Security Modernization Act.

### US Financial / Securities
- **SOX / SEC Cyber Rules** — Sarbanes-Oxley and SEC cybersecurity disclosure requirements.

### US Privacy
- **CCPA/CPRA** — California Consumer Privacy Act and California Privacy Rights Act.
- **COPPA** — Children's Online Privacy Protection Act. Triggered by DC-MINOR.
- **FERPA** — Family Educational Rights and Privacy Act.

### US Sector-Specific
- **BIPA** — Biometric Information Privacy Act (Illinois). Triggered by DC-BIO.
- **ITAR/EAR** — International Traffic in Arms Regulations / Export Administration Regulations. Triggered by DC-ITAR.

### EU / International
- **NIS2** (standalone) — Network and Information Security Directive 2. Critical infrastructure operators.
- **LGPD** — Brazil's General Data Protection Law.

### APAC
- **Korea AI Basic Act** — South Korea's framework for AI governance.
- **Japan AI Promotion Act** — Japan's AI regulatory framework.
- **Singapore AIGS** — AI Governance and Standards framework.
- **MAS TRM** — Monetary Authority of Singapore Technology Risk Management.
- **Australia Privacy Act** — Australian privacy and data protection requirements.

### Critical Infrastructure
- **NERC CIP** — North American Electric Reliability Corporation Critical Infrastructure Protection. Triggered by DC-CRIT.
