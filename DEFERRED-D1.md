# DEFERRED-D1 — newer-control overlay edges NOT backfilled (PROD-REPAIRS D1)

Branch: `aksi-structural-repairs`. This note records every D1 backfill edge that was **deliberately
deferred** rather than asserted into production. Principle applied: *under-repairing D1 is correct; injecting
an un-derivable or format-noisy edge into production is not.* Each deferred item below is mechanically
recoverable from the named source and is left for a follow-up pass / human review.

## What D1 DID apply (for context)
Backfilled **110 newer-control edges** into **10 overlays** (ccpa, colorado-ai-act, eu-ai-act, gdpr, hipaa,
imda-mgf, iso-27001, iso-42001, nist-ai-rmf, nist-csf), each carried **verbatim** from the matching
`aksi-ultra/research/<regime>.crosswalk.json` (coverage + verified unchanged; 0 promotions, verified by
`validate.py framework` F4 + a coverage/verified equality check). `cmmc-l2`, `fedramp`, `glba` already mapped
the newer controls (39-control overlays) and needed no additions.

The 15 newer controls: GOV-05, GOV-06, GOV-07, PR-09, PR-10, PR-11, PR-12, DE-05, DE-06, RS-04, RS-05, RS-06,
RC-03, PAY-01, PAY-02.

---

## Deferred A — non-standard file serialization (research exists; backfill is mechanical but would reformat)
These shipped overlays use a custom **inline-array** JSON style (e.g. `"triggered_by": ["DC-FIN"]` on one line)
that `json.dump` cannot reproduce, so a programmatic backfill would reformat the entire file (a large, noisy,
convention-breaking diff). The newer-control edges below **exist in research** and should be inserted with a
**format-preserving editor** (surgical insert), not a re-dump.

| Overlay | Research source | Deferred newer-control edges (available in research) |
|---|---|---|
| `dora` | `research/dora.crosswalk.json` | GOV-05, GOV-06, GOV-07, PR-09, PR-10, PR-11, PR-12, DE-05, DE-06, RS-04, RS-05, RS-06, RC-03 |
| `pci-dss-v4` | `research/pci-dss-v4.crosswalk.json` | GOV-05, GOV-06, PR-09, PR-11, PR-12, DE-06, RS-05, RC-03, **PAY-01, PAY-02** |
| `soc2` | `research/soc2.crosswalk.json` | GOV-05, GOV-06, GOV-07, PR-09, PR-10, PR-11, PR-12, DE-05, DE-06, RS-04, RS-05, RS-06, RC-03 |

## Deferred B — no research crosswalk exists (no mechanically-derivable source)
These shipped overlays have **no** matching `aksi-ultra/research` crosswalk, so no newer-control edge is
mechanically derivable. All 15 newer controls remain unmapped; they require authoring against the regime's
current text (REVIEW-FIRST) before any assertion.

| Overlay | Note |
|---|---|
| `mas-trm` | MAS Technology Risk Management (Singapore) — no research crosswalk; defer all newer controls. |
| `nis2` | EU NIS2 Directive — no research crosswalk; defer all newer controls. |
| `securities-mnpi` | SEC MNPI / Reg FD overlay — no research crosswalk; defer all newer controls. |

## Deferred C — D6 certification stubs (out of scope for this pass)
| Overlay | Note |
|---|---|
| `aiuc-1` | Cert stub mapping 0 controls (D6). `research/aiuc-1.crosswalk.json` exists (≈37 controls) and could fill it in a future **D6** pass — out of scope here (D1/D3/D5/D8 only). |
| `gov-contractor` | Cert stub, 0 controls, no research crosswalk (D6). Out of scope. |

## Deferred D — D3 scaffold overlays (built as wiring stubs; no requirement mappings)
The five D3 overlays with no research crosswalk were created as schema-valid **scaffolds** (`scaffold: true`,
empty `framework_mapping`, control wiring only). They assert NO requirement mappings and must be populated from
an authoritative source before any assertion.

| Overlay | Intended source |
|---|---|
| `agent-payments` | Activation overlay for the PAY family; author against agentic-payments / x402 + sanctions sources. |
| `agent-runtime-threats` | Threat-spine; populate from the six threat-taxonomy crosswalks (owasp-agentic, owasp-llm, mitre-atlas, mitre-attack-agent, google-saif, csa-aicm). |
| `csa_ccm` | CCM subset of `research/csa-aicm.crosswalk.json`. |
| `eu_gpai_code` | EU GPAI Code of Practice (voluntary; final 2025-07-10). |
| `fda_medical_device_cybersecurity` | FD&C 524B premarket cybersecurity slice of `research/fda-ai-device.crosswalk.json`. |

## Consequence — controls still with empty `regulatory_mappings`
**PAY-01, PAY-02** remain with empty `regulatory_mappings`: the only overlay that references them by trigger
(`agent-payments`) is a D3 scaffold with no requirement IDs, and the two regimes that map PAY in research
(`pci-dss-v4`) are in **Deferred A** (format). Resolving Deferred A (pci-dss-v4) and/or populating
`agent-payments` will populate PAY-01/PAY-02 traceability (re-run the D8 derivation afterward).

---

*Acceptance for the applied D1 edges: `validate.py framework` F4 (D8 symmetry) = symmetric; F5 = no unexpected
empty overlays; a coverage/verified equality check confirmed 0 promotions vs the research source.*
*Prepared on branch `aksi-structural-repairs` — not merged. Kevin merges.*
