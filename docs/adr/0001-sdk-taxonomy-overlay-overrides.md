# ADR 0001: SDK Taxonomy Overlay Overrides

## Status

Accepted for the AKSI v0.6 SDK migration tracked by [ANC-1614](/ANC/issues/ANC-1614).

## Context

The frozen AKSI v0.6 platform graph maps data classifications to every framework overlay that may be relevant. That platform graph is intentionally broad because the platform can ask follow-up questions, store tenant-specific posture, and route operators through review workflows.

The SDK activation resolver is a runtime contract for developers. It should auto-enable overlays only when the data class is a strong enough signal and the overlay is ready for default local use. Over-activating jurisdiction-specific overlays inside the SDK makes first-run output noisy, can imply obligations the developer did not declare, and weakens the adoption path for the runtime controls.

This decision touches the data-classification-driven overlay activation mechanism described in the patent disclosure log. The mechanism is unchanged; this ADR documents the product boundary between broad platform recommendations and conservative SDK defaults.

## Decision

The v0.6 asset generator may apply `SDK_TAXONOMY_OVERLAY_OVERRIDES` when copying taxonomy data from the platform graph into SDK shared assets.

The current SDK defaults are:

- `DC-BIO` activates `eu-ai-act`.
- `DC-CUI` activates `cmmc-l2`.
- `DC-FCI` activates `fedramp`.
- `DC-FIN` activates `glba` and `soc2`.
- `DC-GEN` activates no non-baseline overlays.
- `DC-GOV` activates `cmmc-l2` and `fedramp`.
- `DC-MNPI` activates `securities-mnpi`.
- `DC-NPI` activates `glba` and `soc2`.
- `DC-PII` activates `ccpa`, `gdpr`, and `soc2`.

All other platform taxonomy mappings are copied through normalization unless the generator explicitly overrides them.

## Consequences

SDK users get a conservative default activation surface that is closer to what can be enforced or explained locally.

The platform can remain broader than the SDK because it has richer tenant context and operator workflows.

Any future SDK/platform divergence in data-class-driven overlay activation must be documented in this ADR or a successor ADR, not only in generator comments.

## Follow-Ups

[ANC-2083](/ANC/issues/ANC-2083) tracks external positioning and reviewer-prompt alignment for the v0.6 canonical target after this SDK merge.
