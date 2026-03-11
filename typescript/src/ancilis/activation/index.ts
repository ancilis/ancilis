/** Activation resolver (Unit 5). */

export { ActivationResolver, BASELINE_CONTROLS, EXTENDED_CONTROLS } from "./resolver.js";
export type { ActivationSpec } from "./resolver.js";
export { ClassificationAdvisory } from "./advisory.js";
export type { ClassificationRecommendation, CertificationUpgradeAdvisory, PatternDetection } from "./advisory.js";
export { loadCertificationProfile, loadCertificationProfiles, loadControlDefinitions, loadOverlayProfiles } from "./loader.js";
