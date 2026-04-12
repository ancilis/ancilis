/** Dependency vulnerability scanning — manifest parsing and OSV.dev lookup. */

export { DependencyScanner } from "./scanner.js";
export { ManifestDetector } from "./manifest.js";
export { OSVClient } from "./osv.js";
export type { Dependency, Manifest, Vuln } from "./types.js";
