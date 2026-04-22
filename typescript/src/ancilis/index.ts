/** Ancilis — runtime policy enforcement for AI agents. */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, parse } from "node:path";
import { packageRootFrom } from "./shared-path.js";

function packageJsonPathFrom(importMetaUrl: string): string {
  let current = packageRootFrom(importMetaUrl);
  const { root } = parse(current);

  while (true) {
    const candidate = join(current, "package.json");
    if (existsSync(candidate)) return candidate;
    if (current === root) throw new Error(`Could not locate package.json from ${importMetaUrl}`);
    current = dirname(current);
  }
}

function readPackageVersion(): string {
  try {
    const pkg = JSON.parse(
      readFileSync(packageJsonPathFrom(import.meta.url), "utf-8"),
    ) as { version?: unknown };
    if (typeof pkg.version === "string" && pkg.version.length > 0) return pkg.version;
  } catch {
    // Keep root imports usable in unusual test/build contexts without package metadata.
  }
  return "0.0.0";
}

export const __version__ = readPackageVersion();

export { Ancilis } from "./facade.js";
export type { AncilisLoadOptions, AncilisToolOptions, AncilisToolRun } from "./facade.js";

export { loadConfig, formatResolvedConfig } from "./config/index.js";
export type { ResolvedConfig, ControlStatus, OverlayActivation, UnavailableOverlay, LoadConfigOptions } from "./config/index.js";

export { Engine, ToolRegistry, DE04IntegrityEvaluator } from "./engine/index.js";
export { ToolStatus } from "./engine/index.js";
export type { Action, ToolInfo, ActionParameters, ActionContext, ControlResult, EvaluationResult, ToolEntry, ControlEvaluator, RateTracker, DE04StoreAdapter } from "./engine/index.js";

export { AncilisMiddleware, BlockedToolCallError, scanResponse } from "./middleware/index.js";
export type { AncilisMiddlewareOptions, McpClientLike, ScanResult, EncryptionFinding, DriftEvent } from "./middleware/index.js";

export { EvidenceStore, GENESIS_SEED, canonicalPayload, computeHash } from "./evidence/index.js";
export type { EvidenceRecord } from "./evidence/index.js";

export {
  ActivationResolver,
  BASELINE_CONTROLS,
  EXTENDED_CONTROLS,
  ClassificationAdvisory,
  loadCertificationProfile,
  loadCertificationProfiles,
  loadControlDefinitions,
  loadOverlayProfiles,
} from "./activation/index.js";
export type { ActivationSpec, ClassificationRecommendation, CertificationUpgradeAdvisory, PatternDetection } from "./activation/index.js";

export { PR05AuditEvaluator, PR06ConfigBaselineEvaluator, PR07TransportEvaluator, PR08InputEvaluator, DE01BaselineEvaluator } from "./controls/index.js";
export {
  PR01IdentityEvaluator,
  PR02ScopeEvaluator,
  PR03ProvenanceEvaluator,
  PR04ExposureEvaluator,
  GOV01PolicyEvaluator,
  GOV02OwnershipEvaluator,
  ID01InventoryEvaluator,
} from "./engine/evaluators/index.js";
export type { BaselineWindow, DeviationFlag } from "./controls/index.js";

export { ReportGenerator, parsePeriod, renderTerminal, renderMarkdown, renderNdjson, renderCsv, renderOscalJson, renderPdf } from "./report/index.js";
export type { ReportData, EvidenceSummary, RenderPdfOptions, RenderPdfResult } from "./report/index.js";

export { BaselineManager } from "./baselines/index.js";
export type { Baseline, ControlSnapshot, ControlDrift, DriftReport, DriftSummary, EvidenceDelta } from "./baselines/index.js";

export { OVERLAY_ID_ALIASES, normalizeOverlayId, normalizeOverlayIds } from "./overlays/index.js";

export { MockEvidenceStore, FakeProducer, ScanResult as ComplianceScanResult, ComplianceScenarios } from "./testing/index.js";
export {
  assertControlPasses,
  assertControlFails,
  assertControlFlags,
  assertPostureAbove,
  assertDecisionAllows,
  assertDecisionBlocks,
  makeTestConfig,
  makeAction,
} from "./testing/index.js";
export type { MakeTestConfigOptions, MakeActionOptions } from "./testing/index.js";

export { SarifImporter } from "./importers/sarif.js";
export { CycloneDxImporter } from "./importers/cyclonedx.js";

export { PluginRegistry } from "./plugins/index.js";
export type {
  AdapterPlugin,
  OverlayPlugin,
  PluginContext,
  PluginDiscoveryOptions,
  PluginMetadata,
  PluginRecord,
  PluginType,
  ProducerPlugin,
} from "./plugins/index.js";

export { DependencyScanner, ManifestDetector, OSVClient } from "./deps/index.js";
export type { Dependency, Manifest, Vuln } from "./deps/index.js";

export { scanDependencies, detectDependencies, buildSbom, queryOsvBatch } from "./dependencies/index.js";
export type { VulnerabilityFinding, CycloneDxBom, CycloneDxComponent, DetectionResult, DependencyScanResult } from "./dependencies/index.js";

export { formatStatus, validateAndFormat, approveTool, runDoctor, runReport, handleScan, runEvidenceVerify, handlePlugins, runPluginsList, runPluginsValidate } from "./cli/index.js";
export type { DoctorResult, PluginsCommandResult, PluginsListOptions, PluginsValidateOptions, ReportCommandOptions, ReportCommandResult } from "./cli/index.js";
export {
  BedrockActionProducer,
  BedrockAdapter,
  CLIActionProducer,
  HTTPActionProducer,
  MCPActionProducer,
  ToolActionProducer,
  BlockedActionError,
  ProducerType,
  wrapTool,
  tool,
  evaluateAndExecute,
} from "./producers/index.js";
export type {
  ActionProducer,
  AnyFn,
  BedrockInvocation,
  BedrockObservation,
  CLIExecutionResult,
  CLIInvocation,
  EvaluateAndExecuteOptions,
  HTTPExecutionResult,
  HTTPObservation,
  HTTPRequest,
  MCPInvocation,
  ToolExecutionResult,
  ToolInvocation,
  ToolWrapOptions,
} from "./producers/index.js";

export {
  AncilisError,
  AncilisWarning,
  ConnectionError,
  ConfigError,
  OverlayNotFoundError,
  StorageError,
  AuthError,
  RateLimitError,
  ScanError,
  UnsupportedFileError,
  UploadError,
  VersionError,
  warnNoOverlays,
  warnSdkUpdate,
  warnStoreSize,
  red,
  yellow,
  blue,
} from "./errors.js";
