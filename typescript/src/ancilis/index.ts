/** Ancilis — runtime policy enforcement for AI agents. */

export { loadConfig, formatResolvedConfig } from "./config/index.js";
export type { ResolvedConfig, ControlStatus, OverlayActivation, UnavailableOverlay, LoadConfigOptions } from "./config/index.js";

export { Engine, ToolRegistry } from "./engine/index.js";
export { ToolStatus } from "./engine/index.js";
export type { Action, ToolInfo, ActionParameters, ActionContext, ControlResult, EvaluationResult, ToolEntry, ControlEvaluator, RateTracker } from "./engine/index.js";

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

export { PR05AuditEvaluator, DE01BaselineEvaluator } from "./controls/index.js";
export {
  PR01IdentityEvaluator,
  PR02ScopeEvaluator,
  PR03ProvenanceEvaluator,
  PR04ExposureEvaluator,
  PR07TransportEvaluator,
  PR08InputEvaluator,
  GOV01PolicyEvaluator,
  GOV02OwnershipEvaluator,
  ID01InventoryEvaluator,
  DE04IntegrityEvaluator,
} from "./engine/evaluators/index.js";
export type { DE04StoreAdapter } from "./engine/evaluators/index.js";
export type { BaselineWindow, DeviationFlag } from "./controls/index.js";

export { ReportGenerator, parsePeriod, renderTerminal, renderMarkdown, renderNdjson, renderCsv, renderOscalJson, renderPdf } from "./report/index.js";
export type { ReportData, EvidenceSummary, RenderPdfOptions, RenderPdfResult } from "./report/index.js";

export { BaselineManager } from "./baselines/index.js";
export type { Baseline, ControlSnapshot, ControlDrift, DriftReport, DriftSummary, EvidenceDelta } from "./baselines/index.js";

export { SarifImporter } from "./importers/sarif.js";
export { CycloneDxImporter } from "./importers/cyclonedx.js";

export { DependencyScanner, ManifestDetector, OSVClient } from "./deps/index.js";
export type { Dependency, Manifest, Vuln } from "./deps/index.js";

export { scanDependencies, detectDependencies, buildSbom, queryOsvBatch } from "./dependencies/index.js";
export type { VulnerabilityFinding, CycloneDxBom, CycloneDxComponent, DetectionResult, DependencyScanResult } from "./dependencies/index.js";

export { formatStatus, validateAndFormat, approveTool, runDoctor, runReport, handleScan } from "./cli/index.js";
export type { DoctorResult, ReportCommandOptions, ReportCommandResult } from "./cli/index.js";
export {
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
