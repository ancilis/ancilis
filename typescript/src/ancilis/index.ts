/** Ancilis — runtime policy enforcement for AI agents. */

export { loadConfig, formatResolvedConfig } from "./config/index.js";
export type { ResolvedConfig, ControlStatus, OverlayActivation, UnavailableOverlay, LoadConfigOptions } from "./config/index.js";

export { Engine, ToolRegistry } from "./engine/index.js";
export type { Action, ToolInfo, ActionParameters, ActionContext, ControlResult, EvaluationResult, ToolEntry, ControlEvaluator, RateTracker } from "./engine/index.js";

export { AncilisMiddleware, BlockedToolCallError } from "./middleware/index.js";
export type { AncilisMiddlewareOptions, McpClientLike, ScanResult, EncryptionFinding, DriftEvent } from "./middleware/index.js";

export { EvidenceStore, GENESIS_SEED, canonicalPayload, computeHash } from "./evidence/index.js";
export type { EvidenceRecord } from "./evidence/index.js";

export { ActivationResolver, BASELINE_CONTROLS, EXTENDED_CONTROLS, ClassificationAdvisory } from "./activation/index.js";
export type { ActivationSpec, ClassificationRecommendation, CertificationUpgradeAdvisory, PatternDetection } from "./activation/index.js";

export { PR05AuditEvaluator, DE01BaselineEvaluator } from "./controls/index.js";
export type { BaselineWindow, DeviationFlag } from "./controls/index.js";

export { ReportGenerator, parsePeriod, renderTerminal, renderMarkdown, renderNdjson, renderCsv, renderOscalJson, renderPdf } from "./report/index.js";
export type { ReportData, EvidenceSummary, RenderPdfOptions } from "./report/index.js";

export { formatStatus, validateAndFormat, approveTool, runDoctor, runReport } from "./cli/index.js";
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
