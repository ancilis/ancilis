/** CLI module exports. */

export { formatStatus } from "./status.js";
export { migrateAndFormat, validateAndFormat } from "./validate.js";
export type { ConfigMigrateOptions, ConfigValidateOptions } from "./validate.js";
export { approveTool } from "./approve.js";
export { runDoctor } from "./doctor.js";
export type { DoctorResult } from "./doctor.js";
export { runReport } from "./report.js";
export type { ReportCommandOptions, ReportCommandResult } from "./report.js";
export { runRemediate } from "./remediate.js";
export type { RemediateCommandOptions, RemediateCommandResult } from "./remediate.js";
export { handleScan } from "./scan.js";
export type { ScanOptions, ControlResult2, EvaluationSummary } from "./scan.js";
export { handleEvidence, runEvidenceVerify, runEvidenceSessions, runEvidenceReset, runEvidenceImport } from "./evidence.js";
export { runConnect } from "./connect.js";
export type { ConnectOptions } from "./connect.js";
export { WatchRunner, getProducersForPaths } from "./watch.js";
export type { WatchRunnerOptions } from "./watch.js";
export { formatHeader, formatDelta, printScanResult, printSessionSummary } from "./watch-display.js";
export type { WatchControlResult } from "./watch-display.js";
export { runInit, detectFramework, sanitizeName } from "./init.js";
export type { InitOptions, DetectionResult } from "./init.js";
export { checkAndNotify, isCiEnvironment, isSuppressed, readCache, writeCache, shouldNotify, fetchLatestVersion } from "./version-check.js";
export { formatTelemetryStatus, readTelemetryStatus, setTelemetryEnabled, flushTelemetryEvents } from "../telemetry/index.js";
