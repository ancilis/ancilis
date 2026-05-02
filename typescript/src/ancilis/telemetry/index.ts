/** Anonymous, opt-in SDK usage telemetry. */

import { randomUUID } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir, platform, release } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline/promises";

const DEFAULT_ENDPOINT = "https://api.ancilis.ai/api/telemetry/events";
const FLUSH_INTERVAL_MS = 60 * 60 * 1000;
const MAX_BATCH_SIZE = 50;

const SKIP_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  ".ancilis",
  ".mypy_cache",
  ".pytest_cache",
  ".ruff_cache",
  ".venv",
  "__pycache__",
  "build",
  "coverage",
  "dist",
  "node_modules",
]);

export const TELEMETRY_EVENT_TYPES = [
  "scan_executed",
  "report_generated",
  "overlay_activated",
  "adapter_used",
  "cli_command",
] as const;

export type TelemetryEventType = typeof TELEMETRY_EVENT_TYPES[number];

export interface TelemetryConfig {
  enabled: boolean;
  installationId: string | null;
  endpoint: string;
  promptedAt: string | null;
}

export interface TelemetryStatus {
  enabled: boolean;
  effectiveEnabled: boolean;
  reason: string | null;
  installationId: string | null;
  endpoint: string;
  configPath: string;
  queuePath: string;
  queuedEvents: number;
  eventTypes: readonly TelemetryEventType[];
}

export interface TelemetryEvent {
  event_type: TelemetryEventType;
  timestamp: string;
  sdk_language: "typescript";
  sdk_version: string;
  runtime_version: string;
  os_platform: string;
  properties: Record<string, unknown>;
}

export interface TelemetryOptions {
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
  now?: Date;
  endpoint?: string;
  sdkVersion?: string;
  fetchImpl?: typeof fetch;
  force?: boolean;
  maxBatchSize?: number;
  flushIntervalMs?: number;
}

interface TelemetryState {
  lastAttemptAt: string | null;
}

function telemetryRoot(options: TelemetryOptions = {}): string {
  return join(options.homeDir ?? homedir(), ".ancilis");
}

export function telemetryConfigPath(options: TelemetryOptions = {}): string {
  return join(telemetryRoot(options), "config.toml");
}

export function telemetryQueuePath(options: TelemetryOptions = {}): string {
  return join(telemetryRoot(options), "telemetry", "events.ndjson");
}

function telemetryStatePath(options: TelemetryOptions = {}): string {
  return join(telemetryRoot(options), "telemetry", "state.json");
}

function ensureParent(path: string): void {
  mkdirSync(dirname(path), { recursive: true });
}

function quoteToml(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, "\\\"")}"`;
}

function parseTelemetryConfig(text: string): Partial<TelemetryConfig> {
  const parsed: Partial<TelemetryConfig> = {};
  let section = "";
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    const sectionMatch = line.match(/^\[([^\]]+)\]$/);
    if (sectionMatch) {
      section = sectionMatch[1] ?? "";
      continue;
    }
    if (section !== "telemetry") continue;
    const [rawKey, ...rawValueParts] = line.split("=");
    if (!rawKey || rawValueParts.length === 0) continue;
    const key = rawKey.trim();
    const rawValue = rawValueParts.join("=").trim();
    const value = rawValue.replace(/^"|"$/g, "");
    if (key === "enabled") parsed.enabled = rawValue === "true";
    if (key === "installation_id") parsed.installationId = value;
    if (key === "endpoint") parsed.endpoint = value;
    if (key === "prompted_at") parsed.promptedAt = value;
  }
  return parsed;
}

function writeTelemetryConfig(config: TelemetryConfig, options: TelemetryOptions = {}): void {
  const path = telemetryConfigPath(options);
  ensureParent(path);
  const lines = [
    "# Ancilis global SDK settings",
    "[telemetry]",
    `enabled = ${config.enabled ? "true" : "false"}`,
    ...(config.installationId === null ? [] : [`installation_id = ${quoteToml(config.installationId)}`]),
    `endpoint = ${quoteToml(config.endpoint)}`,
    `prompted_at = ${quoteToml(config.promptedAt ?? new Date().toISOString())}`,
    "",
  ];
  writeFileSync(path, lines.join("\n"), "utf-8");
}

export function isDoNotTrackEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const value = env.DO_NOT_TRACK ?? env.DNT;
  if (value === undefined) return false;
  return !["", "0", "false", "no", "off"].includes(value.toLowerCase());
}

export function readTelemetryConfig(options: TelemetryOptions = {}): TelemetryConfig {
  const env = options.env ?? process.env;
  const endpoint = options.endpoint ?? env.ANCILIS_TELEMETRY_ENDPOINT ?? DEFAULT_ENDPOINT;
  const path = telemetryConfigPath(options);
  if (!existsSync(path)) {
    return {
      enabled: false,
      installationId: null,
      endpoint,
      promptedAt: null,
    };
  }

  try {
    const parsed = parseTelemetryConfig(readFileSync(path, "utf-8"));
    return {
      enabled: parsed.enabled ?? false,
      installationId: parsed.installationId ?? null,
      endpoint: options.endpoint ?? env.ANCILIS_TELEMETRY_ENDPOINT ?? parsed.endpoint ?? DEFAULT_ENDPOINT,
      promptedAt: parsed.promptedAt ?? null,
    };
  } catch {
    return {
      enabled: false,
      installationId: null,
      endpoint,
      promptedAt: null,
    };
  }
}

export function setTelemetryEnabled(enabled: boolean, options: TelemetryOptions = {}): TelemetryConfig {
  const current = readTelemetryConfig(options);
  const config: TelemetryConfig = {
    enabled,
    installationId: enabled ? current.installationId ?? randomUUID() : current.installationId,
    endpoint: options.endpoint ?? current.endpoint,
    promptedAt: options.now?.toISOString() ?? current.promptedAt ?? new Date().toISOString(),
  };
  writeTelemetryConfig(config, options);
  return config;
}

function readQueueLines(options: TelemetryOptions = {}): string[] {
  const path = telemetryQueuePath(options);
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf-8").split(/\r?\n/).filter(line => line.trim().length > 0);
}

function queueEventCount(options: TelemetryOptions = {}): number {
  return readQueueLines(options).length;
}

export function readTelemetryStatus(options: TelemetryOptions = {}): TelemetryStatus {
  const config = readTelemetryConfig(options);
  const dnt = isDoNotTrackEnabled(options.env ?? process.env);
  const enabled = config.enabled && config.installationId !== null;
  return {
    enabled,
    effectiveEnabled: enabled && !dnt,
    reason: dnt ? "DO_NOT_TRACK is set" : enabled ? null : "telemetry is off",
    installationId: config.installationId,
    endpoint: config.endpoint,
    configPath: telemetryConfigPath(options),
    queuePath: telemetryQueuePath(options),
    queuedEvents: queueEventCount(options),
    eventTypes: TELEMETRY_EVENT_TYPES,
  };
}

export function formatTelemetryStatus(status: TelemetryStatus): string {
  const lines = [
    `Telemetry: ${status.effectiveEnabled ? "on" : "off"}`,
    status.reason ? `Reason: ${status.reason}` : null,
    `Config: ${status.configPath}`,
    `Queue: ${status.queuedEvents} event(s) at ${status.queuePath}`,
    `Endpoint: ${status.endpoint}`,
    "Collected event types:",
    ...status.eventTypes.map(eventType => `  - ${eventType}`),
    "",
    "No file paths, file contents, evidence data, email addresses, or API keys are collected.",
  ].filter((line): line is string => line !== null);
  return lines.join("\n");
}

function readTelemetryState(options: TelemetryOptions = {}): TelemetryState {
  const path = telemetryStatePath(options);
  if (!existsSync(path)) return { lastAttemptAt: null };
  try {
    const raw = JSON.parse(readFileSync(path, "utf-8")) as Partial<TelemetryState>;
    return { lastAttemptAt: typeof raw.lastAttemptAt === "string" ? raw.lastAttemptAt : null };
  } catch {
    return { lastAttemptAt: null };
  }
}

function writeTelemetryState(state: TelemetryState, options: TelemetryOptions = {}): void {
  const path = telemetryStatePath(options);
  ensureParent(path);
  writeFileSync(path, JSON.stringify(state, null, 2), "utf-8");
}

function rewriteQueue(lines: string[], options: TelemetryOptions = {}): void {
  const path = telemetryQueuePath(options);
  if (lines.length === 0) {
    rmSync(path, { force: true });
    return;
  }
  ensureParent(path);
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, `${lines.join("\n")}\n`, "utf-8");
  renameSync(tmp, path);
}

function flushAllowed(options: TelemetryOptions = {}): boolean {
  if (options.force) return true;
  const state = readTelemetryState(options);
  if (state.lastAttemptAt === null) return true;
  const last = Date.parse(state.lastAttemptAt);
  if (Number.isNaN(last)) return true;
  const now = options.now?.getTime() ?? Date.now();
  return now - last >= (options.flushIntervalMs ?? FLUSH_INTERVAL_MS);
}

function telemetryEvent(
  eventType: TelemetryEventType,
  properties: Record<string, unknown>,
  options: TelemetryOptions = {},
): TelemetryEvent {
  return {
    event_type: eventType,
    timestamp: (options.now ?? new Date()).toISOString(),
    sdk_language: "typescript",
    sdk_version: options.sdkVersion ?? "0.1.0-preview.1",
    runtime_version: process.version,
    os_platform: `${platform()} ${release()}`,
    properties,
  };
}

export async function recordTelemetryEvent(
  eventType: TelemetryEventType,
  properties: Record<string, unknown> = {},
  options: TelemetryOptions = {},
): Promise<void> {
  const status = readTelemetryStatus(options);
  if (!status.effectiveEnabled || status.installationId === null) return;

  const path = telemetryQueuePath(options);
  ensureParent(path);
  appendFileSync(path, `${JSON.stringify(telemetryEvent(eventType, properties, options))}\n`, "utf-8");
  void flushTelemetryEvents(options).catch(() => {});
}

export function recordAdapterUsed(adapterType: string): void {
  void recordTelemetryEvent("adapter_used", { adapter_type: adapterType }).catch(() => {});
}

export async function flushTelemetryEvents(options: TelemetryOptions = {}): Promise<{ sent: boolean; count: number; error?: string }> {
  const status = readTelemetryStatus(options);
  if (!status.effectiveEnabled || status.installationId === null) return { sent: false, count: 0 };
  if (!flushAllowed(options)) return { sent: false, count: 0 };

  const lines = readQueueLines(options);
  if (lines.length === 0) return { sent: false, count: 0 };

  const batchSize = options.maxBatchSize ?? MAX_BATCH_SIZE;
  const batch = lines.slice(0, batchSize).map(line => JSON.parse(line) as TelemetryEvent);
  const remaining = lines.slice(batch.length);
  writeTelemetryState({ lastAttemptAt: (options.now ?? new Date()).toISOString() }, options);

  try {
    const fetchImpl = options.fetchImpl ?? globalThis.fetch;
    const signal = AbortSignal.timeout(2000);
    const response = await fetchImpl(status.endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        installation_id: status.installationId,
        events: batch,
      }),
      signal,
    });
    if (!response.ok) return { sent: false, count: 0, error: `HTTP ${response.status}` };
    rewriteQueue(remaining, options);
    return { sent: true, count: batch.length };
  } catch (error: unknown) {
    return { sent: false, count: 0, error: error instanceof Error ? error.message : String(error) };
  }
}

export async function maybePromptForTelemetryConsent(options: TelemetryOptions & {
  input?: NodeJS.ReadableStream & { isTTY?: boolean };
  output?: NodeJS.WritableStream & { isTTY?: boolean };
} = {}): Promise<boolean> {
  const env = options.env ?? process.env;
  if (isDoNotTrackEnabled(env) || env.CI || env.ANCILIS_TELEMETRY_DISABLE_PROMPT) return false;

  const current = readTelemetryConfig(options);
  if (current.promptedAt !== null || current.installationId !== null) return false;

  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  if (!input.isTTY || !output.isTTY) return false;

  const rl = createInterface({ input, output });
  try {
    const answer = await rl.question("Help improve Ancilis by sharing anonymous usage data? (y/N) ");
    const enabled = answer.trim().toLowerCase().startsWith("y");
    setTelemetryEnabled(enabled, options);
    return enabled;
  } finally {
    rl.close();
  }
}

export function bucketCount(count: number): "0" | "1-10" | "10-100" | "100+" {
  if (count <= 0) return "0";
  if (count <= 10) return "1-10";
  if (count <= 100) return "10-100";
  return "100+";
}

export function bucketDuration(durationMs: number): "<1s" | "1-5s" | "5-30s" | "30s+" {
  if (durationMs < 1000) return "<1s";
  if (durationMs < 5000) return "1-5s";
  if (durationMs < 30000) return "5-30s";
  return "30s+";
}

export function countProjectFiles(root: string, limit = 101): number {
  let count = 0;
  const visit = (dir: string): void => {
    if (count >= limit) return;
    let dirEntries;
    try {
      dirEntries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of dirEntries) {
      if (count >= limit) return;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) visit(join(dir, entry.name));
        continue;
      }
      if (entry.isFile()) count += 1;
    }
  };
  visit(root);
  return count;
}
