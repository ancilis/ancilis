/** BedrockActionProducer — normalizes AWS Bedrock Runtime calls into Actions. */

import { createHash, randomUUID } from "node:crypto";
import type { ResolvedConfig } from "../config/index.js";
import type { Action } from "../engine/action.js";
import { Engine } from "../engine/engine.js";
import { ToolRegistry, ToolStatus } from "../engine/registry.js";
import type { ToolEntry } from "../engine/registry.js";
import type { EvaluationResult } from "../engine/result.js";
import { matchesToolList } from "../engine/tool-matching.js";
import type { EvidenceRecord } from "../evidence/record.js";
import { EvidenceStore } from "../evidence/store.js";
import { canonicalJsonStringify } from "../evidence/chain.js";
import { ProducerType } from "./protocol.js";

const PROVIDER = "aws-bedrock";
const PRODUCER_VERSION = "0.1.0";
const SENSITIVE_KEY_PARTS = [
  "access_key",
  "accesskey",
  "authorization",
  "canonical_request",
  "credential",
  "secret",
  "security_token",
  "session_token",
  "signature",
  "signed_headers",
  "x-amz-security-token",
];
const SAFE_AUTH_MODES = new Set(["iam", "session", "role"]);

type UnknownRecord = Record<string, unknown>;

export interface BedrockInvocation extends UnknownRecord {
  operation?: string;
  operationName?: string;
  operation_name?: string;
  modelId?: string;
  model_id?: string;
  region?: string;
  regionName?: string;
  region_name?: string;
  requestBody?: unknown;
  request_body?: unknown;
  responseBody?: unknown;
  response_body?: unknown;
  streamChunks?: unknown[];
  stream_chunks?: unknown[];
  responseStream?: unknown[];
  response_stream?: unknown[];
  input?: UnknownRecord;
  output?: UnknownRecord;
  response?: UnknownRecord;
  httpStatus?: number;
  http_status?: number;
  requestId?: string;
  request_id?: string;
  latencyMs?: number;
  latency_ms?: number;
  duration_ms?: number;
  headers?: Record<string, unknown>;
  responseMetadata?: UnknownRecord;
  response_metadata?: UnknownRecord;
  agentId?: string;
  agent_id?: string;
  agent?: string;
  agent_name?: string;
  authMode?: string;
  auth_mode?: string;
}

export interface BedrockObservation {
  action: Action;
  evaluation: EvaluationResult;
  evidence: EvidenceRecord;
}

interface NormalizedInvocation {
  operation: string;
  modelId: string;
  region: string | null;
  requestBody: unknown;
  responseBody: unknown;
  streamChunks: unknown[] | null;
  httpStatus: number | null;
  requestId: string | null;
  latencyMs: number | null;
  headers: Record<string, unknown>;
  responseMetadata: Record<string, unknown>;
  agentId: string;
  authMode: string | null;
}

interface ModelMetadata {
  id: string;
  provider: string;
  family: string;
  inference_profile_arn?: string;
}

export class BedrockActionProducer {
  private _config: ResolvedConfig;
  private _engine: Engine;
  private _registry: ToolRegistry;
  private _evidenceStore: EvidenceStore;
  private _sessionId: string = randomUUID();

  constructor(
    config: ResolvedConfig,
    engine: Engine,
    registry?: ToolRegistry,
    evidenceStore?: EvidenceStore,
  ) {
    this._config = config;
    this._engine = engine;
    this._registry = registry ?? engine.registry;
    this._evidenceStore = evidenceStore ?? new EvidenceStore(config);
  }

  get producerType(): ProducerType { return ProducerType.FRAMEWORK; }
  get producerVersion(): string { return PRODUCER_VERSION; }
  get sessionId(): string { return this._sessionId; }

  translate(rawInvocation: unknown): Action {
    const invocation = normalizeInvocation(rawInvocation, this._config.agentName);
    const usage = extractUsage(invocation.responseBody);
    let streamRequestId: string | null = null;
    let streamChunkCount = 0;

    if (invocation.streamChunks) {
      const streamUsage = extractStreamUsage(invocation.streamChunks);
      Object.assign(usage, streamUsage.usage);
      streamRequestId = streamUsage.requestId;
      streamChunkCount = streamUsage.chunkCount;
    }

    const requestId =
      invocation.requestId ??
      streamRequestId ??
      metadataRequestId(invocation.responseMetadata) ??
      headerValue(invocation.headers, "x-amzn-requestid");
    const region = invocation.region ?? regionFromModelId(invocation.modelId);
    const endpoint = endpointFor(region);
    const model = modelMetadata(invocation.modelId);
    const authMode = resolveAuthMode(invocation, invocation.headers);

    const payload: Record<string, unknown> = {
      provider: PROVIDER,
      operation: invocation.operation,
      model_id: invocation.modelId,
      region,
      destination: endpoint,
      http_status: invocation.httpStatus,
      request_id: requestId,
      latency_ms: invocation.latencyMs,
      streaming: invocation.operation === "InvokeModelWithResponseStream" || invocation.streamChunks !== null,
      model,
      deployment: {
        provider: PROVIDER,
        region,
        model_id: invocation.modelId,
        model_family: model.family,
      },
      request: {
        body_present: invocation.requestBody !== undefined && invocation.requestBody !== null,
        body_keys: bodyKeys(invocation.requestBody),
      },
      response: {
        body_present: invocation.responseBody !== undefined && invocation.responseBody !== null,
        body_keys: bodyKeys(invocation.responseBody),
      },
    };
    const deployment = payload["deployment"] as Record<string, unknown>;
    if (model.inference_profile_arn) {
      deployment["inference_profile_arn"] = model.inference_profile_arn;
    }
    if (authMode) payload["auth_mode"] = authMode;
    if (usage.input_tokens !== undefined) payload["input_tokens"] = usage.input_tokens;
    if (usage.output_tokens !== undefined) payload["output_tokens"] = usage.output_tokens;
    if (payload["streaming"] === true) payload["stream"] = { chunk_count: streamChunkCount };

    const toolName = toolNameFor(invocation.operation);
    const entry = this._registry.lookup(toolName);
    const parameterHash = createHash("sha256")
      .update(canonicalJsonStringify(payload))
      .digest("hex");

    return {
      actionId: randomUUID(),
      timestamp: new Date().toISOString(),
      agentId: invocation.agentId,
      sourceType: this.producerType,
      producerType: this.producerType,
      producerVersion: this.producerVersion,
      agentOwner: this._config.agentOwner ?? null,
      actionType: "api_request",
      tool: {
        name: toolName,
        server: endpoint,
        descriptionHash: entry?.descriptionHash ?? null,
      },
      parameters: { raw: payload, parameterHash },
      context: {
        sessionId: this._sessionId,
        dataClassifications: buildDataClassificationCodes(this._config),
        activeOverlays: [...this._config.activeOverlays.keys()],
      },
    };
  }

  async observe(rawInvocation: unknown): Promise<BedrockObservation> {
    const normalized = normalizeInvocation(rawInvocation, this._config.agentName);
    const toolName = this.ensureRegistered(normalized.operation);
    const action = this.translate(rawInvocation);
    const evaluation = this._engine.evaluate(action);
    const evidence = await this._evidenceStore.store(
      evaluation,
      toolName,
      outputSummary(action),
    );
    return { action, evaluation, evidence };
  }

  computeToolHash(toolIdentifier: unknown): string {
    return createHash("sha256").update(String(toolIdentifier)).digest("hex");
  }

  registerTools(registry: ToolRegistry): string[] {
    const registered: string[] = [];
    const now = new Date().toISOString();
    for (const operation of ["InvokeModel", "InvokeModelWithResponseStream"]) {
      const name = toolNameFor(operation);
      registry.register({
        name,
        descriptionHash: this.computeToolHash(name),
        status: ToolStatus.OBSERVED,
        firstSeen: now,
        statusChanged: now,
      } satisfies ToolEntry);
      registered.push(name);
    }
    return registered;
  }

  private ensureRegistered(operation: string): string {
    const name = toolNameFor(operation);
    if (this._registry.lookup(name)) return name;
    const status = matchesToolList(name, this._config.toolsAllowed)
      ? ToolStatus.APPROVED
      : ToolStatus.OBSERVED;
    const now = new Date().toISOString();
    this._registry.register({
      name,
      descriptionHash: this.computeToolHash(name),
      status,
      approvedBy: status === ToolStatus.APPROVED ? "config" : null,
      firstSeen: now,
      statusChanged: now,
    } satisfies ToolEntry);
    return name;
  }
}

export const BedrockAdapter = BedrockActionProducer;

function normalizeInvocation(rawInvocation: unknown, defaultAgentId: string): NormalizedInvocation {
  const raw = isRecord(rawInvocation) ? rawInvocation : {};
  const input = firstRecord(valueAt(raw, "input"));
  const output = firstRecord(valueAt(raw, "output"));
  const response = firstRecord(valueAt(raw, "response"));
  const responseMetadata = firstRecord(
    valueAt(raw, "responseMetadata"),
    valueAt(raw, "response_metadata"),
    valueAt(raw, "ResponseMetadata"),
    valueAt(output, "$metadata"),
    valueAt(response, "$metadata"),
    valueAt(response, "ResponseMetadata"),
  );
  const headers = firstRecord(
    valueAt(raw, "headers"),
    valueAt(raw, "request_headers"),
    valueAt(responseMetadata, "HTTPHeaders"),
    valueAt(responseMetadata, "httpHeaders"),
  );
  const responseBody =
    firstPresent(raw, "responseBody", "response_body") ??
    firstPresent(output, "body", "Body", "responseBody", "response_body") ??
    firstPresent(response, "body", "Body", "responseBody", "response_body");
  const operation =
    optionalString(firstPresent(raw, "operation", "operationName", "operation_name")) ??
    operationFromCommand(rawInvocation) ??
    "InvokeModel";
  const modelId =
    optionalString(firstPresent(raw, "modelId", "model_id", "model")) ??
    optionalString(firstPresent(input, "modelId", "model_id", "model")) ??
    "unknown-model";

  return {
    operation,
    modelId,
    region: optionalString(firstPresent(raw, "region", "regionName", "region_name")),
    requestBody:
      firstPresent(raw, "requestBody", "request_body", "body") ??
      firstPresent(input, "body", "Body", "requestBody", "request_body"),
    responseBody,
    streamChunks: asArray(firstPresent(raw, "streamChunks", "stream_chunks", "responseStream", "response_stream") ?? firstPresent(output, "body")),
    httpStatus:
      optionalNumber(firstPresent(raw, "httpStatus", "http_status", "status_code")) ??
      metadataStatusCode(responseMetadata),
    requestId:
      optionalString(firstPresent(raw, "requestId", "request_id")) ??
      metadataRequestId(responseMetadata),
    latencyMs: optionalNumber(firstPresent(raw, "latencyMs", "latency_ms", "duration_ms")),
    headers,
    responseMetadata,
    agentId:
      optionalString(firstPresent(raw, "agentId", "agent_id", "agent", "agent_name")) ??
      defaultAgentId,
    authMode:
      optionalString(firstPresent(raw, "authMode", "auth_mode")) ??
      nestedAuthMode(raw),
  };
}

function toolNameFor(operation: string): string {
  return `${PROVIDER}:${operation}`;
}

function endpointFor(region: string | null): string {
  return region ? `bedrock-runtime.${region}.amazonaws.com` : "bedrock-runtime.amazonaws.com";
}

function modelMetadata(modelId: string): ModelMetadata {
  const inferenceProfileArn = modelId.includes(":inference-profile/") ? modelId : undefined;
  let modelReference = inferenceProfileArn ? modelId.split("/").pop() ?? modelId : modelId;
  if (modelReference.startsWith("us.")) modelReference = modelReference.slice(3);
  const provider = modelReference.includes(".") ? modelReference.split(".")[0] ?? "unknown" : "unknown";
  let family = "unknown";
  if (modelReference.startsWith("anthropic.claude")) {
    family = "anthropic.claude";
  } else if (modelReference.startsWith("amazon.titan")) {
    family = "amazon.titan";
  } else if (modelReference.includes(".")) {
    family = modelReference.split(".").slice(0, 2).join(".");
  }

  const metadata: ModelMetadata = { id: modelId, provider, family };
  if (inferenceProfileArn) metadata.inference_profile_arn = inferenceProfileArn;
  return metadata;
}

function extractUsage(body: unknown): Record<string, number> {
  const parsed = parseBody(body);
  if (!isRecord(parsed)) return {};

  const usage = valueAt(parsed, "usage");
  if (isRecord(usage)) {
    return tokenUsage(usage, ["input_tokens", "inputTokens", "inputTokenCount"], ["output_tokens", "outputTokens", "outputTokenCount"]);
  }

  const tokenUsageData = tokenUsage(
    parsed,
    ["input_tokens", "inputTokens", "inputTokenCount", "inputTextTokenCount"],
    ["output_tokens", "outputTokens", "outputTokenCount"],
  );
  if (tokenUsageData.output_tokens === undefined) {
    const results = valueAt(parsed, "results");
    if (Array.isArray(results)) {
      let outputTokens = 0;
      let found = false;
      for (const item of results) {
        if (!isRecord(item)) continue;
        const tokenCount = optionalNumber(valueAt(item, "tokenCount"));
        if (tokenCount !== null) {
          outputTokens += tokenCount;
          found = true;
        }
      }
      if (found) tokenUsageData.output_tokens = outputTokens;
    }
  }
  return tokenUsageData;
}

function extractStreamUsage(chunks: unknown[]): {
  usage: Record<string, number>;
  requestId: string | null;
  chunkCount: number;
} {
  const usage: Record<string, number> = {};
  let requestId: string | null = null;
  let chunkCount = 0;
  for (const chunk of chunks) {
    chunkCount += 1;
    const parsedChunk = parseStreamChunk(chunk);
    if (!isRecord(parsedChunk)) continue;
    Object.assign(usage, extractUsage(parsedChunk));
    if (Object.keys(usage).length === 0) {
      const metrics = valueAt(parsedChunk, "amazon-bedrock-invocationMetrics");
      if (isRecord(metrics)) {
        Object.assign(usage, tokenUsage(metrics, ["inputTokenCount", "input_tokens"], ["outputTokenCount", "output_tokens"]));
      }
    }
    const metadata = valueAt(parsedChunk, "metadata");
    if (isRecord(metadata)) {
      Object.assign(usage, extractUsage(metadata));
      requestId ??= optionalString(firstPresent(metadata, "request_id", "requestId", "RequestId"));
    }
  }
  return { usage, requestId, chunkCount };
}

function parseStreamChunk(chunk: unknown): unknown {
  if (isRecord(chunk)) {
    if ("metadata" in chunk) return chunk;
    const chunkPayload = valueAt(chunk, "chunk");
    if (isRecord(chunkPayload) && "bytes" in chunkPayload) {
      return parseBody(valueAt(chunkPayload, "bytes"));
    }
    if ("bytes" in chunk) return parseBody(valueAt(chunk, "bytes"));
  }
  return parseBody(chunk);
}

function parseBody(body: unknown): unknown {
  if (body === null || body === undefined) return null;
  if (body instanceof Uint8Array) {
    try {
      return JSON.parse(Buffer.from(body).toString("utf-8"));
    } catch {
      return null;
    }
  }
  if (isRecord(body)) return body;
  if (typeof body === "string") {
    try {
      return JSON.parse(body);
    } catch {
      return null;
    }
  }
  return null;
}

function bodyKeys(body: unknown): string[] {
  const parsed = parseBody(body);
  if (!isRecord(parsed)) return [];
  return Object.keys(parsed)
    .filter(key => !isSensitiveKey(key))
    .sort();
}

function tokenUsage(data: UnknownRecord, inputKeys: string[], outputKeys: string[]): Record<string, number> {
  const usage: Record<string, number> = {};
  const inputTokens = firstNumber(data, inputKeys);
  const outputTokens = firstNumber(data, outputKeys);
  if (inputTokens !== null) usage["input_tokens"] = inputTokens;
  if (outputTokens !== null) usage["output_tokens"] = outputTokens;
  return usage;
}

function firstNumber(data: UnknownRecord, keys: string[]): number | null {
  for (const key of keys) {
    const value = optionalNumber(valueAt(data, key));
    if (value !== null) return value;
  }
  return null;
}

function resolveAuthMode(invocation: NormalizedInvocation, headers: Record<string, unknown>): string | null {
  if (invocation.authMode) {
    const explicitMode = safeAuthMode(invocation.authMode);
    if (explicitMode) return explicitMode;
  }
  if (headerValue(headers, "x-amz-security-token")) return "session";
  const authorization = headerValue(headers, "authorization");
  if (authorization?.includes("AWS4-HMAC-SHA256")) return "iam";
  return null;
}

function safeAuthMode(value: string): string | null {
  const mode = value.trim().toLowerCase().replaceAll("_", "-");
  return SAFE_AUTH_MODES.has(mode) ? mode : null;
}

function nestedAuthMode(raw: UnknownRecord): string | null {
  const auth = valueAt(raw, "auth");
  if (!isRecord(auth)) return null;
  return optionalString(firstPresent(auth, "mode", "authMode", "auth_mode"));
}

function metadataStatusCode(metadata: UnknownRecord): number | null {
  return optionalNumber(firstPresent(metadata, "HTTPStatusCode", "httpStatusCode", "http_status"));
}

function metadataRequestId(metadata: UnknownRecord): string | null {
  return optionalString(firstPresent(metadata, "RequestId", "requestId", "request_id"));
}

function headerValue(headers: Record<string, unknown>, key: string): string | null {
  for (const [headerKey, value] of Object.entries(headers)) {
    if (headerKey.toLowerCase() === key.toLowerCase()) return String(value);
  }
  return null;
}

function regionFromModelId(modelId: string): string | null {
  if (!modelId.startsWith("arn:")) return null;
  const parts = modelId.split(":");
  return parts.length > 3 && parts[3] ? parts[3] : null;
}

function operationFromCommand(rawInvocation: unknown): string | null {
  if (!rawInvocation || typeof rawInvocation !== "object") return null;
  const ctor = (rawInvocation as { constructor?: { name?: string } }).constructor?.name;
  if (ctor === "InvokeModelCommand" || ctor === "InvokeModelWithResponseStreamCommand") {
    return ctor.replace(/Command$/, "");
  }
  return null;
}

function valueAt(data: unknown, key: string): unknown {
  if (!isRecord(data)) return undefined;
  return data[key];
}

function firstPresent(data: unknown, ...keys: string[]): unknown {
  if (!isRecord(data)) return undefined;
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(data, key)) return data[key];
  }
  return undefined;
}

function firstRecord(...values: unknown[]): Record<string, unknown> {
  for (const value of values) {
    if (isRecord(value)) return { ...value };
  }
  return {};
}

function asArray(value: unknown): unknown[] | null {
  return Array.isArray(value) ? value : null;
}

function optionalString(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return String(value);
}

function optionalNumber(value: unknown): number | null {
  if (value === null || value === undefined || typeof value === "boolean") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function isSensitiveKey(key: string): boolean {
  const lowered = key.toLowerCase().replaceAll("-", "_");
  return SENSITIVE_KEY_PARTS.some(part => lowered.includes(part));
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function buildDataClassificationCodes(config: ResolvedConfig): string[] {
  const codes: string[] = [];
  for (const dcCodes of config.dataClassifications.values()) {
    for (const code of dcCodes) {
      if (!codes.includes(code)) codes.push(code);
    }
  }
  return codes;
}

function outputSummary(action: Action): string {
  const raw = action.parameters.raw;
  return `${raw["provider"]} ${raw["operation"]} ${raw["model_id"]}`;
}
