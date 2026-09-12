/** CLIActionProducer — intercepts CLI/subprocess tool calls for evaluation. */

import { createHash, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import { basename, delimiter, isAbsolute, join, resolve } from "node:path";
import type { ResolvedConfig } from "../config/index.js";
import type { Action } from "../engine/action.js";
import { Engine } from "../engine/engine.js";
import { ContentFingerprintStatus, ToolRegistry, ToolStatus } from "../engine/registry.js";
import type { ToolEntry } from "../engine/registry.js";
import type { EvaluationResult } from "../engine/result.js";
import { EvidenceStore } from "../evidence/store.js";
import { scanResponse } from "../middleware/response-scanner.js";
import type { ScanResult } from "../middleware/response-scanner.js";
import { matchesToolList } from "../engine/tool-matching.js";
import { recordAdapterUsed } from "../telemetry/index.js";
import { ProducerType } from "./protocol.js";

/** Bound fingerprinting I/O so a tool path cannot consume unbounded resources. */
const EXECUTABLE_HASH_MAX_BYTES = 64 * 1024 * 1024;
const EXECUTABLE_HASH_CHUNK_BYTES = 64 * 1024;

export interface CLIInvocation {
  command: string[];
  agentName: string;
  workingDirectory?: string;
  environment?: Record<string, string>;
}

export interface CLIExecutionResult {
  action: Action;
  evaluation: EvaluationResult;
  blocked: boolean;
  stdout?: string;
  stderr?: string;
  returnCode?: number;
  scanResult?: ScanResult;
}

export class CLIActionProducer {
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
    recordAdapterUsed("cli");
  }

  get producerType(): ProducerType { return ProducerType.CLI; }
  get producerVersion(): string { return "0.1.0"; }
  /** Unique identifier for this producer instance (one per agent run). */
  get sessionId(): string { return this._sessionId; }

  private _resolveToolName(command: string[]): string {
    if (!command.length) return "cli:unknown";
    return `cli:${basename(command[0]!)}`;
  }

  private _buildDcCodes(): string[] {
    const codes: string[] = [];
    for (const dcCodes of this._config.dataClassifications.values()) {
      for (const code of dcCodes) {
        if (!codes.includes(code)) codes.push(code);
      }
    }
    return codes;
  }

  translate(invocation: CLIInvocation): Action {
    const toolName = this._resolveToolName(invocation.command);
    const args = invocation.command.slice(1);
    const raw: Record<string, unknown> = {
      command: invocation.command,
      args,
    };
    if (invocation.workingDirectory) {
      raw["working_directory"] = invocation.workingDirectory;
    }
    const paramHash = createHash("sha256")
      .update(JSON.stringify(invocation.command))
      .digest("hex");
    const entry = this._registry.lookup(toolName);
    const isCliContentEntry = entry?.contentFingerprintStatus != null;

    return {
      actionId: randomUUID(),
      timestamp: new Date().toISOString(),
      agentId: invocation.agentName,
      sourceType: this.producerType,
      producerType: this.producerType,
      producerVersion: this.producerVersion,
      agentOwner: this._config.agentOwner ?? null,
      actionType: "tool_call",
      tool: {
        name: toolName,
        descriptionHash: isCliContentEntry ? null : (entry?.descriptionHash ?? null),
        contentFingerprint: isCliContentEntry && invocation.command[0]
          ? this._contentFingerprint(invocation.command[0])
          : null,
      },
      parameters: { raw, parameterHash: paramHash },
      context: {
        sessionId: this._sessionId,
        dataClassifications: this._buildDcCodes(),
        activeOverlays: [...this._config.activeOverlays.keys()],
      },
    };
  }

  computeToolHash(toolIdentifier: string): string {
    const toolPath = this._resolveToolPath(toolIdentifier);
    const contentHash = this._getExecutableContentHash(toolPath);
    const input = `${toolPath ?? toolIdentifier}:${contentHash}`;
    return createHash("sha256").update(input).digest("hex");
  }

  private _contentFingerprint(toolIdentifier: string): string | null {
    const contentHash = this._getExecutableContentHash(this._resolveToolPath(toolIdentifier));
    return contentHash === "unavailable" ? null : contentHash;
  }

  registerTools(registry: ToolRegistry): string[] {
    const registered: string[] = [];
    const now = new Date().toISOString();
    for (const toolSpec of this._config.toolsAllowed) {
      let bareName = toolSpec;
      if (bareName.startsWith("cli:")) bareName = bareName.slice(4);
      const cliName = `cli:${bareName}`;
      const contentFingerprint = this._contentFingerprint(bareName);
      registry.register({
        name: cliName,
        contentFingerprint,
        contentFingerprintStatus: contentFingerprint == null
          ? ContentFingerprintStatus.UNAVAILABLE
          : ContentFingerprintStatus.AVAILABLE,
        status: ToolStatus.APPROVED,
        approvedBy: "config",
        firstSeen: now,
        statusChanged: now,
      } satisfies ToolEntry);
      registered.push(cliName);
    }
    return registered;
  }

  private _autoRegister(toolName: string, command: string[]): void {
    if (this._registry.lookup(toolName)) return;
    const toolIdentifier = command[0] ?? "unknown";
    const contentFingerprint = this._contentFingerprint(toolIdentifier);
    const status = matchesToolList(toolName, this._config.toolsAllowed)
      ? ToolStatus.APPROVED
      : ToolStatus.OBSERVED;
    const now = new Date().toISOString();
    this._registry.register({
      name: toolName,
      contentFingerprint,
      contentFingerprintStatus: contentFingerprint == null
        ? ContentFingerprintStatus.UNAVAILABLE
        : ContentFingerprintStatus.AVAILABLE,
      status,
      approvedBy: status === ToolStatus.APPROVED ? "config" : null,
      firstSeen: now,
      statusChanged: now,
    } satisfies ToolEntry);
  }

  async execute(
    command: string[],
    agentName: string,
    workingDirectory?: string,
    timeoutMs = 30000,
  ): Promise<CLIExecutionResult> {
    const toolName = this._resolveToolName(command);
    this._autoRegister(toolName, command);

    const invocation: CLIInvocation = { command, agentName, workingDirectory };
    const action = this.translate(invocation);
    const evaluation = this._engine.evaluate(action);
    await this._evidenceStore.store(evaluation, toolName);

    const blocked = evaluation.decision === "BLOCK";
    let stdout: string | undefined;
    let stderr: string | undefined;
    let returnCode: number | undefined;
    let scanResult: ScanResult | undefined;

    if (!blocked) {
      const result = spawnSync(command[0]!, command.slice(1), {
        cwd: workingDirectory,
        timeout: timeoutMs,
        encoding: "utf-8",
      });
      stdout = result.stdout || undefined;
      stderr = result.stderr || undefined;
      returnCode = result.status ?? undefined;

      if (result.error) {
        const error = result.error as NodeJS.ErrnoException;
        if (error.code === "ETIMEDOUT") {
          stderr = `Command timed out after ${timeoutMs}ms`;
          returnCode = -1;
        } else if (error.code === "ENOENT") {
          stderr = `Command not found: ${command[0]}`;
          returnCode = -1;
        } else {
          stderr = stderr ?? error.message ?? "Command failed";
          returnCode = returnCode ?? -1;
        }
      } else if (returnCode === null || returnCode === undefined) {
        returnCode = -1;
        stderr = stderr ?? "Command failed";
      }

      if (stdout) {
        const scan = scanResponse(toolName, stdout);
        if (scan.patterns.length > 0 || scan.encryptionFindings.length > 0) {
          scanResult = scan;
        }
      }
    }

    return { action, evaluation, blocked, stdout, stderr, returnCode, scanResult };
  }

  private _getExecutableContentHash(toolPath: string | null): string {
    if (!toolPath) return "unavailable";

    let descriptor: number | undefined;
    try {
      const flags = fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0);
      descriptor = fs.openSync(toolPath, flags);
      const initial = fs.fstatSync(descriptor);
      if (!initial.isFile() || initial.size > EXECUTABLE_HASH_MAX_BYTES) return "unavailable";

      const digest = createHash("sha256");
      const buffer = Buffer.allocUnsafe(EXECUTABLE_HASH_CHUNK_BYTES);
      let remaining = initial.size;
      while (remaining > 0) {
        const bytesRead = fs.readSync(descriptor, buffer, 0, Math.min(buffer.length, remaining), null);
        if (bytesRead === 0) return "unavailable";
        digest.update(buffer.subarray(0, bytesRead));
        remaining -= bytesRead;
      }

      const final = fs.fstatSync(descriptor);
      if (
        final.dev !== initial.dev
        || final.ino !== initial.ino
        || final.size !== initial.size
        || final.mtimeMs !== initial.mtimeMs
        || final.ctimeMs !== initial.ctimeMs
      ) return "unavailable";
      return digest.digest("hex");
    } catch {
      return "unavailable";
    } finally {
      if (descriptor !== undefined) {
        try {
          fs.closeSync(descriptor);
        } catch {
          // The descriptor is already unusable; hashing remains unavailable.
        }
      }
    }
  }

  private _resolveToolPath(toolName: string): string | null {
    const candidates: string[] = [];
    if (toolName.includes("/") || toolName.includes("\\")) {
      candidates.push(isAbsolute(toolName) ? toolName : resolve(toolName));
    } else {
      const pathValue = process.env.PATH ?? "";
      for (const dir of pathValue.split(delimiter)) {
        if (dir) candidates.push(join(dir, toolName));
      }
    }

    for (const candidate of candidates) {
      try {
        fs.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      } catch {
        // continue
      }
    }
    return null;
  }
}
