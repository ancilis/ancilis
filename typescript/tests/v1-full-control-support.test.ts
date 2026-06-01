/**
 * V1 release contract for AKSI v0.6 full control support.
 */

import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { sharedPathFrom } from "../src/ancilis/shared-path.js";
import { loadConfig } from "../src/ancilis/config/index.js";
import { Engine } from "../src/ancilis/engine/engine.js";
import { CatalogBackedEvaluator } from "../src/ancilis/engine/evaluators/catalog-backed.js";
import { ToolRegistry, ToolStatus } from "../src/ancilis/engine/registry.js";
import type { Action } from "../src/ancilis/engine/action.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";

function loadSharedControls(): Array<{ id: string; support_level?: string; common?: boolean }> {
  const controlsDir = sharedPathFrom(import.meta.url, "controls");
  return readdirSync(controlsDir)
    .filter(file => file.endsWith(".json"))
    .map(file => JSON.parse(readFileSync(sharedPathFrom(import.meta.url, "controls", file), "utf-8")));
}

function makeAction(): Action {
  return {
    actionId: randomUUID(),
    timestamp: "2026-05-20T12:00:00+00:00",
    agentId: "v1-agent",
    agentOwner: "security-team",
    actionType: "tool_call",
    tool: {
      name: "read_file",
      descriptionHash: "v1-support",
    },
    parameters: {
      raw: {},
      parameterHash: "v1-support",
    },
    context: {
      sessionId: "v1-support-session",
    },
  };
}

function makeRegistry(): ToolRegistry {
  const registry = new ToolRegistry();
  registry.register({
    name: "read_file",
    status: ToolStatus.APPROVED,
    descriptionHash: "v1-support",
    approvedBy: "v1-release-test",
    firstSeen: "2026-05-20T12:00:00+00:00",
    statusChanged: "2026-05-20T12:00:00+00:00",
  });
  return registry;
}

describe("v1 full AKSI control support", () => {
  it("marks every shared control as either direct runtime or attestation-backed", () => {
    const controls = loadSharedControls();
    const directRuntimeControls = new Set([
      "DE-01", "DE-02", "DE-03", "DE-04",
      "GOV-01", "GOV-02", "GOV-03",
      "ID-01",
      "PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "PR-06", "PR-07", "PR-08", "PR-09",
      "RS-02",
    ]);

    expect(controls).toHaveLength(41);
    expect(new Set(controls.filter(control => control.support_level === "runtime_evaluator").map(control => control.id))).toEqual(directRuntimeControls);
    expect(
      Object.fromEntries(
        controls
          .filter(control => !["runtime_evaluator", "attestation"].includes(control.support_level ?? ""))
          .map(control => [control.id, control.support_level]),
      ),
    ).toEqual({});
  });

  it("evaluates every active v0.6 control without missing evaluator fallbacks", () => {
    const config = loadConfig({
      raw: {
        agent: {
          name: "v1-agent",
          owner: "security-team",
        },
      },
    });

    const result = new Engine(config, { registry: makeRegistry() }).evaluate(makeAction());
    const activeControlIds = [...config.controls.entries()]
      .filter(([, status]) => status.enabled)
      .map(([controlId]) => controlId)
      .sort();
    const configuredControlIds = [...config.controls.keys()].sort();

    expect(activeControlIds).toHaveLength(39);
    expect(configuredControlIds).toHaveLength(41);
    expect(result.controlResults.map(control => control.controlId).sort()).toEqual(configuredControlIds);
    expect(
      result.controlResults
        .filter(control =>
          control.detail.includes("No evaluator implemented") ||
          control.detail.includes("Evaluator is not registered") ||
          control.detail.startsWith("DEFERRED:")
        )
        .map(control => control.controlId),
    ).toEqual([]);
  });

  it("does not describe flagged catalog-backed controls as all passed", () => {
    const config = loadConfig({
      raw: {
        agent: {
          name: "v1-agent",
          owner: "security-team",
        },
      },
    });

    const result = new Engine(config, { registry: makeRegistry() }).evaluate(makeAction());

    expect(result.controlResults.some(control => control.result === "FLAG")).toBe(true);
    expect(result.decision).toBe("ALLOW");
    expect(result.decisionReason).not.toBe("All controls passed.");
    expect(result.decisionReason).toContain("Flagged controls");
  });

  it("does not pass catalog-backed controls from empty action wrapper keys", () => {
    const evaluator = new CatalogBackedEvaluator("ID-02", "Tool, Model and Integration Registry", ["tool"]);

    const result = evaluator.evaluate(makeAction(), {} as ResolvedConfig);

    expect(result.result).toBe("FLAG");
    expect(result.evidenceData.support_mode).toBe("catalog_backed_attestation");
    expect(result.evidenceData.matched_keywords).toEqual(["tool"]);
  });

  it("does not pass catalog-backed controls from keyword-padded action text", () => {
    const evaluator = new CatalogBackedEvaluator("PR-12", "Secrets, Credential and Wallet Key Custody", ["key", "custody"]);
    const action = makeAction();
    action.parameters.raw = {
      description: "sanctions screening, spend cap, identity verification, key custody, memory and provenance, risk policy threshold",
    };

    const result = evaluator.evaluate(action, {} as ResolvedConfig);

    expect(result.result).toBe("FLAG");
    expect(result.evidenceData.support_mode).toBe("catalog_backed_attestation");
    expect(result.evidenceData.matched_keywords).toEqual(["key", "custody"]);
  });

  it("passes catalog-backed controls only with explicit manual attestation", () => {
    const evaluator = new CatalogBackedEvaluator("PR-12", "Secrets, Credential and Wallet Key Custody", ["key", "custody"]);
    const action = makeAction();
    action.parameters.raw = {
      manual_attestations: {
        "PR-12": true,
      },
    };

    const result = evaluator.evaluate(action, {} as ResolvedConfig);

    expect(result.result).toBe("PASS");
    expect(result.evidenceData.support_mode).toBe("catalog_backed_attestation");
    expect(result.evidenceData.manual_attestation_present).toBe(true);
  });
});
