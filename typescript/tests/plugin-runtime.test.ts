import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ActivationResolver,
  Engine,
  EvidenceStore,
  PluginRegistry,
  loadConfig,
  resolveEvidenceAdapter,
  resolveRuntimeProducers,
  translateRuntimeAction,
} from "../src/ancilis/index.js";

type PluginType = "producer" | "overlay" | "adapter";

interface FixturePlugin {
  name: string;
  type: PluginType;
  minSdkVersion?: string;
  maxSdkVersion?: string;
  module?: string;
  exportName?: string;
}

const tempDirs: string[] = [];

function makeTempProject(): string {
  const dir = mkdtempSync(join(tmpdir(), "ancilis-plugin-runtime-"));
  tempDirs.push(dir);
  mkdirSync(join(dir, "node_modules"), { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "fixture-project", version: "1.0.0" }, null, 2));
  return dir;
}

function writePluginPackage(rootDir: string, packageName: string, plugins: unknown[], moduleBody: string): string {
  const packageDir = join(rootDir, "node_modules", packageName);
  mkdirSync(packageDir, { recursive: true });
  writeFileSync(
    join(packageDir, "package.json"),
    JSON.stringify(
      {
        name: packageName,
        version: "1.2.3",
        type: "module",
        ancilis: { plugins },
      },
      null,
      2,
    ),
  );
  writeFileSync(join(packageDir, "index.js"), moduleBody);
  return packageDir;
}

function pluginMetadata(plugin: FixturePlugin): Record<string, unknown> {
  return {
    name: plugin.name,
    type: plugin.type,
    minSdkVersion: plugin.minSdkVersion ?? "0.1.0",
    maxSdkVersion: plugin.maxSdkVersion,
    module: plugin.module ?? "./index.js",
    export: plugin.exportName ?? "plugin",
  };
}

function makeConfig(overrides: Record<string, unknown> = {}) {
  return loadConfig({
    raw: {
      agent: { name: "runtime-agent" },
      security: { mode: "audit" },
      ...overrides,
    },
  });
}

const producerPluginModule = `
import { createHash, randomUUID } from "node:crypto";

class RuntimeProducer {
  constructor(config) {
    this.toolName = String(config.toolName ?? "plugin:fake.lookup");
    this.agentName = String(config.agentName ?? "runtime-agent");
    this.descriptionHash = createHash("sha256").update(this.toolName).digest("hex");
  }

  get producerType() {
    return "framework";
  }

  get producerVersion() {
    return "1.0.0";
  }

  translate(rawInvocation) {
    const payload = { raw: rawInvocation ?? {} };
    return {
      actionId: randomUUID(),
      timestamp: new Date().toISOString(),
      agentId: this.agentName,
      sourceType: "framework",
      producerType: this.producerType,
      producerVersion: this.producerVersion,
      actionType: "tool_call",
      tool: {
        name: this.toolName,
        descriptionHash: this.descriptionHash,
      },
      parameters: {
        raw: payload,
        parameterHash: createHash("sha256").update(JSON.stringify(payload)).digest("hex"),
      },
      context: {
        sessionId: "plugin-session",
        dataClassifications: [],
        activeOverlays: [],
      },
    };
  }

  computeToolHash(toolIdentifier) {
    return createHash("sha256").update(String(toolIdentifier)).digest("hex");
  }

  registerTools(registry) {
    const now = new Date().toISOString();
    registry.register({
      name: this.toolName,
      descriptionHash: this.descriptionHash,
      status: "approved",
      approvedBy: "plugin-test",
      firstSeen: now,
      statusChanged: now,
    });
    return [this.toolName];
  }
}

export const plugin = {
  metadata: {
    name: "fake-producer",
    pluginType: "producer",
    version: "1.0.0",
    packageName: "ancilis-producer-runtime",
    packageVersion: "1.2.3",
    minSdkVersion: "0.1.0",
    module: "./index.js",
    exportName: "plugin",
  },
  createProducer(context) {
    if (context.config.failCreate) {
      throw new Error("boom");
    }
    return new RuntimeProducer(context.config);
  },
};

export const collidingPlugin = {
  metadata: {
    name: "tool",
    pluginType: "producer",
    version: "1.0.0",
    packageName: "ancilis-producer-runtime",
    packageVersion: "1.2.3",
    minSdkVersion: "0.1.0",
    module: "./index.js",
    exportName: "collidingPlugin",
  },
  createProducer(context) {
    return new RuntimeProducer(context.config);
  },
};
`;

const overlayPluginModule = `
export const plugin = {
  metadata: {
    name: "acme-risk",
    pluginType: "overlay",
    version: "1.0.0",
    packageName: "ancilis-overlay-runtime",
    packageVersion: "1.2.3",
    minSdkVersion: "0.1.0",
    module: "./index.js",
    exportName: "plugin",
  },
  loadOverlayProfile(context) {
    if (context.config.failLoad) {
      throw new Error("overlay boom");
    }
    return {
      id: "plugin:acme-risk",
      name: "Acme Risk Overlay",
      version: "1.0.0",
      trigger_type: "data_classification",
      triggered_by: ["DC-PII"],
      description: "Fake plugin overlay for runtime activation tests.",
      control_adjustments: {
        "PR-01": {
          threshold_adjustment: "strict",
          regulatory_citation: "ACME-RISK-1",
        },
      },
      evidence_requirements: {
        "PR-01": ["acme-risk-review"],
      },
      controls: {
        "PR-01": {
          applicable: true,
          evidence_requirements: ["acme-risk-review"],
          framework_reference: "ACME-RISK-1",
        },
      },
      evidence_retention_minimum_days: 730,
      human_oversight_required: true,
    };
  },
};

export const certificationPlugin = {
  metadata: {
    name: "acme-cert",
    pluginType: "overlay",
    version: "1.0.0",
    packageName: "ancilis-overlay-runtime",
    packageVersion: "1.2.3",
    minSdkVersion: "0.1.0",
    module: "./index.js",
    exportName: "certificationPlugin",
  },
  loadOverlayProfile() {
    return {
      id: "plugin:acme-cert",
      name: "Acme Certification Overlay",
      version: "1.0.0",
      trigger_type: "certification_target",
      triggered_by: ["aiuc-1"],
      control_adjustments: {
        "PR-01": {
          threshold_adjustment: "strict",
          regulatory_citation: "ACME-CERT-1",
        },
      },
      evidence_requirements: {
        "PR-01": ["acme-cert-review"],
      },
      controls: {
        "PR-01": {
          applicable: true,
          evidence_requirements: ["acme-cert-review"],
          framework_reference: "ACME-CERT-1",
        },
      },
      evidence_retention_minimum_days: 365,
      human_oversight_required: false,
    };
  },
};

export const malformedPlugin = {
  metadata: {
    name: "bad-overlay",
    pluginType: "overlay",
    version: "1.0.0",
    packageName: "ancilis-overlay-runtime",
    packageVersion: "1.2.3",
    minSdkVersion: "0.1.0",
    module: "./index.js",
    exportName: "malformedPlugin",
  },
  loadOverlayProfile() {
    return { id: "bad-overlay" };
  },
};
`;

const adapterPluginModule = `
class FakeEvidenceAdapter {
  constructor(config) {
    this.payloads = [];
    this.failStore = Boolean(config.failStore);
  }

  store(payload) {
    if (this.failStore) {
      throw new Error("adapter store boom");
    }
    this.payloads.push(payload);
  }

  query(query = {}) {
    if (!query.toolName) {
      return this.payloads.map((payload) => payload.record);
    }
    return this.payloads
      .map((payload) => payload.record)
      .filter((record) => record.toolName === query.toolName);
  }

  export(exportRequest = {}) {
    return {
      format: exportRequest.format ?? "json",
      records: this.payloads.map((payload) => payload.record.recordId),
    };
  }
}

export const plugin = {
  metadata: {
    name: "fake-evidence",
    pluginType: "adapter",
    version: "1.0.0",
    packageName: "ancilis-adapter-runtime",
    packageVersion: "1.2.3",
    minSdkVersion: "0.1.0",
    module: "./index.js",
    exportName: "plugin",
  },
  createAdapter(context) {
    if (context.config.failCreate) {
      throw new Error("adapter create boom");
    }
    return new FakeEvidenceAdapter(context.config);
  },
};
`;

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("plugin runtime producers", () => {
  it("discovers a plugin producer and evaluates actions without changing engine semantics", async () => {
    const rootDir = makeTempProject();
    writePluginPackage(
      rootDir,
      "ancilis-producer-runtime",
      [
        pluginMetadata({ name: "fake-producer", type: "producer" }),
      ],
      producerPluginModule,
    );

    const config = makeConfig();
    const engine = new Engine(config);
    const store = new EvidenceStore(config, { inMemory: true });
    const pluginRegistry = await PluginRegistry.discover({ rootDir, validateExports: true });

    const selection = await resolveRuntimeProducers(config, {
      engine,
      evidenceStore: store,
      pluginRegistry,
      pluginNames: ["plugin:fake-producer"],
      pluginConfigs: {
        "fake-producer": {
          toolName: "plugin:fake.lookup",
          agentName: "runtime-agent",
        },
      },
    });

    expect(Object.keys(selection.producers).sort()).toEqual([
      "cli",
      "http",
      "mcp",
      "plugin:fake-producer",
      "tool",
    ]);
    expect(selection.warnings).toEqual([]);

    const pluginProducer = selection.producers["plugin:fake-producer"];
    expect(pluginProducer.registerTools(engine.registry)).toEqual(["plugin:fake.lookup"]);

    const action = translateRuntimeAction(pluginProducer, { query: "status" });
    const evaluation = engine.evaluate(action);
    const record = await store.store(evaluation, action.tool.name);

    expect(action.tool.name).toBe("plugin:fake.lookup");
    expect(action.producerType).toBe("framework");
    expect(evaluation.decision).toBe("ALLOW");
    expect(record.toolName).toBe("plugin:fake.lookup");
    await expect(store.getSummary({ sessionId: "plugin-session" })).resolves.toMatchObject({
      totalEvaluations: 1,
    });
  });

  it("warns and skips colliding or broken plugin producers while keeping built-ins", async () => {
    const rootDir = makeTempProject();
    writePluginPackage(
      rootDir,
      "ancilis-producer-runtime",
      [
        pluginMetadata({ name: "fake-producer", type: "producer" }),
        pluginMetadata({ name: "tool", type: "producer", exportName: "collidingPlugin" }),
      ],
      producerPluginModule,
    );

    const config = makeConfig();
    const pluginRegistry = await PluginRegistry.discover({ rootDir, validateExports: true });

    const selection = await resolveRuntimeProducers(config, {
      pluginRegistry,
      pluginNames: ["plugin:tool", "plugin:fake-producer"],
      pluginConfigs: {
        "fake-producer": { failCreate: true },
      },
    });

    expect(Object.keys(selection.producers)).toEqual(["cli", "http", "mcp", "tool"]);
    expect(selection.warnings).toEqual([
      "Plugin producer 'tool' collides with built-in producer 'tool' and was skipped.",
      "failed to create plugin producer 'fake-producer': boom",
    ]);
  });

  it("exports runtime selection helpers from the package root", async () => {
    const root = await import("../src/ancilis/index.js");
    const producers = await import("../src/ancilis/producers/index.js");

    expect(root.resolveRuntimeProducers).toBe(resolveRuntimeProducers);
    expect(root.translateRuntimeAction).toBe(translateRuntimeAction);
    expect(producers.resolveRuntimeProducers).toBe(resolveRuntimeProducers);
    expect(producers.translateRuntimeAction).toBe(translateRuntimeAction);
  });
});

describe("plugin overlays", () => {
  it("activates a plugin overlay from data classification and explicit config loading", async () => {
    const rootDir = makeTempProject();
    writePluginPackage(
      rootDir,
      "ancilis-overlay-runtime",
      [
        pluginMetadata({ name: "acme-risk", type: "overlay" }),
      ],
      overlayPluginModule,
    );
    const pluginRegistry = await PluginRegistry.discover({ rootDir });

    const spec = new ActivationResolver({
      pluginRegistry,
      pluginConfigs: { "acme-risk": { tenant: "acme" } },
    }).resolve({ dataHandling: ["personal_info"] });

    expect(spec.activeOverlays).toContain("plugin:acme-risk");
    expect(spec.activationSource["plugin:acme-risk"]).toBe("my_agent_handles:personal_info");
    expect(spec.controlThresholds["PR-01"]).toBe("strict");
    expect(spec.evidenceRequirements["PR-01"]).toContain("acme-risk-review");
    expect(spec.evidenceRetentionDays).toBeGreaterThanOrEqual(730);
    expect(spec.humanOversightRequired).toBe(true);

    const config = loadConfig({
      raw: {
        agent: { name: "plugin-overlay-agent" },
        compliance: { overlays: ["plugin:acme-risk"] },
      },
      pluginRegistry,
      pluginConfigs: { "acme-risk": { tenant: "acme" } },
    });

    expect(config.activeOverlays.has("plugin:acme-risk")).toBe(true);
    expect(config.controls.get("PR-01")?.threshold).toBe("strict");
    expect(config.warnings).toEqual([]);
  });

  it("activates a plugin overlay from certification targets", async () => {
    const rootDir = makeTempProject();
    writePluginPackage(
      rootDir,
      "ancilis-overlay-runtime",
      [
        pluginMetadata({ name: "acme-cert", type: "overlay", exportName: "certificationPlugin" }),
      ],
      overlayPluginModule,
    );
    const pluginRegistry = await PluginRegistry.discover({ rootDir, validateExports: true });

    const spec = new ActivationResolver({ pluginRegistry }).resolve({ certificationTargets: ["aiuc-1"] });

    expect(spec.activeOverlays).toContain("plugin:acme-cert");
    expect(spec.activationSource["plugin:acme-cert"]).toBe("certification_targets:aiuc-1");
    expect(spec.controlThresholds["PR-01"]).toBe("strict");
    expect(spec.evidenceRequirements["PR-01"]).toContain("acme-cert-review");
  });

  it("warns and skips malformed plugin overlays without crashing config resolution", async () => {
    const rootDir = makeTempProject();
    writePluginPackage(
      rootDir,
      "ancilis-overlay-runtime",
      [
        pluginMetadata({ name: "bad-overlay", type: "overlay", exportName: "malformedPlugin" }),
      ],
      overlayPluginModule,
    );
    const pluginRegistry = await PluginRegistry.discover({ rootDir, validateExports: true });

    const config = loadConfig({
      raw: {
        agent: { name: "plugin-overlay-agent" },
        compliance: { overlays: ["plugin:bad-overlay"] },
      },
      pluginRegistry,
    });

    expect(config.activeOverlays.size).toBe(0);
    expect(config.warnings).toContain(
      "Skipping Ancilis plugin overlay bad-overlay: overlay id must be explicit and namespaced as plugin:<name>",
    );
  });
});

describe("plugin evidence adapters", () => {
  it("selects a plugin evidence adapter and forwards canonical evidence records", async () => {
    const rootDir = makeTempProject();
    writePluginPackage(
      rootDir,
      "ancilis-adapter-runtime",
      [
        pluginMetadata({ name: "fake-evidence", type: "adapter" }),
      ],
      adapterPluginModule,
    );
    const pluginRegistry = await PluginRegistry.discover({ rootDir, validateExports: true });
    const config = makeConfig();

    const selection = await resolveEvidenceAdapter(config, {
      pluginName: "plugin:fake-evidence",
      pluginRegistry,
      pluginConfigs: {
        "fake-evidence": { sink: "fake" },
      },
    });
    const store = new EvidenceStore(config, {
      inMemory: true,
      evidenceAdapter: selection.adapter,
      evidenceAdapterMetadata: { adapterSink: "fake" },
    });

    const record = await store.store(
      {
        evaluationId: "eval-adapter-001",
        actionId: "action-adapter-001",
        timestamp: "2026-04-14T03:55:00Z",
        agentId: "runtime-agent",
        sourceType: "framework",
        mode: "audit",
        controlResults: [
          {
            controlId: "PR-01",
            controlName: "Agent Identity",
            result: "PASS",
            detail: "Agent identity verified",
            evidenceData: { agent_id: "runtime-agent" },
            durationMs: 1.5,
          },
        ],
        decision: "ALLOW",
        activeOverlays: ["financial"],
        dataClassifications: ["internal"],
        detectedDataTypes: ["email"],
        totalDurationMs: 6.0,
        context: { sessionId: "adapter-session" },
      },
      "plugin:fake.lookup",
    );

    expect(selection.warnings).toEqual([]);
    expect(selection.adapter).not.toBeNull();
    const adapter = selection.adapter as {
      payloads: Array<{ record: { recordHash: string; toolName: string }; adapterMetadata: Record<string, unknown> }>;
      query(query?: { toolName?: string }): unknown;
      export(exportRequest?: { format?: string }): unknown;
    };
    expect(adapter.payloads).toHaveLength(1);
    expect(adapter.payloads[0]?.record.recordHash).toBe(record.recordHash);
    expect(adapter.payloads[0]?.record.toolName).toBe("plugin:fake.lookup");
    expect(adapter.payloads[0]?.adapterMetadata).toEqual({ adapterSink: "fake" });
    expect(adapter.query({ toolName: "plugin:fake.lookup" })).toEqual([record]);
    expect(adapter.export({ format: "json" })).toEqual({
      format: "json",
      records: [record.recordId],
    });
    await expect(store.getSummary({ sessionId: "adapter-session" })).resolves.toMatchObject({
      totalEvaluations: 1,
    });
  });

  it("keeps DuckDB as the default evidence path when no plugin adapter is selected", async () => {
    const config = makeConfig();
    const selection = await resolveEvidenceAdapter(config);
    const store = new EvidenceStore(config, { inMemory: true, evidenceAdapter: selection.adapter });
    const record = await store.store(
      {
        evaluationId: "eval-default-001",
        actionId: "action-default-001",
        timestamp: "2026-04-14T03:55:00Z",
        agentId: "runtime-agent",
        sourceType: "framework",
        mode: "audit",
        controlResults: [],
        decision: "ALLOW",
        activeOverlays: [],
        dataClassifications: [],
        totalDurationMs: 1.0,
      },
      "builtin-tool",
    );

    expect(selection.adapter).toBeNull();
    expect(selection.warnings).toEqual([]);
    expect(record.toolName).toBe("builtin-tool");
    await expect(store.count()).resolves.toBe(1);
  });

  it("warns on adapter creation failures and adapter store hook failures without losing canonical records", async () => {
    const rootDir = makeTempProject();
    writePluginPackage(
      rootDir,
      "ancilis-adapter-runtime",
      [
        pluginMetadata({ name: "fake-evidence", type: "adapter" }),
      ],
      adapterPluginModule,
    );
    const pluginRegistry = await PluginRegistry.discover({ rootDir, validateExports: true });
    const config = makeConfig();
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    try {
      const createFailure = await resolveEvidenceAdapter(config, {
        pluginName: "plugin:fake-evidence",
        pluginRegistry,
        pluginConfigs: {
          "fake-evidence": { failCreate: true },
        },
      });

      expect(createFailure.adapter).toBeNull();
      expect(createFailure.warnings).toEqual([
        "failed to create plugin evidence adapter 'fake-evidence': adapter create boom",
      ]);

      const workingSelection = await resolveEvidenceAdapter(config, {
        pluginName: "plugin:fake-evidence",
        pluginRegistry,
        pluginConfigs: {
          "fake-evidence": { failStore: true },
        },
      });
      const store = new EvidenceStore(config, {
        inMemory: true,
        evidenceAdapter: workingSelection.adapter,
      });

      const record = await store.store(
        {
          evaluationId: "eval-broken-001",
          actionId: "action-broken-001",
          timestamp: "2026-04-14T03:55:00Z",
          agentId: "runtime-agent",
          sourceType: "framework",
          mode: "audit",
          controlResults: [],
          decision: "ALLOW",
          activeOverlays: [],
          dataClassifications: [],
          totalDurationMs: 1.0,
          context: { sessionId: "adapter-session" },
        },
        "plugin:broken.lookup",
      );

      expect(record.toolName).toBe("plugin:broken.lookup");
      await expect(store.count()).resolves.toBe(1);
      expect(warnSpy).toHaveBeenCalledWith("[ancilis] plugin evidence adapter store hook failed: adapter store boom");
    } finally {
      warnSpy.mockRestore();
    }
  });
});
