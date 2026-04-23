import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";

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
  const dir = mkdtempSync(join(tmpdir(), "ancilis-plugins-"));
  tempDirs.push(dir);
  mkdirSync(join(dir, "node_modules"), { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "fixture-project", version: "1.0.0" }, null, 2));
  return dir;
}

function writePluginPackage(rootDir: string, packageName: string, plugins: unknown[], moduleBody = "export const plugin = {};"): string {
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

function captureIo(): {
  io: { stdout(message: string): void; stderr(message: string): void };
  stdout(): string;
  stderr(): string;
} {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: {
      stdout(message: string) {
        out.push(message);
      },
      stderr(message: string) {
        err.push(message);
      },
    },
    stdout: () => out.join(""),
    stderr: () => err.join(""),
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("PluginRegistry", () => {
  it("exports plugin contracts and discovers producer overlay and adapter metadata", async () => {
    const rootDir = makeTempProject();
    writePluginPackage(rootDir, "ancilis-fixture", [
      pluginMetadata({ name: "fixture-producer", type: "producer" }),
      pluginMetadata({ name: "fixture-overlay", type: "overlay" }),
      pluginMetadata({ name: "fixture-adapter", type: "adapter" }),
    ]);

    const plugins = await import("../src/ancilis/plugins/index.js");
    const root = await import("../src/ancilis/index.js");
    const registry = await plugins.PluginRegistry.discover({ rootDir });

    expect(plugins.PluginRegistry).toBeTypeOf("function");
    expect(root.PluginRegistry).toBe(plugins.PluginRegistry);
    expect(registry.records.map((record) => record.name)).toEqual([
      "fixture-producer",
      "fixture-overlay",
      "fixture-adapter",
    ]);
    expect(registry.compatible().map((record) => record.metadata.pluginType)).toEqual([
      "producer",
      "overlay",
      "adapter",
    ]);
  });

  it("lists package metadata without importing plugin modules", async () => {
    const rootDir = makeTempProject();
    const marker = join(rootDir, "imported-marker");
    writePluginPackage(
      rootDir,
      "ancilis-lazy",
      [pluginMetadata({ name: "lazy-producer", type: "producer" })],
      `import { writeFileSync } from "node:fs"; writeFileSync(${JSON.stringify(marker)}, "imported"); export const plugin = {};`,
    );

    const { PluginRegistry } = await import("../src/ancilis/plugins/index.js");
    const registry = await PluginRegistry.discover({ rootDir });

    expect(registry.compatible().map((record) => record.name)).toEqual(["lazy-producer"]);
    expect(existsSync(marker)).toBe(false);
  });

  it("skips malformed and incompatible plugin metadata with reasons", async () => {
    const rootDir = makeTempProject();
    writePluginPackage(rootDir, "ancilis-bad", [
      { name: "missing-type", minSdkVersion: "0.1.0", module: "./index.js", export: "plugin" },
      pluginMetadata({ name: "future-plugin", type: "producer", minSdkVersion: "99.0.0" }),
    ]);

    const { PluginRegistry } = await import("../src/ancilis/plugins/index.js");
    const registry = await PluginRegistry.discover({ rootDir });

    expect(registry.compatible()).toEqual([]);
    expect(registry.skipped().map((record) => record.name)).toEqual(["ancilis-bad#0", "future-plugin"]);
    expect(registry.skipped()[0]!.skipReason).toContain("missing PluginMetadata");
    expect(registry.skipped()[1]!.skipReason).toContain("requires Ancilis SDK >=99.0.0");
  });

  it("keeps discovering plugins when a package has invalid JSON metadata", async () => {
    const rootDir = makeTempProject();
    mkdirSync(join(rootDir, "node_modules", "ancilis-invalid-json"), { recursive: true });
    writeFileSync(join(rootDir, "node_modules", "ancilis-invalid-json", "package.json"), "{ bad json");
    writePluginPackage(rootDir, "ancilis-good", [
      pluginMetadata({ name: "good-producer", type: "producer" }),
    ]);

    const { PluginRegistry } = await import("../src/ancilis/plugins/index.js");
    const registry = await PluginRegistry.discover({ rootDir });

    expect(registry.compatible().map((record) => record.name)).toEqual(["good-producer"]);
    expect(registry.skipped().map((record) => record.name)).toContain("ancilis-invalid-json");
    expect(registry.skipped().find((record) => record.name === "ancilis-invalid-json")!.skipReason).toContain(
      "failed to read package metadata",
    );
  });

  it("records non-object plugin metadata entries as skipped records", async () => {
    const rootDir = makeTempProject();
    writePluginPackage(rootDir, "ancilis-weird", [
      null,
      "not metadata",
      pluginMetadata({ name: "valid-weird-producer", type: "producer" }),
    ]);

    const { PluginRegistry } = await import("../src/ancilis/plugins/index.js");
    const registry = await PluginRegistry.discover({ rootDir });

    expect(registry.compatible().map((record) => record.name)).toEqual(["valid-weird-producer"]);
    expect(registry.skipped().map((record) => record.name)).toEqual(["ancilis-weird#0", "ancilis-weird#1"]);
    expect(registry.skipped().map((record) => record.skipReason)).toEqual([
      "missing PluginMetadata",
      "missing PluginMetadata",
    ]);
  });

  it("validates dynamic imports and reports missing exports or import failures as skipped records", async () => {
    const rootDir = makeTempProject();
    writePluginPackage(rootDir, "ancilis-imports", [
      pluginMetadata({ name: "missing-export", type: "producer", exportName: "missingPlugin" }),
      pluginMetadata({ name: "missing-module", type: "producer", module: "./missing.js" }),
    ]);

    const { PluginRegistry } = await import("../src/ancilis/plugins/index.js");
    const registry = await PluginRegistry.discover({ rootDir, validateExports: true });

    expect(registry.compatible()).toEqual([]);
    expect(registry.skipped().map((record) => record.name)).toEqual(["missing-export", "missing-module"]);
    expect(registry.skipped()[0]!.skipReason).toContain("missing plugin export: missingPlugin");
    expect(registry.skipped()[1]!.skipReason).toContain("failed to load plugin module");
  });
});

describe("ancilis plugins CLI", () => {
  it("lists compatible and skipped plugins with Python-style table output", async () => {
    const rootDir = makeTempProject();
    writePluginPackage(rootDir, "ancilis-cli-fixture", [
      pluginMetadata({ name: "cli-producer", type: "producer" }),
      pluginMetadata({ name: "cli-future", type: "overlay", minSdkVersion: "99.0.0" }),
    ]);
    const { io, stdout } = captureIo();

    const exitCode = await runCli(["plugins", "list", "--root", rootDir], io);

    expect(exitCode).toBe(0);
    expect(stdout()).toContain("TYPE");
    expect(stdout()).toContain("cli-producer");
    expect(stdout()).toContain("compatible");
    expect(stdout()).toContain("cli-future");
    expect(stdout()).toContain("skipped: requires Ancilis SDK >=99.0.0");
  });

  it("validates a plugin package by path", async () => {
    const rootDir = makeTempProject();
    const packageDir = writePluginPackage(rootDir, "ancilis-valid", [
      pluginMetadata({ name: "valid-producer", type: "producer" }),
    ]);
    const { io, stdout } = captureIo();

    const exitCode = await runCli(["plugins", "validate", packageDir, "--root", rootDir], io);

    expect(exitCode).toBe(0);
    expect(stdout()).toContain("Validated 1 Ancilis plugin entry point(s).");
  });

  it("returns non-zero for validation failures", async () => {
    const rootDir = makeTempProject();
    const packageDir = writePluginPackage(rootDir, "ancilis-invalid", [
      pluginMetadata({ name: "invalid-producer", type: "producer", exportName: "missingPlugin" }),
    ]);
    const { io, stderr } = captureIo();

    const exitCode = await runCli(["plugins", "validate", packageDir, "--root", rootDir], io);

    expect(exitCode).toBe(1);
    expect(stderr()).toContain("invalid-producer");
    expect(stderr()).toContain("missing plugin export: missingPlugin");
  });
});
