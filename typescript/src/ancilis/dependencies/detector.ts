/** Lockfile detection and dependency parsing for npm ecosystems. */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import type { Dependency, DetectionResult } from "./types.js";

// Priority order: pnpm > yarn > npm
const MANIFEST_CANDIDATES = [
  "pnpm-lock.yaml",
  "yarn.lock",
  "package-lock.json",
] as const;

type ManifestFormat = "pnpm-lock.yaml" | "yarn.lock" | "package-lock.json";

// ---------------------------------------------------------------------------
// package-lock.json
// ---------------------------------------------------------------------------

interface PackageLockV2 {
  lockfileVersion?: number;
  packages?: Record<string, { version?: string; dev?: boolean }>;
  dependencies?: Record<string, { version: string }>;
}

function parsePackageLock(content: string): Dependency[] {
  let data: PackageLockV2;
  try {
    data = JSON.parse(content) as PackageLockV2;
  } catch {
    return [];
  }

  const deps: Dependency[] = [];

  if (data.lockfileVersion && data.lockfileVersion >= 2 && data.packages) {
    for (const [path, info] of Object.entries(data.packages)) {
      // Skip the root package entry (empty string key or workspace root)
      if (!path || !path.startsWith("node_modules/")) continue;
      if (!info.version) continue;
      // Extract package name from path like "node_modules/foo" or "node_modules/@scope/foo"
      const name = path.replace(/^node_modules\//, "");
      // Skip nested node_modules (e.g. "node_modules/foo/node_modules/bar")
      if (name.includes("node_modules")) continue;
      deps.push({ name, version: info.version, ecosystem: "npm" });
    }
  } else if (data.dependencies) {
    // v1 format
    for (const [name, info] of Object.entries(data.dependencies)) {
      if (info.version) {
        deps.push({ name, version: info.version, ecosystem: "npm" });
      }
    }
  }

  return deps;
}

// ---------------------------------------------------------------------------
// yarn.lock  (classic v1 and Berry v2+)
// ---------------------------------------------------------------------------

function parseYarnLock(content: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");
  let currentNames: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    // Skip comments and empty lines
    if (line.startsWith("#") || line.trim() === "") {
      currentNames = [];
      continue;
    }

    // Berry YAML-ish header: `"foo@npm:^1.0.0":` or classic: `foo@^1.0.0:`
    // Both end with `:` and don't start with spaces
    if (!line.startsWith(" ") && line.endsWith(":")) {
      const specifiers = line.slice(0, -1).split(",").map((s) => s.trim());
      currentNames = specifiers
        .map((s) => {
          // Remove surrounding quotes
          const unquoted = s.replace(/^"|"$/g, "");
          // Berry npm protocol: "foo@npm:^1.0.0"
          const berryMatch = unquoted.match(/^(@?[^@]+)@npm:/);
          if (berryMatch) return berryMatch[1] ?? "";
          // Classic: foo@^1.0.0 or @scope/foo@^1.0.0
          const classicMatch = unquoted.match(/^(@?[^@]+)@/);
          return classicMatch ? (classicMatch[1] ?? "") : "";
        })
        .filter(Boolean);
      continue;
    }

    // Version line: `  version "1.2.3"` or `  version: 1.2.3`
    const versionMatch = line.match(/^\s+version[:\s]+"?([^\s"]+)"?/);
    if (versionMatch && currentNames.length > 0) {
      const version = versionMatch[1]!;
      for (const name of currentNames) {
        deps.push({ name, version, ecosystem: "npm" });
      }
      currentNames = [];
      continue;
    }
  }

  // Deduplicate by name (keep first seen)
  const seen = new Set<string>();
  return deps.filter((d) => {
    if (seen.has(d.name)) return false;
    seen.add(d.name);
    return true;
  });
}

// ---------------------------------------------------------------------------
// pnpm-lock.yaml
// ---------------------------------------------------------------------------

function parsePnpmLock(content: string): Dependency[] {
  let data: Record<string, unknown>;
  try {
    data = parseYaml(content) as Record<string, unknown>;
  } catch {
    return [];
  }

  const deps: Dependency[] = [];

  // pnpm v6/v7/v8: packages object with keys like "/lodash@4.17.21" or "/lodash/4.17.21"
  // pnpm v9: keys like "lodash@4.17.21"
  const packages = data["packages"] as Record<string, unknown> | undefined;
  if (!packages) return [];

  for (const key of Object.keys(packages)) {
    // Strip leading slash
    const stripped = key.startsWith("/") ? key.slice(1) : key;

    // pnpm v9 format: "name@version" or "@scope/name@version"
    // pnpm v6 format: "name/version" or "@scope/name/version"
    let name: string;
    let version: string;

    if (stripped.includes("@") && !stripped.startsWith("@")) {
      // Simple scoped: "lodash@4.17.21"
      const atIdx = stripped.lastIndexOf("@");
      name = stripped.slice(0, atIdx);
      version = stripped.slice(atIdx + 1);
    } else if (stripped.startsWith("@")) {
      // Scoped package: "@scope/pkg@1.0.0"
      // Find the @version part after the package name
      const secondAt = stripped.indexOf("@", 1);
      if (secondAt === -1) {
        // pnpm v6: "@scope/pkg/1.0.0"
        const slashIdx = stripped.lastIndexOf("/");
        name = stripped.slice(0, slashIdx);
        version = stripped.slice(slashIdx + 1);
      } else {
        name = stripped.slice(0, secondAt);
        version = stripped.slice(secondAt + 1);
      }
    } else {
      // pnpm v6 non-scoped: "name/version"
      const slashIdx = stripped.lastIndexOf("/");
      if (slashIdx === -1) continue;
      name = stripped.slice(0, slashIdx);
      version = stripped.slice(slashIdx + 1);
    }

    // Strip any trailing peer specifiers like "_foo@1.0.0"
    version = version.split("_")[0]!;

    if (name && version) {
      deps.push({ name, version, ecosystem: "npm" });
    }
  }

  return deps;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function detectDependencies(projectDir: string): DetectionResult | null {
  for (const filename of MANIFEST_CANDIDATES) {
    const fullPath = join(projectDir, filename);
    if (!existsSync(fullPath)) continue;

    const content = readFileSync(fullPath, "utf-8");
    let dependencies: Dependency[];

    switch (filename as ManifestFormat) {
      case "pnpm-lock.yaml":
        dependencies = parsePnpmLock(content);
        break;
      case "yarn.lock":
        dependencies = parseYarnLock(content);
        break;
      case "package-lock.json":
        dependencies = parsePackageLock(content);
        break;
    }

    return { manifestPath: fullPath, manifestFormat: filename as ManifestFormat, dependencies };
  }

  return null;
}
