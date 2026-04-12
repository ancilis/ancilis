/** Manifest detection and dependency parsing for common Node.js manifest formats. */

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import type { Dependency, Manifest } from "./types.js";

// ----- package-lock.json -----

function parsePackageLockJson(path: string): Dependency[] {
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(readFileSync(path, "utf-8")) as Record<string, unknown>;
  } catch {
    return [];
  }

  const deps: Dependency[] = [];
  const lockVersion = (data["lockfileVersion"] as number | undefined) ?? 1;

  if (lockVersion >= 2 && data["packages"] && typeof data["packages"] === "object") {
    // v2/v3: packages is { "node_modules/name": { version: "x.y.z" } }
    for (const [key, info] of Object.entries(data["packages"] as Record<string, unknown>)) {
      if (!key) continue; // skip root entry ""
      if (!(info && typeof info === "object")) continue;
      const pkg = info as Record<string, unknown>;
      const version = pkg["version"] as string | undefined;
      if (!version) continue;
      // Strip "node_modules/" prefix, possibly nested like "node_modules/a/node_modules/b"
      const name = key.replace(/^.*node_modules\//, "");
      deps.push({ name, version, sourceFile: path });
    }
  } else if (data["dependencies"] && typeof data["dependencies"] === "object") {
    // v1: dependencies is { "name": { version: "x.y.z" } }
    for (const [name, info] of Object.entries(data["dependencies"] as Record<string, unknown>)) {
      if (!(info && typeof info === "object")) continue;
      const pkg = info as Record<string, unknown>;
      const version = pkg["version"] as string | undefined;
      if (version) {
        deps.push({ name, version, sourceFile: path });
      }
    }
  }

  return deps;
}

// ----- yarn.lock -----

function parseYarnLock(path: string): Dependency[] {
  let content: string;
  try {
    content = readFileSync(path, "utf-8");
  } catch {
    return [];
  }

  const deps: Dependency[] = [];
  const seen = new Set<string>();
  const lines = content.split("\n");

  let currentName: string | null = null;

  for (const line of lines) {
    // Skip comment and blank lines
    if (line.startsWith("#") || line.trim() === "") {
      currentName = null;
      continue;
    }

    // Package specifier: not indented, ends with ":"
    if (!line.startsWith(" ") && !line.startsWith("\t") && line.endsWith(":")) {
      // May be: "pkg@^1.0.0": or pkg@^1.0.0: or "@scope/pkg@^1.0.0":
      const raw = line.slice(0, -1).replace(/^"|"$/g, "").trim();
      // Take the first specifier if comma-separated
      const firstSpec = raw.split(",")[0]!.trim().replace(/^"|"$/g, "").trim();
      // The name is everything before the last "@" (handles scoped packages "@scope/name@version")
      const lastAt = firstSpec.lastIndexOf("@");
      currentName = lastAt > 0 ? firstSpec.slice(0, lastAt) : null;
      continue;
    }

    // Version line inside a block: "  version "x.y.z""
    if (currentName !== null) {
      const vMatch = /^\s+version\s+"([^"]+)"/.exec(line);
      if (vMatch && !seen.has(currentName)) {
        seen.add(currentName);
        deps.push({ name: currentName, version: vMatch[1]!, sourceFile: path });
        currentName = null;
      }
    }
  }

  return deps;
}

// ----- pnpm-lock.yaml -----

function parsePnpmLock(path: string): Dependency[] {
  let content: string;
  try {
    content = readFileSync(path, "utf-8");
  } catch {
    return [];
  }

  let data: Record<string, unknown>;
  try {
    data = parseYaml(content) as Record<string, unknown>;
  } catch {
    return [];
  }

  // v5–v6 use "packages"; v9 uses "snapshots" for fully resolved packages
  const section = (data["packages"] ?? data["snapshots"]) as Record<string, unknown> | undefined;
  if (!section || typeof section !== "object") return [];

  const deps: Dependency[] = [];

  for (const key of Object.keys(section)) {
    // v5: "/lodash@4.17.21", v6+: "lodash@4.17.21", possibly with qualifiers "(patch_hash)"
    const cleanKey = key.replace(/^\//, "");
    // Match "name@version" — name may be scoped "@scope/pkg"
    const match = /^(@?[^@(]+)@([^@()\s]+)/.exec(cleanKey);
    if (match) {
      const name = match[1]!;
      const version = match[2]!;
      deps.push({ name, version, sourceFile: path });
    }
  }

  return deps;
}

// ----- package.json (fallback) -----

const PINNED_VERSION = /^\d/;

function parsePackageJson(path: string): Dependency[] {
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(readFileSync(path, "utf-8")) as Record<string, unknown>;
  } catch {
    return [];
  }

  const deps: Dependency[] = [];

  for (const section of ["dependencies", "devDependencies"] as const) {
    const entries = data[section] as Record<string, string> | undefined;
    if (!entries || typeof entries !== "object") continue;
    for (const [name, version] of Object.entries(entries)) {
      if (typeof version === "string" && PINNED_VERSION.test(version)) {
        deps.push({ name, version, sourceFile: path });
      }
    }
  }

  return deps;
}

// ----- ManifestDetector -----

type Handler = (path: string) => Dependency[];

const HANDLERS: Array<[filename: string, format: string, handler: Handler]> = [
  ["package-lock.json", "package-lock.json", parsePackageLockJson],
  ["yarn.lock", "yarn.lock", parseYarnLock],
  ["pnpm-lock.yaml", "pnpm-lock.yaml", parsePnpmLock],
  ["package.json", "package.json", parsePackageJson],
];

export class ManifestDetector {
  /** Find and parse all supported manifest files in `projectDir`. */
  detect(projectDir: string): Manifest[] {
    const manifests: Manifest[] = [];

    for (const [filename, format, handler] of HANDLERS) {
      const candidate = join(projectDir, filename);
      if (existsSync(candidate)) {
        const dependencies = handler(candidate);
        manifests.push({ path: candidate, format, dependencies });
      }
    }

    return manifests;
  }
}
