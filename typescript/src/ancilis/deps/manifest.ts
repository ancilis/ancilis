/** Manifest detection and dependency parsing for Node.js package formats. */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Dependency, Manifest } from "./types.js";

// ---------------------------------------------------------------------------
// package-lock.json (npm)
// ---------------------------------------------------------------------------

interface PkgLockDep {
  version?: string;
  dependencies?: Record<string, PkgLockDep>;
}

interface PackageLock {
  packages?: Record<string, { version?: string }>;
  dependencies?: Record<string, PkgLockDep>;
}

function parsePackageLock(filePath: string): Dependency[] {
  let data: PackageLock;
  try {
    data = JSON.parse(readFileSync(filePath, "utf-8")) as PackageLock;
  } catch {
    return [];
  }

  const deps: Dependency[] = [];

  // npm v7+ lockfileVersion 2/3 — packages section (preferred)
  if (data.packages && typeof data.packages === "object") {
    for (const [key, info] of Object.entries(data.packages)) {
      if (key === "") continue; // root package entry
      const name = key.startsWith("node_modules/") ? key.slice("node_modules/".length) : key;
      if (name && info.version) {
        deps.push({ name, version: info.version, sourceFile: filePath });
      }
    }
    return deps;
  }

  // npm v4-v6 — dependencies section
  if (data.dependencies && typeof data.dependencies === "object") {
    for (const [name, info] of Object.entries(data.dependencies)) {
      if (info.version) {
        deps.push({ name, version: info.version, sourceFile: filePath });
      }
    }
  }
  return deps;
}

// ---------------------------------------------------------------------------
// yarn.lock (v1 and berry)
// ---------------------------------------------------------------------------

// Yarn v1 blocks look like:
//   "packagename@^1.0.0", "packagename@^1.0.0, packagename@^1.0.1":
//     version "1.2.3"
const YARN_BLOCK_START = /^"?([^@\s"]+)@/;
const YARN_VERSION = /^\s+version\s+"?([^"\s]+)"?/;

function parseYarnLock(filePath: string): Dependency[] {
  let text: string;
  try {
    text = readFileSync(filePath, "utf-8");
  } catch {
    return [];
  }

  const deps: Dependency[] = [];
  const lines = text.split("\n");
  let currentName: string | null = null;

  for (const line of lines) {
    if (line.startsWith("#") || line.trim() === "") {
      currentName = null;
      continue;
    }

    // Block start — non-indented line with @
    const blockMatch = YARN_BLOCK_START.exec(line);
    if (blockMatch && !line.startsWith(" ") && !line.startsWith("\t")) {
      currentName = blockMatch[1]!;
      continue;
    }

    if (currentName !== null) {
      const versionMatch = YARN_VERSION.exec(line);
      if (versionMatch) {
        deps.push({ name: currentName, version: versionMatch[1]!, sourceFile: filePath });
        currentName = null;
      }
    }
  }

  return deps;
}

// ---------------------------------------------------------------------------
// pnpm-lock.yaml (v6+)
// ---------------------------------------------------------------------------

// Minimal regex for pnpm-lock.yaml packages section entries like:
//   /packagename@1.2.3:   or   packagename@1.2.3:
const PNPM_PKG_LINE = /^\s+\/?([^@\s/]+)@([^\s:]+)\s*:/;

function parsePnpmLock(filePath: string): Dependency[] {
  let text: string;
  try {
    text = readFileSync(filePath, "utf-8");
  } catch {
    return [];
  }

  const deps: Dependency[] = [];
  let inPackages = false;

  for (const line of text.split("\n")) {
    if (line.startsWith("packages:")) {
      inPackages = true;
      continue;
    }
    if (inPackages && line.length > 0 && line[0] !== " " && line[0] !== "\t" && !line.startsWith("#")) {
      inPackages = false;
      continue;
    }
    if (!inPackages) continue;

    const m = PNPM_PKG_LINE.exec(line);
    if (m) {
      deps.push({ name: m[1]!, version: m[2]!, sourceFile: filePath });
    }
  }

  return deps;
}

// ---------------------------------------------------------------------------
// package.json (fallback — only exact pinned versions)
// ---------------------------------------------------------------------------

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

// Matches exact version strings like "1.2.3" or "=1.2.3" but NOT "^" / "~" / "*" / ">="
const EXACT_VERSION = /^=?(\d+\.\d+\.\d+(?:[.-][A-Za-z0-9]+)*)$/;

function parsePackageJson(filePath: string): Dependency[] {
  let data: PackageJson;
  try {
    data = JSON.parse(readFileSync(filePath, "utf-8")) as PackageJson;
  } catch {
    return [];
  }

  const deps: Dependency[] = [];
  for (const section of [data.dependencies ?? {}, data.devDependencies ?? {}]) {
    for (const [name, spec] of Object.entries(section)) {
      const m = EXACT_VERSION.exec(spec.trim());
      if (m) {
        deps.push({ name, version: m[1]!, sourceFile: filePath });
      }
    }
  }
  return deps;
}

// ---------------------------------------------------------------------------
// ManifestDetector
// ---------------------------------------------------------------------------

type ManifestHandler = (filePath: string) => Dependency[];

const HANDLERS: Array<[string, string, ManifestHandler]> = [
  ["package-lock.json", "package-lock.json", parsePackageLock],
  ["yarn.lock", "yarn.lock", parseYarnLock],
  ["pnpm-lock.yaml", "pnpm-lock.yaml", parsePnpmLock],
  ["package.json", "package.json", parsePackageJson],
];

export class ManifestDetector {
  detect(projectDir: string): Manifest[] {
    const manifests: Manifest[] = [];
    for (const [filename, format, handler] of HANDLERS) {
      const candidate = join(projectDir, filename);
      if (!existsSync(candidate)) continue;
      const deps = handler(candidate);
      manifests.push({ path: candidate, format, dependencies: deps });
    }
    return manifests;
  }
}
