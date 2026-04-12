/** ancilis version-check — non-blocking npm registry update notifications. */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CliIo {
  stdout(message: string): void;
  stderr(message: string): void;
}

interface VersionCache {
  latestVersion: string;
  checkedAt: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_TTL_SECONDS = 86400; // 24 hours
const FETCH_TIMEOUT_MS = 1000;
const NPM_REGISTRY_URL = "https://registry.npmjs.org/ancilis/latest";

// ---------------------------------------------------------------------------
// Environment detection
// ---------------------------------------------------------------------------

export function isCiEnvironment(): boolean {
  const ciVars = [
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "JENKINS_URL",
    "CIRCLECI",
    "TRAVIS",
    "TF_BUILD",
    "BUILDKITE",
  ];
  return ciVars.some((v) => Boolean(process.env[v]));
}

export function isSuppressed(args: string[]): boolean {
  if (args.includes("--no-update-check")) return true;
  const envVal = process.env["ANCILIS_NO_UPDATE_CHECK"];
  if (envVal && ["1", "true", "yes"].includes(envVal.toLowerCase())) return true;
  return isCiEnvironment();
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

function defaultCachePath(): string {
  return join(homedir(), ".ancilis", "version-check.json");
}

export function readCache(
  cachePath?: string,
  ttlSeconds?: number,
): { latestVersion: string } | null {
  const path = cachePath ?? defaultCachePath();
  const ttl = (ttlSeconds ?? DEFAULT_TTL_SECONDS) * 1000;

  if (!existsSync(path)) return null;

  try {
    const raw = readFileSync(path, "utf-8");
    const parsed = JSON.parse(raw) as VersionCache;
    if (typeof parsed.latestVersion !== "string" || typeof parsed.checkedAt !== "number") {
      return null;
    }
    if (Date.now() - parsed.checkedAt > ttl) return null;
    return { latestVersion: parsed.latestVersion };
  } catch {
    return null;
  }
}

export function writeCache(latestVersion: string, cachePath?: string): void {
  const path = cachePath ?? defaultCachePath();
  try {
    const dir = dirname(path);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    const data: VersionCache = { latestVersion, checkedAt: Date.now() };
    writeFileSync(path, JSON.stringify(data), "utf-8");
  } catch {
    // Silent failure — cache write errors must never crash the CLI
  }
}

// ---------------------------------------------------------------------------
// Registry fetch
// ---------------------------------------------------------------------------

export async function fetchLatestVersion(registryUrl?: string): Promise<string | null> {
  try {
    const url = registryUrl ?? NPM_REGISTRY_URL;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const response = await fetch(url, { signal: controller.signal });
      if (!response.ok) return null;
      const body = await response.json() as Record<string, unknown>;
      const version = body["version"];
      return typeof version === "string" ? version : null;
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Version comparison
// ---------------------------------------------------------------------------

function parseSemver(version: string): [number, number, number] | null {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (!match) return null;
  return [parseInt(match[1]!, 10), parseInt(match[2]!, 10), parseInt(match[3]!, 10)];
}

export function shouldNotify(installed: string, latest: string): boolean {
  const a = parseSemver(installed);
  const b = parseSemver(latest);
  if (!a || !b) return false;
  if (b[0] !== a[0]) return b[0] > a[0];
  if (b[1] !== a[1]) return b[1] > a[1];
  return b[2] > a[2];
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export function checkAndNotify(
  installedVersion: string,
  args: string[],
  io?: CliIo,
  cachePath?: string,
): void {
  if (isSuppressed(args)) return;

  const err = (msg: string): void => {
    const line = msg.endsWith("\n") ? msg : `${msg}\n`;
    if (io) {
      io.stderr(line);
    } else {
      process.stderr.write(line);
    }
  };

  const cached = readCache(cachePath);
  if (cached) {
    if (shouldNotify(installedVersion, cached.latestVersion)) {
      err(`\nUpdate available: ancilis ${installedVersion} → ${cached.latestVersion}`);
      err(`  Run: npm update -g ancilis`);
    }
    return;
  }

  // Fire-and-forget: fetch in background, write cache for next invocation
  void fetchLatestVersion().then((latest) => {
    if (latest !== null) {
      writeCache(latest, cachePath);
    }
  });
}
