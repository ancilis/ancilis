/** ancilis.cli.watch — file watcher with debounced posture re-evaluation. */

import { watch } from "node:fs";
import { join, basename } from "node:path";
import type { ResolvedConfig } from "../config/index.js";
import { runEvaluation } from "./scan.js";
import type { ControlResult2 } from "./scan.js";
import { printScanResult, printSessionSummary } from "./watch-display.js";

const DEP_MANIFESTS = new Set([
  "package.json",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
]);

/** Directories always ignored by the watcher regardless of .ancilisignore. */
const HARDCODED_IGNORE = new Set([".ancilis", "node_modules", ".git"]);

/** Map changed file paths to affected producer names. */
export function getProducersForPaths(changedPaths: string[]): string[] {
  const producers = new Set<string>();
  for (const p of changedPaths) {
    const name = basename(p).toLowerCase();
    if (DEP_MANIFESTS.has(name)) {
      producers.add("dependency");
    } else if (p.endsWith(".duckdb") || p.endsWith(".db")) {
      producers.add("evidence");
    } else {
      producers.add("all");
    }
  }
  return producers.size > 0 ? [...producers] : ["all"];
}

function isHardcodeIgnored(filePath: string, watchDir: string): boolean {
  const rel = filePath.startsWith(watchDir)
    ? filePath.slice(watchDir.length).replace(/^[\\/]/, "")
    : filePath;
  const first = rel.split(/[\\/]/)[0];
  return first !== undefined && HARDCODED_IGNORE.has(first);
}

export interface WatchRunnerOptions {
  config: ResolvedConfig;
  dbPath?: string;
  /** Debounce window in seconds (default: 2) */
  debounce: number;
  /** Clear terminal before each scan result */
  clear: boolean;
  watchDir: string;
  /** Optional producer filter list */
  producers?: string[];
  /** ISO datetime lower bound for evidence query */
  since: string;
  sessionId?: string;
}

export class WatchRunner {
  private readonly config: ResolvedConfig;
  private readonly dbPath?: string;
  private readonly debounce: number;
  private readonly clear: boolean;
  private readonly watchDir: string;
  private readonly filterProducers?: Set<string>;
  private readonly since: string;

  private pending = new Set<string>();
  private debounceTimer?: ReturnType<typeof setTimeout>;
  private prevResults: ControlResult2[] | null = null;
  private prevPosture: string | null = null;
  private totalScans = 0;
  private readonly startTime = new Date();

  constructor(opts: WatchRunnerOptions) {
    this.config = opts.config;
    this.dbPath = opts.dbPath;
    this.debounce = opts.debounce;
    this.clear = opts.clear;
    this.watchDir = opts.watchDir;
    this.filterProducers = opts.producers ? new Set(opts.producers) : undefined;
    this.since = opts.since;
  }

  async run(): Promise<void> {
    // Initial scan always includes dep scan
    await this._doScan(null, true);

    return new Promise<void>(resolve => {
      const watcher = watch(
        this.watchDir,
        { recursive: true },
        (_eventType, filename) => {
          if (!filename) return;
          const fullPath = join(this.watchDir, filename);
          if (isHardcodeIgnored(fullPath, this.watchDir)) return;

          this.pending.add(fullPath);

          // Reset debounce timer
          if (this.debounceTimer !== undefined) clearTimeout(this.debounceTimer);
          this.debounceTimer = setTimeout(() => {
            const changed = [...this.pending];
            this.pending.clear();

            const producers = getProducersForPaths(changed);

            if (this.filterProducers !== undefined) {
              const effective = producers.filter(
                p => this.filterProducers!.has(p) || this.filterProducers!.has("all"),
              );
              if (effective.length === 0) return;
            }

            const runDep = producers.includes("dependency") || producers.includes("all");
            void this._doScan(changed, runDep);
          }, this.debounce * 1000);
        },
      );

      process.once("SIGINT", () => {
        watcher.close();
        if (this.debounceTimer !== undefined) clearTimeout(this.debounceTimer);
        printSessionSummary(this.startTime, this.totalScans, this.prevResults, this.prevPosture);
        resolve();
      });
    });
  }

  private async _doScan(changedPaths: string[] | null, runDep: boolean): Promise<void> {
    const result = await runEvaluation(this.config, {
      since: this.since,
      db: this.dbPath,
      runDepScan: runDep,
    });

    this.totalScans += 1;
    printScanResult({
      agentName: this.config.agentName,
      controlResults: result.controlResults,
      posture: result.posture,
      totalEvals: result.totalEvals,
      prevResults: this.prevResults,
      changedPaths,
      clear: this.clear,
    });
    this.prevResults = result.controlResults;
    this.prevPosture = result.posture;
  }
}
