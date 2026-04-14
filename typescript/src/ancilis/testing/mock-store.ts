/** MockEvidenceStore — in-memory evidence store for testing. */

import { EvidenceStore } from "../evidence/store.js";
import type { EvidenceRecord } from "../evidence/record.js";
import type { EvaluationResult } from "../engine/result.js";
import { makeTestConfig } from "./helpers.js";

/**
 * In-memory evidence store for testing.
 *
 * Drop-in replacement for EvidenceStore that uses DuckDB `:memory:` mode.
 * No filesystem writes, no DuckDB files. Safe to use in any test environment.
 *
 * @example
 * const store = new MockEvidenceStore();
 * await store.store(evaluation, "my_tool");
 * expect(store.count()).resolves.toBe(1);
 * await store.close();
 */
export class MockEvidenceStore {
  private readonly _store: EvidenceStore;

  constructor(
    agentName: string = "test-agent",
    mode: "audit" | "enforce" = "audit",
    overlay?: string,
  ) {
    const config = makeTestConfig({ agentName, mode, overlay });
    this._store = new EvidenceStore(config, { inMemory: true });
  }

  /** Store an evaluation result. */
  async store(evaluation: EvaluationResult, toolName: string = "test_tool"): Promise<EvidenceRecord> {
    return this._store.store(evaluation, toolName);
  }

  /** Count stored records. */
  async count(): Promise<number> {
    const summary = await this._store.getSummary();
    return (summary.totalEvaluations as number | undefined) ?? 0;
  }

  /** Get summary of stored records. */
  async getSummary(): Promise<Record<string, unknown>> {
    return this._store.getSummary() as Promise<Record<string, unknown>>;
  }

  /** Verify the hash chain integrity. */
  async verifyChain(): Promise<{ valid: boolean; errors: string[] }> {
    return this._store.verifyChain();
  }

  /** Reset all evidence records. */
  async reset(): Promise<number> {
    return this._store.reset();
  }

  /** Close the underlying DuckDB connection. */
  async close(): Promise<void> {
    return this._store.close();
  }
}
