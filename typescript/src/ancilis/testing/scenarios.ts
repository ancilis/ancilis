/**
 * Pre-built compliance test scenarios.
 *
 * Each factory returns a `FakeProducer` pre-configured for a specific
 * compliance state.  Use these to write fast, self-documenting tests
 * without hand-crafting config objects.
 *
 * @example
 * ```ts
 * import { ComplianceScenarios, expectControlToPass, expectPostureAbove } from "ancilis/testing";
 *
 * // Test that your agent logic passes full compliance
 * const producer = ComplianceScenarios.fullyCompliant();
 * const { evaluation } = await producer.evaluate("read_file");
 * expectControlToPass(evaluation, "PR-01");
 *
 * // Test a known-failing identity scenario
 * const broken = ComplianceScenarios.missingIdentity();
 * const { evaluation: ev2 } = await broken.evaluate("send_email");
 * expectControlToFail(ev2, "PR-01");
 * ```
 */

import { loadConfig } from "../config/index.js";
import type { ResolvedConfig } from "../config/index.js";
import { FakeProducer } from "./fake-producer.js";

export class ComplianceScenarios {
  /**
   * A fully-compliant scenario.  The agent identity matches the config so
   * PR-01 passes.  Mode is `audit` so control findings are logged but never
   * block execution — any FAIL will surface as an ALLOW with logged detail.
   *
   * Use this to assert that "happy path" agent code satisfies identity and
   * other controls without having to pre-register every tool.
   */
  static fullyCompliant(): FakeProducer {
    const config = loadConfig({
      raw: {
        agent: { name: "compliant-agent", owner: "security-team" },
        security: { mode: "audit" },
      },
    });
    // defaultAgentId matches config.agentName so PR-01 passes
    return new FakeProducer({ config, defaultAgentId: "compliant-agent" });
  }

  /**
   * A scenario where agent identity is absent — PR-01 (Identity) will FAIL.
   *
   * Use this to verify that your code handles identity-check failures
   * correctly (e.g. logs, fallback logic, user-facing error messages).
   */
  static missingIdentity(): FakeProducer {
    const config = loadConfig({
      raw: {
        agent: { name: "registered-agent" },
        security: { mode: "audit" },
      },
    });
    // Empty string triggers "Agent identity missing" in PR-01
    return new FakeProducer({ config, defaultAgentId: "" });
  }

  /**
   * A minimal-viable scenario — only PR-01 is enabled; all other controls
   * are disabled.  Useful for testing a single control in isolation.
   */
  static minimalViable(): FakeProducer {
    const config = loadConfig({
      raw: {
        agent: { name: "minimal-agent" },
        security: {
          mode: "audit",
          controls: {
            "PR-02": { enabled: false },
            "PR-03": { enabled: false },
            "PR-04": { enabled: false },
            "PR-05": { enabled: false },
            "DE-01": { enabled: false },
          },
        },
      },
    });
    return new FakeProducer({ config, defaultAgentId: "minimal-agent" });
  }

  /**
   * An enforce-mode scenario.  Any control failure results in `BLOCK`.
   *
   * Use this to verify that your code handles `BlockedActionError`
   * correctly when the engine is in strict enforcement mode.
   */
  static enforceMode(): FakeProducer {
    const config = loadConfig({
      raw: {
        agent: { name: "strict-agent" },
        security: { mode: "enforce" },
      },
    });
    return new FakeProducer({ config, defaultAgentId: "strict-agent" });
  }

  /**
   * Returns the `ResolvedConfig` for the fully-compliant scenario without
   * wrapping it in a `FakeProducer`.  Useful when you need the raw config
   * to construct your own `Engine` or `EvidenceStore`.
   */
  static fullyCompliantConfig(): ResolvedConfig {
    return loadConfig({
      raw: {
        agent: { name: "compliant-agent", owner: "security-team" },
        security: { mode: "enforce" },
      },
    });
  }

  /**
   * Returns the `ResolvedConfig` for the minimal scenario without a
   * `FakeProducer` wrapper.
   */
  static minimalViableConfig(): ResolvedConfig {
    return loadConfig({
      raw: {
        agent: { name: "minimal-agent" },
        security: {
          mode: "audit",
          controls: {
            "PR-02": { enabled: false },
            "PR-03": { enabled: false },
            "PR-04": { enabled: false },
            "PR-05": { enabled: false },
            "DE-01": { enabled: false },
          },
        },
      },
    });
  }
}
