import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import {
  bucketCount,
  bucketDuration,
  flushTelemetryEvents,
  formatTelemetryStatus,
  readTelemetryStatus,
  recordTelemetryEvent,
  setTelemetryEnabled,
  telemetryConfigPath,
  telemetryQueuePath,
} from "../src/ancilis/telemetry/index.js";

const packageVersion = JSON.parse(
  readFileSync(new URL("../../package.json", import.meta.url), "utf-8"),
) as { version: string };

function tmpHome(): string {
  const dir = join(tmpdir(), `ancilis-telemetry-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

describe("anonymous telemetry", () => {
  it("defaults off and respects DO_NOT_TRACK", () => {
    const homeDir = tmpHome();

    expect(readTelemetryStatus({ homeDir }).effectiveEnabled).toBe(false);

    setTelemetryEnabled(true, { homeDir, endpoint: "https://telemetry.example.test/events" });
    const status = readTelemetryStatus({ homeDir, env: { DO_NOT_TRACK: "1" } });

    expect(status.enabled).toBe(true);
    expect(status.effectiveEnabled).toBe(false);
    expect(status.reason).toBe("DO_NOT_TRACK is set");
    expect(formatTelemetryStatus(status)).toContain("No file paths");
  });

  it("stores consent in the global config without creating an id for off-only state", () => {
    const homeDir = tmpHome();

    const disabled = setTelemetryEnabled(false, { homeDir });
    expect(disabled.installationId).toBeNull();
    expect(readFileSync(telemetryConfigPath({ homeDir }), "utf-8")).not.toContain("installation_id");

    const enabled = setTelemetryEnabled(true, { homeDir });
    expect(enabled.installationId).toMatch(/[0-9a-f-]{36}/);
    expect(readFileSync(telemetryConfigPath({ homeDir }), "utf-8")).toContain("enabled = true");
  });

  it("queues anonymous events and silently flushes batches", async () => {
    const homeDir = tmpHome();
    setTelemetryEnabled(true, {
      homeDir,
      endpoint: "https://telemetry.example.test/events",
      now: new Date("2026-05-02T00:00:00Z"),
    });

    await recordTelemetryEvent("scan_executed", { overlay_ids: ["soc2"] }, {
      homeDir,
      fetchImpl: async () => {
        throw new Error("offline");
      },
    });

    expect(existsSync(telemetryQueuePath({ homeDir }))).toBe(true);
    expect(readTelemetryStatus({ homeDir }).queuedEvents).toBe(1);

    const payloads: unknown[] = [];
    const result = await flushTelemetryEvents({
      homeDir,
      force: true,
      fetchImpl: async (_url, init) => {
        payloads.push(JSON.parse(String(init?.body)));
        return new Response("{}", { status: 202 });
      },
    });

    expect(result).toEqual({ sent: true, count: 1 });
    expect(readTelemetryStatus({ homeDir }).queuedEvents).toBe(0);
    expect(payloads).toHaveLength(1);
    expect(JSON.stringify(payloads[0])).not.toContain(process.cwd());
  });

  it("records the current package version in queued events", async () => {
    const homeDir = tmpHome();
    setTelemetryEnabled(true, { homeDir });

    await recordTelemetryEvent("cli_command", { command: "status", exit_code: 0 }, {
      homeDir,
      fetchImpl: async () => {
        throw new Error("offline");
      },
    });

    const [line] = readFileSync(telemetryQueuePath({ homeDir }), "utf-8").trim().split("\n");
    const event = JSON.parse(line) as { sdk_version: string };

    expect(event.sdk_version).toBe(packageVersion.version);
  });

  it("uses coarse buckets for scan metadata", () => {
    expect(bucketCount(0)).toBe("0");
    expect(bucketCount(10)).toBe("1-10");
    expect(bucketCount(100)).toBe("10-100");
    expect(bucketCount(101)).toBe("100+");
    expect(bucketDuration(500)).toBe("<1s");
    expect(bucketDuration(5000)).toBe("5-30s");
  });
});
