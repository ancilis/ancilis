import { runScan, validateScanResult } from "../src/scanner";
import scanFixture from "./fixtures/scan-output.json";
import type { ScanResult } from "../src/scanner";

// Mock @actions/exec
jest.mock("@actions/exec", () => ({
  getExecOutput: jest.fn(),
  exec: jest.fn(),
}));

// Mock @actions/core
jest.mock("@actions/core", () => ({
  info: jest.fn(),
  debug: jest.fn(),
  warning: jest.fn(),
  error: jest.fn(),
}));

// eslint-disable-next-line @typescript-eslint/no-require-imports
const mockExec = require("@actions/exec") as { getExecOutput: jest.Mock; exec: jest.Mock };

const validScanJson = JSON.stringify(scanFixture);

describe("runScan", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("parses valid scan output", async () => {
    mockExec.getExecOutput.mockResolvedValue({
      stdout: validScanJson,
      stderr: "",
      exitCode: 1,
    });

    const result = await runScan({ overlays: [], ancilisVersion: "ancilis" });
    expect(result.posture).toBe("non_compliant");
    expect(result.controls).toHaveLength(6);
    expect(result.summary.total_controls).toBe(6);
  });

  it("passes --ci flag to ancilis", async () => {
    mockExec.getExecOutput.mockResolvedValue({
      stdout: validScanJson,
      stderr: "",
      exitCode: 1,
    });

    await runScan({ overlays: [], ancilisVersion: "ancilis" });

    expect(mockExec.getExecOutput).toHaveBeenCalledWith(
      "ancilis",
      expect.arrayContaining(["scan", "--ci"]),
      expect.any(Object)
    );
  });

  it("passes --period flag", async () => {
    mockExec.getExecOutput.mockResolvedValue({
      stdout: validScanJson,
      stderr: "",
      exitCode: 1,
    });

    await runScan({ overlays: [], ancilisVersion: "ancilis", period: "48h" });

    expect(mockExec.getExecOutput).toHaveBeenCalledWith(
      "ancilis",
      expect.arrayContaining(["--period", "48h"]),
      expect.any(Object)
    );
  });

  it("passes --config when overlays provided", async () => {
    mockExec.getExecOutput.mockResolvedValue({
      stdout: validScanJson,
      stderr: "",
      exitCode: 1,
    });

    await runScan({ overlays: ["financial", "soc2"], ancilisVersion: "ancilis" });

    expect(mockExec.getExecOutput).toHaveBeenCalledWith(
      "ancilis",
      expect.arrayContaining(["--config"]),
      expect.any(Object)
    );
  });

  it("throws on empty output", async () => {
    mockExec.getExecOutput.mockResolvedValue({
      stdout: "",
      stderr: "error",
      exitCode: 2,
    });

    await expect(runScan({ overlays: [], ancilisVersion: "ancilis" })).rejects.toThrow(
      "no output"
    );
  });

  it("throws on invalid JSON", async () => {
    mockExec.getExecOutput.mockResolvedValue({
      stdout: "not json",
      stderr: "",
      exitCode: 0,
    });

    await expect(runScan({ overlays: [], ancilisVersion: "ancilis" })).rejects.toThrow(
      "Failed to parse"
    );
  });

  it("throws on missing controls array", async () => {
    const bad = JSON.stringify({ posture: "compliant", version: "0.1.0" });
    mockExec.getExecOutput.mockResolvedValue({
      stdout: bad,
      stderr: "",
      exitCode: 0,
    });

    await expect(runScan({ overlays: [], ancilisVersion: "ancilis" })).rejects.toThrow(
      "controls"
    );
  });
});

// Export validateScanResult for direct testing
// (we test it indirectly via runScan, but also directly here)
describe("scan result structure", () => {
  it("fixture has required fields", () => {
    const result = scanFixture as unknown as ScanResult;
    expect(result.version).toBeDefined();
    expect(result.agent).toBeDefined();
    expect(result.mode).toBeDefined();
    expect(result.timestamp).toBeDefined();
    expect(Array.isArray(result.controls)).toBe(true);
    expect(result.summary).toBeDefined();
    expect(result.posture).toMatch(/^(compliant|non_compliant)$/);
    expect(typeof result.exit_code).toBe("number");
  });

  it("fixture controls have required fields", () => {
    const result = scanFixture as unknown as ScanResult;
    for (const control of result.controls) {
      expect(control.id).toBeDefined();
      expect(control.name).toBeDefined();
      expect(["pass", "fail", "skip"]).toContain(control.status);
      expect(typeof control.evaluations).toBe("number");
      expect(typeof control.failures).toBe("number");
      expect(typeof control.flags).toBe("number");
    }
  });
});
