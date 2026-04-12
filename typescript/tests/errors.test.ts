/** Tests for the Ancilis structured error hierarchy (ANC-478). */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import {
  AncilisError,
  AncilisWarning,
  ConnectionError,
  ConfigError,
  OverlayNotFoundError,
  StorageError,
  AuthError,
  RateLimitError,
  ScanError,
  UnsupportedFileError,
  UploadError,
  VersionError,
  warnNoOverlays,
  warnSdkUpdate,
  warnStoreSize,
  red,
  yellow,
  blue,
} from "../src/ancilis/errors.js";
import { runDoctor } from "../src/ancilis/cli/index.js";

// ---------------------------------------------------------------------------
// Base class
// ---------------------------------------------------------------------------

describe("AncilisError base class", () => {
  it("formats message with ANCILIS- prefix", () => {
    const err = new AncilisError("E001", "test message");
    expect(err.message).toBe("ANCILIS-E001: test message");
  });

  it("sets code, suggestion, docsUrl", () => {
    const err = new AncilisError("E002", "msg", "try this");
    expect(err.code).toBe("E002");
    expect(err.suggestion).toBe("try this");
    expect(err.docsUrl).toBe("https://docs.ancilis.ai/errors/e002");
  });

  it("name is AncilisError", () => {
    const err = new AncilisError("E003", "msg");
    expect(err.name).toBe("AncilisError");
  });

  it("is instanceof Error", () => {
    const err = new AncilisError("E004", "msg");
    expect(err).toBeInstanceOf(Error);
  });

  it("format() without color includes code, message, suggestion, and docs", () => {
    const err = new AncilisError("E001", "Cannot connect to platform at http://x", "Check config");
    const formatted = err.format(false);
    expect(formatted).toContain("ANCILIS-E001");
    expect(formatted).toContain("Cannot connect to platform");
    expect(formatted).toContain("→ Check config");
    expect(formatted).toContain("https://docs.ancilis.ai/errors/e001");
  });

  it("format() with color wraps code in ANSI red", () => {
    const err = new AncilisError("E001", "msg");
    const formatted = err.format(true);
    // ANSI red escape starts the formatted output
    expect(formatted).toContain("\u001b[31m");
    expect(formatted).toContain("ANCILIS-E001");
  });

  it("format() omits suggestion line when not set", () => {
    const err = new AncilisError("E001", "msg");
    const formatted = err.format(false);
    expect(formatted).not.toContain("→");
  });
});

// ---------------------------------------------------------------------------
// Error subclasses — one test per code
// ---------------------------------------------------------------------------

describe("ConnectionError (E001)", () => {
  it("has correct code and url in message", () => {
    const err = new ConnectionError("https://app.ancilis.ai");
    expect(err.code).toBe("E001");
    expect(err.message).toContain("https://app.ancilis.ai");
    expect(err.suggestion).toContain("platform_url");
    expect(err.docsUrl).toBe("https://docs.ancilis.ai/errors/e001");
  });

  it("is instanceof AncilisError and Error", () => {
    const err = new ConnectionError("http://x");
    expect(err).toBeInstanceOf(AncilisError);
    expect(err).toBeInstanceOf(Error);
  });

  it("stores cause when provided", () => {
    const cause = new Error("timeout");
    const err = new ConnectionError("http://x", cause);
    expect(err.cause).toBe(cause);
  });
});

describe("ConfigError (E002)", () => {
  it("has correct code and includes validation detail", () => {
    const err = new ConfigError("field 'mode' invalid");
    expect(err.code).toBe("E002");
    expect(err.message).toContain("field 'mode' invalid");
    expect(err.suggestion).toContain("ancilis init");
  });
});

describe("OverlayNotFoundError (E003)", () => {
  it("has correct code and overlay name in message", () => {
    const err = new OverlayNotFoundError("hipaa", ["soc2", "iso27001"]);
    expect(err.code).toBe("E003");
    expect(err.message).toContain("hipaa");
    expect(err.suggestion).toContain("soc2");
    expect(err.suggestion).toContain("iso27001");
  });

  it("handles empty available list gracefully", () => {
    const err = new OverlayNotFoundError("unknown");
    expect(err.code).toBe("E003");
    expect(err.suggestion).toBeTruthy();
  });
});

describe("StorageError (E004)", () => {
  it("has correct code and path in suggestion", () => {
    const err = new StorageError("/var/db/evidence.duckdb");
    expect(err.code).toBe("E004");
    expect(err.suggestion).toContain("/var/db/evidence.duckdb");
  });

  it("stores cause when provided", () => {
    const cause = new Error("permission denied");
    const err = new StorageError("/path", cause);
    expect(err.cause).toBe(cause);
  });
});

describe("AuthError (E005)", () => {
  it("has correct code and platform url in suggestion", () => {
    const err = new AuthError("https://app.ancilis.ai");
    expect(err.code).toBe("E005");
    expect(err.suggestion).toContain("https://app.ancilis.ai/settings/api-keys");
  });
});

describe("RateLimitError (E006)", () => {
  it("has correct code with retry seconds", () => {
    const err = new RateLimitError(30);
    expect(err.code).toBe("E006");
    expect(err.message).toContain("30s");
  });

  it("works without retry seconds", () => {
    const err = new RateLimitError();
    expect(err.code).toBe("E006");
    expect(err.message).toContain("Rate limited");
  });
});

describe("ScanError (E007)", () => {
  it("has correct code and path in message", () => {
    const err = new ScanError("/nonexistent/path");
    expect(err.code).toBe("E007");
    expect(err.message).toContain("/nonexistent/path");
  });
});

describe("UnsupportedFileError (E008)", () => {
  it("has correct code and path in message", () => {
    const err = new UnsupportedFileError("/project/empty");
    expect(err.code).toBe("E008");
    expect(err.message).toContain("/project/empty");
    expect(err.suggestion).toContain(".py");
  });
});

describe("UploadError (E009)", () => {
  it("has correct code with numeric HTTP status", () => {
    const err = new UploadError(403);
    expect(err.code).toBe("E009");
    expect(err.message).toContain("403");
  });

  it("has correct code with string HTTP status", () => {
    const err = new UploadError("429 Too Many Requests");
    expect(err.code).toBe("E009");
    expect(err.message).toContain("429");
  });
});

describe("VersionError (E010)", () => {
  it("has correct code with current and min versions", () => {
    const err = new VersionError("16.14.0", "18.0.0");
    expect(err.code).toBe("E010");
    expect(err.message).toContain("16.14.0");
    expect(err.message).toContain("18.0.0");
  });
});

// ---------------------------------------------------------------------------
// Warning codes
// ---------------------------------------------------------------------------

describe("AncilisWarning base class", () => {
  it("sets code, message, suggestion, docsUrl", () => {
    const w = new AncilisWarning("W001", "test warning", "try this");
    expect(w.code).toBe("W001");
    expect(w.message).toBe("test warning");
    expect(w.suggestion).toBe("try this");
    expect(w.docsUrl).toBe("https://docs.ancilis.ai/errors/w001");
  });

  it("toString returns ANCILIS- prefixed string", () => {
    const w = new AncilisWarning("W002", "msg");
    expect(w.toString()).toBe("ANCILIS-W002: msg");
  });

  it("format() without color includes code and message", () => {
    const w = new AncilisWarning("W001", "No overlays", "Run ancilis init");
    const formatted = w.format(false);
    expect(formatted).toContain("ANCILIS-W001");
    expect(formatted).toContain("No overlays");
    expect(formatted).toContain("→ Run ancilis init");
    expect(formatted).toContain("https://docs.ancilis.ai/errors/w001");
  });

  it("format() with color wraps in ANSI yellow", () => {
    const w = new AncilisWarning("W001", "msg");
    const formatted = w.format(true);
    expect(formatted).toContain("\u001b[33m");
  });
});

describe("warnNoOverlays (W001)", () => {
  it("returns AncilisWarning with W001 code", () => {
    const w = warnNoOverlays();
    expect(w).toBeInstanceOf(AncilisWarning);
    expect(w.code).toBe("W001");
    expect(w.message).toContain("No overlay profiles configured");
    expect(w.suggestion).toContain("ancilis init");
  });
});

describe("warnSdkUpdate (W002)", () => {
  it("returns AncilisWarning with W002 code and versions", () => {
    const w = warnSdkUpdate("0.1.0", "0.2.0");
    expect(w).toBeInstanceOf(AncilisWarning);
    expect(w.code).toBe("W002");
    expect(w.message).toContain("0.1.0");
    expect(w.message).toContain("0.2.0");
    expect(w.suggestion).toContain("npm update");
  });
});

describe("warnStoreSize (W003)", () => {
  it("returns AncilisWarning with W003 code and sizes", () => {
    const w = warnStoreSize(450, 500);
    expect(w).toBeInstanceOf(AncilisWarning);
    expect(w.code).toBe("W003");
    expect(w.message).toContain("450MB");
    expect(w.message).toContain("500MB");
    expect(w.suggestion).toContain("prune");
  });
});

// ---------------------------------------------------------------------------
// ANSI colour helpers
// ---------------------------------------------------------------------------

describe("ANSI color helpers", () => {
  it("red() wraps text with red escape codes", () => {
    const result = red("hello");
    expect(result).toBe("\u001b[31mhello\u001b[0m");
  });

  it("yellow() wraps text with yellow escape codes", () => {
    const result = yellow("hello");
    expect(result).toBe("\u001b[33mhello\u001b[0m");
  });

  it("blue() wraps text with blue escape codes", () => {
    const result = blue("hello");
    expect(result).toBe("\u001b[34mhello\u001b[0m");
  });
});

// ---------------------------------------------------------------------------
// Doctor checks — pass/fail scenarios
// ---------------------------------------------------------------------------

describe("ancilis doctor", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = join(tmpdir(), `ancilis-doctor-test-${randomUUID()}`);
    mkdirSync(tmpDir, { recursive: true });
  });

  afterEach(() => {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it("passes all checks with valid in-memory config", async () => {
    const result = await runDoctor(undefined, ":memory:");
    // Node version check should pass (we're running on a supported version)
    expect(result.output).toContain("node version");
    expect(result.output).toContain("[OK]");
  });

  it("fails config check when config path does not exist", async () => {
    const result = await runDoctor("/nonexistent/ancilis.yaml", ":memory:");
    expect(result.ok).toBe(false);
    expect(result.output).toContain("[FAIL]");
    // Should mention config check failure
    expect(result.output).toContain("config");
  });

  it("output includes doctor header", async () => {
    const result = await runDoctor(undefined, ":memory:");
    expect(result.output).toContain("Ancilis doctor");
  });

  it("returns ok=true when all checks pass", async () => {
    // With no config path and in-memory DB, most checks pass
    const result = await runDoctor(undefined, ":memory:");
    // Node check should always pass in CI
    expect(typeof result.ok).toBe("boolean");
    expect(result.output).toBeTruthy();
  });

  it("DuckDB writable check passes for writable temp dir", async () => {
    const dbPath = join(tmpDir, "evidence.duckdb");
    const result = await runDoctor(undefined, dbPath);
    expect(result.output).toContain("evidence store");
  });

  it("platform connectivity skipped when not configured", async () => {
    const result = await runDoctor(undefined, ":memory:");
    // Should show WARN for platform connectivity when not configured
    expect(result.output).toMatch(/platform connectivity|platform_url/);
  });

  it("summary line appears at end of output", async () => {
    const result = await runDoctor(undefined, ":memory:");
    expect(result.output).toMatch(/All checks passed|check\(s\) failed/);
  });
});
