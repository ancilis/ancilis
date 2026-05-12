import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { isPrefixed, is_prefixed, prefix, unprefix } from "../src/ancilis/aksi/identifiers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "../..");
const PREFIX_DISCIPLINE_SCRIPT = join(REPO_ROOT, "scripts", "check_aksi_prefix_discipline.mjs");

describe("AKSI identifier utilities", () => {
  it("adds the AKSI product namespace", () => {
    expect(prefix("PR-04")).toBe("AKSI-PR-04");
  });

  it("keeps prefix idempotent for product-facing IDs", () => {
    expect(prefix("AKSI-PR-04")).toBe("AKSI-PR-04");
  });

  it("removes the hyphenated AKSI product namespace", () => {
    expect(unprefix("AKSI-PR-04")).toBe("PR-04");
  });

  it("accepts the legacy underscore namespace", () => {
    expect(unprefix("AKSI_PR-04")).toBe("PR-04");
  });

  it("only normalizes legacy namespace at the start", () => {
    expect(unprefix("LEGACY_AKSI_PR-04")).toBe("LEGACY_AKSI_PR-04");
  });

  it("identifies product-facing IDs", () => {
    expect(isPrefixed("AKSI-PR-04")).toBe(true);
    expect(is_prefixed("AKSI-PR-04")).toBe(true);
    expect(isPrefixed("PR-04")).toBe(false);
    expect(is_prefixed("PR-04")).toBe(false);
  });
});

describe("AKSI prefix discipline guard", () => {
  function withFixture(fn: (fixtureDir: string) => void): void {
    const fixtureDir = mkdtempSync(join(tmpdir(), "ancilis-aksi-prefix-"));
    try {
      fn(fixtureDir);
    } finally {
      rmSync(fixtureDir, { recursive: true, force: true });
    }
  }

  it("passes when scanned code uses internal IDs", () => {
    withFixture((fixtureDir) => {
      writeFileSync(join(fixtureDir, "good.ts"), 'const controlId = "PR-04";\n');

      expect(() => {
        execFileSync("node", [PREFIX_DISCIPLINE_SCRIPT], {
          cwd: REPO_ROOT,
          env: {
            ...process.env,
            ANCILIS_AKSI_PREFIX_SCAN_ROOTS: fixtureDir,
          },
        });
      }).not.toThrow();
    });
  });

  it("fails when scanned code hardcodes product-facing prefixes", () => {
    withFixture((fixtureDir) => {
      writeFileSync(join(fixtureDir, "bad.ts"), 'const controlId = "AKSI-PR-04";\n');

      expect(() => {
        execFileSync("node", [PREFIX_DISCIPLINE_SCRIPT], {
          cwd: REPO_ROOT,
          env: {
            ...process.env,
            ANCILIS_AKSI_PREFIX_SCAN_ROOTS: fixtureDir,
          },
        });
      }).toThrow(/raw AKSI prefix literal/);
    });
  });
});
