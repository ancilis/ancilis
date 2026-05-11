import { describe, expect, it } from "vitest";
import { isPrefixed, is_prefixed, prefix, unprefix } from "../src/ancilis/aksi/identifiers.js";

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

  it("identifies product-facing IDs", () => {
    expect(isPrefixed("AKSI-PR-04")).toBe(true);
    expect(is_prefixed("AKSI-PR-04")).toBe(true);
    expect(isPrefixed("PR-04")).toBe(false);
    expect(is_prefixed("PR-04")).toBe(false);
  });
});
