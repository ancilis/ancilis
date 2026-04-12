import { describe, expect, it, vi, afterEach } from "vitest";
import { queryOsvBatch } from "../../src/ancilis/dependencies/osv.js";
import type { Dependency } from "../../src/ancilis/dependencies/types.js";

afterEach(() => {
  vi.restoreAllMocks();
});

function mockFetch(response: unknown, ok = true, status = 200): void {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok,
      status,
      json: vi.fn().mockResolvedValue(response),
    })
  );
}

function mockFetchError(): void {
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("Network error")));
}

const LODASH_DEP: Dependency = { name: "lodash", version: "4.17.20", ecosystem: "npm" };
const SAFE_DEP: Dependency = { name: "safe-pkg", version: "1.0.0", ecosystem: "npm" };

describe("queryOsvBatch", () => {
  it("returns empty findings for empty dependency list", async () => {
    const { findings, error } = await queryOsvBatch([]);
    expect(findings).toEqual([]);
    expect(error).toBeNull();
  });

  it("returns findings with correct shape for a vulnerable package", async () => {
    mockFetch({
      results: [
        {
          vulns: [
            {
              id: "GHSA-abc-def-ghi",
              aliases: ["CVE-2021-23337"],
              summary: "Prototype pollution in lodash",
              severity: [{ type: "CVSS_V3", score: "7.2" }],
              affected: [
                {
                  package: { name: "lodash", ecosystem: "npm" },
                  ranges: [
                    {
                      type: "SEMVER",
                      events: [{ introduced: "0" }, { fixed: "4.17.21" }],
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    });

    const { findings, error } = await queryOsvBatch([LODASH_DEP]);
    expect(error).toBeNull();
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.cveId).toBe("CVE-2021-23337");
    expect(f.packageName).toBe("lodash");
    expect(f.installedVersion).toBe("4.17.20");
    expect(f.severity).toBe("high");
    expect(f.cvssScore).toBeCloseTo(7.2);
    expect(f.fixedVersion).toBe("4.17.21");
    expect(f.summary).toBe("Prototype pollution in lodash");
  });

  it("uses GHSA id when no CVE alias present", async () => {
    mockFetch({
      results: [
        {
          vulns: [
            {
              id: "GHSA-xyz-1234",
              aliases: [],
              summary: "Some issue",
              severity: [],
              affected: [],
            },
          ],
        },
      ],
    });

    const { findings } = await queryOsvBatch([LODASH_DEP]);
    expect(findings[0]!.cveId).toBe("GHSA-xyz-1234");
  });

  it("returns empty findings when package has no vulns", async () => {
    mockFetch({ results: [{ vulns: [] }] });
    const { findings, error } = await queryOsvBatch([SAFE_DEP]);
    expect(findings).toEqual([]);
    expect(error).toBeNull();
  });

  it("maps CVSS scores to correct severity buckets", async () => {
    const scores = [
      { score: "9.8", expected: "critical" },
      { score: "7.5", expected: "high" },
      { score: "5.0", expected: "medium" },
      { score: "2.0", expected: "low" },
    ] as const;

    for (const { score, expected } of scores) {
      mockFetch({
        results: [
          {
            vulns: [
              {
                id: "TEST-001",
                aliases: [],
                summary: "test",
                severity: [{ type: "CVSS_V3", score }],
                affected: [],
              },
            ],
          },
        ],
      });

      const { findings } = await queryOsvBatch([SAFE_DEP]);
      expect(findings[0]!.severity).toBe(expected);
    }
  });

  it("falls back to database_specific severity when no CVSS score", async () => {
    mockFetch({
      results: [
        {
          vulns: [
            {
              id: "TEST-002",
              aliases: [],
              summary: "test",
              severity: [],
              database_specific: { severity: "CRITICAL" },
              affected: [],
            },
          ],
        },
      ],
    });

    const { findings } = await queryOsvBatch([SAFE_DEP]);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.cvssScore).toBeNull();
  });

  it("returns error and empty findings when OSV.dev is unreachable", async () => {
    mockFetchError();
    const { findings, error } = await queryOsvBatch([LODASH_DEP]);
    expect(findings).toEqual([]);
    expect(error).not.toBeNull();
    expect(error).toMatch(/unreachable/i);
  });

  it("handles multiple packages in a single batch", async () => {
    mockFetch({
      results: [
        {
          vulns: [
            {
              id: "CVE-A",
              aliases: [],
              summary: "vuln in A",
              severity: [{ type: "CVSS_V3", score: "9.0" }],
              affected: [],
            },
          ],
        },
        { vulns: [] },
      ],
    });

    const deps: Dependency[] = [
      { name: "pkg-a", version: "1.0.0", ecosystem: "npm" },
      { name: "pkg-b", version: "2.0.0", ecosystem: "npm" },
    ];
    const { findings, error } = await queryOsvBatch(deps);
    expect(error).toBeNull();
    expect(findings).toHaveLength(1);
    expect(findings[0]!.packageName).toBe("pkg-a");
  });
});
