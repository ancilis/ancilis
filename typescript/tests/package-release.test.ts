import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { afterEach, describe, expect, it } from "vitest";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function installPackedPackage(): string {
  const packDir = makeTempDir("ancilis-pack-");
  const installDir = makeTempDir("ancilis-install-");
  const packed = JSON.parse(
    execFileSync("npm", ["pack", "--json", "--pack-destination", packDir], {
      cwd: process.cwd(),
      encoding: "utf-8",
    }),
  ) as Array<{ filename: string }>;
  const tarballPath = join(packDir, packed[0]!.filename);

  execFileSync("npm", ["init", "-y"], { cwd: installDir, stdio: "ignore" });
  execFileSync("npm", ["install", tarballPath], {
    cwd: installDir,
    stdio: "pipe",
  });

  return installDir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("packaged CLI release readiness", () => {
  it("runs `ancilis --help` after installing the packed tarball", () => {
    const installDir = installPackedPackage();
    const output = execFileSync("npx", ["--no-install", "ancilis", "--help"], {
      cwd: installDir,
      encoding: "utf-8",
    });

    expect(output).toContain("ancilis doctor");
    expect(output).toContain("ancilis report");
  }, 120_000);

  it("runs `ancilis doctor` successfully from the installed tarball", () => {
    const installDir = installPackedPackage();
    writeFileSync(join(installDir, "ancilis.yaml"), "agent:\n  name: packaged-smoke\n");

    const output = execFileSync(
      "npx",
      ["--no-install", "ancilis", "doctor", "--config", "ancilis.yaml", "--db", "doctor.duckdb"],
      {
        cwd: installDir,
        encoding: "utf-8",
      },
    );

    expect(output).toContain("Ancilis doctor");
    expect(output).toContain("[OK] config:");
    expect(output).toContain("[OK] assets:");
  }, 120_000);

  it("package smoke script exercises installed oscal report export", () => {
    const output = execFileSync("node", ["scripts/ts_package_smoke.mjs"], {
      cwd: process.cwd(),
      encoding: "utf-8",
    });

    expect(output).toContain("ts-cli-formats-ok");
    expect(output).toContain("ts-report-oscal-ok");
  }, 120_000);

});

describe("publish configuration", () => {
  it("defines a prepublishOnly gate that builds, tests, and runs the package smoke check", () => {
    const pkg = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf-8")) as {
      scripts?: Record<string, string>;
    };

    expect(pkg.scripts?.prepublishOnly).toBe("npm run build && npm test && node scripts/ts_package_smoke.mjs");
  });

  it("ships a dedicated npm release workflow with OIDC provenance publishing", () => {
    const workflow = parseYaml(
      readFileSync(join(process.cwd(), ".github", "workflows", "release-typescript.yml"), "utf-8"),
    ) as {
      name?: string;
      on?: { push?: { tags?: string[] }; workflow_dispatch?: Record<string, never> };
      permissions?: Record<string, string>;
      jobs?: Record<
        string,
        {
          needs?: string | string[];
          steps?: Array<{ uses?: string; run?: string }>;
        }
      >;
    };

    expect(workflow.name).toBe("Release TypeScript");
    expect(workflow.on?.push?.tags).toContain("v*");
    expect(workflow.permissions).toMatchObject({
      contents: "read",
      "id-token": "write",
    });

    const verifyJob = workflow.jobs?.verify_typescript_release;
    expect(verifyJob).toBeDefined();
    const verifyRuns = verifyJob?.steps?.flatMap((step) => (step.run ? [step.run] : [])) ?? [];
    expect(verifyRuns).toContain("npm ci");
    expect(verifyRuns).toContain("npx vitest run");
    expect(verifyRuns.some((run) => run.includes("ts_package_smoke.mjs"))).toBe(true);

    const publishJob = workflow.jobs?.publish_typescript;
    expect(publishJob?.needs).toBe("verify_typescript_release");
    const publishRuns = publishJob?.steps?.flatMap((step) => (step.run ? [step.run] : [])) ?? [];
    expect(publishRuns.some((run) => run.includes("npm publish") && run.includes("--provenance"))).toBe(true);
  });

  it("publishes the exact tarball verified by the release job", () => {
    const workflow = parseYaml(
      readFileSync(join(process.cwd(), ".github", "workflows", "release-typescript.yml"), "utf-8"),
    ) as {
      jobs?: Record<
        string,
        {
          steps?: Array<{ uses?: string; run?: string; env?: Record<string, string> }>;
        }
      >;
    };

    const verifyJob = workflow.jobs?.verify_typescript_release;
    const verifyUses = verifyJob?.steps?.flatMap((step) => (step.uses ? [step.uses] : [])) ?? [];
    expect(verifyUses.some((u) => u.includes("actions/upload-artifact@"))).toBe(true);

    const publishJob = workflow.jobs?.publish_typescript;
    const publishUses = publishJob?.steps?.flatMap((step) => (step.uses ? [step.uses] : [])) ?? [];
    expect(publishUses.some((u) => u.includes("actions/download-artifact@"))).toBe(true);

    const publishRuns = publishJob?.steps?.flatMap((step) => (step.run ? [step.run] : [])) ?? [];
    expect(publishRuns).not.toContain("npm ci");
    expect(publishRuns).not.toContain("npm run build");
    expect(publishRuns.some((run) => /npm publish .*\.tgz --provenance/.test(run))).toBe(true);

    const publishStep = publishJob?.steps?.find((step) => step.run?.includes("npm publish"));
    expect(publishStep?.env).toMatchObject({
      NODE_AUTH_TOKEN: "${{ secrets.NPM_TOKEN }}",
    });
  });
});
