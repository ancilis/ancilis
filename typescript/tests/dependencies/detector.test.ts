import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { detectDependencies } from "../../src/ancilis/dependencies/detector.js";

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), "ancilis-dep-test-"));
}

describe("detectDependencies", () => {
  it("returns null when no lockfile exists", () => {
    const dir = makeTmpDir();
    expect(detectDependencies(dir)).toBeNull();
  });

  it("parses package-lock.json v2 (packages field)", () => {
    const dir = makeTmpDir();
    const lockfile = {
      lockfileVersion: 2,
      packages: {
        "": { name: "my-app" },
        "node_modules/lodash": { version: "4.17.21" },
        "node_modules/@types/node": { version: "20.0.0" },
        "node_modules/react/node_modules/scheduler": { version: "0.23.0" },
      },
    };
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify(lockfile));
    const result = detectDependencies(dir);
    expect(result).not.toBeNull();
    expect(result!.manifestFormat).toBe("package-lock.json");
    const names = result!.dependencies.map((d) => d.name);
    expect(names).toContain("lodash");
    expect(names).toContain("@types/node");
    // nested node_modules should be filtered out
    expect(names).not.toContain("scheduler");
    expect(result!.dependencies[0]!.ecosystem).toBe("npm");
  });

  it("parses package-lock.json v1 (dependencies field)", () => {
    const dir = makeTmpDir();
    const lockfile = {
      lockfileVersion: 1,
      dependencies: {
        express: { version: "4.18.2" },
        "body-parser": { version: "1.20.1" },
      },
    };
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify(lockfile));
    const result = detectDependencies(dir);
    expect(result).not.toBeNull();
    const names = result!.dependencies.map((d) => d.name);
    expect(names).toContain("express");
    expect(names).toContain("body-parser");
  });

  it("parses yarn.lock classic format", () => {
    const dir = makeTmpDir();
    const yarnLock = `# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-abc==

react@^18.0.0, react@^18.2.0:
  version "18.2.0"
  resolved "https://registry.yarnpkg.com/react/-/react-18.2.0.tgz"

"@scope/pkg@^1.0.0":
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.2.3.tgz"
`;
    writeFileSync(join(dir, "yarn.lock"), yarnLock);
    const result = detectDependencies(dir);
    expect(result).not.toBeNull();
    expect(result!.manifestFormat).toBe("yarn.lock");
    const names = result!.dependencies.map((d) => d.name);
    expect(names).toContain("lodash");
    expect(names).toContain("react");
    expect(names).toContain("@scope/pkg");
    // Dedup: react appears once even though it had two specifiers
    expect(names.filter((n) => n === "react")).toHaveLength(1);
  });

  it("parses pnpm-lock.yaml v9 format", () => {
    const dir = makeTmpDir();
    const pnpmLock = `lockfileVersion: '9.0'

packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-abc==}
  '@types/node@20.0.0':
    resolution: {integrity: sha512-def==}
`;
    writeFileSync(join(dir, "pnpm-lock.yaml"), pnpmLock);
    const result = detectDependencies(dir);
    expect(result).not.toBeNull();
    expect(result!.manifestFormat).toBe("pnpm-lock.yaml");
    const names = result!.dependencies.map((d) => d.name);
    expect(names).toContain("lodash");
    expect(names).toContain("@types/node");
  });

  it("prefers pnpm-lock.yaml over yarn.lock over package-lock.json", () => {
    const dir = makeTmpDir();
    // Write all three
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({ lockfileVersion: 2, packages: { "node_modules/from-npm": { version: "1.0.0" } } })
    );
    const yarnLock = `# yarn lockfile v1\nfrom-yarn@^1.0.0:\n  version "1.0.0"\n`;
    writeFileSync(join(dir, "yarn.lock"), yarnLock);
    const pnpmLock = `lockfileVersion: '9.0'\npackages:\n  from-pnpm@1.0.0:\n    resolution: {}\n`;
    writeFileSync(join(dir, "pnpm-lock.yaml"), pnpmLock);

    const result = detectDependencies(dir);
    expect(result).not.toBeNull();
    expect(result!.manifestFormat).toBe("pnpm-lock.yaml");
    expect(result!.dependencies.map((d) => d.name)).toContain("from-pnpm");
  });

  it("returns correct ecosystem for all dependencies", () => {
    const dir = makeTmpDir();
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 2,
        packages: { "node_modules/express": { version: "4.18.2" } },
      })
    );
    const result = detectDependencies(dir);
    for (const dep of result!.dependencies) {
      expect(dep.ecosystem).toBe("npm");
    }
  });
});
