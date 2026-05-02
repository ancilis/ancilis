import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";

type WorkflowStep = {
  name?: string;
  run?: string;
  uses?: string;
  env?: Record<string, string>;
  "working-directory"?: string;
};

type Workflow = {
  jobs?: Record<
    string,
    {
      needs?: string | string[];
      steps?: WorkflowStep[];
    }
  >;
};

function readJson<T>(...pathParts: string[]): T {
  return JSON.parse(readFileSync(join(process.cwd(), ...pathParts), "utf-8")) as T;
}

function readWorkflow(fileName: string): Workflow {
  return parseYaml(readFileSync(join(process.cwd(), ".github", "workflows", fileName), "utf-8")) as Workflow;
}

function readText(...pathParts: string[]): string {
  return readFileSync(join(process.cwd(), ...pathParts), "utf-8");
}

function steps(workflow: Workflow, jobName: string): WorkflowStep[] {
  return workflow.jobs?.[jobName]?.steps ?? [];
}

function hasRun(stepList: WorkflowStep[], expected: string, workingDirectory?: string): boolean {
  return stepList.some((step) => {
    if (workingDirectory !== undefined && step["working-directory"] !== workingDirectory) {
      return false;
    }
    return step.run?.includes(expected) ?? false;
  });
}

function indexOfRun(stepList: WorkflowStep[], expected: string, workingDirectory?: string): number {
  return stepList.findIndex((step) => {
    if (workingDirectory !== undefined && step["working-directory"] !== workingDirectory) {
      return false;
    }
    return step.run?.includes(expected) ?? false;
  });
}

describe("release dependency security gates", () => {
  it("defines explicit audit scripts for root npm, scan-action, and the Python lockfile", () => {
    const rootPackage = readJson<{ scripts?: Record<string, string> }>("package.json");
    const scanActionPackage = readJson<{ scripts?: Record<string, string> }>("scan-action", "package.json");

    expect(rootPackage.scripts?.["security:audit:npm"]).toBe("npm audit --audit-level=high");
    expect(rootPackage.scripts?.["security:audit:scan-action"]).toBe("npm --prefix scan-action run security:audit");
    expect(rootPackage.scripts?.["security:audit:python-lock"]).toBe(
      "pip-audit --desc --requirement requirements-lock.txt --ignore-vuln CVE-2026-4539",
    );
    expect(scanActionPackage.scripts?.["security:audit"]).toBe("npm audit --audit-level=moderate");
  });

  it("runs all dependency audits in the main CI dependency-audit job", () => {
    const dependencyAuditSteps = steps(readWorkflow("ci.yml"), "dependency-audit");

    expect(hasRun(dependencyAuditSteps, "npm run security:audit:python-lock")).toBe(true);
    expect(hasRun(dependencyAuditSteps, "npm ci --include=dev")).toBe(true);
    expect(hasRun(dependencyAuditSteps, "npm run security:audit:npm")).toBe(true);
    expect(hasRun(dependencyAuditSteps, "npm ci --include=dev", "scan-action")).toBe(true);
    expect(hasRun(dependencyAuditSteps, "npm run security:audit", "scan-action")).toBe(true);
  });

  it("runs TypeScript release audits before packing the published tarball", () => {
    const verifyReleaseSteps = steps(readWorkflow("release-typescript.yml"), "verify_typescript_release");
    const packVerifiedTarballIndex = indexOfRun(
      verifyReleaseSteps,
      "npm pack --json --pack-destination release-artifacts",
    );

    expect(packVerifiedTarballIndex).toBeGreaterThan(0);
    expect(indexOfRun(verifyReleaseSteps, "npm run security:audit:npm")).toBeGreaterThanOrEqual(0);
    expect(indexOfRun(verifyReleaseSteps, "npm run security:audit:npm")).toBeLessThan(packVerifiedTarballIndex);
    expect(hasRun(verifyReleaseSteps, "npm ci --include=dev", "scan-action")).toBe(true);
    expect(indexOfRun(verifyReleaseSteps, "npm run security:audit", "scan-action")).toBeLessThan(
      packVerifiedTarballIndex,
    );

    const buildSteps = steps(readWorkflow("ts-sdk-release.yml"), "build");
    const packTarballIndex = indexOfRun(buildSteps, "npm pack --json --pack-destination release-dist");

    expect(packTarballIndex).toBeGreaterThan(0);
    expect(indexOfRun(buildSteps, "npm run security:audit:npm")).toBeGreaterThanOrEqual(0);
    expect(indexOfRun(buildSteps, "npm run security:audit:npm")).toBeLessThan(packTarballIndex);
    expect(hasRun(buildSteps, "npm ci --include=dev", "scan-action")).toBe(true);
    expect(indexOfRun(buildSteps, "npm run security:audit", "scan-action")).toBeLessThan(packTarballIndex);
  });

  it("audits requirements-lock.txt during Python release verification", () => {
    const verifyPythonSteps = steps(readWorkflow("release-python.yml"), "verify_python_release");

    expect(hasRun(verifyPythonSteps, "python -m pip install pip-audit")).toBe(true);
    expect(hasRun(verifyPythonSteps, "npm run security:audit:python-lock")).toBe(true);
  });

  it("publishes the exact TypeScript tarball verified by the release job", () => {
    const workflow = readWorkflow("release-typescript.yml");
    const verifyJobSteps = steps(workflow, "verify_typescript_release");
    const publishJobSteps = steps(workflow, "publish_typescript");

    expect(verifyJobSteps.some((step) => step.uses?.startsWith("actions/upload-artifact@"))).toBe(true);
    expect(publishJobSteps.some((step) => step.uses?.startsWith("actions/download-artifact@"))).toBe(true);
    expect(publishJobSteps.some((step) => step.run === "npm publish release-artifacts/*.tgz --provenance")).toBe(
      true,
    );
    expect(publishJobSteps.some((step) => step.run === "npm ci" || step.run === "npm run build")).toBe(false);
  });

  it("documents required operator commands and emergency direct-main exception handling", () => {
    const releaseReadme = readText("docs", "release", "README.md");
    const releaseChecklist = readText("docs", "release", "CHECKLIST.md");

    for (const command of [
      "npm ci --include=dev",
      "npm run security:audit:npm",
      "cd scan-action && npm ci --include=dev",
      "cd scan-action && npm run security:audit",
      "python -m pip install pip-audit",
      "npm run security:audit:python-lock",
    ]) {
      expect(releaseReadme).toContain(command);
      expect(releaseChecklist).toContain(command);
    }

    expect(releaseReadme).toMatch(/direct-main emergency merge/i);
    expect(releaseReadme).toMatch(/exception/i);
    expect(releaseChecklist).toMatch(/direct-main emergency merge/i);
  });
});
