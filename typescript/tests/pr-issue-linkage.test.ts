import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";

type WorkflowStep = {
  uses?: string;
  run?: string;
  env?: Record<string, string>;
};

type Workflow = {
  name?: string;
  on?: {
    pull_request?: {
      branches?: string[];
    };
    push?: unknown;
  };
  jobs?: Record<
    string,
    {
      steps?: WorkflowStep[];
    }
  >;
};

function runGuard(
  title: string,
  headRef: string,
  authorLogin = "",
): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync("node", ["scripts/check_pr_issue_linkage.mjs"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PR_TITLE: title,
      PR_HEAD_REF: headRef,
      PR_AUTHOR_LOGIN: authorLogin,
    },
    encoding: "utf-8",
  });

  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function readWorkflow(fileName: string): Workflow {
  return parseYaml(readFileSync(join(process.cwd(), ".github", "workflows", fileName), "utf-8")) as Workflow;
}

describe("PR issue linkage guard", () => {
  it("accepts pull requests when the title contains an ANC issue id", () => {
    const result = runGuard("feat: ANC-1508 enforce PR linkage", "feature/no-ticket-needed");

    expect(result.status).toBe(0);
  });

  it("accepts pull requests when the head branch contains an ANC issue id", () => {
    const result = runGuard("feat: enforce PR linkage", "feature/anc-1508-pr-linkage");

    expect(result.status).toBe(0);
  });

  it("matches ANC issue ids regardless of case", () => {
    const result = runGuard("feat: link policy", "feature/Anc-1508-pr-linkage");

    expect(result.status).toBe(0);
  });

  it("rejects pull requests when both title and branch omit an ANC issue id", () => {
    const result = runGuard("feat: link policy", "feature/pr-linkage");

    expect(result.status).toBe(1);
    expect(`${result.stdout}\n${result.stderr}`).toMatch(/ANC-\d+/i);
  });

  it("accepts Dependabot pull requests on dependabot branches without an ANC issue id", () => {
    const result = runGuard(
      "chore(deps): bump vite from 4.5.0 to 4.5.1",
      "dependabot/npm_and_yarn/vite-4.5.1",
      "dependabot[bot]",
    );

    expect(result.status).toBe(0);
  });

  it("rejects human-authored pull requests on dependabot branches without an ANC issue id", () => {
    const result = runGuard(
      "feat: sneak past linkage",
      "dependabot/npm_and_yarn/vite-4.5.1",
      "octocat",
    );

    expect(result.status).toBe(1);
    expect(`${result.stdout}\n${result.stderr}`).toMatch(/ANC-\d+/i);
  });

  it("rejects Dependabot-authored pull requests when the branch is not a dependabot branch", () => {
    const result = runGuard(
      "chore(deps): bump vite from 4.5.0 to 4.5.1",
      "chore/dependabot-bump-vite",
      "dependabot[bot]",
    );

    expect(result.status).toBe(1);
    expect(`${result.stdout}\n${result.stderr}`).toMatch(/ANC-\d+/i);
  });
});

describe("PR issue linkage governance", () => {
  it("ships a PR-only workflow that runs the linkage guard before full CI", () => {
    const workflow = readWorkflow("pr-issue-linkage.yml");
    const steps = workflow.jobs?.validate_issue_linkage?.steps ?? [];
    const runStep = steps.find((step) => step.run?.includes("node scripts/check_pr_issue_linkage.mjs"));

    expect(workflow.name).toBe("PR Issue Linkage");
    expect(workflow.on?.pull_request?.branches).toContain("main");
    expect(workflow.on?.push).toBeUndefined();
    expect(steps.some((step) => step.uses?.startsWith("actions/checkout@"))).toBe(true);
    expect(runStep?.env).toMatchObject({
      PR_TITLE: "${{ github.event.pull_request.title }}",
      PR_HEAD_REF: "${{ github.event.pull_request.head.ref }}",
      PR_AUTHOR_LOGIN: "${{ github.event.pull_request.user.login }}",
    });
  });

  it("documents the one-issue-per-PR rule and narrow Dependabot exception in CONTRIBUTING", () => {
    const contributing = readFileSync(join(process.cwd(), "CONTRIBUTING.md"), "utf-8");

    expect(contributing).toMatch(/one issue per pull request/i);
    expect(contributing).toMatch(/ANC-\d+/i);
    expect(contributing).toMatch(/dependabot\[bot\]/i);
    expect(contributing).toMatch(/dependabot\//i);
  });
});
