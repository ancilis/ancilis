/** AKSI v0.6 freeze metadata validation. */

import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "../..");
const AKSI_VERSION_PATH = join(REPO_ROOT, "shared", "aksi_version.json");
const PLATFORM_REPO = "/Volumes/MiniAlbus/projects/ancilis-one-shot";

interface AksiVersion {
  framework_version: string;
  framework_commit_sha: string;
  framework_repo: string;
  framework_branch: string;
  framework_path: string;
  framework_master_sha256: string;
  frozen_at: string;
  frozen_for_sdk_build: string;
}

function loadAksiVersion(): AksiVersion {
  return JSON.parse(readFileSync(AKSI_VERSION_PATH, "utf8")) as AksiVersion;
}

function git(args: string[]): Buffer {
  return execFileSync("git", ["-C", PLATFORM_REPO, ...args]);
}

describe("AKSI v0.6 freeze metadata", () => {
  it("points to an existing platform commit", () => {
    const metadata = loadAksiVersion();

    expect(metadata.framework_version).toBe("0.6");
    expect(metadata.framework_repo).toBe("ancilis-one-shot");
    expect(metadata.framework_branch).toBe("codex/aksi-production-grade-framework");
    expect(metadata.framework_path).toBe("docs/framework/aksi-framework-master.md");
    expect(metadata.frozen_for_sdk_build).toBe("aksi-v06-sdk-full-support");

    expect(() => {
      git(["cat-file", "-e", `${metadata.framework_commit_sha}^{commit}`]);
    }).not.toThrow();
  });

  it("matches the frozen framework master checksum", () => {
    const metadata = loadAksiVersion();
    const content = git([
      "show",
      `${metadata.framework_commit_sha}:${metadata.framework_path}`,
    ]);
    const digest = createHash("sha256").update(content).digest("hex");

    expect(digest).toBe(metadata.framework_master_sha256);
  });
});
