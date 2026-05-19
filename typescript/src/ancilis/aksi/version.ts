/** AKSI framework version metadata. */

import { readFileSync } from "node:fs";
import { sharedPathFrom } from "../shared-path.js";

export const DEFAULT_AKSI_FRAMEWORK_VERSION = "0.6";

export interface AksiFrameworkMetadata {
  framework_version: string;
  framework_commit_sha?: string;
  framework_repo?: string;
  framework_branch?: string;
  framework_path?: string;
  framework_master_sha256?: string;
  frozen_at?: string;
  frozen_for_sdk_build?: string;
}

export function loadFrameworkMetadata(): AksiFrameworkMetadata {
  try {
    const parsed = JSON.parse(readFileSync(sharedPathFrom(import.meta.url, "aksi_version.json"), "utf-8")) as unknown;
    if (parsed && typeof parsed === "object") {
      const metadata = parsed as Partial<AksiFrameworkMetadata>;
      if (typeof metadata.framework_version === "string" && metadata.framework_version.length > 0) {
        return metadata as AksiFrameworkMetadata;
      }
    }
  } catch {
    // Keep SDK imports usable if shared assets are absent in unusual test/build contexts.
  }
  return { framework_version: DEFAULT_AKSI_FRAMEWORK_VERSION };
}

export const AKSI_FRAMEWORK_VERSION = loadFrameworkMetadata().framework_version;
