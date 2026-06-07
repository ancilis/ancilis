/** ancilis.cli.init — interactive project scaffold with framework detection. */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { generateAncilisYaml } from "./templates/ancilis-yaml.js";
import { getScanScript } from "./templates/scan-scripts.js";
import { normalizeOverlayId } from "../overlays/index.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AVAILABLE_OVERLAYS = [
  "soc2",
  "gdpr",
  "hipaa",
  "iso-42001",
  "eu-ai-act",
  "nist-csf",
  "pci-dss-v4",
  "cmmc-l2",
  "glba",
  "securities-mnpi",
];

const AVAILABLE_FRAMEWORKS = ["langchain", "openai", "anthropic", "mcp", "generic"];

/** Package names that map to framework hints in package.json */
const FRAMEWORK_PACKAGES: Array<[RegExp, string]> = [
  [/^langchain$|^@langchain\//, "langchain"],
  [/^@anthropic-ai\/sdk$/, "anthropic"],
  [/^@modelcontextprotocol\/sdk$/, "mcp"],
  [/^openai$/, "openai"],
];

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface InitOptions {
  framework?: string;
  overlay?: string;
  agentName?: string;
  detect?: boolean;
  noSample?: boolean;
  dir?: string;
}

export interface DetectionResult {
  framework: string;
  confidence: "high" | "medium" | "low";
  source: string;
}

// ---------------------------------------------------------------------------
// Framework detection
// ---------------------------------------------------------------------------

/** Detect framework from package.json in the given directory. */
export function detectFramework(projectDir: string): DetectionResult | null {
  const pkgPath = join(projectDir, "package.json");
  if (!existsSync(pkgPath)) return null;

  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(readFileSync(pkgPath, "utf-8")) as Record<string, unknown>;
  } catch {
    return null;
  }

  const allDeps: string[] = [
    ...Object.keys((pkg.dependencies as Record<string, unknown> | undefined) ?? {}),
    ...Object.keys((pkg.devDependencies as Record<string, unknown> | undefined) ?? {}),
  ];

  for (const [pattern, framework] of FRAMEWORK_PACKAGES) {
    if (allDeps.some(dep => pattern.test(dep))) {
      return { framework, confidence: "high", source: "package.json" };
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Convert arbitrary string to valid agent name (lowercase, hyphens). */
export function sanitizeName(raw: string): string {
  const name = raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return name || "my-agent";
}

function promptLine(rl: ReturnType<typeof createInterface>, question: string): Promise<string> {
  return new Promise(resolve => rl.question(question, resolve));
}

async function promptFrameworkSelection(rl: ReturnType<typeof createInterface>): Promise<string> {
  process.stdout.write("Select agent framework:\n");
  AVAILABLE_FRAMEWORKS.forEach((fw, i) => {
    process.stdout.write(`  ${i + 1}. ${fw}\n`);
  });
  const answer = await promptLine(rl, `Framework [generic]: `);
  const trimmed = answer.trim().toLowerCase();
  if (!trimmed) return "generic";
  // Accept numeric index or name
  const idx = parseInt(trimmed, 10);
  if (!isNaN(idx) && idx >= 1 && idx <= AVAILABLE_FRAMEWORKS.length) {
    return AVAILABLE_FRAMEWORKS[idx - 1]!;
  }
  return AVAILABLE_FRAMEWORKS.includes(trimmed) ? trimmed : "generic";
}

async function promptOverlaySelection(rl: ReturnType<typeof createInterface>): Promise<string> {
  process.stdout.write("Available compliance overlays:\n");
  AVAILABLE_OVERLAYS.forEach((ol, i) => {
    process.stdout.write(`  ${String(i + 1).padStart(2)}. ${ol}\n`);
  });
  process.stdout.write("  [none] — skip overlay selection\n");
  const answer = await promptLine(rl, `Select overlay [soc2]: `);
  const trimmed = answer.trim().toLowerCase();
  if (!trimmed) return "soc2";
  if (trimmed === "none") return "none";
  const idx = parseInt(trimmed, 10);
  if (!isNaN(idx) && idx >= 1 && idx <= AVAILABLE_OVERLAYS.length) {
    return AVAILABLE_OVERLAYS[idx - 1]!;
  }
  return AVAILABLE_OVERLAYS.includes(trimmed) ? trimmed : "soc2";
}

function generateEnvExample(targetDir: string): void {
  const envFile = join(targetDir, ".env.example");
  if (!existsSync(envFile)) {
    writeFileSync(
      envFile,
      "# Ancilis platform API key (optional for local-only scanning)\n" +
      "# Get yours at https://app.ancilis.ai/settings\n" +
      "# ANCILIS_API_KEY=your-api-key-here\n",
      "utf-8",
    );
  }
}

// Append `.ancilis/` to an existing .gitignore. Returns true only if the file
// was actually changed (it is never created — the user may not use git).
function updateGitignore(targetDir: string): boolean {
  const gitignorePath = join(targetDir, ".gitignore");
  if (!existsSync(gitignorePath)) return false; // Don't create it — user may not be using git
  const content = readFileSync(gitignorePath, "utf-8");
  if (content.includes(".ancilis/")) return false; // already ignored
  const separator = content && !content.endsWith("\n") ? "\n" : "";
  writeFileSync(gitignorePath, content + separator + ".ancilis/\n", "utf-8");
  return true;
}

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------

export async function runInit(
  options: InitOptions,
  io?: { stdout(m: string): void; stderr(m: string): void },
): Promise<{ ok: boolean; output: string }> {
  const out = (m: string): void => {
    if (io) {
      io.stdout(m.endsWith("\n") ? m : `${m}\n`);
    } else {
      process.stdout.write(m.endsWith("\n") ? m : `${m}\n`);
    }
  };

  const targetDir = resolve(options.dir ?? ".");
  if (!existsSync(targetDir)) {
    mkdirSync(targetDir, { recursive: true });
  }

  const configFile = join(targetDir, "ancilis.yaml");
  const isInteractive = !options.detect && !options.framework;

  // Check existing file — always protect regardless of mode
  if (existsSync(configFile)) {
    return { ok: false, output: "ancilis.yaml already exists. Remove it first to re-initialize." };
  }

  let rl: ReturnType<typeof createInterface> | null = null;
  if (isInteractive) {
    rl = createInterface({ input: process.stdin, output: process.stdout });
  }

  try {
    // 1. Framework resolution
    let framework = options.framework;
    if (framework === undefined) {
      const detected = detectFramework(targetDir);
      if (detected && (detected.confidence === "high" || detected.confidence === "medium")) {
        out(`Detected framework: ${detected.framework} (from ${detected.source})`);
        if (options.detect) {
          framework = detected.framework;
        } else if (rl !== null) {
          const confirm = await promptLine(rl, `Use ${detected.framework}? [Y/n]: `);
          framework = confirm.trim().toLowerCase() === "n" ? undefined : detected.framework;
        }
      }
      if (framework === undefined) {
        if (options.detect) {
          out("No framework detected — using generic.");
          framework = "generic";
        } else if (rl !== null) {
          framework = await promptFrameworkSelection(rl);
        } else {
          framework = "generic";
        }
      }
    }

    // 2. Overlay resolution
    let overlay = options.overlay;
    if (overlay === undefined) {
      if (rl !== null) {
        overlay = await promptOverlaySelection(rl);
      } else {
        overlay = "soc2";
      }
    }
    overlay = normalizeOverlayId(overlay);

    // 3. Agent name
    let agentName = options.agentName;
    if (agentName === undefined) {
      const defaultName = sanitizeName(targetDir.split(/[\\/]/).pop() ?? "my-agent");
      if (rl !== null) {
        const answer = await promptLine(rl, `Agent name [${defaultName}]: `);
        agentName = answer.trim() || defaultName;
      } else {
        agentName = defaultName;
      }
    }
    agentName = sanitizeName(agentName);

    // 4. Generate files
    const created: string[] = [];

    const yamlContent = generateAncilisYaml(agentName, overlay);
    writeFileSync(configFile, yamlContent, "utf-8");
    created.push("ancilis.yaml");

    if (!options.noSample) {
      const scanScript = join(targetDir, "ancilis_scan.ts");
      if (!existsSync(scanScript)) {
        writeFileSync(scanScript, getScanScript(framework), "utf-8");
        created.push("ancilis_scan.ts");
      }
    }

    generateEnvExample(targetDir);
    created.push(".env.example");

    if (updateGitignore(targetDir)) {
      created.push("updated .gitignore");
    }

    // 5. Print results
    out("");
    for (const f of created) {
      out(`\u2713 ${f}`);
    }
    out("");
    out("Next steps:");
    out("  1. Review ancilis.yaml and adjust settings");
    out("  2. Run: ancilis doctor       — verify your setup");
    out("  3. Run: ancilis scan          — run your first compliance scan");
    out("  4. Visit https://docs.ancilis.ai/quickstart for the full guide");

    return { ok: true, output: "" };
  } finally {
    rl?.close();
  }
}
