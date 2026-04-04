import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

const cwd = process.cwd();
const temp = mkdtempSync(join(tmpdir(), "ancilis-ts-smoke-"));
const tarballArg = process.argv[2];

try {
  const tarballPath = (() => {
    if (tarballArg) {
      return tarballArg;
    }

    const pkg = execFileSync("npm", ["pack", "--json"], { cwd, encoding: "utf8" });
    const [{ filename }] = JSON.parse(pkg);
    return join(cwd, filename);
  })();

  execFileSync("npm", ["init", "-y"], { cwd: temp, stdio: "ignore" });
  execFileSync("npm", ["install", tarballPath], { cwd: temp, stdio: "inherit" });
  execFileSync(
    "node",
    [
      "--input-type=module",
      "-e",
      "const mod = await import('ancilis'); if (!mod.loadConfig || !mod.AncilisMiddleware) process.exit(1); console.log('ts-package-ok');",
    ],
    { cwd: temp, stdio: "inherit" },
  );
  const helpOutput = execFileSync("npx", ["--no-install", "ancilis", "--help"], {
    cwd: temp,
    encoding: "utf8",
  });
  if (!helpOutput.includes("ancilis doctor") || !helpOutput.includes("ancilis report")) {
    throw new Error("installed ancilis --help output is incomplete");
  }
  console.log("ts-cli-help-ok");
  if (!helpOutput.includes("ndjson") || !helpOutput.includes("csv") || !helpOutput.includes("oscal-json")) {
    throw new Error("installed ancilis --help is missing supported report formats");
  }
  console.log("ts-cli-formats-ok");

  writeFileSync(
    join(temp, "ancilis.yaml"),
    [
      "agent:",
      "  name: smoke-agent",
      "security:",
      "  mode: audit",
      "my_agent_handles:",
      "  - credit_cards",
      "compliance:",
      "  evidence:",
      "    retention_days: 365",
      "",
    ].join("\n"),
  );
  const doctorOutput = execFileSync(
    "npx",
    ["--no-install", "ancilis", "doctor", "--config", "ancilis.yaml", "--db", "smoke.duckdb"],
    {
      cwd: temp,
      encoding: "utf8",
    },
  );
  if (
    !doctorOutput.includes("Ancilis doctor") ||
    !doctorOutput.includes("[OK] config:") ||
    !doctorOutput.includes("[OK] assets:")
  ) {
    throw new Error("installed ancilis doctor smoke check failed");
  }
  console.log("ts-doctor-ok");

  const reportOutput = execFileSync(
    "npx",
    [
      "--no-install",
      "ancilis",
      "report",
      "--config",
      "ancilis.yaml",
      "--db",
      "smoke.duckdb",
      "--format",
      "oscal-json",
      "--output",
      "smoke-oscal.json",
    ],
    {
      cwd: temp,
      encoding: "utf8",
    },
  );
  if (!reportOutput.includes("Report written to smoke-oscal.json")) {
    throw new Error("installed ancilis report smoke check failed");
  }
  const reportDocument = JSON.parse(readFileSync(join(temp, "smoke-oscal.json"), "utf8"));
  if (
    !reportDocument["assessment-results"]?.metadata?.title?.includes("smoke-agent")
    || !Array.isArray(reportDocument["assessment-results"]?.results?.[0]?.findings)
  ) {
    throw new Error("installed ancilis oscal report output is invalid");
  }
  console.log("ts-report-oscal-ok");
} finally {
  rmSync(temp, { recursive: true, force: true });
}
