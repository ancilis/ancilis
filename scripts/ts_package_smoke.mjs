import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

const cwd = process.cwd();
const temp = mkdtempSync(join(tmpdir(), "ancilis-ts-smoke-"));

try {
  const pkg = execFileSync("npm", ["pack", "--json"], { cwd, encoding: "utf8" });
  const [{ filename }] = JSON.parse(pkg);
  execFileSync("npm", ["init", "-y"], { cwd: temp, stdio: "ignore" });
  execFileSync("npm", ["install", join(cwd, filename)], { cwd: temp, stdio: "inherit" });
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

  writeFileSync(join(temp, "ancilis.yaml"), "agent:\n  name: smoke-agent\n");
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
} finally {
  rmSync(temp, { recursive: true, force: true });
}
