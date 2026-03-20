import { mkdtempSync, rmSync } from "node:fs";
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
} finally {
  rmSync(temp, { recursive: true, force: true });
}
