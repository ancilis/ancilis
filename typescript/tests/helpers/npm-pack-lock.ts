import { mkdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const lockDir = join(tmpdir(), "ancilis-npm-pack.lock");
const staleAfterMs = 10 * 60 * 1000;

function wait(ms: number): void {
  const buffer = new SharedArrayBuffer(4);
  Atomics.wait(new Int32Array(buffer), 0, 0, ms);
}

export function withNpmPackLock<T>(fn: () => T): T {
  const deadline = Date.now() + 120_000;

  while (true) {
    try {
      mkdirSync(lockDir);
      break;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "EEXIST") {
        throw error;
      }

      try {
        const ageMs = Date.now() - statSync(lockDir).mtimeMs;
        if (ageMs > staleAfterMs) {
          rmSync(lockDir, { recursive: true, force: true });
          continue;
        }
      } catch (statError) {
        if ((statError as NodeJS.ErrnoException).code !== "ENOENT") {
          throw statError;
        }
      }

      if (Date.now() > deadline) {
        throw new Error("Timed out waiting for npm pack test lock");
      }
      wait(50);
    }
  }

  try {
    return fn();
  } finally {
    rmSync(lockDir, { recursive: true, force: true });
  }
}
