import { existsSync } from "node:fs";
import { dirname, join, parse } from "node:path";
import { fileURLToPath } from "node:url";

export function packageRootFrom(importMetaUrl: string): string {
  let current = dirname(fileURLToPath(importMetaUrl));
  const { root } = parse(current);

  while (true) {
    const candidate = join(current, "shared");
    if (existsSync(candidate)) {
      return current;
    }
    if (current === root) {
      throw new Error(`Could not locate shared/ runtime assets from ${importMetaUrl}`);
    }
    current = dirname(current);
  }
}

export function sharedPathFrom(importMetaUrl: string, ...parts: string[]): string {
  return join(packageRootFrom(importMetaUrl), "shared", ...parts);
}
