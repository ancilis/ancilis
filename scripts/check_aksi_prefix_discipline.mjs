#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

const SCAN_ROOTS = [
  "python/src",
  "typescript/src",
  "python/tests",
  "typescript/tests",
  "scripts",
];

const CODE_EXTENSIONS = new Set([
  ".cjs",
  ".cts",
  ".js",
  ".jsx",
  ".mjs",
  ".mts",
  ".py",
  ".ts",
  ".tsx",
]);

const ALLOWED_FILES = new Set([
  "python/src/ancilis/aksi/identifiers.py",
  "python/tests/test_aksi_identifiers.py",
  "scripts/check_aksi_prefix_discipline.mjs",
  "typescript/src/ancilis/aksi/identifiers.ts",
  "typescript/tests/aksi-identifiers.test.ts",
]);

const RAW_PREFIX_LITERAL = /(["'`])AKSI-|(["'`])AKSI_(?!PREFIX\b)/;

function normalizePath(path) {
  return relative(REPO_ROOT, path).split(sep).join("/");
}

function extension(path) {
  const match = path.match(/(\.[^.]+)$/);
  return match ? match[1] : "";
}

function* walk(path) {
  if (!existsSync(path)) return;
  const stat = statSync(path);
  if (stat.isDirectory()) {
    for (const child of readdirSync(path)) {
      if (child === "node_modules" || child === "__pycache__" || child === ".git") continue;
      yield* walk(resolve(path, child));
    }
    return;
  }
  if (stat.isFile()) yield path;
}

const violations = [];

for (const scanRoot of SCAN_ROOTS) {
  for (const file of walk(resolve(REPO_ROOT, scanRoot))) {
    const rel = normalizePath(file);
    if (ALLOWED_FILES.has(rel)) continue;
    if (!CODE_EXTENSIONS.has(extension(rel))) continue;

    const lines = readFileSync(file, "utf8").split(/\r?\n/);
    lines.forEach((line, index) => {
      if (RAW_PREFIX_LITERAL.test(line)) {
        violations.push(`${rel}:${index + 1}: raw AKSI prefix literal must use an identifier utility`);
      }
    });
  }
}

if (violations.length > 0) {
  console.error("AKSI prefix discipline violations:");
  for (const violation of violations) console.error(`- ${violation}`);
  process.exit(1);
}
