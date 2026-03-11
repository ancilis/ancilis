/** ancilis approve-tool — quick tool approval. */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

export function approveTool(
  toolName: string,
  configPath = "ancilis.yaml",
): { success: boolean; message: string } {
  if (!existsSync(configPath)) {
    return { success: false, message: `Config file not found: ${configPath}` };
  }

  const raw = parseYaml(readFileSync(configPath, "utf-8")) ?? {};

  const security = raw.security ?? {};
  const tools = security.tools ?? {};
  const allowed: string[] = tools.allowed ?? [];

  if (allowed.includes(toolName)) {
    return { success: true, message: `'${toolName}' is already in the approved tools list.` };
  }

  allowed.push(toolName);
  tools.allowed = allowed;
  security.tools = tools;
  raw.security = security;

  writeFileSync(configPath, stringifyYaml(raw));

  return {
    success: true,
    message: `Added '${toolName}' to approved tools in ${configPath}.\nScope enforcement will now allow calls to ${toolName}.`,
  };
}
