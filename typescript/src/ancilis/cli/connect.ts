/** ancilis connect — platform connection status and setup instructions. */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

interface CliIo {
  stdout(message: string): void;
  stderr(message: string): void;
}

export interface ConnectOptions {
  /** Override home directory for testing. */
  homeDir?: string;
}

export async function runConnect(
  _args: string[],
  io?: CliIo,
  opts: ConnectOptions = {},
): Promise<{ ok: boolean; output: string }> {
  const out = (msg: string): void => {
    const line = msg.endsWith("\n") ? msg : `${msg}\n`;
    if (io) { io.stdout(line); } else { process.stdout.write(line); }
  };

  const home = opts.homeDir ?? homedir();
  const platformPath = join(home, ".ancilis", "platform.json");

  const lines: string[] = [];

  if (existsSync(platformPath)) {
    try {
      const data = JSON.parse(readFileSync(platformPath, "utf-8")) as Record<string, unknown>;
      const platform = (data.platform as string | undefined) ?? "ancilis.ai";
      lines.push("Status: connected");
      lines.push(`  Platform: ${platform}`);
    } catch {
      lines.push("Status: connected");
    }
    lines.push(`  Config: ${platformPath}`);
  } else {
    lines.push(`Status: not connected`);
    lines.push(``);
    lines.push(`To connect to the Ancilis platform:`);
    lines.push(`  1. Sign up at https://app.ancilis.ai`);
    lines.push(`  2. Create an API key in Settings`);
    lines.push(`  3. Run: ancilis connect --api-key <key>`);
  }

  const output = lines.join("\n");
  out(output);
  return { ok: true, output };
}
