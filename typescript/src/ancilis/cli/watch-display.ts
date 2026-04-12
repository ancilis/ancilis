/** ancilis.cli.watch-display — terminal rendering for watch mode. */

const USE_COLOR = process.env["NO_COLOR"] === undefined;

const RESET = USE_COLOR ? "\x1b[0m" : "";
const GREEN = USE_COLOR ? "\x1b[32m" : "";
const RED = USE_COLOR ? "\x1b[31m" : "";
const DIM = USE_COLOR ? "\x1b[2m" : "";
const BOLD = USE_COLOR ? "\x1b[1m" : "";

const STATUS_MARKS: Record<string, string> = {
  pass: "\u2713",
  fail: "\u2717",
  skip: "\u2013",
};
const STATUS_COLORS: Record<string, string> = {
  pass: GREEN,
  fail: RED,
  skip: DIM,
};

export interface WatchControlResult {
  id: string;
  name: string;
  status: "pass" | "fail" | "skip";
  evaluations: number;
  failures: number;
  flags: number;
}

export function formatHeader(agentName: string, posture: string, totalEvals: number): string {
  const now = new Date();
  const ts = now.toTimeString().slice(0, 8);
  const postureColor = posture === "compliant" ? GREEN : RED;
  return `${DIM}${ts}${RESET} ${postureColor}${posture}${RESET} \u2014 ${agentName} (${totalEvals} evals)`;
}

export function formatDelta(
  prevResults: WatchControlResult[] | null,
  newResults: WatchControlResult[],
): string[] {
  if (prevResults === null) return [];
  const prevMap = new Map(prevResults.map(r => [r.id, r.status]));
  const lines: string[] = [];
  for (const ctrl of newResults) {
    const old = prevMap.get(ctrl.id);
    const next = ctrl.status;
    if (old !== undefined && old !== next) {
      const oldMark = STATUS_MARKS[old] ?? "?";
      const newMark = STATUS_MARKS[next] ?? "?";
      lines.push(`  ${ctrl.name}: ${oldMark} \u2192 ${newMark}`);
    }
  }
  return lines;
}

export function printScanResult(opts: {
  agentName: string;
  controlResults: WatchControlResult[];
  posture: string;
  totalEvals: number;
  prevResults: WatchControlResult[] | null;
  changedPaths: string[] | null;
  clear: boolean;
}): void {
  if (opts.clear) {
    process.stdout.write("\x1b[2J\x1b[H");
  }
  process.stdout.write(formatHeader(opts.agentName, opts.posture, opts.totalEvals) + "\n");

  if (opts.changedPaths && opts.changedPaths.length > 0) {
    const shown = opts.changedPaths.slice(0, 3);
    const suffix = opts.changedPaths.length > 3 ? "..." : "";
    process.stdout.write(`  ${DIM}Changed: ${shown.join(", ")}${suffix}${RESET}\n`);
  }

  const delta = formatDelta(opts.prevResults, opts.controlResults);
  if (delta.length > 0) {
    process.stdout.write(`  ${BOLD}Changes:${RESET}\n`);
    for (const line of delta) {
      process.stdout.write(line + "\n");
    }
  }

  for (const ctrl of opts.controlResults) {
    const mark = STATUS_MARKS[ctrl.status] ?? "?";
    const color = STATUS_COLORS[ctrl.status] ?? "";
    let detail = `${ctrl.evaluations} evals`;
    if (ctrl.failures > 0) detail += `, ${ctrl.failures} failures`;
    process.stdout.write(`  ${color}${mark}${RESET} ${color}${ctrl.name}${RESET} \u2014 ${ctrl.status} (${detail})\n`);
  }
}

export function printSessionSummary(
  startTime: Date,
  totalScans: number,
  finalResults: WatchControlResult[] | null,
  finalPosture: string | null,
): void {
  const elapsed = Date.now() - startTime.getTime();
  const minutes = Math.floor(elapsed / 60000);
  const seconds = Math.floor((elapsed % 60000) / 1000);
  process.stdout.write("\n");
  process.stdout.write(`${BOLD}Watch session ended${RESET} \u2014 ${minutes}m ${seconds}s, ${totalScans} scan(s)\n`);
  if (finalResults !== null && finalPosture !== null) {
    const color = finalPosture === "compliant" ? GREEN : RED;
    const passing = finalResults.filter(r => r.status === "pass").length;
    const total = finalResults.length;
    process.stdout.write(`  Final posture: ${color}${finalPosture}${RESET} \u2014 ${passing}/${total} controls passing\n`);
  }
}
