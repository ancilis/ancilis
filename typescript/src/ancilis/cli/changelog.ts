/** Public changelog CLI command. */

export const DEFAULT_CHANGELOG_URL = "https://api.ancilis.ai/v1/changelog";
export const CHANGELOG_URL_ENV = "ANCILIS_CHANGELOG_URL";
export const CHANGELOG_TIMEOUT_MS = 2_000;
export const CHANGELOG_MAX_LIMIT = 100;

const NOTE_LIST_KEYS = ["notes", "items", "data", "release_notes", "releases"] as const;
const LINK_RE = /\[([^\]]+)\]\([^)]+\)/g;
const HEADING_RE = /^\s{0,3}#{1,6}\s*/gm;
const CODE_RE = /`([^`]+)`/g;
const BOLD_RE = /(\*\*|__)(.*?)\1/g;
const ITALIC_RE = /(?<!\*)\*([^*\n]+)\*(?!\*)/g;

export interface CliIo {
  stdout(message: string): void;
  stderr(message: string): void;
}

export interface ChangelogPayload {
  notes: Array<Record<string, unknown>>;
  [key: string]: unknown;
}

export type ChangelogFetch = (
  input: string,
  init?: RequestInit,
) => Promise<Response>;

export class ChangelogError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChangelogError";
  }
}

function print(writer: (message: string) => void, message: string): void {
  writer(message.endsWith("\n") ? message : `${message}\n`);
}

export function resolveChangelogUrl(
  url?: string,
  env: Record<string, string | undefined> = process.env,
): string {
  if (url) return url;
  return env[CHANGELOG_URL_ENV] || DEFAULT_CHANGELOG_URL;
}

export function addLimitToUrl(url: string, limit: number): string {
  const parsed = new URL(url);
  parsed.searchParams.delete("limit");
  parsed.searchParams.append("limit", String(limit));
  return parsed.toString();
}

export function normalizeChangelogPayload(payload: unknown, limit: number): ChangelogPayload {
  let notes: Array<Record<string, unknown>> = [];
  let metadata: Record<string, unknown> = {};

  if (Array.isArray(payload)) {
    notes = dictNotes(payload);
  } else if (isRecord(payload)) {
    const key = findNoteListKey(payload);
    if (key === null) {
      if (looksLikeNote(payload)) {
        notes = [{ ...payload }];
      } else {
        metadata = { ...payload };
      }
    } else {
      notes = dictNotes(payload[key]);
      metadata = Object.fromEntries(
        Object.entries(payload).filter(([entryKey]) => entryKey !== key),
      );
    }
  } else {
    throw new ChangelogError("Unexpected changelog response shape");
  }

  return { ...metadata, notes: notes.slice(0, limit) };
}

export async function fetchChangelog(
  url: string,
  limit: number,
  fetchImpl: ChangelogFetch = globalThis.fetch,
): Promise<ChangelogPayload> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CHANGELOG_TIMEOUT_MS);

  try {
    const response = await fetchImpl(addLimitToUrl(url, limit), {
      headers: {
        Accept: "application/json",
        "User-Agent": "ancilis-cli/0.1.0",
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new ChangelogError(`Could not fetch changelog: HTTP ${response.status}`);
    }

    let payload: unknown;
    try {
      payload = await response.json();
    } catch (error: unknown) {
      throw new ChangelogError(`Could not parse changelog response: ${errorMessage(error)}`);
    }

    return normalizeChangelogPayload(payload, limit);
  } catch (error: unknown) {
    if (error instanceof ChangelogError) throw error;
    if (isAbortError(error)) {
      throw new ChangelogError("Could not fetch changelog: request timed out");
    }
    throw new ChangelogError(`Could not fetch changelog: ${errorMessage(error)}`);
  } finally {
    clearTimeout(timer);
  }
}

export function renderChangelog(notes: Array<Record<string, unknown>>): string {
  if (notes.length === 0) return "No changelog entries found.";

  return notes.map((note) => {
    const version = text(note["version"] ?? note["tag"] ?? "unversioned");
    const date = formatDate(note["published_at"] ?? note["date"] ?? note["publishedAt"]);
    const category = text(note["category"] ?? note["type"] ?? "release");
    const title = text(note["title"] ?? "Untitled release");
    const body = simplifyMarkdown(
      text(note["body"] ?? note["markdown"] ?? note["description"] ?? ""),
    );

    const lines = [`${version} | ${date} | ${category}`, title];
    if (body) lines.push(body);
    return lines.join("\n");
  }).join("\n\n");
}

export async function runChangelog(
  args: string[],
  io: CliIo,
  env: Record<string, string | undefined> = process.env,
  fetchImpl: ChangelogFetch = globalThis.fetch,
): Promise<number> {
  let limit = 10;
  let url: string | undefined;
  let jsonOutput = false;

  try {
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index];
      if (arg === "--json") {
        jsonOutput = true;
        continue;
      }
      if (arg === "--limit") {
        const value = readOption(args, index, arg);
        limit = parseLimit(value);
        index += 1;
        continue;
      }
      if (arg === "--url") {
        url = readOption(args, index, arg);
        index += 1;
        continue;
      }
      throw new ChangelogError(`Unknown option for changelog: ${arg}`);
    }

    const payload = await fetchChangelog(resolveChangelogUrl(url, env), limit, fetchImpl);
    print(io.stdout, jsonOutput ? JSON.stringify(payload, null, 2) : renderChangelog(payload.notes));
    return 0;
  } catch (error: unknown) {
    print(io.stderr, errorMessage(error));
    return 1;
  }
}

function readOption(args: string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (value === undefined || value.startsWith("-")) {
    throw new ChangelogError(`Missing value for ${flag}`);
  }
  return value;
}

function parseLimit(value: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || String(parsed) !== value || parsed < 1) {
    throw new ChangelogError("--limit must be a positive integer");
  }
  return Math.min(parsed, CHANGELOG_MAX_LIMIT);
}

function findNoteListKey(payload: Record<string, unknown>): string | null {
  for (const key of NOTE_LIST_KEYS) {
    if (Array.isArray(payload[key])) return key;
  }
  return null;
}

function dictNotes(value: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(value)) return [];
  return value.filter(isRecord).map((note) => ({ ...note }));
}

function looksLikeNote(payload: Record<string, unknown>): boolean {
  return ["title", "body", "version", "published_at"].some((key) => key in payload);
}

function text(value: unknown): string {
  return String(value).trim();
}

function formatDate(value: unknown): string {
  const valueText = text(value);
  if (!valueText) return "undated";
  return valueText.length >= 10 ? valueText.slice(0, 10) : valueText;
}

function simplifyMarkdown(markdown: string): string {
  const plain = markdown
    .replace(LINK_RE, "$1")
    .replace(HEADING_RE, "")
    .replace(CODE_RE, "$1")
    .replace(BOLD_RE, "$2")
    .replace(ITALIC_RE, "$1");

  return plain.split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => line.startsWith("- ") || line.startsWith("* ") ? line.slice(2).trim() : line)
    .join("\n");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAbortError(error: unknown): boolean {
  return isRecord(error) && error["name"] === "AbortError";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
