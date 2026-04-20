import { afterEach, describe, expect, it, vi } from "vitest";
import {
  addLimitToUrl,
  DEFAULT_CHANGELOG_URL,
  resolveChangelogUrl,
  runChangelog,
} from "../src/ancilis/cli/changelog.js";
import { runCli } from "../src/cli.js";

function captureIo(): {
  io: { stdout(message: string): void; stderr(message: string): void };
  stdout(): string;
  stderr(): string;
} {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: {
      stdout(message: string) {
        out.push(message);
      },
      stderr(message: string) {
        err.push(message);
      },
    },
    stdout: () => out.join(""),
    stderr: () => err.join(""),
  };
}

const changelogPayload = {
  notes: [{
    version: "1.2.3",
    published_at: "2026-04-20T10:00:00.000Z",
    category: "sdk",
    title: "TypeScript CLI release",
    body: "## Highlights\n- **Runtime** [guardrails](https://example.test)\n- `safe` changelog output",
    extra: { preserved: true },
  }],
};

function jsonResponse(payload: unknown, ok = true, status = 200): Response {
  return {
    ok,
    status,
    json: async () => payload,
  } as Response;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("changelog CLI helpers", () => {
  it("resolves URL precedence and appends limit without duplicating existing limit", () => {
    expect(resolveChangelogUrl("https://cli.example/feed", {
      ANCILIS_CHANGELOG_URL: "https://env.example/feed",
    })).toBe("https://cli.example/feed");
    expect(resolveChangelogUrl(undefined, {
      ANCILIS_CHANGELOG_URL: "https://env.example/feed",
    })).toBe("https://env.example/feed");
    expect(resolveChangelogUrl(undefined, {})).toBe(DEFAULT_CHANGELOG_URL);

    expect(addLimitToUrl("https://example.test/v1/changelog?limit=99&channel=stable", 5))
      .toBe("https://example.test/v1/changelog?channel=stable&limit=5");
  });
});

describe("runChangelog", () => {
  it("prints terminal output with version date category title and simplified markdown body", async () => {
    const fetchMock = vi.fn(async () => jsonResponse(changelogPayload));
    const { io, stdout, stderr } = captureIo();

    const exitCode = await runChangelog(
      ["--url", "https://example.test/v1/changelog", "--limit", "5"],
      io,
      {},
      fetchMock,
    );

    expect(exitCode).toBe(0);
    expect(stderr()).toBe("");
    expect(fetchMock).toHaveBeenCalledWith(
      "https://example.test/v1/changelog?limit=5",
      expect.objectContaining({
        headers: expect.objectContaining({ Accept: "application/json" }),
        signal: expect.any(AbortSignal),
      }),
    );
    expect(stdout()).toContain("1.2.3 | 2026-04-20 | sdk");
    expect(stdout()).toContain("TypeScript CLI release");
    expect(stdout()).toContain("Highlights");
    expect(stdout()).toContain("Runtime guardrails");
    expect(stdout()).toContain("safe changelog output");
  });

  it("prints normalized JSON preserving returned note fields", async () => {
    const fetchMock = vi.fn(async () => jsonResponse(changelogPayload));
    const { io, stdout, stderr } = captureIo();

    const exitCode = await runChangelog(["--json"], io, {
      ANCILIS_CHANGELOG_URL: "https://env.example/v1/changelog",
    }, fetchMock);

    expect(exitCode).toBe(0);
    expect(stderr()).toBe("");
    const parsed = JSON.parse(stdout()) as typeof changelogPayload;
    expect(parsed.notes[0]).toMatchObject({
      version: "1.2.3",
      title: "TypeScript CLI release",
      extra: { preserved: true },
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://env.example/v1/changelog?limit=10",
      expect.any(Object),
    );
  });

  it("reports fetch failures without writing to stdout", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ error: "down" }, false, 503));
    const { io, stdout, stderr } = captureIo();

    const exitCode = await runChangelog(["--url", "https://example.test/fail"], io, {}, fetchMock);

    expect(exitCode).toBe(1);
    expect(stdout()).toBe("");
    expect(stderr()).toContain("Could not fetch changelog: HTTP 503");
  });

  it("aborts slow fetches with a concise timeout error", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn((_url: string | URL | Request, init?: RequestInit) => (
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
        });
      })
    ));
    const { io, stdout, stderr } = captureIo();

    const result = runChangelog(["--url", "https://example.test/slow"], io, {}, fetchMock);
    await vi.advanceTimersByTimeAsync(2_000);
    const exitCode = await result;

    expect(exitCode).toBe(1);
    expect(stdout()).toBe("");
    expect(stderr()).toContain("Could not fetch changelog: request timed out");
  });
});

describe("runCli changelog dispatch", () => {
  it("lists changelog in help and dispatches the command", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(changelogPayload));
    const helpIo = captureIo();
    const changelogIo = captureIo();

    expect(await runCli(["--help"], helpIo.io)).toBe(0);
    expect(helpIo.stdout()).toContain("ancilis changelog");

    const exitCode = await runCli([
      "changelog",
      "--url",
      "https://example.test/v1/changelog",
      "--limit",
      "1",
    ], changelogIo.io);

    expect(exitCode).toBe(0);
    expect(changelogIo.stderr()).toBe("");
    expect(changelogIo.stdout()).toContain("TypeScript CLI release");
    expect(fetchMock).toHaveBeenCalledWith(
      "https://example.test/v1/changelog?limit=1",
      expect.any(Object),
    );
  });
});
