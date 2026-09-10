import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as SDK from "../src/ancilis/index.js";

const make = (options = {}) =>
  SDK.Ancilis.open({ tenant: "tenant-a", source: "app", ...options });
const settings = {
  name: "read",
  surface: "document" as const,
  operation: "READ" as const,
};
const input = (patch = {}) => ({
  call_id: "c1",
  occurred_at: "2026-09-10T00:00:00.000000Z",
  surface: "document",
  operation: "READ",
  phase: "START",
  chunk_index: null,
  outcome: "STARTED",
  authority: {
    principal: null,
    service: null,
    delegation: null,
    approval: null,
    scope: null,
    basis: "APPLICATION_ASSERTION",
  },
  artifacts: [],
  relationships: [],
  provenance_refs: [],
  capture_gaps: [],
  ...patch,
});
const vectors = JSON.parse(
  readFileSync("tests/fixtures/episodes/native-vectors.json", "utf8"),
);

describe("cross-language unsigned snapshot contract", () => {
  const fixtures = JSON.parse(
    readFileSync("tests/fixtures/episodes/native-cross-language.json", "utf8"),
  );
  for (const fixture of fixtures.cases)
    it(fixture.name, () => {
      expect(
        SDK.verifyEpisodeSnapshot(fixture.snapshot, {
          assessedAt: "2026-09-10T00:00:00.000000Z",
        }),
      ).toEqual(fixture.expected);
    });
  it("normalizes JSON integer negative zero", () => {
    expect(SDK.canonicalEpisodeJSON(JSON.parse("-0"))).toBe("0");
  });
  it("keeps manual capacity advisory unless strict capture is selected", () => {
    for (const strictCapture of [false, true]) {
      const sdk = make({ maxEvents: 1, strictCapture });
      sdk.episode("one", { expectedSurfaces: ["document"] }, (e) => {
        e.observe(input());
        if (strictCapture)
          expect(() => e.observe(input({ call_id: "c2" }))).toThrow(
            "LEDGER_EVENT_CAP",
          );
        else expect(e.observe(input({ call_id: "c2" }))).toBeUndefined();
        expect(e.inspect().coverage.lost_events).toBe(1);
      });
    }
  });
});

describe("native episode public contract", () => {
  it("exports a native entry point alongside unchanged load", () => {
    expect(SDK.Ancilis.open).toBeTypeOf("function");
    expect(SDK.Ancilis.load).toBeTypeOf("function");
  });
  it("matches independent policy/open/event/revision vectors and Unicode code-point order", () => {
    expect(
      Buffer.from(
        SDK.canonicalEpisodeJSON(vectors.canonical_nonbmp.value),
      ).toString("hex"),
    ).toBe(vectors.canonical_nonbmp.utf8_hex);
    for (const [domain, key, digest] of [
      ["ancilis-native-policy/1", "policy", "policy_sha256"],
      ["ancilis-episode-open/1", "open", "open_sha256"],
      ["ancilis-observation-id/1", "event_preimage", "event_id"],
      ["ancilis-native-revision/2", "revision_preimage", "revision_id"],
      [
        "ancilis-native-revision/2",
        "partial_revision_preimage",
        "partial_revision_id",
      ],
    ])
      expect(SDK.hashEpisodePayload(domain, vectors[key])).toBe(
        vectors[digest],
      );
    for (const x of [
      NaN,
      1.5,
      undefined,
      "\ud800",
      {
        get secret() {
          throw Error("getter ran");
        },
      },
    ])
      expect(() => SDK.canonicalEpisodeJSON(x)).toThrow();
  });
  it("captures five actual operations with one owner and preserves earlier sensitive evidence", async () => {
    const sdk = make();
    const secret = Buffer.from("SYNTHETIC PAN 4111111111111111");
    const memory = new Map();
    const read = sdk.attachTool(() => secret, {
      ...settings,
      capture: (f) =>
        f.phase === "END"
          ? { artifacts: [SDK.ContentEvidence.fromBytes("doc", f.result)] }
          : null,
    });
    const execute = sdk.attachTool((v: Buffer) => v.length, {
      name: "execute",
      surface: "execution",
      operation: "EXECUTE",
    });
    const write = sdk.attachTool(
      (v: Buffer) => {
        memory.set("doc", v);
        return "stored";
      },
      { name: "write", surface: "memory", operation: "WRITE" },
    );
    const recall = sdk.attachTool(() => memory.get("doc"), {
      name: "recall",
      surface: "memory",
      operation: "READ",
    });
    const output = sdk.attachTool(() => "Processed synthetic request.", {
      name: "output",
      surface: "output",
      operation: "WRITE",
      capture: (f) =>
        f.phase === "END"
          ? {
              artifacts: [
                SDK.ContentEvidence.fromBytes("final", Buffer.from(f.result)),
              ],
            }
          : null,
    });
    let episode;
    await sdk.episode(
      "one",
      {
        expectedSurfaces: ["output", "document", "tool", "memory", "execution"],
      },
      (e) => {
        episode = e;
        const value = read();
        expect(execute(value)).toBe(secret.length);
        write(value);
        expect(recall()).toBe(secret);
        expect(output()).toBe("Processed synthetic request.");
      },
    );
    const snapshot = episode.inspect();
    expect(snapshot.observations).toHaveLength(10);
    expect(snapshot.coverage.missing_surfaces).toEqual(["tool"]);
    expect(snapshot.coverage.complete).toBe(false);
    expect(snapshot.claims_basis).toContain("COLLECTOR_ASSERTION");
    expect(
      snapshot.observations.flatMap((x) => x.artifacts).map((x) => x.artifact),
    ).toEqual(["doc", "final"]);
    expect(JSON.stringify(snapshot)).not.toContain(secret.toString());
    expect(sdk.diagnostics().attachments.map((x) => x.completed)).toEqual([
      1, 1, 1, 1, 1,
    ]);
    expect(await sdk.flush()).toMatchObject({
      storage: "MEMORY_ONLY",
      durable: 0,
      lost: 0,
    });
    await sdk.close();
  });
  it("deduplicates attachment, keeps this/attributes, and preserves sync result/error identity", () => {
    const sdk = make();
    const obj = { v: 42 };
    const fn = Object.assign(
      function () {
        return this;
      },
      { description: "test", parameters: { type: "object" } },
    );
    const wrapped = sdk.attachTool(fn, settings);
    expect(sdk.attachTool(fn, settings)).toBe(wrapped);
    expect(sdk.attachTool(wrapped, settings)).toBe(wrapped);
    expect(wrapped.description).toBe("test");
    expect(wrapped.parameters).toBe(fn.parameters);
    expect(wrapped.call(obj)).toBe(obj);
    expect(() =>
      sdk.attachTool(fn, { ...settings, surface: "memory" }),
    ).toThrow();
    expect(() => make().attachTool(wrapped, settings)).toThrow();
    const error = new Error("SENSITIVE");
    const fail = sdk.attachTool(
      () => {
        throw error;
      },
      { ...settings, name: "fail" },
    );
    sdk.episode("one", { expectedSurfaces: ["document"] }, () =>
      expect(() => fail()).toThrow(error),
    );
    expect(JSON.stringify(sdk.diagnostics())).not.toContain("SENSITIVE");
  });
  it("preserves async function kind, resolved identity and rejection identity", async () => {
    const sdk = make();
    const value = { ok: true };
    const error = new Error("original");
    const fn = sdk.attachTool(async () => value, settings);
    expect(fn.constructor.name).toBe("AsyncFunction");
    await sdk.episode("one", { expectedSurfaces: ["document"] }, async () => {
      expect(await fn()).toBe(value);
      const bad = sdk.attachTool(
        async () => {
          throw error;
        },
        { ...settings, name: "bad" },
      );
      await expect(bad()).rejects.toBe(error);
    });
  });
  it("never subscribes lazy thenables or consumes custom iterators", () => {
    const sdk = make();
    let calls = 0;
    const lazy = {
      then() {
        calls++;
        return "query";
      },
      builder: true,
    };
    const iterator = {
      next() {
        calls++;
        return { done: false, value: 1 };
      },
      [Symbol.iterator]() {
        return this;
      },
    };
    sdk.episode("one", { expectedSurfaces: ["document"] }, (e) => {
      expect(sdk.attachTool(() => lazy, settings)()).toBe(lazy);
      expect(
        sdk.attachTool(() => iterator, { ...settings, name: "iterator" })(),
      ).toBe(iterator);
      expect(calls).toBe(0);
      expect(e.inspect().coverage.reasons).toContain(
        "UNSUPPORTED_RETURN_PROTOCOL",
      );
    });
  });
  it("forwards generator send/throw/return and early close without draining ahead", () => {
    const sdk = make();
    let final = 0;
    function* stream() {
      try {
        const next = yield 1;
        try {
          yield next;
        } catch (e) {
          yield e;
        }
        return 9;
      } finally {
        final++;
      }
    }
    const wrapped = sdk.attachTool(stream, settings);
    sdk.episode("one", { expectedSurfaces: ["document"] }, (e) => {
      const g = wrapped();
      expect(g.next()).toEqual({ done: false, value: 1 });
      expect(g.next(7)).toEqual({ done: false, value: 7 });
      const error = new Error("throw");
      expect(g.throw(error).value).toBe(error);
      expect(g.next()).toEqual({ done: true, value: 9 });
      expect(final).toBe(1);
      const early = wrapped();
      early.next();
      early.return(5);
      expect(final).toBe(2);
      expect(e.inspect().coverage.incomplete_calls).toBe(1);
    });
  });
  it("forwards async-generator finalization and cancellation errors", async () => {
    const sdk = make();
    let final = 0;
    const cancelled = new Error("cancel");
    async function* stream() {
      try {
        yield 1;
        yield 2;
      } finally {
        final++;
      }
    }
    await sdk.episode("one", { expectedSurfaces: ["document"] }, async (e) => {
      const g = sdk.attachTool(stream, settings)();
      expect(await g.next()).toEqual({ done: false, value: 1 });
      await expect(g.throw(cancelled)).rejects.toBe(cancelled);
      expect(final).toBe(1);
      expect(e.inspect().coverage.incomplete_calls).toBe(1);
    });
  });
  it("isolates concurrent and nested episode contexts and supports explicit binding", async () => {
    const sdk = make();
    const fn = sdk.attachTool((v: string) => v, settings);
    let bound;
    await Promise.all(
      ["a", "b"].map((id) =>
        sdk.episode(id, { expectedSurfaces: ["document"] }, async (e) => {
          await Promise.resolve();
          expect(fn(id)).toBe(id);
          if (id === "a") bound = sdk.bindEpisode(fn, e);
          sdk.episode(id + "-inner", { expectedSurfaces: ["memory"] }, () =>
            fn("inner"),
          );
          fn(id);
        }),
      ),
    );
    bound("later");
    expect(sdk.getEpisode("a").inspect().observations).toHaveLength(6);
    expect(sdk.getEpisode("b").inspect().observations).toHaveLength(4);
    fn("uncorrelated");
    expect(sdk.diagnostics().reasons.UNCORRELATED_CALL).toBe(1);
  });
  it("contains capture callback failure and releases frames without leaking values", () => {
    const sdk = make();
    const value = { private: "SECRET" };
    const wrapped = sdk.attachTool(() => value, {
      ...settings,
      capture() {
        throw new Error("SECRET");
      },
    });
    sdk.episode("one", { expectedSurfaces: ["document"] }, (e) => {
      expect(wrapped()).toBe(value);
      expect(e.inspect().coverage.lost_events).toBeGreaterThan(0);
    });
    expect(JSON.stringify(sdk.diagnostics())).not.toContain("SECRET");
  });
  it("exact manual duplicates are no-ops but changed bytes and artifact rebinding conflict", () => {
    const sdk = make();
    for (const id of ["a", "b"])
      sdk.episode(id, { expectedSurfaces: ["document"] }, (e) => {
        const a = e.observe(input());
        const rev = e.inspect().revision_id;
        expect(e.observe(input())).toEqual(a);
        expect(e.inspect().revision_id).toBe(rev);
        expect(() =>
          e.observe(input({ capture_gaps: ["CONTENT_NOT_CAPTURED"] })),
        ).toThrow("EVENT_CONFLICT");
      });
    expect(sdk.getEpisode("a").inspect().observations[0].event_id).not.toBe(
      sdk.getEpisode("b").inspect().observations[0].event_id,
    );
    sdk.episode("content", { expectedSurfaces: ["document"] }, (e) => {
      e.observe(
        input({
          artifacts: [SDK.ContentEvidence.fromBytes("doc", Buffer.from("a"))],
        }),
      );
      expect(() =>
        e.observe(
          input({
            call_id: "c2",
            artifacts: [SDK.ContentEvidence.fromBytes("doc", Buffer.from("b"))],
          }),
        ),
      ).toThrow("ARTIFACT_REBIND");
    });
  });
  it("rejects forged manual authority, malformed timestamps, extra fields and unknown codes", () => {
    const sdk = make();
    sdk.episode("one", { expectedSurfaces: ["document"] }, (e) => {
      for (const bad of [
        input({ tenant: "b" }),
        input({ occurred_at: "2026-99-99T00:00:00.000000Z" }),
        input({ capture_gaps: ["PASS"] }),
        input({
          relationships: [
            {
              kind: "BYTE_EQUAL",
              from_artifact: "a",
              to_artifact: "b",
              basis: "BYTE_COMPARISON",
              method: "ancilis-byte-equality/1",
              evidence_refs: [],
            },
          ],
        }),
      ])
        expect(() => e.observe(bad)).toThrow();
    });
  });
  it("never lets inspection mutation edit admitted history or immutable revision identity", () => {
    const sdk = make();
    sdk.episode("one", { expectedSurfaces: ["document"] }, (e) => {
      e.observe(input());
      const first = e.inspect();
      try {
        first.observations[0].call_id = "forged";
      } catch {}
      expect(e.inspect().observations[0].call_id).toBe("c1");
      expect(e.inspect().revision_id).toBe(first.revision_id);
    });
  });
  it("advisory caps preserve 300 application calls and explicit discard frees capacity", () => {
    const sdk = make({ maxEpisodes: 2, maxEvents: 4 });
    const fn = sdk.attachTool(() => 1, settings);
    for (let i = 0; i < 300; i++)
      expect(
        sdk.episode("e" + i, { expectedSurfaces: ["document"] }, () => fn()),
      ).toBe(1);
    expect(sdk.diagnostics().reasons.LEDGER_EPISODE_CAP).toBe(298);
    const old = sdk.getEpisode("e0");
    expect(sdk.discardEpisode("e0")).toBe(true);
    sdk.episode("e0", { expectedSurfaces: ["document"] }, (e) => {
      expect(e.inspect().open_sha256).not.toBe(old.inspect().open_sha256);
      expect(() => sdk.discardEpisode("e0")).toThrow();
    });
    expect(sdk.diagnostics().reasons.DISCARDED_EPISODE).toBe(1);
  });
  it("reports event/byte exhaustion persistently and strict capacity is opt-in", async () => {
    const sdk = make({ maxEvents: 1 });
    const fn = sdk.attachTool(() => 42, settings);
    sdk.episode("one", { expectedSurfaces: ["document"] }, (e) => {
      expect(fn()).toBe(42);
      expect(e.inspect().coverage.lost_events).toBeGreaterThan(0);
    });
    expect((await sdk.flush()).lost).toBeGreaterThan(0);
    const strict = make({ maxEpisodes: 1, strictCapture: true });
    strict.episode("one", { expectedSurfaces: ["document"] }, () => {});
    expect(() =>
      strict.episode("two", { expectedSurfaces: ["document"] }, () => {}),
    ).toThrow("LEDGER_EPISODE_CAP");
    const tiny = make({ maxBytes: 1 });
    tiny.episode("one", { expectedSurfaces: ["document"] }, (e) => {
      expect(tiny.attachTool(() => 42, settings)()).toBe(42);
      expect(e.inspect().coverage.reasons).toContain("LEDGER_BYTE_CAP");
    });
  });
  it("preserves upstream behavior after finish, detach and close without closing client", async () => {
    const sdk = make();
    const fn = sdk.attachTool(() => 42, settings);
    sdk.episode("one", { expectedSurfaces: ["document"] }, (e) => {
      e.finish();
      expect(fn()).toBe(42);
    });
    sdk.detach(fn);
    expect(fn()).toBe(42);
    await sdk.close();
    await sdk.close();
    expect(fn()).toBe(42);
    expect(() =>
      sdk.episode("two", { expectedSurfaces: ["document"] }, () => {}),
    ).toThrow("SDK_CLOSED");
  });
  it("explicit MCP attachment preserves caller ownership and bounds unknown-tool diagnostics", async () => {
    const sdk = make();
    let calls = 0;
    const client = {
      owned: true,
      callTool: async function (arg) {
        calls++;
        expect(this.owned).toBe(true);
        return arg;
      },
      close() {
        throw Error("caller owned");
      },
    };
    const options = {
      surfaces: { read: { surface: "document", operation: "READ" } },
    };
    const wrapped = sdk.attachMcp(client, options);
    expect(sdk.attachMcp(client, options)).toBe(wrapped);
    await sdk.episode("one", { expectedSurfaces: ["document"] }, async () => {
      const arg = { name: "read" };
      expect(await wrapped.callTool(arg)).toBe(arg);
      for (let i = 0; i < 10000; i++)
        await wrapped.callTool({ name: "unknown" + i });
    });
    expect(calls).toBe(10001);
    expect(sdk.diagnostics().reasons.UNMAPPED_TOOL).toBe(10000);
    expect(JSON.stringify(sdk.diagnostics()).length).toBeLessThan(8000);
    await sdk.close();
  });
});

describe("native capture boundaries", () => {
  it("does not double count a saturated episode as a new capacity incident for every call", () => {
    const sdk = make({ maxEpisodes: 1 });
    const fn = sdk.attachTool(() => 1, settings);
    sdk.episode("stored", { expectedSurfaces: ["document"] }, () => fn());
    sdk.episode("lost", { expectedSurfaces: ["document"] }, () => {
      fn();
      fn();
    });
    expect(sdk.diagnostics().reasons.LEDGER_EPISODE_CAP).toBe(1);
    expect(sdk.diagnostics().lost).toBeGreaterThan(0);
  });
  it("rejects another SDK MCP wrapper and calls the original with getter-valued tool names untouched", async () => {
    const sdk = make();
    let reads = 0,
      calls = 0;
    const client = {
      callTool: async (arg) => {
        calls++;
        return arg;
      },
    };
    const options = {
      surfaces: { read: { surface: "document", operation: "READ" } },
    };
    const wrapped = sdk.attachMcp(client, options);
    expect(() => make().attachMcp(wrapped, options)).toThrow("SOURCE_MISMATCH");
    const args = {
      get name() {
        reads++;
        throw Error("SECRET");
      },
    };
    expect(await wrapped.callTool(args)).toBe(args);
    expect(reads).toBe(0);
    expect(calls).toBe(1);
  });
  it("contains malformed capture results and does not suppress loss", () => {
    const sdk = make();
    const fn = sdk.attachTool(() => 42, {
      ...settings,
      capture: () => ({ artifacts: 7 }),
    });
    sdk.episode("one", { expectedSurfaces: ["document"] }, () =>
      expect(fn()).toBe(42),
    );
    expect(sdk.diagnostics().reasons.CAPTURE_CALLBACK_FAILED).toBe(2);
  });
  it("keeps async iteration for ordinary functions returning a native async generator", async () => {
    const sdk = make();
    async function* values() {
      yield 1;
    }
    const fn = sdk.attachTool(() => values(), settings);
    await sdk.episode("one", { expectedSurfaces: ["document"] }, async () => {
      const seen = [];
      for await (const value of fn()) seen.push(value);
      expect(seen).toEqual([1]);
    });
  });
  it("records late phases as incomplete and refuses observations after SDK finish", () => {
    const sdk = make();
    sdk.episode("one", { expectedSurfaces: ["document"] }, (e) => {
      e.observe(input());
      e.observe(input({ phase: "END", outcome: "SUCCEEDED" }));
      expect(() =>
        e.observe(
          input({ phase: "CHUNK", outcome: "OBSERVED", chunk_index: 0 }),
        ),
      ).toThrow("INVALID_OBSERVATION");
      e.finish();
      expect(() => e.observe(input({ call_id: "c2" }))).toThrow(
        "EPISODE_FINISHED",
      );
    });
  });
});

describe("payload-bound incremental revisions", () => {
  it("matches chain vectors and binds tenant/open in genesis", () => {
    const H = SDK.hashEpisodePayload;
    expect(
      H("ancilis-native-observation-chain/1", {
        open_sha256: vectors.open_sha256,
      }),
    ).toBe(vectors.genesis_chain);
    expect(H("ancilis-observation-payload/1", vectors.observation)).toBe(
      vectors.observation_payload_sha256,
    );
    expect(
      H("ancilis-native-observation-chain/1", {
        previous_observation_chain_sha256: vectors.genesis_chain,
        observation_sha256: vectors.observation_payload_sha256,
      }),
    ).toBe(vectors.first_observation_chain);
    const a = make(),
      b = make({ tenant: "tenant-b" });
    a.episode("e", { expectedSurfaces: ["document"] }, () => {});
    b.episode("e", { expectedSurfaces: ["document"] }, () => {});
    expect(a.getEpisode("e").inspect().observation_chain_sha256).not.toBe(
      b.getEpisode("e").inspect().observation_chain_sha256,
    );
  });
  it("commits the full admitted payload and keeps chain stable for conflicts/loss", () => {
    const sdk = make({ maxEvents: 1 });
    sdk.episode("one", { expectedSurfaces: ["document"] }, (e) => {
      const genesis = e.inspect().observation_chain_sha256;
      e.observe(input());
      const snap = e.inspect();
      const H = SDK.hashEpisodePayload;
      expect(snap.observation_chain_sha256).toBe(
        H("ancilis-native-observation-chain/1", {
          previous_observation_chain_sha256: genesis,
          observation_sha256: H(
            "ancilis-observation-payload/1",
            snap.observations[0],
          ),
        }),
      );
      const rev = snap.revision_id;
      e.observe(input());
      expect(e.inspect().revision_id).toBe(rev);
      expect(() =>
        e.observe(input({ capture_gaps: ["CONTENT_NOT_CAPTURED"] })),
      ).toThrow();
      const conflict = e.inspect();
      expect(conflict.observation_chain_sha256).toBe(
        snap.observation_chain_sha256,
      );
      expect(conflict.revision_id).not.toBe(rev);
      expect(e.observe(input({ call_id: "c2" }))).toBeUndefined();
      expect(e.inspect().observation_chain_sha256).toBe(
        snap.observation_chain_sha256,
      );
    });
  });
  it("checks native integrity without claiming signer, protected bodies or reconstruction", () => {
    const sdk = make();
    sdk.episode("one", { expectedSurfaces: ["document"] }, (e) => {
      e.observe(input());
      e.observe(input({ phase: "END", outcome: "SUCCEEDED" }));
    });
    const snap = sdk.getEpisode("one").inspect();
    const result = SDK.verifyEpisodeSnapshot(snap, {
      expectedTenant: "tenant-a",
    });
    expect(result).toMatchObject({
      status: "UNVERIFIED",
      envelope_authenticated: false,
      protected_bodies: "NOT_REQUESTED",
      reconstruction: "UNSUPPORTED",
      verified_claim_refs: [],
    });
    expect(result.reasons).toContain("NATIVE_CHAIN_MATCH");
    for (const mutate of [
      (s) => (s.observations[0].authority.principal = "forged"),
      (s) => (s.observations[0].captured_at = "2026-09-09T00:00:00.000000Z"),
      (s) => s.observations.reverse(),
      (s) => s.observations.pop(),
      (s) => s.observations.push(s.observations[0]),
      (s) => (s.revision_method = "ancilis-native-revision/1"),
      (s) => (s.coverage.observed_surfaces = []),
    ]) {
      const bad = structuredClone(snap);
      mutate(bad);
      expect(SDK.verifyEpisodeSnapshot(bad).status).toBe("REJECTED");
    }
    expect(
      SDK.verifyEpisodeSnapshot(snap, { expectedTenant: "other" }).status,
    ).toBe("REJECTED");
  });
  it("rejects scope/order tampering even after recomputing a self-consistent chain", () => {
    const sdk = make();
    sdk.episode("one", { expectedSurfaces: ["document"] }, (e) => {
      e.observe(input());
    });
    const snapshot = sdk.getEpisode("one").inspect();
    snapshot.observations[0].episode_open = "a".repeat(64);
    const H = SDK.hashEpisodePayload;
    let chain = H("ancilis-native-observation-chain/1", {
      open_sha256: snapshot.open_sha256,
    });
    for (const row of snapshot.observations)
      chain = H("ancilis-native-observation-chain/1", {
        previous_observation_chain_sha256: chain,
        observation_sha256: H("ancilis-observation-payload/1", row),
      });
    snapshot.observation_chain_sha256 = chain;
    snapshot.revision_id = H("ancilis-native-revision/2", {
      open_sha256: snapshot.open_sha256,
      revision: snapshot.revision,
      previous_revision_id: snapshot.previous_revision_id,
      observation_chain_sha256: chain,
      coverage: snapshot.coverage,
    });
    expect(SDK.verifyEpisodeSnapshot(snapshot).status).toBe("REJECTED");
  });
  it("discard yields an explicit tombstone, not full-history verification or withdrawal", () => {
    const sdk = make();
    sdk.episode("one", { expectedSurfaces: ["document"] }, (e) => {
      e.observe(input());
      e.observe(input({ phase: "END", outcome: "SUCCEEDED" }));
    });
    const handle = sdk.getEpisode("one");
    const prior = handle.inspect();
    sdk.discardEpisode("one");
    const tombstone = handle.inspect();
    expect(tombstone.observations).toEqual([]);
    expect(tombstone.coverage.observed_surfaces).toEqual([]);
    expect(tombstone.coverage.missing_surfaces).toEqual(["document"]);
    expect(tombstone.previous_revision_id).toBe(prior.revision_id);
    expect(tombstone.observation_chain_sha256).toBe(
      SDK.hashEpisodePayload("ancilis-native-observation-chain/1", {
        open_sha256: tombstone.open_sha256,
      }),
    );
    expect(SDK.verifyEpisodeSnapshot(tombstone)).toMatchObject({
      status: "UNVERIFIED",
      verified_claim_refs: [],
    });
    expect(SDK.verifyEpisodeSnapshot(tombstone).reasons).toContain(
      "NATIVE_HISTORY_DISCARDED",
    );
  });
});
