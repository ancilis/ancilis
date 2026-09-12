import { readFileSync } from 'node:fs';
import { describe, it, expect } from 'vitest';
import * as SDK from '../src/ancilis/index.js';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
const v = JSON.parse(readFileSync('tests/fixtures/episodes/classification-vectors.json', 'utf8'));
const s = JSON.parse(readFileSync('tests/fixtures/episodes/signed-vectors.json', 'utf8'));
const body = Buffer.from(v.body_hex, 'hex');
const api = (name: string): any => { const value = (SDK as any)[name]; expect(value, `Missing public API ${name}`).toBeTypeOf('function'); return value; };
const adapter = (resolve: any = () => structuredClone(v.response)) => new (api('TrustedClassificationAdapter'))({ ...v.adapter, resolve });
const semantic = (propose: any) => new (api('ExperimentalSemanticProvider'))({ provider_id: 'demo', method_id: 'demo/1', runtime_id: 'synthetic', propose });
const assess = (options: any = {}) => api('assessEpisodeClassifications')(options.wire ?? v.export, { trust: new SDK.EpisodeTrustPolicy(v.trust_policy), adapter: adapter(), bodyResolver: () => body, assessedAt: v.assessed_at, ...options });
const unknown = (r: any) => ({ schema: 'ancilis-classification-response/1', request_sha256: r.request_sha256, outcome: 'UNKNOWN', classification: null, evidence_refs: [], reasons: ['STALE_LABEL'] });
const proposal = (r: any) => ({ schema: 'ancilis-semantic-proposal/1', request_sha256: r.request_sha256, status: 'PROPOSED', proposed_classification: 'DEMO-SENSITIVE', evidence_refs: ['bc'.repeat(32)], reasons: [] });
describe('classification provider boundary', () => {
    it('matches exact vector and bypasses semantic on trusted result', async () => {
        const report = await assess({ adapter: adapter((r: any, b: Uint8Array) => { expect(r).toEqual(v.request); expect(Buffer.from(b)).toEqual(body); return v.response; }) });
        expect(report.toJSON()).toEqual(v.report);
        expect(report.origin).toBe('LOCAL_ASSESSMENT');
        const bypass = await assess({ experimentalSemantic: semantic(() => { throw new Error('must bypass'); }) });
        expect(bypass.toJSON().classifications[0].semantic.state).toBe('NOT_REQUESTED');
    });
    it.each([null, Buffer.from('wrong')])('gates all providers on bodies', async (b) => {
        let calls = 0;
        const r = await assess({ bodyResolver: () => b, adapter: adapter(() => { calls++; return v.response; }) });
        expect(r.toJSON().classifications).toEqual([]);
        expect(calls).toBe(0);
    });
    it('requires ALL_REFERENCED and a trusted attempt before semantics', async () => {
        await expect(assess({ trust: new SDK.EpisodeTrustPolicy({ ...v.trust_policy, body_mode: 'NONE' }) })).rejects.toThrow('BODY_VERIFICATION_REQUIRED');
        await expect(assess({ adapter: undefined, experimentalSemantic: semantic(proposal) })).rejects.toThrow('SEMANTIC_REQUIRES_TRUSTED_ADAPTER');
        const r = await assess({ adapter: undefined });
        expect(r.toJSON().classifications[0].sdk_reason).toBe('CLASSIFICATION_PROVIDER_UNAVAILABLE');
    });
    it.each([{ request_sha256: '00'.repeat(32) }, { extra: true }, { classification: null }, { evidence_refs: [] }, { classification: 'UNSUPPORTED-CLASS' }, { outcome: 'SUPPORTED_NEGATIVE' }, { verified: true }])('rejects malformed responses', async (change) => {
        const row = (await assess({ adapter: adapter(() => ({ ...v.response, ...change })) })).toJSON().classifications[0];
        expect(row.outcome).toBe('ERROR');
        expect(row.sdk_reason).toBe('INVALID_ADAPTER_RESPONSE');
        expect(row.response).toBeNull();
    });
    it.each(['UNKNOWN', 'ABSTAIN', 'ERROR', 'UNSUPPORTED'])('preserves %s and never promotes proposals', async (outcome) => {
        let calls = 0;
        const row = (await assess({ adapter: adapter((r: any) => ({ ...unknown(r), outcome })), experimentalSemantic: semantic((r: any) => { calls++; return proposal(r); }) })).toJSON().classifications[0];
        expect(row.outcome).toBe(outcome);
        expect(row.classification).toBeNull();
        expect(calls).toBe(outcome === 'UNKNOWN' ? 1 : 0);
    });
    it('continues after row errors and sanitizes messages', async () => {
        let calls = 0;
        const r = (await assess({ wire: s.multiple_export, adapter: adapter((r: any) => { if (++calls === 1)
                throw new Error('private-secret'); return unknown(r); }) })).toJSON();
        expect(calls).toBe(3);
        expect(r.classifications.map((r: any) => r.outcome)).toEqual(['ERROR', 'UNKNOWN', 'UNKNOWN']);
        expect(JSON.stringify(r)).not.toContain('private-secret');
    });
    it('passes independent callback body copies and frozen requests', async () => {
        let calls = 0;
        const r = (await assess({ wire: s.multiple_export, adapter: adapter((r: any, b: Uint8Array) => { expect(Buffer.from(b)).toEqual(body); b.fill(0); expect(Object.isFrozen(r.reference)).toBe(true); calls++; return unknown(r); }), experimentalSemantic: semantic((r: any, b: Uint8Array) => { expect(Buffer.from(b)).toEqual(body); return proposal(r); }) })).toJSON();
        expect(calls).toBe(3);
        expect(r.classifications.every((r: any) => r.outcome === 'UNKNOWN')).toBe(true);
    });
    it('does not let a retained resolver alias alter the authenticated body', async () => {
        const alias = Buffer.from(body);
        const r = await assess({ bodyResolver: () => alias, adapter: adapter((r: any, b: Uint8Array) => { alias.fill(0); expect(Buffer.from(b)).toEqual(body); return v.response; }) });
        expect(r.toJSON().classifications[0].outcome).toBe('SUPPORTED_POSITIVE');
    });
    it('rejects self-qualified semantic output', async () => {
        const row = (await assess({ adapter: adapter(unknown), experimentalSemantic: semantic((r: any) => ({ ...proposal(r), qualification: 'QUALIFIED' })) })).toJSON().classifications[0];
        expect(row.outcome).toBe('UNKNOWN');
        expect(row.semantic.sdk_reason).toBe('INVALID_SEMANTIC_RESPONSE');
    });
    it('preserves report history, import origin, and limits', async () => {
        const r = await assess(), d = r.toJSON(), H = api('ClassificationHistory'), h = new H(d.tenant, d.episode, d.open_sha256, { maxReports: 2 });
        expect(h.append(r)).toBe(true);
        expect(h.append(r)).toBe(false);
        h.append(await assess({ assessedAt: '2026-09-11T01:00:00.000000Z', adapter: adapter(unknown) }));
        expect(h.inspect().map((e: any) => e.report.classifications[0].outcome)).toEqual(['SUPPORTED_POSITIVE', 'UNKNOWN']);
        const parsed = new (api('EpisodeClassificationReport'))(d);
        expect(parsed.origin).toBe('PARSED_UNAUTHENTICATED');
        const p = new H(d.tenant, d.episode, d.open_sha256);
        p.append(parsed);
        expect(p.inspect()[0].origin).toBe('PARSED_UNAUTHENTICATED');
        const third = await assess({ assessedAt: '2026-09-11T02:00:00.000000Z', adapter: adapter(unknown) });
        expect(() => h.append(third)).toThrow('HISTORY_LIMIT');
        expect(h.inspect().length).toBe(2);
        d.classifications[0].classification = 'forged';
        expect(() => new (api('EpisodeClassificationReport'))(d)).toThrow('INVALID_CLASSIFICATION_REPORT');
    });
    it('propagates post-await cancellation', async () => {
        const controller = new AbortController(), reason = new Error('cancelled');
        await expect(assess({ signal: controller.signal, adapter: adapter(async () => { controller.abort(reason); return v.response; }) })).rejects.toBe(reason);
    });
    it('validates real outputs using shared schemas', async () => {
        const r = (await assess()).toJSON(), ajv = new Ajv2020({ strict: true });
        addFormats(ajv);
        for (const [name, value] of [['classification-request', r.classifications[0].request], ['classification-response', r.classifications[0].response], ['classification-report', r]]) {
            const validator = ajv.compile(JSON.parse(readFileSync(`shared/episodes/v1/${name}.schema.json`, 'utf8')));
            expect(validator(value), JSON.stringify(validator.errors)).toBe(true);
        }
    });
});
it('matches full semantic request and report vector', async () => {
    const r = (await assess({ adapter: adapter(unknown), experimentalSemantic: semantic(proposal) })).toJSON();
    expect(r).toEqual(v.semantic_report);
    const ajv = new Ajv2020({ strict: true });
    addFormats(ajv);
    for (const [name, value] of [['semantic-request', r.classifications[0].semantic.request], ['semantic-proposal', r.classifications[0].semantic.response], ['classification-report', r]]) {
        const check = ajv.compile(JSON.parse(readFileSync(`shared/episodes/v1/${name}.schema.json`, 'utf8')));
        expect(check(value), JSON.stringify(check.errors)).toBe(true);
    }
});
it('retains empty episode scope and clears unauthenticated scope', async () => {
    const owner = SDK.Ancilis.open({ tenant: 'tenant', source: 'source' }), signer = SDK.EpisodeSigner.fromSeed({ tenant: 'tenant', source: 'source', keyId: 'key-1', seed: Buffer.from(s.seed_hex, 'hex') });
    let wire = '';
    owner.episode('empty-classification', { expectedSurfaces: ['tool'] }, e => { wire = e.exportSigned(signer); });
    const r = (await assess({ wire })).toJSON();
    expect(r.tenant).toBe('tenant');
    expect(r.verification.protected_bodies).toBe('NO_REFERENCES');
    expect(r.classifications).toEqual([]);
    const envelope = JSON.parse(v.export);
    envelope.signature = '00'.repeat(64);
    const invalid = (await assess({ wire: SDK.canonicalEpisodeJSON(envelope) })).toJSON();
    expect(invalid.tenant).toBeNull();
    expect(invalid.classifications).toEqual([]);
});
it('enforces history bytes/scope and detaches views', async () => {
    const report = await assess(), d = report.toJSON(), H = api('ClassificationHistory'), h = new H(d.tenant, d.episode, d.open_sha256, { maxBytes: 1 });
    expect(() => h.append(report)).toThrow('HISTORY_LIMIT');
    expect(h.inspect()).toEqual([]);
    expect(() => new H('other', d.episode, d.open_sha256).append(report)).toThrow('HISTORY_SCOPE_MISMATCH');
    const history = new H(d.tenant, d.episode, d.open_sha256);
    history.append(report);
    history.inspect()[0].report.classifications[0].outcome = 'ERROR';
    expect(history.inspect()[0].report.classifications[0].outcome).toBe('SUPPORTED_POSITIVE');
});
it('requires the selected receipt set and does not upgrade imported origin', async () => {
    const row = (await assess({ adapter: adapter(() => ({ ...v.response, evidence_refs: ['cd'.repeat(32)] })) })).toJSON().classifications[0];
    expect(row.sdk_reason).toBe('INVALID_ADAPTER_RESPONSE');
    const r = await assess(), d = r.toJSON(), h = new (api('ClassificationHistory'))(d.tenant, d.episode, d.open_sha256);
    h.append(new (api('EpisodeClassificationReport'))(d));
    expect(h.append(r)).toBe(false);
    expect(h.inspect()[0].origin).toBe('PARSED_UNAUTHENTICATED');
});
