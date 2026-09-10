// ═══ COSMOS AS AN x402 EXTERNAL VERIFIER — the closed-verdict contract ═════════════════════════════════
// The host (x402#3376 evcHost.ts) validates our stdout against a CLOSED schema and a CLOSED code registry.
// Anything it does not recognise is discarded and replaced with a generic fail-closed class, so a verdict
// that is merely "sensible" is worthless: it must be schema-exact. These assertions are the contract.
'use strict';
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const evc = require('../x402/evc-verifier');
const guardrails = require('../core/guardrails');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };
const eq = (a, e, m) => {
  if (a === e) { pass++; console.log('  ✓ ' + m); return; }
  fail++; console.log('  ✗ ' + m + '\n      expected: ' + JSON.stringify(e) + '\n      actual:   ' + JSON.stringify(a));
};

const fakeFetch = (body, status) => async () => ({ ok: (status || 200) < 400, status: status || 200, json: async () => body });
// x402 mints a fresh single-use nonce per response, so the DEFAULT context carries one. A context
// without any idempotency source is now a refusal, asserted separately in section I.
const CTX = { amount: 3000, payee: 'api.openai.com', resource: 'https://api.openai.com/v1/x', network: 'eip155:8453', nonce: 'v0.1755900300.aa11' };
const BUNDLE = { grant_id: 'grn_x', currency: 'USD', category: 'api' };
const req = (over) => Object.assign({ x402_evc: CTX, bundle: BUNDLE }, over || {});
const run = (body, status, opts) => evc.decide(req(), Object.assign({ url: 'http://x', fetch: fakeFetch(body, status), divisor: 1 }, opts));

const runPub = (body) => evc.decide(req(), { url: 'http://internal:8787', publicUrl: 'https://cosmos.example', fetch: fakeFetch(body), divisor: 1 });

(async () => {
  console.log('\n── M · REASON COVERAGE — the negative control ───────────────────────────────────────────────');
  // Without this, a new denial reason maps to a default and every caller is told the wrong thing. It is
  // the S8 pattern from writ-port: a table is decorative unless something fails when it is incomplete.
  //
  // ⚠ DERIVED FROM SOURCE, not hand-listed. Ramu's review of this PR: the first version appended four
  // names by hand to guardrails.REASONS, which is a control whose coverage is whatever someone remembered
  // to type. Scanning the decision path instead immediately turned up NINE more reasons Cosmos can return
  // — the 400-class validation errors and the 503 signer-unavailable — every one of which was silently
  // defaulting to internal_error. A hand-maintained list cannot fail when it is incomplete; this can.
  const SOURCES = ['core/guardrails.js', 'core/agent-view.js', 'api/authorize.js'];
  const emitted = new Set(guardrails.REASONS);
  for (const f of SOURCES) {
    const src = fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
    for (const m of src.matchAll(/reason\s*[:=]\s*'([A-Z][A-Z0-9_]+)'/g)) emitted.add(m[1]);
    for (const m of src.matchAll(/HttpError\(\s*\d+\s*,\s*'([A-Z][A-Z0-9_]+)'/g)) emitted.add(m[1]);
    for (const m of src.matchAll(/need\([^,]*,\s*'([A-Z][A-Z0-9_]+)'/g)) emitted.add(m[1]);
  }
  ok(emitted.size >= 20, '★ the scan actually found the reason surface (' + emitted.size + ' reasons across ' + SOURCES.length + ' files) — a regex that matches nothing would pass the next assertion vacuously');
  const unmapped = [...emitted].filter((r) => !evc.REASON_TO_CODE[r]);
  ok(unmapped.length === 0, '★★ every reason Cosmos can emit has an EVC code (unmapped: ' + JSON.stringify(unmapped) + ')');
  const outOfRegistry = Object.entries(evc.REASON_TO_CODE).filter(([, c]) => !evc.EVC_CODES.has(c));
  ok(outOfRegistry.length === 0, '★★ every mapped code is in the closed EVC registry — an unknown code is silently discarded by the host (bad: ' + JSON.stringify(outOfRegistry) + ')');
  eq(evc.EVC_CODES.size, 15, '★ the registry copied from the PR still has its 15 codes');

  console.log('\n── S · THE CLOSED VERDICT SCHEMA ───────────────────────────────────────────────────────────');
  const a = await run({ decision: 'ALLOW', receipt_id: 'auth_1234567890abcdef1234', checks: [] });
  eq(JSON.stringify(Object.keys(a).sort()), '["verdict"]',
    '★★ an ALLOW carries ONLY `verdict` — their schema rejects any other key, so the receipt id CANNOT ride along on an allow');
  eq(a.verdict, 'allow', 'the allow verdict is spelled exactly "allow"');

  const d = await run({ decision: 'DENY', reason: 'PER_PAYMENT_LIMIT', receipt_id: 'auth_1234567890abcdef1234',
                        checks: [{ name: 'Under per-payment cap', pass: false }, { name: 'Active', pass: true }] });
  ok(Object.keys(d).every((k) => ['verdict', 'code', 'message', 'detail'].includes(k)),
    '★★ a DENY carries only keys their schema allows (got ' + JSON.stringify(Object.keys(d)) + ')');
  eq(d.code, 'scope_exceeded', '★ PER_PAYMENT_LIMIT maps to scope_exceeded');
  eq(typeof d.message, 'string', 'message is a string, which their schema requires');
  ok(d.detail && typeof d.detail === 'object' && !Array.isArray(d.detail), 'detail is a plain object, not an array');

  console.log('\n── R · THE REFUSAL CARRIES THE RECEIPT — the whole reason to be here ────────────────────────');
  eq((d.detail || {}).cosmos_receipt_id, 'auth_1234567890abcdef1234',
    '★★ the DENY names the signed receipt — their allow has nowhere to put evidence and their deny does, which is exactly the slot x402 leaves empty — their spec returns a receipt "only on success" (extension-offer-and-receipt.md:263). ⚠ Scope: that is true of x402, NOT in general — Google AP2 and Microsoft both sign refusals, see docs/PRIOR-ART-2026-09-08.md');
  eq((d.detail || {}).cosmos_evidence, 'http://x/evidence/auth_1234567890abcdef1234', '★★ …as an ABSOLUTE url. A relative path is unfetchable by the resource server and its caller, neither of which knows where Cosmos lives (Ramu, review of #13)');
  eq(JSON.stringify((d.detail || {}).failed_checks), '["Under per-payment cap"]', '★ …and names the check that failed, not just a code');
  const pub = await runPub({ decision: 'DENY', reason: 'DAILY_LIMIT', receipt_id: 'auth_bbbbbbbbbbbbbbbbbbbb', checks: [] });
  eq((pub.detail || {}).cosmos_evidence, 'https://cosmos.example/evidence/auth_bbbbbbbbbbbbbbbbbbbb',
    '★★ COSMOS_PUBLIC_URL wins over the internal address we dial — the deployment case is Cosmos on a private host and the counterparty on the internet, and publishing the private one helps nobody');

  console.log('\n── F · FAIL-CLOSED. Every abnormal path is a DENY, never an allow ──────────────────────────');
  const unreachable = await evc.decide(req(), { url: 'http://x', divisor: 1, fetch: async () => { throw new Error('ECONNREFUSED'); } });
  eq(unreachable.verdict, 'deny', '★★ Cosmos unreachable is a DENY — a gate that opens when its verifier is down is not a gate');
  eq(unreachable.code, 'internal_error', '★ …classified internal_error');
  eq((await evc.decide(null, { url: 'http://x', fetch: fakeFetch({}), divisor: 1 })).code, 'malformed_input', 'a non-object request is malformed_input');
  eq((await evc.decide({ bundle: BUNDLE }, { url: 'http://x', fetch: fakeFetch({}), divisor: 1 })).code, 'malformed_input', 'a missing x402_evc envelope is malformed_input');
  eq((await evc.decide({ x402_evc: CTX }, { url: 'http://x', fetch: fakeFetch({}), divisor: 1 })).code, 'invalid_bundle', 'a missing bundle is invalid_bundle');
  eq((await evc.decide({ x402_evc: CTX, bundle: { grant_id: 'g' } }, { url: 'http://x', fetch: fakeFetch({}), divisor: 1 })).code, 'invalid_bundle',
    '★ a bundle without currency+category is invalid_bundle — x402 expresses an asset and a network, never a policy currency or a category');
  eq((await run({ decision: 'WAT' })).code, 'internal_error', '★ an unrecognised Cosmos decision is a DENY, not a pass-through');
  eq((await run({ error: 'GRANT_NOT_FOUND' }, 404)).code, 'invalid_bundle', '★ a 404 from Cosmos is invalid_bundle, not internal_error');

  console.log('\n── U · UNITS. x402 amounts are asset base units; Cosmos policy is currency minor units ──────');
  eq(evc.toMinor(1000000, 10000), 100, '★ 1 USDC at 6dp ÷ 10000 = 100 USD minor — the divisor is deployment config');
  eq(evc.toMinor(1500, 10000), null, '★★ a conversion that does not divide evenly is REFUSED, never rounded — no float in the money path');
  eq(evc.toMinor(-1, 1), null, 'a negative amount is refused');
  eq(evc.toMinor(1.5, 1), null, 'a fractional amount is refused');
  eq(evc.toMinor('3000', 1), 3000, 'a decimal string amount is accepted (x402 carries amounts as strings)');
  eq((await run({ decision: 'ALLOW' }, 200, { divisor: 7 })).code, 'malformed_input', '★ an indivisible amount denies rather than silently truncating money');

  console.log('\n── E · ESCALATE has no home in their model, and must not become an allow ───────────────────');
  const e = await run({ decision: 'ESCALATE', reason: 'APPROVAL_REQUIRED', receipt_id: 'auth_aaaaaaaaaaaaaaaaaaaa', checks: [] });
  eq(e.verdict, 'deny', '★★ ESCALATE is a DENY — their gate has no pending state and MUST NOT fail open');
  eq(e.code, 'scope_exceeded', '★ …coded scope_exceeded: outside what may be authorized without a human');
  ok(/approval/i.test(e.message), '★ …and the message says approval is required, so the caller is not told a flat no');
  eq((e.detail || {}).cosmos_receipt_id, 'auth_aaaaaaaaaaaaaaaaaaaa', '★ the escalation receipt is still named');

  console.log('\n── I · THE REQUEST BODY. Stubbing fetch hid a total failure ────────────────────────────────');
  // ⚠⚠ FOUND ON A PHONE, NOT HERE. Every assertion above stubs `fetch`, so nothing ever looked at what we
  // actually SEND. The verifier omitted `idempotency_key`, `/authorize` requires it, and so EVERY
  // x402-gated payment came back `malformed_input` — the module was 100% broken against a real Cosmos
  // while this suite was green. A stub proves the shape of a reply, never that the request was valid.
  {
    const sent = [];
    const capture = async (u, o) => { sent.push(JSON.parse(o.body)); return { ok: true, status: 200, json: async () => ({ decision: 'ALLOW' }) }; };
    await evc.decide(req(), { url: 'http://x', divisor: 1, fetch: capture });
    ok(sent.length === 1 && typeof sent[0].idempotency_key === 'string' && sent[0].idempotency_key.length > 0,
      '★★ the request ALWAYS carries an idempotency_key — /authorize rejects it otherwise and every gated payment is denied as malformed. Sent: ' + JSON.stringify(sent[0] && sent[0].idempotency_key));
    for (const k of ['grant_id', 'amount_minor', 'currency', 'category']) {
      ok(sent[0][k] !== undefined, '★ the request carries ' + k);
    }

    const sent2 = [];
    const cap2 = async (u, o) => { sent2.push(JSON.parse(o.body)); return { ok: true, status: 200, json: async () => ({ decision: 'ALLOW' }) }; };
    await evc.decide(req(), { url: 'http://x', divisor: 1, fetch: cap2 });
    eq(sent2[0].idempotency_key, sent[0].idempotency_key,
      '★★ the same request derives the SAME key — a random one would make every retry a fresh authorization and reserve budget twice');

    const bodyOf = async (r) => { const got = []; await evc.decide(r, { url: 'http://x', divisor: 1,
      fetch: async (u, o) => { got.push(JSON.parse(o.body)); return { ok: true, status: 200, json: async () => ({ decision: 'ALLOW' }) }; } }); return got[0]; };

    const nonced = await bodyOf(Object.assign({}, req(), { x402_evc: Object.assign({}, CTX, { nonce: 'v0.1755900300.9f2c' }) }));
    eq(nonced.idempotency_key, 'x402:v0.1755900300.9f2c',
      '★ when x402 supplies its single-use nonce, THAT is the key — their replay grain becomes ours');

    // ⚠⚠ RAMU'S CATCH, and the reason there is no hash fallback any more. The first version derived a key
    // from (grant, amount, currency, category, payee) when no nonce was present — which is ONLY the fields
    // two IDENTICAL LEGITIMATE spends also share. An agent buying the same $5 search twice on purpose got
    // the first receipt back and Cosmos reserved budget ONCE for two real payments: an under-reserve.
    // The original §I tested only the different-spend direction, so it passed while blind to this.
    const twiceA = await bodyOf(Object.assign({}, req(), { x402_evc: Object.assign({}, CTX, { nonce: 'n-first' }) }));
    const twiceB = await bodyOf(Object.assign({}, req(), { x402_evc: Object.assign({}, CTX, { nonce: 'n-second' }) }));
    ok(twiceA.idempotency_key !== twiceB.idempotency_key,
      '★★ two IDENTICAL spends under different nonces get DIFFERENT keys — the second real payment is authorized and reserved on its own, not collapsed into the first receipt');
    ok(twiceA.amount_minor === twiceB.amount_minor && twiceA.grant_id === twiceB.grant_id,
      '★ …and they really are identical in every other field, so the previous assertion is about the key and nothing else');

    // No nonce, no bundle key: a retry and a second identical purchase are the same bytes. Refuse.
    const noSource = await evc.decide({ x402_evc: { amount: 3000, payee: 'p' }, bundle: { grant_id: 'g', currency: 'USD', category: 'api' } },
      { url: 'http://x', divisor: 1, fetch: async () => { throw new Error('MUST NOT be called'); } });
    eq(noSource.verdict, 'deny', '★★ no idempotency source at all -> DENY, and Cosmos is never even called');
    eq(noSource.code, 'nonce_missing', '★★ …coded nonce_missing, which is the EVC registry entry that means exactly this');
    ok(/indistinguishable/.test(noSource.message), '★ …and the message says why, rather than a bare code');
  }

  console.log('\n── C · THE CLI CONTRACT — one JSON object on stdout, exit 0 ────────────────────────────────');
  const cli = (stdin) => spawnSync(process.execPath, [path.join(__dirname, '..', 'x402', 'evc-verifier.js')],
    { input: stdin, encoding: 'utf8', env: Object.assign({}, process.env, { COSMOS_URL: 'http://127.0.0.1:1', COSMOS_X402_TIMEOUT_MS: '400' }) });
  const c1 = cli('not json at all');
  eq(c1.status, 0, '★★ exit 0 even on a deny — a non-zero exit is a host fail-closed class and throws away our code and receipt id');
  const objs = c1.stdout.trim().split('\n').filter(Boolean);
  eq(objs.length, 1, '★★ exactly ONE object on stdout — a second one is the host\'s `multiple_objects` failure class');
  eq(JSON.parse(objs[0]).code, 'malformed_input', '★ unparseable stdin denies with malformed_input');
  const c2 = cli(JSON.stringify(req()));
  eq(c2.status, 0, 'exit 0 when Cosmos is unreachable too');
  eq(JSON.parse(c2.stdout.trim()).verdict, 'deny', '★★ a dead Cosmos on a real spawn denies — the end-to-end fail-closed path, not just the unit');

  console.log('\nx402-evc (external verifier contract): ' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); process.exit(1); });
