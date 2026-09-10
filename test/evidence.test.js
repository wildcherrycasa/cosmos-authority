// ═══ EVIDENCE END-TO-END — a stranger verifies a real receipt with no account ══════════════════════════
//
// The product claim, tested literally: /authorize issues a COSE_Sign1 receipt; /evidence serves it;
// /.well-known/jwks.json publishes the key; and an INDEPENDENT verifier — written in Python, from the RFCs,
// with no Cosmos code and no CBOR library — says VALID. Then a one-byte tamper fails on SIGNATURE_INVALID
// specifically. Then the Python Sig_structure bytes are compared to Node's, which is the cross-language
// check the CBOR commit flagged as open.
'use strict';
const fs = require('fs'), os = require('os'), path = require('path');
const { spawnSync } = require('child_process');
const { start } = require('../api/server');
const receipt = require('../core/receipt');
const cose = require('../core/cose');
const CC = require('../core/capability-commitment');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };
const eq = (a, e, m) => {
  if (a === e) { pass++; console.log('  ✓ ' + m); return; }
  fail++; console.log('  ✗ ' + m);
  console.log('      expected: ' + JSON.stringify(e));
  console.log('      actual:   ' + JSON.stringify(a));
};

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cosmos-evidence-'));
const LOG = path.join(TMP, 'log.jsonl');
const PY = path.join(__dirname, '..', 'verifier', 'cosmos_verify.py');
const listen = (file) => new Promise((r) => { const h = start({ port: 0, file, quiet: true }); h.server.on('listening', () => r(Object.assign(h, { port: h.server.address().port }))); });
const close = (h) => new Promise((r) => { h.store.close(); if (h.server.closeAllConnections) h.server.closeAllConnections(); h.server.close(() => r()); });
// `python` DOES NOT EXIST on macOS 12.3+ or on a default Ubuntu — only `python3`. See test/demo.test.js.
const PYBIN = (() => {
  for (const c of [process.env.COSMOS_PYTHON, 'python3', 'python'].filter(Boolean)) {
    if (spawnSync(c, ['--version'], { encoding: 'utf8' }).status === 0) return c;
  }
  return 'python3';
})();
const py = (...args) => {
  const r = spawnSync(PYBIN, [PY, ...args], { encoding: 'utf8' });
  return { code: r.status, out: (r.stdout || '') + (r.stderr || '') };
};

// ★★ A stranger's console is not ours. Python picks stdout's encoding from the locale, and on Windows
// that is cp1252 — so ONE non-ASCII glyph inside a print() turns a VALID receipt into a
// UnicodeEncodeError traceback and exit 1. That is exactly what happened: the approver warning shipped
// with a "⚠" and every Windows reader got a crash instead of the caveat. PYTHONIOENCODING
// reproduces the failure on ANY OS, so it is pinned here rather than left to whoever happens to run
// Windows. Deliberately no errors="replace" in the verifier: masking this would print "?" and pass.
const pyAscii = (...args) => {
  const r = spawnSync(PYBIN, [PY, ...args], { encoding: 'utf8', env: { ...process.env, PYTHONIOENCODING: 'ascii' } });
  return { code: r.status, out: (r.stdout || '') + (r.stderr || '') };
};

(async () => {
  let h = await listen(LOG);
  const B = () => 'http://localhost:' + h.port;
  const post = (p, o) => fetch(B() + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(o) }).then(async (r) => ({ status: r.status, body: await r.json() }));
  const get = (p) => fetch(B() + p).then(async (r) => ({ status: r.status, body: await r.json() }));

  // ── A0 · Accept negotiation, judged PURELY — deliberately before any wire call ────────────────────────
  // Widening this negotiation breaks every JSON response in the suite, so the wire tests die at the first
  // fetch and no assertion gets to say why (mutation E5, 2026-09-06: three suites red, zero ✗ lines). A pure
  // check placed ahead of the wire always gets to name the defect.
  { const { wantsCose } = require('../api/evidence');
    const hdr = [['application/cose', true], ['application/cose;q=0.9', true], ['APPLICATION/COSE', true],
      ['application/json, application/cose', true], [' application/cose , */*', true],
      ['application/cose;q=0', false], ['*/*', false], ['application/json', false], ['', false], [undefined, false],
      ['application/cose-x', false], ['text/application/cose', false]];
    const bad = hdr.filter(([h, want]) => wantsCose(h) !== want).map(([h]) => JSON.stringify(h));
    ok(bad.length === 0, 'A0 · ★★ Accept negotiation judged correctly for 12 headers — `*/*`, no header and `application/json` MUST stay JSON (offenders: ' + JSON.stringify(bad) + ')');
  }

  console.log('\n── A · /authorize issues a signed receipt ──────────────────────────────────────────────────');
  const g = (await post('/grants', { org_id: 'o1', agent_id: 'a1', currency: 'USD', budget_minor: 50000,
    per_payment_cap_minor: 1700, daily_cap_minor: 5000, allowed_categories: ['api', 'cloud'], approval_threshold_minor: 1500 })).body;
  const a = (await post('/authorize', { grant_id: g.grant_id, amount_minor: 1200, currency: 'USD', category: 'api', merchant: 'api.openai.com', description: 'embeddings batch 4471', idempotency_key: 'k1' })).body;
  eq(a.decision, 'ALLOW', 'A1 · ALLOW');
  eq(a.signed, true, 'A2 · ★★ the decision is SIGNED — no more `signed: false`');
  eq(a.receipt_id, a.authorization_id, 'A3 · receipt_id is the authorization id');
  eq(a.evidence, '/evidence/' + a.authorization_id, 'A4 · the response points at its own evidence');
  ok(typeof a.kid === 'string' && a.kid.length > 0, 'A5 · the signing kid is named (' + a.kid + ')');
  ok(!('allowed_categories' in a), 'A6 · ★ the grant\'s full category set is NOT disclosed in the response');

  console.log('\n── B · /evidence and /.well-known/jwks.json ─────────────────────────────────────────────────');
  const ev = await get(a.evidence);
  eq(ev.status, 200, 'B1 · evidence is served');
  ok(typeof ev.body.cose_base64 === 'string' && ev.body.cose_base64.length > 100, 'B2 · ★ the COSE bytes are the artifact');
  eq(ev.body.self_check, 'ok', 'B3 · the server\'s self-check against its own JWKS passes');
  eq(ev.body.payload_unverified.decision, 'ALLOW', 'B4 · the decoded payload is shown — labelled UNVERIFIED');
  eq(ev.body.payload_unverified.amount_minor, 1200, 'B5 · amount is an integer in the payload');
  ok(ev.body.payload_unverified.capability_proof && Array.isArray(ev.body.payload_unverified.capability_proof.path),
     'B6 · ★ a capability membership proof rides in the receipt');
  const jw = await get('/.well-known/jwks.json');
  eq(jw.status, 200, 'B7 · JWKS is published');
  ok(jw.body.keys.some((k) => k.kid === a.kid && k.kty === 'OKP' && k.crv === 'Ed25519'), 'B8 · ★ the signing key is in it, as OKP/Ed25519');
  ok(!JSON.stringify(jw.body).includes('"d"'), 'B9 · ★ no private material in the JWKS');
  eq((await get('/evidence/auth_00000000000000000000')).status, 404, 'B10 · unknown receipt → 404');
  eq((await get('/evidence/nope')).status, 400, 'B11 · malformed id → 400');

  console.log('\n── B2 · RAW `application/cose` — the artifact without the JSON around it ────────────────────');
  { const r = await fetch(B() + a.evidence, { headers: { accept: 'application/cose' } });
    const rawBytes = Buffer.from(await r.arrayBuffer());
    eq(r.status, 200, 'B2b · raw COSE is served');
    eq(r.headers.get('content-type'), 'application/cose', 'B2c · ★ content-type is application/cose (RFC 9052 §14.4.1), not JSON');
    ok(rawBytes.equals(Buffer.from(ev.body.cose_base64, 'base64')),
      'B2d · ★★ the raw bytes are BYTE-IDENTICAL to base64-decoding the JSON form — two representations, one artifact');
    eq(Number(r.headers.get('content-length')), rawBytes.length, 'B2e · content-length matches the body (' + rawBytes.length + ' bytes)');
    eq(r.headers.get('x-cosmos-kid'), a.kid, 'B2f · ★ the raw response names its kid — a bare fetch can still find the key');
    ok(/jwks/.test(r.headers.get('link') || ''), 'B2g · ★ …and links the JWKS: ' + r.headers.get('link'));
    ok(receipt.verify(rawBytes, jw.body).ok === true, 'B2h · ★★ the raw bytes verify against the published JWKS with no unwrapping step');
    // the default is unchanged, and errors stay JSON even when COSE was asked for
    ok(typeof (await get(a.evidence)).body.cose_base64 === 'string', 'B2i · ★ no Accept header → the JSON envelope is unchanged');
    const miss = await fetch(B() + '/evidence/auth_00000000000000000000', { headers: { accept: 'application/cose' } });
    eq(miss.status + ':' + (await miss.json()).error, '404:RECEIPT_NOT_FOUND', 'B2j · ★ an error is still JSON — never an empty 404 body of "COSE"');
  }

  console.log('\n── B3 · ★★ THE APPROVER CLAIM STATES ITS OWN LIMITS, IN THE SIGNED BYTES ───────────────────');
  // Review finding, 2026-09-06: the receipt carried `approver_id` with the "client-asserted" disclaimer
  // living in a SOURCE COMMENT. No auditor reads source. A valid signature next to `approver_id=ops-1`
  // reads as "ops-1 approved, cryptographically proven"; what is actually proven is "the bytes are intact,
  // and somebody told Cosmos that ops-1 approved". Schema 2 puts the difference inside the signature.
  { const jg = (await post('/grants', { org_id: 'o1', agent_id: 'a-appr', currency: 'USD', budget_minor: 50000,
      per_payment_cap_minor: 5000, daily_cap_minor: 50000, allowed_categories: ['api'], approval_threshold_minor: 1000 })).body;
    const esc = (await post('/authorize', { grant_id: jg.grant_id, amount_minor: 1600, currency: 'USD', category: 'api', idempotency_key: 'ap1' })).body;
    eq(esc.decision, 'ESCALATE', 'B3a · over the approval line → ESCALATE');
    const ap = (await post('/approvals/' + esc.authorization_id, { decision: 'approve', approver_id: 'ops-1', channel: 'test' })).body;
    eq(ap.decision, 'ALLOW', 'B3b · a human approval → ALLOW');
    const apEv = await get('/evidence/' + ap.receipt_id);
    const ap_p = apEv.body.payload_unverified;
    eq(ap_p.approver_id, 'ops-1', 'B3c · the receipt records who CLAIMED to approve');
    eq(ap_p.approver_authenticated, false, 'B3d · ★★ …and states, INSIDE THE SIGNED PAYLOAD, that the identity was never authenticated');
    eq(ap_p.cosmos_schema, 4, 'B3e · schema 4 — bumped three times now, always by the same rule: a new field changes how an EXISTING one must be read (approver_authenticated, rail_reported_by, then rail_state). An old verifier must fail closed, not under-report');
    // and it survives the round trip through real verification, not just through our own JSON rendering
    const apBytes = Buffer.from(apEv.body.cose_base64, 'base64');
    const apV = receipt.verify(apBytes, (await get('/.well-known/jwks.json')).body);
    eq(apV.ok + '/' + apV.payload.approver_authenticated, 'true/false', 'B3f · ★★ a VALID signature over a receipt that says the approver is unverified — the two facts coexist, which is the honest artifact');
    // a first-pass decision has no approver at all: the field must be null, not a misleading `false`
    const plain = (await post('/authorize', { grant_id: jg.grant_id, amount_minor: 100, currency: 'USD', category: 'api', idempotency_key: 'ap2' })).body;
    const pl_p = (await get('/evidence/' + plain.receipt_id)).body.payload_unverified;
    eq(String(pl_p.approver_id) + '/' + String(pl_p.approver_authenticated), 'null/null',
      'B3g · ★ no approver → both fields null; "false" would imply an approver was checked and rejected');

    // ★★ THE CALLER MUST NOT BE ABLE TO SET IT. A disclosure the subject can switch off is not a
    // disclosure. Mutation P4 (`!!d.approver_authenticated`) SURVIVED the suite above: nothing proved the
    // request body cannot reach this field, so a single careless spread in api/approvals.js would let the
    // caller assert its own authentication and have Cosmos SIGN the claim.
    const esc2 = (await post('/authorize', { grant_id: jg.grant_id, amount_minor: 1600, currency: 'USD', category: 'api', idempotency_key: 'ap3' })).body;
    const forged = (await post('/approvals/' + esc2.authorization_id,
      { decision: 'approve', approver_id: 'ops-1', channel: 'test', approver_authenticated: true })).body;
    const fp = (await get('/evidence/' + forged.receipt_id)).body.payload_unverified;
    eq(fp.approver_authenticated, false,
      'B3h · ★★ a caller that PUTS approver_authenticated:true in the request body still gets a receipt saying false — the flag is the issuer\'s statement, never the caller\'s');

    // …and the stranger's verifier must SAY it. Mutation P6 (delete the warning) also survived: the field
    // existing in CBOR is worthless if the only tool anyone runs prints it silently.
    const apPath = path.join(TMP, 'approval.json'), apJwks = path.join(TMP, 'approval-jwks.json');
    fs.writeFileSync(apPath, JSON.stringify(apEv.body));
    fs.writeFileSync(apJwks, JSON.stringify((await get('/.well-known/jwks.json')).body));
    const apPy = py(apPath, apJwks);
    eq(apPy.code, 0, 'B3i · the approval receipt verifies in Python');
    ok(/NOT AUTHENTICATED/.test(apPy.out) && /does NOT prove/.test(apPy.out),
      'B3j · ★★ …and the verifier a stranger runs PRINTS the qualifier, so the warning cannot live only in CBOR');

  // The receipt above is the WORST case for this: the warning is the one branch a Windows reader most
  // needs and the only branch that carried a glyph.
  const apAscii = pyAscii(apPath, apJwks);
  eq(apAscii.code, 0,
    'B3m · ★★ the same receipt still verifies when stdout cannot encode anything but ASCII — a reader on a cp1252 console gets the verdict, not a traceback');
  ok(/NOT AUTHENTICATED/.test(apAscii.out) && /does NOT prove/.test(apAscii.out) && !/UnicodeEncodeError/.test(apAscii.out),
    'B3n · ★★ …and the caveat itself survives the ASCII console; it is the sentence, not the glyph, that carries the warning');

    // ONLY THE BOOLEAN `true` COUNTS — asserted at the unit, because the API cannot see this difference.
    // B3h goes through /approvals, where the body never reaches the field, so `!!x` and `x === true` behave
    // identically and mutation P4 survived it. The strictness is a property of buildPayload itself: the day
    // an authenticated path exists it will pass a real boolean, and anything else — 1, "true", "false", {} —
    // must NOT be read as proof of authentication. `!!` would promote every one of them.
    const base = { authorization_id: 'auth_' + '0'.repeat(20), decision: 'ALLOW', reason: 'APPROVED_BY_HUMAN',
      org_id: 'o', grant_id: 'g', agent_id: 'a', amount_minor: 1, currency: 'USD',
      intent_hash: 'x', envelope_hash: 'x', policy_version: 1, policy_hash: 'x', capability_root: 'x',
      idempotency_key: 'k', decided_at: 0, approver_id: 'ops-1' };
    const truthy = [1, 'true', 'false', 'yes', {}, []];
    const promoted = truthy.filter((v) => receipt.buildPayload(Object.assign({}, base, { approver_authenticated: v })).approver_authenticated !== false);
    ok(promoted.length === 0, 'B3k · ★★ only the boolean true counts — ' + JSON.stringify(truthy) + ' all stay false (promoted: ' + JSON.stringify(promoted) + ')');
    eq(receipt.buildPayload(Object.assign({}, base, { approver_authenticated: true })).approver_authenticated, true,
      'B3l · …and a genuine boolean true is honoured, so the field is not hard-coded false');
  }

  console.log('\n── C · OFFLINE VERIFICATION IN NODE (receipt.verify against the published JWKS only) ───────');
  const bytes = Buffer.from(ev.body.cose_base64, 'base64');
  const v = receipt.verify(bytes, jw.body);
  eq(v.ok, true, 'C1 · ★★ verifies with nothing but the bytes and the JWKS');
  eq(v.payload.decision, 'ALLOW', 'C2 · verdict recovered');
  eq(v.payload.merchant, 'api.openai.com', 'C3 · merchant recovered');
  ok(Array.isArray(v.payload.checks) && v.payload.checks.length === 7, 'C4 · ★ all 7 policy checks are inside the signed payload');
  ok(CC.verifyMembership(v.payload.capability_root, v.payload.capability_proof), 'C5 · ★ the capability proof verifies against the root');
  ok(!('allowed_categories' in v.payload), 'C6 · ★ …without the receipt disclosing the other categories');

  // Flip a byte INSIDE the payload, located by parsing rather than by a magic offset from the end.
  // `t.length - 90` used to work and silently stopped meaning "payload content" when schema 2 added a
  // field: the offset landed on a CBOR length byte and the receipt failed as CBOR_TRUNCATED — a real
  // failure, but not the one the assertion is named for. A test whose meaning depends on the payload's
  // byte length is a test that will lie the next time the payload changes.
  const tamperPayload = (src) => {
    const t = Buffer.from(src), pb = cose.parse(src).payloadBstr, at = src.indexOf(pb);
    if (at < 0 || pb.length < 8) throw new Error('cannot locate payload to tamper');
    t[at + Math.floor(pb.length / 2)] ^= 0x01;
    return t;
  };
  eq(receipt.verify(tamperPayload(bytes), jw.body).reason, 'SIGNATURE_INVALID', 'C7 · ★★ a one-byte tamper → SIGNATURE_INVALID, specifically');
  eq(receipt.verify(bytes, { keys: [] }).reason, 'KEY_UNKNOWN', 'C8 · ★ an unpublished key → KEY_UNKNOWN');
  eq(receipt.verify(bytes, { keys: jw.body.keys.map((k) => Object.assign({}, k, { status: 'revoked' })) }).reason, 'KEY_REVOKED', 'C9 · ★ a revoked key → KEY_REVOKED');
  eq(receipt.verify(bytes, { keys: jw.body.keys.map((k) => Object.assign({}, k, { status: 'retired' })) }).ok, true, 'C10 · ★ a RETIRED key still verifies history');

  { // A receipt VALIDLY SIGNED over a BAD proof — the only way to reach CAPABILITY_PROOF_INVALID past the
    // signature check. Issued with the server's own key, so the signature is genuine and the proof is not.
    const p = receipt.open(bytes).payload; p.capability_proof.path[0].hash = 'f'.repeat(64);
    const forged = receipt.issue(p, h.keystore).cose;
    eq(receipt.verify(forged, jw.body).reason, 'CAPABILITY_PROOF_INVALID',
       'C11 · ★★ a genuine signature over a broken Merkle path → CAPABILITY_PROOF_INVALID, not ok');
    fs.writeFileSync(path.join(TMP, 'badproof.cose'), forged); }

  console.log('\n── D · DENY and ESCALATE are receipts too ─────────────────────────────────────────────────');
  const d = (await post('/authorize', { grant_id: g.grant_id, amount_minor: 3000, currency: 'USD', category: 'api', idempotency_key: 'k2' })).body;
  eq(d.decision + '/' + d.signed, 'DENY/true', 'D1 · ★★ a DENY is signed — "the authority said no" is the receipt nobody else issues');
  const dv = receipt.verify(Buffer.from((await get(d.evidence)).body.cose_base64, 'base64'), jw.body);
  eq(dv.ok + '/' + dv.payload.reason, 'true/PER_PAYMENT_LIMIT', 'D2 · ★ it verifies and carries the reason');
  ok(dv.payload.checks.some((c) => c.name === 'Under per-payment cap' && c.pass === false), 'D3 · ★ the failing check is named inside the signed payload');
  const e = (await post('/authorize', { grant_id: g.grant_id, amount_minor: 1600, currency: 'USD', category: 'cloud', idempotency_key: 'k3' })).body;
  eq(e.decision + '/' + e.signed, 'ESCALATE/true', 'D4 · an ESCALATE is signed');
  const rep = (await post('/authorize', { grant_id: g.grant_id, amount_minor: 1200, currency: 'USD', category: 'api', merchant: 'api.openai.com', description: 'embeddings batch 4471', idempotency_key: 'k1' })).body;
  eq(rep.idempotent_replay + '/' + rep.receipt_id, 'true/' + a.receipt_id, 'D5 · ★ an idempotent replay returns the SAME receipt, not a second one');

  console.log('\n── E · ★★ THE STRANGER: Python verifier, no Cosmos code, no CBOR library ───────────────────');
  const evPath = path.join(TMP, 'receipt.json'), jwPath = path.join(TMP, 'jwks.json'), cosePath = path.join(TMP, 'receipt.cose');
  fs.writeFileSync(evPath, JSON.stringify(ev.body)); fs.writeFileSync(jwPath, JSON.stringify(jw.body)); fs.writeFileSync(cosePath, bytes);
  const pyOk = py(evPath, jwPath);
  eq(pyOk.code, 0, 'E1 · ★★ python exits 0 on the real receipt');
  ok(/^VALID/m.test(pyOk.out), 'E2 · ★★ …and prints VALID');
  ok(/decision=ALLOW/.test(pyOk.out), 'E3 · it read the verdict');
  ok(/capability proof: ok/.test(pyOk.out), 'E4 · ★ it verified the Merkle proof with its own sha256');
  eq(py(cosePath, jwPath).code, 0, 'E5 · raw .cose bytes work too');

  { const t = tamperPayload(bytes);
    const tp = path.join(TMP, 'tampered.cose'); fs.writeFileSync(tp, t);
    const r = py(tp, jwPath);
    eq(r.code, 1, 'E6 · ★★ a tampered receipt exits 1');
    ok(/SIGNATURE_INVALID/.test(r.out), 'E7 · ★★ …with SIGNATURE_INVALID, specifically'); }
  { const ep = path.join(TMP, 'empty-jwks.json'); fs.writeFileSync(ep, '{"keys":[]}');
    ok(/KEY_UNKNOWN/.test(py(evPath, ep).out), 'E8 · ★ an unpublished key → KEY_UNKNOWN'); }
  { const rp = path.join(TMP, 'revoked-jwks.json'); fs.writeFileSync(rp, JSON.stringify({ keys: jw.body.keys.map((k) => Object.assign({}, k, { status: 'revoked' })) }));
    ok(/KEY_REVOKED/.test(py(evPath, rp).out), 'E9 · ★ a revoked key → KEY_REVOKED'); }
  const dvPath = path.join(TMP, 'deny.json'); fs.writeFileSync(dvPath, JSON.stringify((await get(d.evidence)).body));
  ok(/decision=DENY reason=PER_PAYMENT_LIMIT/.test(py(dvPath, jwPath).out), 'E10 · ★ the DENY verifies in Python with its reason');
  { const r = py(path.join(TMP, 'badproof.cose'), jwPath);
    eq(r.code + '/' + /CAPABILITY_PROOF_INVALID/.test(r.out), '1/true',
       'E11 · ★★ Python rejects a genuinely-signed receipt with a broken Merkle path — its sha256 walk has teeth'); }

  console.log('\n── F · ★★ CROSS-LANGUAGE BYTE CHECK: Python\'s Sig_structure == Node\'s ─────────────────────');
  { const dbg = py(cosePath, jwPath, '--debug');
    const m = /debug sig_structure hex: ([0-9a-f]+)/.exec(dbg.out);
    const parsed = cose.parse(bytes);
    const nodeTbs = cose.toBeSigned(parsed.protectedBstr, parsed.payloadBstr).toString('hex');
    ok(m && m[1] === nodeTbs, 'F1 · ★★ two implementations, two languages, written from the RFCs independently → identical ' + (nodeTbs.length / 2) + ' bytes. This closes the open CBOR cross-check for the encoder path signing depends on.'); }

  console.log('\n── G · RESTART: evidence is durable ───────────────────────────────────────────────────────');
  await close(h);
  h = await listen(LOG);
  const ev2 = await get(a.evidence);
  eq(ev2.status + '/' + ev2.body.cose_base64, '200/' + ev.body.cose_base64, 'G1 · ★★ the receipt is served byte-identical after a restart');
  const rep2 = (await post('/authorize', { grant_id: g.grant_id, amount_minor: 1200, currency: 'USD', category: 'api', merchant: 'api.openai.com', description: 'embeddings batch 4471', idempotency_key: 'k1' })).body;
  eq(rep2.signed + '/' + rep2.receipt_id + '/' + rep2.rehydrated, 'true/' + a.receipt_id + '/true', 'G2 · ★ a rehydrated idempotent replay still reports signed + the original receipt id');

  await close(h);
  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch (_) {}
  console.log('\nevidence (end-to-end + python): ' + pass + ' passed, ' + fail + ' failed');
  process.exitCode = fail ? 1 : 0;
})().catch((e) => { console.error('\nFATAL', e); process.exit(1); });   // exit: open servers would keep the loop alive
