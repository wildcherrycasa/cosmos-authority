// ═══ AUTHORIZATION ENVELOPE — the evidence artifact ════════════════════════════════════════════════════
//
// Thinnest coverage of the seven ported modules: ONE Writ suite, 13 assertions, and its heaviest users
// were Postgres suites that never ran. It is also the thing Cosmos sells — the content-addressed commitment
// that what a provider was asked to execute is bound to an authorization that was actually made.
//
// The module makes four claims in its own header. This file tests all four:
//   1. "Content-addressed by a canonical SHA-256"
//   2. "Any change to any bound field yields a different hash and is detectable"   <- §B, mechanically
//   3. "Holds fingerprints/hashes ONLY - never a raw credential, secret, or token" <- §C
//   4. "the builder never synthesizes authority that did not exist"                <- §E
//
// ⚠ NOTE FOR THE READER: this module canonicalizes with JSON.stringify over a hand-ordered object literal
// (canon(), line 18) — NOT with core/jcs.js. Cosmos therefore has TWO canonicalization schemes: the
// envelope hash uses this fixed-key-order form, the receipt signature uses RFC 8785 JCS. Both are
// deterministic; they are simply not the same function. Do not "unify" them without re-hashing history.
'use strict';
const E = require('../core/authorization-envelope');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };
const eq = (actual, expected, m) => {
  if (actual === expected) { pass++; console.log('  ✓ ' + m); return; }
  fail++; console.log('  ✗ ' + m);
  console.log('      expected: ' + JSON.stringify(expected));
  console.log('      actual:   ' + JSON.stringify(actual));
};
const throws = (fn, code, m) => {
  try { fn(); fail++; console.log('  ✗ ' + m); console.log('      expected throw ' + code + ', got none'); }
  catch (e) {
    if (String(e.code) === code || String(e.message).includes(code)) { pass++; console.log('  ✓ ' + m); }
    else { fail++; console.log('  ✗ ' + m); console.log('      expected throw ' + code); console.log('      actual:   ' + e.message); }
  }
};

// A fully-populated envelope: every bound field non-null, so §B can perturb each one in turn.
const FULL = () => ({
  orgId: 'org_acme', agentId: 'agt_research_01', authId: 'auth_01J8ZK',
  intentHash: 'a'.repeat(64), amountMinor: 1200, asset: 'USD', network: 'none',
  category: 'api', merchant: 'api.openai.com',
  vendorRef: 'vnd_1', destinationRef: 'dst_1', destinationFingerprint: 'b'.repeat(64),
  credentialFingerprint: 'c'.repeat(64),
  policyVersion: 1, policyHash: 'd'.repeat(64), budgetResult: 'ALLOW',
  treasuryVersion: 3, treasuryHash: 'e'.repeat(64), treasuryCommittedBasis: 500000,
  approvalRequired: true, approvalRequestId: 'apr_1',
  requesterId: 'usr_req', approverId: 'usr_apr', approvalEvidenceHash: 'f'.repeat(64),
  riskDecision: 'pass', riskHash: '0'.repeat(64),
  idempotencyKey: 'agt:req_9931', ledgerAuthRef: 'led_1',
  authorizedAt: 1788134400000, expiresAt: 1788134700000, auditHash: '1'.repeat(64),
});
const REQUIRED = ['orgId', 'agentId', 'authId', 'intentHash', 'amountMinor', 'idempotencyKey',
                  'policyVersion', 'policyHash', 'credentialFingerprint', 'budgetResult', 'auditHash'];

console.log('\n── A · CONTENT ADDRESSING ─────────────────────────────────────────────────────────────────────');

eq(E.SCHEMA_VERSION, 2, 'A1 · SCHEMA_VERSION is 2');
ok(/^\{"schema_version":2,/.test(E.canon(FULL())),
   'A2 · ★ schema_version is bound FIRST — a version bump re-hashes every envelope, by design');
eq(E.hashDoc(FULL()), E.hashDoc(FULL()), 'A3 · deterministic — same fields, same hash');
eq(E.hashDoc(FULL()).length, 64, 'A4 · the hash is a 64-char sha256 hex digest');
ok(/^[0-9a-f]{64}$/.test(E.hashDoc(FULL())), 'A5 · lowercase hex only');

{ // Key INSERTION order of the input must not matter — canon() reads named properties into a fixed literal.
  const f = FULL(); const reversed = {};
  for (const k of Object.keys(f).reverse()) reversed[k] = f[k];
  eq(E.hashDoc(reversed), E.hashDoc(f),
     'A6 · ★ input key insertion order is irrelevant — canon() imposes its own field order');
}
eq(E.build(FULL()).hash, E.hashDoc(FULL()),
   'A7 · ★ the hash ON the built envelope equals hashDoc() of the fields it was built from');

console.log('\n── B · "any change to any bound field yields a different hash" (the module\'s own claim) ───────');

// Every bound field, perturbed one at a time. If ANY of these collides, evidence is forgeable.
const PERTURB = {
  orgId: 'org_other', agentId: 'agt_other', authId: 'auth_other', intentHash: 'z'.repeat(64),
  amountMinor: 1201, asset: 'EUR', network: 'internal', category: 'cloud',
  merchant: 'api.anthropic.com', vendorRef: 'vnd_2', destinationRef: 'dst_2',
  destinationFingerprint: 'z'.repeat(64), credentialFingerprint: 'z'.repeat(64),
  policyVersion: 2, policyHash: 'z'.repeat(64), budgetResult: 'DENY',
  treasuryVersion: 4, treasuryHash: 'z'.repeat(64), treasuryCommittedBasis: 500001,
  approvalRequired: false, approvalRequestId: 'apr_2',
  requesterId: 'usr_req2', approverId: 'usr_apr2', approvalEvidenceHash: 'z'.repeat(64),
  riskDecision: 'review', riskHash: 'z'.repeat(64),
  idempotencyKey: 'agt:req_9932', ledgerAuthRef: 'led_2',
  authorizedAt: 1788134400001, expiresAt: 1788134700001, auditHash: 'z'.repeat(64),
};
const BASE = E.hashDoc(FULL());
let collided = [];
for (const k of Object.keys(PERTURB)) {
  const f = FULL(); f[k] = PERTURB[k];
  if (E.hashDoc(f) === BASE) collided.push(k);
}
ok(collided.length === 0,
   'B1 · ★★ all ' + Object.keys(PERTURB).length + ' bound fields change the hash when perturbed' +
   (collided.length ? ' — COLLIDED: ' + collided.join(', ') : ''));
eq(Object.keys(PERTURB).length, 31, 'B2 · the perturbation set covers 31 input fields');

// The mirror property, and the dangerous one: a field NOT in canon() is NOT covered.
{ const f = FULL(); f.somethingCosmosAddedLater = 'not-bound';
  eq(E.hashDoc(f), BASE,
     'B3 · ⚠★ an UNBOUND field does NOT change the hash — anything added to the envelope later must be ' +
     'added to canon() or it is silently unprotected');
}

console.log('\n── C · SECRET REFUSAL — "never a raw credential, secret, or token" ────────────────────────────');

for (const k of ['authorization', 'apiKey', 'api_key', 'api-key', 'secret', 'token',
                 'privateKey', 'private_key', 'password', 'bearer']) {
  throws(() => E.build(Object.assign(FULL(), { [k]: 'x' })), 'SECRET_IN_ENVELOPE',
         'C · a field named "' + k + '" is refused');
}
throws(() => E.build(Object.assign(FULL(), { APIKEY: 'x' })), 'SECRET_IN_ENVELOPE',
       'C11 · the match is case-insensitive (APIKEY)');
throws(() => E.build(Object.assign(FULL(), { myAuthorizationHeader: 'x' })), 'SECRET_IN_ENVELOPE',
       'C12 · ★ the match is a SUBSTRING, not anchored — myAuthorizationHeader is caught');
throws(() => E.build({ apiKey: 'x' }), 'SECRET_IN_ENVELOPE',
       'C13 · ★ the secret check runs BEFORE required-field validation — it fails closed first');

ok(E.build(FULL()).credential_fingerprint === 'c'.repeat(64),
   'C14 · ★ credentialFingerprint is explicitly ALLOWED — a fingerprint is not a credential');
ok(E.build(FULL()).risk_hash === '0'.repeat(64), 'C15 · riskHash is allowed');
ok(!Object.keys(E.build(FULL())).some((k) =>
     /(authorization|api[-_]?key|secret|token|private[-_]?key|password|bearer)/i.test(k)),
   'C16 · ★ the BUILT envelope contains no secret-shaped key');

// The honest limit of this guard, stated as a test rather than left to be discovered.
{ const env = E.build(Object.assign(FULL(), { merchant: 'sk-live-REALSECRETVALUE' }));
  eq(env.merchant, 'sk-live-REALSECRETVALUE',
     'C17 · ⚠★ the guard inspects KEY NAMES ONLY — a secret placed in a VALUE passes through untouched');
}

console.log('\n── D · REQUIRED FIELDS AND AMOUNT VALIDATION ──────────────────────────────────────────────────');

for (const k of REQUIRED) {
  const f = FULL(); delete f[k];
  throws(() => E.build(f), 'MISSING_ENVELOPE_FIELD', 'D · missing "' + k + '" is refused');
}
{ const f = FULL(); f.orgId = null;
  throws(() => E.build(f), 'MISSING_ENVELOPE_FIELD', 'D12 · null is treated as missing'); }
{ const f = FULL(); f.orgId = '';
  throws(() => E.build(f), 'MISSING_ENVELOPE_FIELD', 'D13 · empty string is treated as missing'); }
{ const f = FULL(); f.policyVersion = 0;
  ok(E.build(f).policy_version === 0, 'D14 · ★ 0 is a VALID required value — only null/"" are missing'); }

for (const [v, label] of [[0, 'zero'], [-1, 'negative'], [12.5, 'a float'], [NaN, 'NaN'], ['abc', 'non-numeric']]) {
  const f = FULL(); f.amountMinor = v;
  throws(() => E.build(f), 'INVALID_AMOUNT_MINOR', 'D · amountMinor = ' + label + ' is refused');
}
{ const f = FULL(); f.amountMinor = '1200';
  ok(E.build(f).amount_minor === 1200,
     'D20 · ⚠ a NUMERIC STRING "1200" is silently coerced and accepted — the API layer must reject it first'); }
{ const a = FULL(), b = FULL(); b.amountMinor = '1200';
  eq(E.hashDoc(b), E.hashDoc(a), 'D21 · ⚠★ 1200 and "1200" hash IDENTICALLY — coercion happens before hashing'); }

console.log('\n── E · THE HONESTY RULE — "never synthesizes authority that did not exist" ────────────────────');

{ const f = FULL();
  f.treasuryVersion = undefined; f.treasuryHash = undefined; f.treasuryCommittedBasis = undefined;
  f.approvalRequestId = undefined; f.requesterId = undefined; f.approverId = undefined;
  f.approvalEvidenceHash = undefined; f.riskDecision = undefined; f.riskHash = undefined;
  const env = E.build(f);
  ok(env.treasury_version === null && env.treasury_hash === null && env.treasury_committed_basis === null,
     'E1 · ★ absent treasury authority is null, not synthesized');
  ok(env.approval_request_id === null && env.requester_id === null && env.approver_id === null &&
     env.approval_evidence_hash === null,
     'E2 · ★ absent approval authority is null, not synthesized');
  ok(env.risk_decision === null && env.risk_hash === null, 'E3 · absent risk authority is null');
}
{ const f = FULL(); delete f.approvalRequired;
  eq(E.build(f).approval_required, false,
     'E4 · ★ an OMITTED approvalRequired defaults to false — the builder never invents an approval line'); }
{ const f = FULL(); f.approvalRequired = 0;
  eq(E.build(f).approval_required, false, 'E4b · approvalRequired is !!-coerced: 0 → false'); }
{ const f = FULL(); f.approvalRequired = 'no';
  eq(E.build(f).approval_required, true,
     'E4c · ⚠ !!-coercion means the STRING "no" becomes true — pass a real boolean'); }
{ const f = FULL(); f.requesterId = 'usr_same'; f.approverId = 'usr_same';
  throws(() => E.build(f), 'APPROVER_EQUALS_REQUESTER',
         'E5 · ★ self-approval is refused — approver may not equal requester'); }
{ const f = FULL(); f.requesterId = 'usr_same'; f.approverId = 'usr_same'; f.approvalRequired = false;
  throws(() => E.build(f), 'APPROVER_EQUALS_REQUESTER',
         'E6 · self-approval is refused even when no approval was required'); }

// ⚠ GAP: the header comment claims "approver without an approval requirement ... is refused". The code
// (line 46) only implements the approver==requester half. This test PINS the actual behaviour so the
// divergence is visible rather than assumed-fixed.
{ const f = FULL(); f.approvalRequired = false; f.approverId = 'usr_apr'; f.requesterId = 'usr_req';
  const env = E.build(f);
  eq(env.approver_id, 'usr_apr',
     'E7 · ⚠★ GAP: an approver on an envelope requiring NO approval is ACCEPTED — the header comment ' +
     'claims this is refused, the code never checks it'); }

console.log('\n── F · DEFAULTS AND FALSY COERCION ────────────────────────────────────────────────────────────');

{ const f = FULL(); delete f.asset; delete f.network;
  const env = E.build(f);
  eq(env.asset, 'USDC', 'F1 · asset defaults to USDC (a Writ default — Cosmos must set it explicitly)');
  eq(env.network, 'internal', 'F2 · network defaults to "internal"'); }
{ const a = FULL(), b = FULL(); delete a.asset; b.asset = 'USDC';
  eq(E.hashDoc(a), E.hashDoc(b), 'F3 · ⚠ an omitted asset and an explicit "USDC" hash identically'); }
{ const a = FULL(), b = FULL(); a.asset = ''; b.asset = 'USDC';
  eq(E.hashDoc(a), E.hashDoc(b), 'F4 · ⚠★ asset:"" is FALSY so it also collides with "USDC"'); }
{ const a = FULL(), b = FULL(); delete a.destinationFingerprint; b.destinationFingerprint = '';
  eq(E.hashDoc(a), E.hashDoc(b), 'F5 · ⚠ an omitted destinationFingerprint collides with ""'); }
{ const f = FULL(); f.treasuryCommittedBasis = 0;
  eq(E.build(f).treasury_committed_basis, 0, 'F6 · ★ 0 survives as 0 — it is NOT flattened to null'); }
{ const f = FULL(); f.authorizedAt = 1788134400000;
  ok(E.build(f).authorized_at instanceof Date, 'F7 · authorizedAt is returned as a Date object'); }
{ const f = FULL(); f.authorizedAt = null; f.expiresAt = null;
  const env = E.build(f);
  ok(env.authorized_at === null && env.expires_at === null, 'F8 · null timestamps stay null, not epoch 0'); }

console.log('\n── G · IMMUTABILITY AND verify() ──────────────────────────────────────────────────────────────');

{ const env = E.build(FULL());
  ok(Object.isFrozen(env), 'G1 · ★ the built envelope is frozen');
  let threw = false;
  try { env.amount_minor = 999999; } catch (_) { threw = true; }
  ok(threw && env.amount_minor === 1200,
     'G2 · ★ mutating a frozen envelope throws in strict mode and the value is unchanged'); }

eq(E.verify(FULL(), BASE), true, 'G3 · verify() accepts matching fields');
{ const f = FULL(); f.amountMinor = 1201;
  eq(E.verify(f, BASE), false, 'G4 · ★ verify() rejects a one-cent tamper'); }
eq(E.verify(FULL(), 'not-a-hash'), false, 'G5 · verify() rejects a wrong expected hash');
{ const f = FULL(); f.orgId = { toString() { throw new Error('boom'); } };
  eq(E.verify(f, BASE), false, 'G6 · ★ verify() FAILS CLOSED when canonicalization throws — never true'); }
eq(E.verify(FULL(), null), false, 'G7 · verify() against a null hash is false, not a crash');

console.log('\nauthorization-envelope: ' + pass + ' passed, ' + fail + ' failed');
if (fail) process.exit(1);
