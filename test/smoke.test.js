// Cosmos day-1 gate. Proves the seven borrowed modules LOAD and RUN standalone — not merely that require()
// did not throw. Writ's failure mode was modules that existed, were counted, and were never exercised; a
// smoke test that only checked loading would reproduce it exactly.
//
// Every check calls the real module and asserts on a real returned value, printing it on failure.
'use strict';
const crypto = require('crypto');

const guardrails = require('../core/guardrails');
const envelope = require('../core/authorization-envelope');
const replayer = require('../core/replay');
const approvals = require('../core/approvals');
const cc = require('../core/capability-commitment');
const { makeKeystore } = require('../core/receipt-keystore');
const { jcs } = require('../core/jcs');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; } else { fail++; console.error('  x ' + m); } };

// ── 1. guardrails — the decision. Signature is evaluate(agent, amount, category) → {approved,reason,checks}
{
  const agent = {
    agentId: 'a1', status: 'active', budget: 1000, spent: 0, spentToday: 0,
    perPaymentCap: 50, dailyCap: 200, allowedCategories: ['api', 'compute'],
  };
  const allow = guardrails.evaluate(agent, 5, 'api');
  ok(allow.approved === true, 'ALLOWS an in-policy spend (got ' + allow.approved + '/' + allow.reason + ')');
  ok(Array.isArray(allow.checks) && allow.checks.length > 0, 'returns a check breakdown (' + allow.checks.length + ' checks)');

  const overCap = guardrails.evaluate(agent, 500, 'api');
  ok(overCap.approved === false && overCap.reason === 'PER_PAYMENT_LIMIT',
    'DENIES over the per-payment cap (got ' + overCap.reason + ')');

  const badCat = guardrails.evaluate(agent, 5, 'gambling');
  ok(badCat.approved === false && badCat.reason === 'CATEGORY_NOT_ALLOWED',
    'DENIES a category outside the allowlist (got ' + badCat.reason + ')');

  const frozen = guardrails.evaluate(Object.assign({}, agent, { status: 'frozen' }), 5, 'api');
  ok(frozen.approved === false && frozen.reason === 'NOT_ACTIVE',
    'DENIES a frozen agent — kill switch (got ' + frozen.reason + ')');

  const broke = guardrails.evaluate(Object.assign({}, agent, { spent: 1000 }), 5, 'api');
  ok(broke.approved === false && broke.reason === 'INSUFFICIENT_BALANCE',
    'DENIES beyond remaining budget (got ' + broke.reason + ')');
}

// ── 2. jcs — canonical bytes, order-independent ──────────────────────────────────────────────────────
{
  ok(jcs({ b: 2, a: 1 }) === jcs({ a: 1, b: 2 }), 'jcs is key-order independent');
  ok(typeof jcs({ a: 1 }) === 'string' && jcs({ a: 1 }).length > 0, 'jcs returns bytes');
}

// ── 3. receipt-keystore — real Ed25519 + published JWKS ──────────────────────────────────────────────
{
  const ks = makeKeystore({ now: 1 });
  const digest = crypto.createHash('sha256').update('hello').digest('hex');
  const signed = ks.sign(digest);
  ok(signed && typeof signed.signature === 'string' && signed.signature.length > 0, 'keystore signs');
  ok(signed && typeof signed.kid === 'string' && signed.kid.length > 0, 'keystore names a kid (' + (signed && signed.kid) + ')');
  const jwks = typeof ks.jwks === 'function' ? ks.jwks() : null;
  ok(jwks && Array.isArray(jwks.keys) && jwks.keys.length >= 1, 'keystore publishes a JWKS with >=1 key');
}

// ── 4. authorization-envelope — hashDoc takes RAW fields; tamper must move the hash ──────────────────
{
  const base = {
    orgId: 'o1', agentId: 'a1', authId: 'auth_1', intentHash: 'ih1',
    amountMinor: 5000000, asset: 'USDC', network: 'internal',
    category: 'api', merchant: 'm1', destinationFingerprint: 'df1',
    credentialFingerprint: 'cf1', policyVersion: 1, policyHash: 'ph1',
    budgetResult: 'OK', idempotencyKey: 'idem1', authorizedAt: 1000, auditHash: 'ah1',
  };
  const h1 = envelope.hashDoc(base);
  ok(h1 === envelope.hashDoc(base), 'envelope hash is deterministic');
  ok(/^[0-9a-f]{64}$/.test(h1), 'envelope hash is a sha256 (' + String(h1).slice(0, 12) + '...)');

  const h3 = envelope.hashDoc(Object.assign({}, base, { amountMinor: 5000001 }));
  ok(h1 !== h3, 'hash MOVES on ONE minor unit — tamper-evident');
  ok(envelope.verify(base, h1) === true, 'verify() accepts the true hash');
  ok(envelope.verify(Object.assign({}, base, { amountMinor: 5000001 }), h1) === false, 'verify() rejects a tampered envelope');

  // the honesty guard that must survive the port: a secret must never enter the envelope
  let threw = null;
  try { envelope.build(Object.assign({}, base, { api_key: 'sk_live_x' })); } catch (e) { threw = e.code; }
  ok(threw === 'SECRET_IN_ENVELOPE', 'REFUSES a secret-shaped field (got ' + threw + ')');
}

// ── 5. capability-commitment — Merkle attenuation. membershipProof(tree, cap); verifyMembership(root, proof)
{
  const caps = [{ type: 'category', value: 'api' }, { type: 'category', value: 'compute' }];
  const c = cc.commitCapabilities(caps);
  ok(c && typeof c.root === 'string' && c.root.length === 64, 'capability set commits to a root');
  ok(c.count === 2, 'root commits to exactly the declared caps (' + c.count + ')');

  const proof = cc.membershipProof(c.tree, caps[0]);
  ok(cc.verifyMembership(c.root, proof) === true, 'a real capability verifies as a member');

  // authority non-amplification: a cap outside the set has NO honest proof
  const forged = cc.membershipProof(c.tree, { type: 'category', value: 'gambling' });
  ok(forged === null, 'a cap NOT in the set yields NO proof (non-amplification)');
  ok(cc.verifyMembership(c.root, { cap: { type: 'category', value: 'gambling' }, path: proof.path }) === false,
    'splicing a real path onto a forged cap does NOT verify');
}

// ── 6. replay — reconstruction from events alone ─────────────────────────────────────────────────────
{
  const events = [
    { kind: 'open', agentId: 'a1', budget: 100 },
    { kind: 'decision', authId: 'x1', agentId: 'a1', amount: 5, category: 'api', approved: true },
    { kind: 'reservation', authId: 'x1', agentId: 'a1', amount: 5 },
    { kind: 'status', authId: 'x1', status: 'settled' },
  ];
  const r = replayer.replay(events);
  ok(r.agents.a1.budget === 100, 'replay reconstructs budget (' + r.agents.a1.budget + ')');
  ok(r.agents.a1.spent === 5, 'replay reconstructs spend (' + r.agents.a1.spent + ')');
  ok(r.authorizations.x1.status === 'settled', 'replay reconstructs terminal status');
  ok(replayer.isDeterministic(events) === true, 'replay is deterministic over the same history');
  ok(JSON.stringify(replayer.replay([...events, { kind: 'not_a_real_kind', x: 1 }])) === JSON.stringify(r),
    'an unknown event kind is INERT (no default case) — this is what makes new event types safe');
}

// ── 7. approvals — escalation threshold ──────────────────────────────────────────────────────────────
{
  const agent = { agentId: 'a1', approvalThreshold: 10 };
  ok(approvals.needsApproval(agent, 50, {}) === true, 'a spend above the approval line escalates');
  ok(approvals.needsApproval(agent, 5, {}) === false, 'a spend below the line does not');
}

console.log((fail === 0 ? 'PASS' : 'FAIL') + ' cosmos smoke: ' + pass + ' passed, ' + fail + ' failed');
process.exit(fail === 0 ? 0 : 1);
