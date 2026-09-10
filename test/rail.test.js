// ═══ THE RAIL HANDOFF — DESIGN §7, closed ══════════════════════════════════════════════════════════════
//
// What this suite has to prove, in the order the design questions were asked:
//   §A/§I  only the holder of a one-shot, per-authorization capability may report — and the log a
//          leaked backup would contain is NOT enough to forge one.
//   §C     a rail that speaks removes the TTL guess in BOTH directions: a settled reservation is never
//          auto-reversed, a submitted one stops racing a timer, a failed one gives the budget back now.
//   §E     a settlement that arrives after the TTL already reversed is recorded as LATE and re-reserved,
//          rather than silently dropped or silently un-reversed.
//   §D/§F  the report is itself a signed receipt, chained to the ALLOW, and the two folds still agree.
//
// ⚠ Boundaries and semantics are DECIDED HERE FROM THE SPEC, not photographed from the implementation:
//   · a `settled` report REQUIRES a tx id; `submitted` and `failed` do not (a settlement that names
//     nothing is a claim with nothing in it to check later).
//   · terminal is terminal: the same outcome replays, a different one is a 409. Cosmos cannot adjudicate
//     which of two contradicting reports is honest, so it refuses to sign the second.
//   · `submitted` is deliberately NOT idempotent — each report is a distinct "still in flight at T".
//   · a report against a DENY is a 409, not a 404: the authorization exists, there is just nothing to settle.
//   · the capability is required in EVERY write mode, including explicitly-open. An open mint is a
//     legitimate demo choice; an open path that can cancel a budget reversal is not.
'use strict';
process.env.COSMOS_RESERVATION_TTL_MS = '60000';      // long by default; §E uses a per-server override

const fs = require('fs'), os = require('os'), path = require('path');
const crypto = require('crypto');
const rail = require('../core/rail');
const replayMod = require('../core/replay');
const view = require('../core/agent-view');
const receipt = require('../core/receipt');
const { start } = require('../api/server');
const { expiredReservations } = require('../api/authorize');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };
const eq = (a, e, m) => {
  if (a === e) { pass++; console.log('  ✓ ' + m); return; }
  fail++; console.log('  ✗ ' + m);
  console.log('      expected: ' + JSON.stringify(e));
  console.log('      actual:   ' + JSON.stringify(a));
};

const TMP = path.join(os.tmpdir(), 'cosmos-rail-' + process.pid);
fs.mkdirSync(TMP, { recursive: true });
const logFile = (n) => path.join(TMP, n + '.jsonl');

function listen(o) {
  return new Promise((r) => {
    const h = start(Object.assign({ port: 0, quiet: true }, o));
    h.server.on('listening', () => r(Object.assign(h, { port: h.server.address().port })));
  });
}
const close = (h) => new Promise((r) => {
  h.store.close();
  if (h.server.closeAllConnections) h.server.closeAllConnections();
  h.server.close(() => r());
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  // ── §A · the capability ─────────────────────────────────────────────────────────────────────────────
  console.log('\n§A · the settlement capability (core/rail.js, pure)');
  {
    const id = 'auth_' + 'a'.repeat(20), other = 'auth_' + 'b'.repeat(20);
    const c = rail.mintCapability(id);
    ok(typeof c.token === 'string' && c.token.length >= 40, 'A1 · mint returns a token');
    ok(/^[0-9a-f]{64}$/.test(c.hash), 'A2 · …and a sha256 hash of it');
    ok(c.hash !== c.token && !c.hash.includes(c.token), 'A3 · ★ the hash is not the token — the durable half cannot be presented');
    ok(rail.capabilityMatches(id, c.token, c.hash), 'A4 · the right token matches');
    ok(!rail.capabilityMatches(id, c.token + 'x', c.hash), 'A5 · a mutated token does not');
    ok(!rail.capabilityMatches(other, c.token, c.hash), 'A6 · ★★ the SAME token presented against another authorization does NOT match — the hash binds the authId');
    ok(!rail.capabilityMatches(id, '', c.hash) && !rail.capabilityMatches(id, null, c.hash) &&
       !rail.capabilityMatches(id, c.token, null), 'A7 · empty / null / missing-hash all refuse rather than throw');
    ok(rail.mintCapability(id).token !== rail.mintCapability(id).token, 'A8 · two mints for one id differ');
    // A token derived from data anyone can read is not a secret. Pin that the mint uses randomness, not
    // the authId: the same input twice must not give the same token (A8), and a caller-chosen seed must
    // reach the token, so the source of entropy is visible rather than assumed.
    const fixed = rail.mintCapability(id, Buffer.alloc(32, 7));
    eq(fixed.token, Buffer.alloc(32, 7).toString('base64url'), 'A9 · the token IS the random bytes, base64url — nothing derived from the authId');
  }

  // ── §B · the fold ───────────────────────────────────────────────────────────────────────────────────
  console.log('\n§B · railState — one pure pass over history');
  {
    const id = 'auth_' + '1'.repeat(20);
    const dec = { kind: 'decision', authId: id, agentId: 'g1', amount: 500, approved: true, decisionKind: 'ALLOW' };
    const res = { kind: 'reservation', authId: id, agentId: 'g1', amount: 500, expiresAt: 1000, railTokenHash: 'hh' };
    eq(rail.railState([dec], id).reserved, false, 'B1 · a decision alone reserves nothing');
    const s2 = rail.railState([dec, res], id);
    ok(s2.reserved && s2.deadline === 1000 && s2.tokenHash === 'hh' && s2.grantId === 'g1', 'B2 · a reservation carries deadline, token hash and grant');
    eq(rail.railState([dec, res, { kind: 'reversal', authId: id, agentId: 'g1', amount: 500 }], id).reserved, false, 'B3 · a reversal closes it');
    const s4 = rail.railState([dec, res, { kind: 'submission', authId: id, agentId: 'g1', expiresAt: 9000, txId: 't1' }], id);
    ok(s4.deadline === 9000 && s4.outcome === 'submitted' && s4.txId === 't1', 'B4 · a submission pushes the deadline out and records the tx');
    eq(rail.railState([dec, res, { kind: 'submission', authId: id, agentId: 'g1', expiresAt: 500 }], id).deadline, 1000,
       'B5 · ★ a submission NEVER shortens a deadline — a rail cannot pull a reservation in early');
    const s6 = rail.railState([dec, res, { kind: 'settlement', authId: id, agentId: 'g1', outcome: 'settled', txId: 'x' }], id);
    ok(s6.settled && !s6.failed && s6.reserved, 'B6 · a settlement is final AND keeps the spend reserved');
    const s7 = rail.railState([dec, res, { kind: 'reversal', authId: id, agentId: 'g1', amount: 500 },
                               { kind: 'settlement', authId: id, agentId: 'g1', outcome: 'failed' }], id);
    ok(s7.failed && !s7.settled && !s7.reserved, 'B7 · a failed report leaves nothing reserved');
    const s8 = rail.railState([dec, res, { kind: 'reversal', authId: id, agentId: 'g1', amount: 500 },
                               { kind: 'reservation', authId: id, agentId: 'g1', amount: 500 },
                               { kind: 'settlement', authId: id, agentId: 'g1', outcome: 'settled', late: true, txId: 'x' }], id);
    ok(s8.settled && s8.late && s8.reserved, 'B8 · ★ late order [reversal, reservation, settlement] folds to settled + late');
    eq(rail.railState([dec, res, { kind: 'settlement', authId: 'auth_' + '2'.repeat(20), outcome: 'settled' }], id).settled, false,
       'B9 · another authorization\'s settlement is not this one\'s');
    eq(rail.sweepable(s6), false, 'B10 · ★★ a settled row is NOT sweepable');
    eq(rail.sweepable(s2), true, 'B11 · a plain reservation is');
  }

  // ── §C · the sweep, which is where the TTL stops being a guess ──────────────────────────────────────
  console.log('\n§C · expiredReservations — the rail removes the guess in both directions');
  {
    const A = 'auth_' + 'c'.repeat(20), Bq = 'auth_' + 'd'.repeat(20);
    const base = [{ kind: 'reservation', authId: A, agentId: 'g1', amount: 100, expiresAt: 1000 }];
    eq(expiredReservations(base, 'g1', 2000).length, 1, 'C1 · an unreported reservation still auto-reverses at TTL (unchanged fallback)');
    eq(expiredReservations(base, 'g1', 900).length, 0, 'C2 · …and not before');
    eq(expiredReservations(base, 'g1', 1000).length, 0,
       'C2a · ★ EXACTLY at the deadline is not yet expired — decided from the spec, and it is the house convention guardrails already uses for `expires_at` (valid AT the instant)');
    const settled = base.concat([{ kind: 'settlement', authId: A, agentId: 'g1', outcome: 'settled', txId: 'x' }]);
    eq(expiredReservations(settled, 'g1', 99999999).length, 0,
       'C3 · ★★ a SETTLED reservation is never auto-reversed, however long after its TTL — the money moved, the spend stands');
    const submitted = base.concat([{ kind: 'submission', authId: A, agentId: 'g1', expiresAt: 50000 }]);
    eq(expiredReservations(submitted, 'g1', 2000).length, 0,
       'C4 · ★★ a SUBMITTED reservation survives its original TTL — a slow-but-successful payment stops racing a timer it was never told about');
    eq(expiredReservations(submitted, 'g1', 60000).length, 1, 'C5 · …but the extended deadline is still a deadline');
    const failed = base.concat([{ kind: 'reversal', authId: A, agentId: 'g1', amount: 100, reason: 'RAIL_FAILED' },
                                { kind: 'settlement', authId: A, agentId: 'g1', outcome: 'failed' }]);
    eq(expiredReservations(failed, 'g1', 99999).length, 0, 'C6 · a failed-and-reversed row has nothing left to reverse (no double credit)');
    eq(expiredReservations(base.concat([{ kind: 'reservation', authId: Bq, agentId: 'g2', amount: 5, expiresAt: 1 }]), 'g1', 5000).length, 1,
       'C7 · another grant\'s reservations are not touched');
    eq(expiredReservations([{ kind: 'submission', authId: A, agentId: 'g1', expiresAt: 9 }], 'g1', 99999).length, 0,
       'C8 · ★ a submission for something never reserved does not resurrect it');
  }

  // ── §D · over real HTTP ─────────────────────────────────────────────────────────────────────────────
  console.log('\n§D · the fifth route, end to end');
  const OPTOKEN = 'operator-token-for-rail-tests';
  const RAILTOKEN = 'rail-token-for-rail-tests-32chars';
  let h = await listen({ file: logFile('d'), writeToken: OPTOKEN, rail: { provider: 'writ', token: RAILTOKEN } });
  const B = () => 'http://localhost:' + h.port;
  const post = (p, o, tok) => fetch(B() + p, {
    method: 'POST',
    headers: Object.assign({ 'content-type': 'application/json' }, tok ? { authorization: 'Bearer ' + tok } : {}),
    body: JSON.stringify(o || {}),
  }).then(async (r) => ({ status: r.status, body: await r.json() }));
  const get = (p, tok) => fetch(B() + p, { headers: tok ? { authorization: 'Bearer ' + tok } : {} })
    .then(async (r) => ({ status: r.status, body: await r.json() }));
  // How a RAIL reports: its own token says WHO is speaking, the handoff header says WHICH authorization
  // was actually routed to it. Neither alone is enough for a terminal outcome.
  const asRail = (path, o, handoff, tok) => fetch(B() + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + (tok || RAILTOKEN), 'x-cosmos-handoff': handoff },
    body: JSON.stringify(o),
  }).then(async (r) => ({ status: r.status, body: await r.json() }));

  const grant = (await post('/grants', {
    org_id: 'org_rail', agent_id: 'agent_rail', currency: 'USD',
    budget_minor: 100000, per_payment_cap_minor: 5000, daily_cap_minor: 90000,
    allowed_categories: ['api'],
  }, OPTOKEN)).body;

  const authorize = (amount, key) => post('/authorize', {
    grant_id: grant.grant_id, amount_minor: amount, currency: 'USD', category: 'api',
    merchant: 'rail.test', idempotency_key: key,
  });

  const a1 = (await authorize(1000, 'd-1')).body;
  eq(a1.decision, 'ALLOW', 'D1 · an ALLOW to work with');
  ok(a1.rail && a1.rail.report_to === '/settlements/' + a1.authorization_id, 'D2 · ★ the ALLOW says where to report back — an ALLOW is no longer a decision with no ending');
  eq(a1.rail.provider, 'writ', 'D3 · …and names the configured rail');
  ok(typeof a1.rail.handoff_token === 'string' && a1.rail.handoff_token.length >= 40, 'D4 · …and carries a one-shot capability');
  ok(Array.isArray(a1.rail.outcomes) && a1.rail.outcomes.join(',') === 'submitted,settled,failed', 'D5 · …and the closed outcome set');

  const d1 = (await authorize(9000, 'd-deny')).body;
  eq(d1.decision, 'DENY', 'D6 · a DENY for contrast');
  eq(d1.rail, null, 'D7 · ★ a DENY carries NO handoff — there is nothing to execute, so there is nothing to report');

  eq((await post('/settlements/' + a1.authorization_id, { outcome: 'settled', tx_id: 't' })).status, 401,
     'D8 · ★★ a report with NO credential is refused');
  eq((await post('/settlements/' + a1.authorization_id, { outcome: 'settled', tx_id: 't' }, 'not-the-token')).status, 401,
     'D9 · ★★ …and so is a wrong one');

  const a2 = (await authorize(1000, 'd-2')).body;
  eq((await post('/settlements/' + a1.authorization_id, { outcome: 'settled', tx_id: 't' }, a2.rail.handoff_token)).status, 401,
     'D10 · ★★ ANOTHER authorization\'s capability is refused — one token, one authorization');

  eq((await asRail('/settlements/' + a1.authorization_id, { outcome: 'teleported', tx_id: 't' }, a1.rail.handoff_token)).body.error, 'INVALID_OUTCOME',
     'D11 · the outcome set is closed');
  eq((await asRail('/settlements/' + a1.authorization_id, { outcome: 'settled' }, a1.rail.handoff_token)).body.error, 'TX_ID_REQUIRED',
     'D12 · ★ a settlement that names no transaction is refused — a claim with nothing in it to look up later');
  eq((await post('/settlements/' + d1.authorization_id, { outcome: 'settled', tx_id: 't' }, OPTOKEN)).body.error, 'NOT_AN_ALLOW',
     'D13 · ★ reporting a settlement against a DENY is refused');
  eq((await post('/settlements/auth_' + 'f'.repeat(20), { outcome: 'settled', tx_id: 't' }, OPTOKEN)).body.error, 'AUTHORIZATION_NOT_FOUND',
     'D14 · an unknown authorization is a 404');
  eq((await post('/settlements/not-an-id', { outcome: 'settled', tx_id: 't' }, OPTOKEN)).body.error, 'INVALID_AUTHORIZATION_ID',
     'D15 · a malformed id is a 400');

  // the happy path
  const rep = await asRail('/settlements/' + a1.authorization_id, { outcome: 'settled', tx_id: '0xdeadbeef', provider: 'writ' }, a1.rail.handoff_token);
  eq(rep.status, 200, 'D16 · the RAIL may report — its own token plus the capability it was handed');
  eq(rep.body.rail_outcome, 'settled', 'D17 · outcome recorded');
  eq(rep.body.rail_reported_by, 'rail', 'D18 · ★ …and WHICH credential class reported it is recorded');
  eq(rep.body.parent_receipt_id, a1.authorization_id, 'D19 · ★★ the report is chained to the ALLOW it descends from');
  ok(/^stl_[0-9a-f]{20}$/.test(rep.body.receipt_id), 'D20 · the report gets its OWN receipt id');
  eq(rep.body.rail_late, false, 'D21 · not late');

  const ev = await get('/evidence/' + rep.body.receipt_id);
  eq(ev.status, 200, 'D22 · ★ the settlement receipt is fetchable from /evidence, unauthenticated like every other receipt');
  eq(ev.body.self_check, 'ok', 'D23 · …and verifies against the published key');
  const jwks = (await get('/.well-known/jwks.json')).body;
  const vv = receipt.verify(Buffer.from(ev.body.cose_base64, 'base64'), jwks);
  ok(vv.ok, 'D24 · an offline verifier accepts it');
  eq(vv.payload.rail_tx_id, '0xdeadbeef', 'D25 · the reported tx id is INSIDE the signed bytes');
  eq(vv.payload.cosmos_schema, 4, 'D26 · schema 4');
  ok(vv.payload.checks.some((c) => c.name === 'Rail outcome observed by Cosmos' && c.pass === false),
     'D27 · ★★ the receipt itself says Cosmos did NOT observe the outcome — a signed claim that names its own limit');
  eq((await get('/evidence/' + a1.authorization_id)).status, 200,
     'D28 · ★★ the ALLOW receipt is STILL fetchable — the settlement did not shadow its parent');

  const again = await asRail('/settlements/' + a1.authorization_id, { outcome: 'settled', tx_id: '0xdeadbeef' }, a1.rail.handoff_token);
  eq(again.body.idempotent_replay, true, 'D29 · the same terminal report replays rather than signing a second receipt');
  eq(again.body.receipt_id, rep.body.receipt_id, 'D30 · …and returns the original receipt id');
  const contra = await asRail('/settlements/' + a1.authorization_id, { outcome: 'failed' }, a1.rail.handoff_token);
  eq(contra.body.error, 'ALREADY_REPORTED', 'D31 · ★★ a CONTRADICTING report is refused — Cosmos cannot adjudicate which rail is honest, so it signs neither');

  // the operator as a second, weaker credential class
  const a3 = (await authorize(1000, 'd-3')).body;
  const opRep = await post('/settlements/' + a3.authorization_id, { outcome: 'settled', tx_id: '0xop' }, OPTOKEN);
  eq(opRep.status, 200, 'D32 · the operator token is accepted as a second credential class');
  eq(opRep.body.rail_reported_by, 'operator', 'D33 · ★★ …and the receipt says so, because "an operator asserted this" and "the rail asserted this" are different facts');

  // failed → the budget comes back NOW
  const a4 = (await authorize(2000, 'd-4')).body;
  const spentBefore = (await get('/audit', OPTOKEN)).body.agents[grant.grant_id].spent;
  const failRep = await asRail('/settlements/' + a4.authorization_id, { outcome: 'failed', provider: 'writ' }, a4.rail.handoff_token);
  eq(failRep.body.rail_outcome, 'failed', 'D34 · a failure can be reported');
  const spentAfter = (await get('/audit', OPTOKEN)).body.agents[grant.grant_id].spent;
  eq(spentBefore - spentAfter, 2000, 'D35 · ★★ a reported failure returns the budget IMMEDIATELY — no five-minute hold on money that provably did not move');

  // submitted → extends, and is deliberately not idempotent
  const a5 = (await authorize(1500, 'd-5')).body;
  const sub1 = await post('/settlements/' + a5.authorization_id, { outcome: 'submitted', tx_id: '0xpending' }, a5.rail.handoff_token);
  eq(sub1.body.rail_outcome, 'submitted', 'D36 · in-flight can be reported');
  ok(sub1.body.reservation_deadline > a5.expires_at, 'D37 · ★★ …and it pushes the reservation deadline PAST the original TTL');
  const sub2 = await post('/settlements/' + a5.authorization_id, { outcome: 'submitted', tx_id: '0xpending' }, a5.rail.handoff_token);
  ok(sub2.body.receipt_id !== sub1.body.receipt_id, 'D38 · ★ a second in-flight report is a NEW fact with its own receipt, not an idempotent replay');
  const fin = await asRail('/settlements/' + a5.authorization_id, { outcome: 'settled', tx_id: '0xpending' }, a5.rail.handoff_token);
  eq(fin.body.rail_outcome, 'settled', 'D39 · …and submitted → settled is a legal transition');

  // ── §F · the two folds still agree ──────────────────────────────────────────────────────────────────
  console.log('\n§F · replay vs live after a rail conversation');
  {
    const v = replayMod.verify(h.store.events(), h.store.live());
    ok(v.ok, 'F1 · ★★ `audit:ledger`\'s check still passes — the incremental projection and the pure fold agree after submission/settlement/reversal');
    const r = replayMod.replay(h.store.events()).authorizations[a1.authorization_id];
    eq(r.txId, '0xdeadbeef', 'F2 · ★ replay.js\'s `settlement` fold is finally reached — the dormant slot is wired');
    eq(replayMod.replay(h.store.events()).authorizations[a5.authorization_id].txId, '0xpending', 'F3 · …and so is `submission`');
  }

  // ── §I · the secret never becomes durable ───────────────────────────────────────────────────────────
  console.log('\n§I · what a leaked backup would contain');
  {
    const raw = fs.readFileSync(logFile('d'), 'utf8');
    ok(!raw.includes(a1.rail.handoff_token), 'I1 · ★★ the raw capability appears NOWHERE in the event log — a leaked backup cannot forge a settlement');
    ok(raw.includes('railTokenHash'), 'I2 · …only its hash does');
    ok(!raw.includes(OPTOKEN), 'I3 · and the operator token is not written either');
    ok(!JSON.stringify(vv.payload).includes(a1.rail.handoff_token), 'I4 · nor is it inside the signed receipt');
    ok(!JSON.stringify((await get('/audit', OPTOKEN)).body).includes(a1.rail.handoff_token), 'I5 · nor in /audit');
  }

  // ── §G · restart ────────────────────────────────────────────────────────────────────────────────────
  console.log('\n§G · nothing but the log survives a restart');
  await close(h);
  h = await listen({ file: logFile('d'), writeToken: OPTOKEN, rail: { provider: 'writ', token: RAILTOKEN } });
  {
    const after = await asRail('/settlements/' + a1.authorization_id, { outcome: 'settled', tx_id: '0xdeadbeef' }, a1.rail.handoff_token);
    eq(after.body.idempotent_replay, true, 'G1 · ★★ a terminal report still replays after a restart — the answer is rebuilt from the log, not from memory');
    eq(after.body.receipt_id, rep.body.receipt_id, 'G2 · …and still names the original receipt');
    eq((await asRail('/settlements/' + a1.authorization_id, { outcome: 'failed' }, a1.rail.handoff_token)).body.error, 'ALREADY_REPORTED',
       'G3 · ★ terminality survives too — a restart is not a second chance to contradict');
    const replayAuth = (await authorize(1000, 'd-1')).body;
    eq(replayAuth.idempotent_replay, true, 'G4 · the original ALLOW replays');
    eq(replayAuth.rail, null,
       'G5 · ★★ …but WITHOUT a usable capability, and that is the deliberate cost of storing only the hash: a token Cosmos can re-serve is a token an attacker holding the log can mint');
  }

  // ── §N · a payment that spans a restart ─────────────────────────────────────────────────────────────
  // §G restarts around a TERMINAL report, where the answer is already written down. The harder case is a
  // payment caught IN FLIGHT: `submitted` extends a deadline that lives only in an event, and the capability
  // hash that authorises the follow-up lives only in the reservation. If either failed to survive a reboot,
  // a real rail would come back to finish a payment and be told it was never authorised — and the TTL would
  // then reverse a spend that actually completed. Nothing in §G covers that, because §G never restarts with
  // work outstanding.
  console.log('\n§N · submitted → restart → settled');
  {
    let nh = await listen({ file: logFile('n'), writeToken: OPTOKEN, rail: { provider: 'writ', token: RAILTOKEN } });
    const NB = () => 'http://localhost:' + nh.port;
    const NP = (path, o, hdrs) => fetch(NB() + path, {
      method: 'POST', headers: Object.assign({ 'content-type': 'application/json' }, hdrs || {}), body: JSON.stringify(o || {}),
    }).then(async (r) => ({ status: r.status, body: await r.json() }));
    const NG = (path, tok) => fetch(NB() + path, { headers: tok ? { authorization: 'Bearer ' + tok } : {} }).then((r) => r.json());

    const ng = (await NP('/grants', { org_id: 'o', agent_id: 'a', currency: 'USD', budget_minor: 20000,
      per_payment_cap_minor: 9000, daily_cap_minor: 19000, allowed_categories: ['api'] }, { authorization: 'Bearer ' + OPTOKEN })).body;
    const n1 = (await NP('/authorize', { grant_id: ng.grant_id, amount_minor: 4000, currency: 'USD', category: 'api', idempotency_key: 'n-1' })).body;
    const railHdrs = { authorization: 'Bearer ' + RAILTOKEN, 'x-cosmos-handoff': n1.rail.handoff_token };

    const nsub = await NP('/settlements/' + n1.authorization_id, { outcome: 'submitted', tx_id: '0xinflight' }, railHdrs);
    eq(nsub.body.rail_outcome, 'submitted', 'N1 · the rail reports in-flight');
    const extended = nsub.body.reservation_deadline;

    await close(nh);
    nh = await listen({ file: logFile('n'), writeToken: OPTOKEN, rail: { provider: 'writ', token: RAILTOKEN } });

    eq(rail.railState(nh.store.events(), n1.authorization_id).deadline, extended,
       'N2 · ★★ the EXTENDED deadline survives the restart — it lives in an event, not in memory, so a slow payment is not reverted by a reboot');
    eq(expiredReservations(nh.store.events(), ng.grant_id, extended - 1).length, 0,
       'N3 · ★ and the restarted process still honours it rather than falling back to the original TTL');

    const nfin = await NP('/settlements/' + n1.authorization_id, { outcome: 'settled', tx_id: '0xinflight' }, railHdrs);
    eq(nfin.status, 200,
       'N4 · ★★★ the SAME capability still works after the restart — the hash is in the reservation event, so a rail that comes back to finish a payment is not told it was never authorised');
    eq(nfin.body.rail_outcome, 'settled', 'N5 · …and the payment completes');
    eq(nfin.body.rail_late, false, 'N6 · ★ not late: the extension held across the reboot, so nothing reversed underneath it');
    eq((await NG('/audit', OPTOKEN)).agents[ng.grant_id].spent, 4000, 'N7 · the spend stands, exactly once');
    eq(expiredReservations(nh.store.events(), ng.grant_id, Date.now() + 1e9).length, 0,
       'N8 · ★★ and a settled row is out of the sweep forever, even across the restart that created it');
    await close(nh);
  }
  await close(h);

  // ── §E · the late settlement — the second design question ───────────────────────────────────────────
  console.log('\n§E · a settlement that arrives after the TTL already reversed');
  {
    const late = await listen({ file: logFile('e'), writeToken: OPTOKEN, reservationTtlMs: 1, rail: { token: RAILTOKEN } });
    const P = (p, o, tok) => fetch('http://localhost:' + late.port + p, {
      method: 'POST', headers: Object.assign({ 'content-type': 'application/json' }, tok ? { authorization: 'Bearer ' + tok } : {}),
      body: JSON.stringify(o || {}),
    }).then(async (r) => ({ status: r.status, body: await r.json() }));
    const G = (p, tok) => fetch('http://localhost:' + late.port + p, { headers: tok ? { authorization: 'Bearer ' + tok } : {} }).then((r) => r.json());
    const PR = (p, o, handoff) => fetch('http://localhost:' + late.port + p, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + RAILTOKEN, 'x-cosmos-handoff': handoff },
      body: JSON.stringify(o),
    }).then(async (r) => ({ status: r.status, body: await r.json() }));

    const g = (await P('/grants', { org_id: 'o', agent_id: 'a', currency: 'USD', budget_minor: 10000,
      per_payment_cap_minor: 5000, daily_cap_minor: 9000, allowed_categories: ['api'] }, OPTOKEN)).body;
    const auth = (p, k) => P('/authorize', { grant_id: g.grant_id, amount_minor: p, currency: 'USD', category: 'api', idempotency_key: k });

    const e1 = (await auth(3000, 'e-1')).body;
    eq(e1.decision, 'ALLOW', 'E1 · an ALLOW with a 1 ms reservation TTL');
    await sleep(20);
    await auth(100, 'e-2');                                   // any next call for this grant runs the sweep
    const spentAfterSweep = (await G('/audit', OPTOKEN)).agents[g.grant_id].spent;
    eq(spentAfterSweep, 100, 'E2 · the TTL reversed it — 3000 handed back, only the second spend stands');

    const lateRep = await PR('/settlements/' + e1.authorization_id, { outcome: 'settled', tx_id: '0xslow' }, e1.rail.handoff_token);
    eq(lateRep.status, 200, 'E3 · ★ a late settlement is ACCEPTED, not dropped — the money moved and the record has to say so');
    eq(lateRep.body.rail_late, true, 'E4 · ★★ …and is marked LATE rather than passed off as ordinary');
    eq(lateRep.body.re_reserved, true, 'E5 · …and the spend is re-reserved');
    eq((await G('/audit', OPTOKEN)).agents[g.grant_id].spent, 3100,
       'E6 · ★★ the budget is corrected: the TTL guessed wrong, so the reversal it made is undone by APPENDING, never by rewriting history');
    const lev = await G('/evidence/' + lateRep.body.receipt_id);
    const lv = receipt.verify(Buffer.from(lev.cose_base64, 'base64'), (await G('/.well-known/jwks.json')));
    eq(lv.payload.rail_late, true, 'E7 · ★ `rail_late` is in the SIGNED bytes — an auditor sees the TTL was wrong without being told');
    // The reversal itself is still in the log. That is the point of append-only: the mistake is visible.
    const evs = late.store.events().filter((e) => e.authId === e1.authorization_id);
    ok(evs.some((e) => e.kind === 'reversal' && e.reason === 'RESERVATION_EXPIRED') &&
       evs.some((e) => e.kind === 'reservation' && e.reason === 'LATE_SETTLEMENT'),
       'E8 · ★★ BOTH events survive — history shows the wrong guess AND its correction, rather than hiding one');
    eq(expiredReservations(late.store.events(), g.grant_id, Date.now() + 1e9).filter((r) => r.authId === e1.authorization_id).length, 0,
       'E9 · ★★ and the re-reserved row can never be swept again — a settled spend is not TTL\'d twice');
    // ⚠ THE DOUBLE-CREDIT CASE. A `failed` report arriving after the TTL already reversed must NOT
    // reverse a second time: the budget would be credited twice for one payment, which is the same class
    // of defect as a double-spend and points the other way. Written because the mutation spec needed a
    // test for it and there was none — the suite could not see it.
    const e3 = (await auth(2000, 'e-3')).body;
    await sleep(20);
    await auth(50, 'e-4');                                    // sweep
    const beforeFail = (await G('/audit', OPTOKEN)).agents[g.grant_id].spent;
    const lateFail = await PR('/settlements/' + e3.authorization_id, { outcome: 'failed' }, e3.rail.handoff_token);
    eq(lateFail.status, 200, 'E10 · a failure reported after the TTL already reversed is still accepted');
    eq((await G('/audit', OPTOKEN)).agents[g.grant_id].spent, beforeFail,
       'E11 · ★★ …but credits NOTHING a second time — the TTL already gave that budget back, and crediting it twice is a double-spend pointing the other way');
    await close(late);
  }

  // ── §H · no environment surface (the PR #15 rule, applied before it can be broken) ───────────────────
  console.log('\n§H · configuration arrives as arguments, never resolved in the module');
  {
    const railSrc = fs.readFileSync(path.join(__dirname, '..', 'core', 'rail.js'), 'utf8');
    ok(!/process\.env/.test(railSrc), 'H1 · ★★ core/rail.js reads NO environment at all — the exact shape that let Cosmos sign with Writ\'s key');
    const settleSrc = fs.readFileSync(path.join(__dirname, '..', 'api', 'settlements.js'), 'utf8');
    ok(!/process\.env/.test(settleSrc), 'H2 · api/settlements.js reads none either');
    const dirs = ['core', 'api', 'mcp', 'x402'];
    let writHits = 0;
    for (const d of dirs) {
      const p = path.join(__dirname, '..', d);
      if (!fs.existsSync(p)) continue;
      for (const f of fs.readdirSync(p).filter((f) => f.endsWith('.js'))) {
        const src = fs.readFileSync(path.join(p, f), 'utf8');
        writHits += (src.match(/process\.env\.WRIT_[A-Z_]*/g) || []).length;
      }
    }
    eq(writHits, 0, 'H3 · ★★ no product module reads a WRIT_* variable — Cosmos cannot inherit Writ\'s configuration by omission');
    // A rail hint is Cosmos's own configuration. Pin that it is namespaced, so the next fork cannot make
    // it fall back to a sibling's by renaming a prefix.
    const srvSrc = fs.readFileSync(path.join(__dirname, '..', 'api', 'server.js'), 'utf8');
    const railEnv = srvSrc.match(/process\.env\.[A-Z_]*RAIL[A-Z_]*/g) || [];
    // Namespacing is the property, not the count — a count assertion just breaks every time a variable is
    // added, which teaches the next person to loosen it rather than to check it.
    ok(railEnv.length >= 4 && railEnv.every((v) => v.startsWith('process.env.COSMOS_')),
       'H4 · ★ every rail variable is COSMOS_-namespaced: ' + railEnv.join(', '));
  }

  // ── §K · THE SELF-SETTLE ATTACK — the review finding, and it was real ───────────────────────────────
  // The handoff capability is returned in the /authorize RESPONSE, i.e. to the REQUESTER: the one party
  // with a motive to lie about whether money moved. The reviewer named `settled`. The severe direction is
  // `failed`, and these assertions exist to make the difference impossible to forget.
  console.log('\n§K · a requester holding its own ALLOW cannot end its own payment');
  {
    const k = await listen({ file: logFile('k'), writeToken: OPTOKEN, rail: { provider: 'writ', token: RAILTOKEN } });
    const KB = 'http://localhost:' + k.port;
    const KP = (path, o, hdrs) => fetch(KB + path, {
      method: 'POST', headers: Object.assign({ 'content-type': 'application/json' }, hdrs || {}), body: JSON.stringify(o || {}),
    }).then(async (r) => ({ status: r.status, body: await r.json() }));
    const KG = (path, tok) => fetch(KB + path, { headers: tok ? { authorization: 'Bearer ' + tok } : {} }).then((r) => r.json());
    const kg = (await KP('/grants', { org_id: 'o', agent_id: 'a', currency: 'USD', budget_minor: 100000,
      per_payment_cap_minor: 9000, daily_cap_minor: 90000, allowed_categories: ['api'] }, { authorization: 'Bearer ' + OPTOKEN })).body;
    const kauth = (n, key) => KP('/authorize', { grant_id: kg.grant_id, amount_minor: n, currency: 'USD', category: 'api', idempotency_key: key });

    const v1 = (await kauth(1000, 'k-1')).body;
    const cap = { authorization: 'Bearer ' + v1.rail.handoff_token };

    // ★★★ THE ONE THAT MATTERS. An agent spends $10 for real, reports `failed`, gets the budget back and
    // spends the same $10 again — an unbounded double-spend with a credential Cosmos handed it.
    const spentBefore = (await KG('/audit', OPTOKEN)).agents[kg.grant_id].spent;
    const selfFail = await KP('/settlements/' + v1.authorization_id, { outcome: 'failed' }, cap);
    eq(selfFail.status, 403, 'K1 · ★★★ the ALLOW holder CANNOT report `failed` on its own authorization');
    eq(selfFail.body.error, 'REPORTER_MAY_NOT_FAILED', 'K2 · …and the refusal names the class and the outcome, not just "no"');
    eq((await KG('/audit', OPTOKEN)).agents[kg.grant_id].spent, spentBefore,
       'K3 · ★★★ the budget did NOT come back — this is the double-spend the capability alone would have bought');

    eq((await KP('/settlements/' + v1.authorization_id, { outcome: 'settled', tx_id: '0xlie' }, cap)).status, 403,
       'K4 · ★★ nor `settled` — a requester may not certify its own payment either');
    eq((await KP('/settlements/' + v1.authorization_id, { outcome: 'submitted', tx_id: '0xip' }, cap)).status, 200,
       'K5 · ★ but it MAY report `submitted`: that only extends its own reservation, so it is self-limiting');

    // The rail's own token is not enough on its own — it must also hold what it was actually handed.
    eq((await KP('/settlements/' + v1.authorization_id, { outcome: 'settled', tx_id: '0x1' },
        { authorization: 'Bearer ' + RAILTOKEN })).status, 401,
       'K6 · ★★ the rail token WITHOUT x-cosmos-handoff is refused — a compromised rail cannot settle authorizations it was never given');
    const v2 = (await kauth(1000, 'k-2')).body;
    eq((await KP('/settlements/' + v1.authorization_id, { outcome: 'settled', tx_id: '0x1' },
        { authorization: 'Bearer ' + RAILTOKEN, 'x-cosmos-handoff': v2.rail.handoff_token })).status, 401,
       'K7 · ★★ …and the rail token with ANOTHER authorization\'s handoff is refused too');
    eq((await KP('/settlements/' + v1.authorization_id, { outcome: 'settled', tx_id: '0xok' },
        { authorization: 'Bearer ' + RAILTOKEN, 'x-cosmos-handoff': v1.rail.handoff_token })).body.rail_reported_by, 'rail',
       'K8 · both together are accepted, and recorded as the `rail` class');
    eq((await KP('/settlements/' + v2.authorization_id, { outcome: 'settled', tx_id: '0xop' },
        { authorization: 'Bearer ' + OPTOKEN })).body.rail_reported_by, 'operator',
       'K9 · the operator may still record a SETTLEMENT — that can only fix or increase recorded spend, so manual reconciliation stays possible');
    // ⛔ …but not the other direction. Every defect in this file has pointed the same way: returning budget
    // is what buys a double-spend. The operator can mint a NEW grant and has no route that credits an
    // EXISTING one, so letting it report `failed` would hand it a power it does not otherwise have.
    const v4 = (await kauth(1000, 'k-4')).body;
    const opFail = await KP('/settlements/' + v4.authorization_id, { outcome: 'failed' }, { authorization: 'Bearer ' + OPTOKEN });
    eq(opFail.status, 403, 'K9a · ★★★ NOT EVEN THE OPERATOR may report `failed` — only the rail, or the TTL, may give budget back');
    eq(opFail.body.error, 'REPORTER_MAY_NOT_FAILED', 'K9b · …and the refusal says which class and which outcome');
    eq((await KP('/settlements/' + v4.authorization_id, { outcome: 'submitted' },
        { authorization: 'Bearer ' + v4.rail.handoff_token })).body.rail_reported_by, 'allow_holder',
       'K9c · ★ the weakest class is named `allow_holder` — for WHO HOLDS IT, because that was the whole defect; `capability` described the mechanism and hid the holder');
    await close(k);

    // ⛔ FAIL CLOSED. With no rail token and no operator token, nothing may end a payment. This is the
    // configuration a demo runs in, and it is exactly where an open settlement path would be worst.
    const open_ = await listen({ file: logFile('k2'), allowUnauthenticatedWrites: true, rail: { provider: 'writ' } });
    const OB = 'http://localhost:' + open_.port;
    const OP = (path, o, hdrs) => fetch(OB + path, {
      method: 'POST', headers: Object.assign({ 'content-type': 'application/json' }, hdrs || {}), body: JSON.stringify(o || {}),
    }).then(async (r) => ({ status: r.status, body: await r.json() }));
    const og = (await OP('/grants', { org_id: 'o', agent_id: 'a', currency: 'USD', budget_minor: 50000,
      per_payment_cap_minor: 9000, daily_cap_minor: 40000, allowed_categories: ['api'] })).body;
    const ov = (await OP('/authorize', { grant_id: og.grant_id, amount_minor: 1000, currency: 'USD', category: 'api', idempotency_key: 'o-1' })).body;
    const ocap = { authorization: 'Bearer ' + ov.rail.handoff_token };
    eq((await OP('/settlements/' + ov.authorization_id, { outcome: 'settled', tx_id: '0x' }, ocap)).status, 403,
       'K10 · ★★ with writes explicitly OPEN and no rail token, a terminal report is still refused — the open-mint choice does not open this path');
    eq((await OP('/settlements/' + ov.authorization_id, { outcome: 'submitted' }, ocap)).status, 200,
       'K11 · …and `submitted` still works, so the fallback is intact rather than broken');
    await close(open_);

    let boom = null;
    try { await listen({ file: logFile('k3'), writeToken: OPTOKEN, rail: { token: 'short' } }); }
    catch (e) { boom = String(e.message); }
    ok(boom && /RAIL_TOKEN_TOO_SHORT/.test(boom), 'K12 · ★ a guessable rail token refuses to boot, the same shape as the write token');
  }

  // ── §L · GRANT_OVERRUN — the second half of the review finding on late settlements ───────────────────
  // Recording money that moved is right; it must not also raise the ceiling. guardrails already refuses
  // every further spend once `spent > budget` (remaining goes negative), so behaviour does not change —
  // what changes is the NAME. `INSUFFICIENT_BALANCE` tells a reader to ask for less; at negative remaining
  // no amount works, and the grant needs an operator rather than a smaller request.
  console.log('\n§L · a grant pushed past its budget by a late settlement');
  {
    const l = await listen({ file: logFile('l'), writeToken: OPTOKEN, reservationTtlMs: 1, rail: { token: RAILTOKEN } });
    const LB = 'http://localhost:' + l.port;
    const LP = (path, o, hdrs) => fetch(LB + path, {
      method: 'POST', headers: Object.assign({ 'content-type': 'application/json' }, hdrs || {}), body: JSON.stringify(o || {}),
    }).then(async (r) => ({ status: r.status, body: await r.json() }));
    const LG = (path, tok) => fetch(LB + path, { headers: tok ? { authorization: 'Bearer ' + tok } : {} }).then((r) => r.json());
    const lg = (await LP('/grants', { org_id: 'o', agent_id: 'a', currency: 'USD', budget_minor: 5000,
      per_payment_cap_minor: 5000, daily_cap_minor: 50000, allowed_categories: ['api'] }, { authorization: 'Bearer ' + OPTOKEN })).body;
    const lauth = (n, key) => LP('/authorize', { grant_id: lg.grant_id, amount_minor: n, currency: 'USD', category: 'api', idempotency_key: key });

    const first = (await lauth(5000, 'l-1')).body;
    eq(first.decision, 'ALLOW', 'L1 · the whole budget is authorized once');
    await sleep(20);
    const second = (await lauth(5000, 'l-2')).body;      // the sweep reverses the first, so this fits
    eq(second.decision, 'ALLOW', 'L2 · the TTL reversed it, so a second identical spend fits');

    const lateSettle = await LP('/settlements/' + first.authorization_id, { outcome: 'settled', tx_id: '0xreal' },
      { authorization: 'Bearer ' + RAILTOKEN, 'x-cosmos-handoff': first.rail.handoff_token });
    eq(lateSettle.body.rail_late, true, 'L3 · …but the FIRST payment really did settle, late');
    // ⚠ THE SECOND ONE MUST BE SETTLED TOO, and finding that out corrected an assumption rather than a bug.
    // The sweep runs at the head of every /authorize, so without this the next call would reverse the
    // still-open second reservation and land the grant exactly AT its budget, not over it. Overrun is a
    // narrower state than it first looks: it needs real, settled spend on both sides.
    await LP('/settlements/' + second.authorization_id, { outcome: 'settled', tx_id: '0xreal2' },
      { authorization: 'Bearer ' + RAILTOKEN, 'x-cosmos-handoff': second.rail.handoff_token });
    eq((await LG('/audit', OPTOKEN)).agents[lg.grant_id].spent, 10000,
       'L4 · ★★ so the grant now carries 10000 of real spend against a 5000 budget — recorded, because the money moved');

    const after = (await lauth(1, 'l-3')).body;
    eq(after.decision, 'DENY', 'L5 · ★★ every further spend is refused — the overrun does NOT raise the ceiling');
    eq(after.reason, 'GRANT_OVERRUN',
       'L6 · ★★ …and the reason is GRANT_OVERRUN, not INSUFFICIENT_BALANCE: at negative remaining no smaller amount works, so a code that says "ask for less" sends the reader down a path with no end');
    ok((after.checks || []).some((c) => c.name === 'Grant not in overrun' && c.pass === false),
       'L7 · ★ the failing check is named inside the signed receipt, not only in the reason string');
    // BOUNDARY, decided from the spec before reading the code back: spent EQUAL to budget is spent-out,
    // not overrun. The grant did exactly what it was told to; the money is simply gone. Overrun means
    // something recorded MORE than the grant ever permitted, and that is strictly greater.
    const atBudget = { status: 'active', expiry: null, budget: 5000, spent: 5000, spentToday: 0,
                       perPaymentCap: 1000, dailyCap: 10000, allowedCategories: ['api'], freeRein: false };
    const gm = { grant_id: 'g', currency: 'USD', per_payment_cap_minor: 1000, daily_cap_minor: 10000,
                 allowed_categories: ['api'], expires_at: null, status: 'active', free_rein: false };
    eq(view.decide(gm, atBudget, 1, 'USD', 'api').reason, 'INSUFFICIENT_BALANCE',
       'L8 · ★★ EXACTLY at budget is spent-out, NOT overrun — the grant did what it was told and the money is gone');
    eq(view.decide(gm, Object.assign({}, atBudget, { spent: 5001 }), 1, 'USD', 'api').reason, 'GRANT_OVERRUN',
       'L9 · ★★ one minor unit PAST budget is overrun — something recorded more than the grant ever permitted');
    await close(l);
  }

  // ── §M · WHAT A VERIFIER ACCEPTS vs WHAT AN ISSUER WRITES ───────────────────────────────────────────
  // Bumping SCHEMA protects a reader in ONE direction: an OLD verifier must refuse a NEW receipt, which it
  // does automatically because it hardcodes its own number. The other direction is a pure loss — a
  // schema-2 receipt has no rail_* fields, so there is nothing a current verifier could print without its
  // caveat, and refusing it would make every receipt already in an audit file unverifiable.
  console.log('\n§M · a receipt issued before the bump still verifies');
  {
    const { makeKeystore } = require('../core/receipt-keystore');
    const cose = require('../core/cose');
    const ks = makeKeystore({ kid: 'schema-compat-test', allowDevKey: true });
    const jw = ks.jwks();

    // A genuine schema-2 payload: exactly what buildPayload produced before the rail fields existed.
    const v3 = receipt.buildPayload({
      decision: 'DENY', reason: 'PER_PAYMENT_LIMIT', authorization_id: 'auth_' + '9'.repeat(20),
      org_id: 'o', grant_id: 'g', agent_id: 'a', amount_minor: 3000, currency: 'USD',
      intent_hash: 'x', envelope_hash: 'y', policy_version: 1, policy_hash: 'z', capability_root: 'r',
      checks: [{ name: 'Under per-payment cap', pass: false }], idempotency_key: 'k', decided_at: 1,
    });
    const legacy = {};
    for (const key of Object.keys(v3)) if (!/^rail_/.test(key)) legacy[key] = v3[key];
    legacy.cosmos_schema = 2;

    const bytes2 = cose.sign1(legacy, ks.activeKid(), (b) => ks.signBytes(b));
    const r2 = receipt.verify(bytes2, jw);
    ok(r2.ok, 'M1 · ★★ a schema-2 receipt STILL VERIFIES — the bump did not orphan receipts already issued');
    eq(r2.payload.decision, 'DENY', 'M2 · …and reads correctly');
    ok(!('rail_outcome' in r2.payload), 'M3 · ★ it carries no rail claim, which is exactly why accepting it is safe: there is nothing to under-report');

    const tmp = path.join(TMP, 'legacy2.json');
    fs.writeFileSync(tmp, JSON.stringify({ cose_base64: bytes2.toString('base64') }));
    const jwf = path.join(TMP, 'legacy-jwks.json');
    fs.writeFileSync(jwf, JSON.stringify(jw));
    const PYBIN = (() => {
      for (const c of [process.env.COSMOS_PYTHON, 'python3', 'python'].filter(Boolean)) {
        if (require('child_process').spawnSync(c, ['--version'], { encoding: 'utf8' }).status === 0) return c;
      }
      return 'python3';
    })();
    const pr = require('child_process').spawnSync(PYBIN,
      [path.join(__dirname, '..', 'verifier', 'cosmos_verify.py'), tmp, jwf],
      { encoding: 'utf8', env: Object.assign({}, process.env, { PYTHONIOENCODING: 'ascii' }) });
    eq(pr.status, 0, 'M4 · ★★ …and the PYTHON verifier a stranger actually runs accepts it too');

    // The set is not a licence to widen. An unknown schema is still refused.
    const future = Object.assign({}, legacy, { cosmos_schema: 99 });
    const b99 = cose.sign1(future, ks.activeKid(), (b) => ks.signBytes(b));
    eq(receipt.verify(b99, jw).reason, 'UNSUPPORTED_SCHEMA', 'M5 · ★ an unknown schema is still refused — ACCEPTED is a set, not "anything"');
    eq(receipt.SCHEMA, 4, 'M6 · ★ and Cosmos still ISSUES exactly one schema. Accepting many and issuing one are different questions');
  }

  // ── §P · the receipt a PHONE issued, verified here ─────────────────────────────────────
  // NOT a receipt this suite minted: these are the actual bytes a Samsung A15 produced in Termux on
  // 2026-09-08, with its network disabled, driven by curl rather than by any client in this repository
  // (docs/PHONE-RAIL-2026-09-08.md). Committed so the cross-machine claim cannot rot into a story about a
  // run nobody can repeat. The signing key was generated inside that phone process and never written to
  // disk, so the JWKS beside it is the only way to check these bytes — which is exactly the claim.
  console.log('\n§P · a receipt issued by the lab phone, verified here');
  {
    const stl = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'phone-rail-settled-2026-09-08.json'), 'utf8'));
    const jw = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'phone-rail-jwks-2026-09-08.json'), 'utf8'));
    const v = receipt.verify(Buffer.from(stl.cose_base64, 'base64'), jw);
    ok(v.ok, 'P1 · ★★★ a receipt signed on ANDROID verifies here — different OS, different CPU, no shared process');
    eq(v.payload.rail_outcome, 'settled', 'P2 · it is a settlement report');
    eq(v.payload.rail_reported_by, 'rail', 'P3 · ★★ reported by the rail class, over real HTTP, by a client this repo did not write');
    eq(v.payload.rail_tx_id, '0xphone_final', 'P4 · carrying the transaction id the reporter asserted');
    ok(/^auth_[0-9a-f]{20}$/.test(v.payload.parent_receipt_id), 'P5 · chained to the ALLOW it descends from');
    eq(v.payload.cosmos_schema, 3, 'P6 · ★★★ the phone receipt is SCHEMA 3 and still verifies under a schema-4 issuer — a REAL older receipt, not a synthetic one, proving the bump did not orphan evidence already made');
    ok(v.payload.checks.some((c) => c.name === 'Rail outcome observed by Cosmos' && c.pass === false),
       'P7 · ★★ the phone-issued bytes carry the same NOT-OBSERVED caveat — the artifact states its own limit wherever it was made');
    ok(!JSON.stringify(jw).includes('"d"'), 'P8 · ★ the committed JWKS is public key material only');
  }

  // ── §Q · PARITY WITH THE RAIL'S OWN STATE MACHINE ───────────────────────────────────
  // Measured against a real rail's engine, read-only, 2026-09-09. ⛔ The rail's full state list and the
  // complete mapping live in a parity note that is NEVER PUBLISHED — a sibling's
  // internal state machine is not ours to disclose, and this file is. What is public is the SHAPE of the
  // problem, which is all a reader needs to understand the code.
  // Cosmos has THREE outcomes because three is all its accounting needs. The mismatch is real and is the
  // point of this section: `reversed` is terminal for that rail and has no Cosmos outcome, so it arrives as
  // `failed` (right arithmetic — the money came back) carrying state `reversed` (right fact — it had
  // executed first). Anything that collapses those two into one word loses the only thing an auditor is
  // looking for, so these assertions exist to stop a future edit doing exactly that.
  console.log('\n§Q · parity with the rail\'s own vocabulary');
  {
    const q = await listen({ file: logFile('q'), writeToken: OPTOKEN, rail: { provider: 'writ', token: RAILTOKEN } });
    const QB = 'http://localhost:' + q.port;
    const QP = (path, o, hdrs) => fetch(QB + path, {
      method: 'POST', headers: Object.assign({ 'content-type': 'application/json' }, hdrs || {}), body: JSON.stringify(o || {}),
    }).then(async (r) => ({ status: r.status, body: await r.json() }));
    const QG = (path, tok) => fetch(QB + path, { headers: tok ? { authorization: 'Bearer ' + tok } : {} }).then((r) => r.json());
    const qg = (await QP('/grants', { org_id: 'o', agent_id: 'a', currency: 'USD', budget_minor: 100000,
      per_payment_cap_minor: 9000, daily_cap_minor: 90000, allowed_categories: ['api'] }, { authorization: 'Bearer ' + OPTOKEN })).body;
    const qauth = (n, key) => QP('/authorize', { grant_id: qg.grant_id, amount_minor: n, currency: 'USD', category: 'api', idempotency_key: key });
    const railHdr = (h) => ({ authorization: 'Bearer ' + RAILTOKEN, 'x-cosmos-handoff': h });

    // THE GAP, end to end: a Writ `reversed` payment.
    const r1 = (await qauth(3000, 'q-1')).body;
    const spentBefore = (await QG('/audit', OPTOKEN)).agents[qg.grant_id].spent;
    const rev = await QP('/settlements/' + r1.authorization_id, { outcome: 'failed', state: 'reversed', provider: 'writ', tx_id: '0xrev' }, railHdr(r1.rail.handoff_token));
    eq(rev.status, 200, 'Q1 · a rail state Cosmos has no outcome for is still reportable');
    eq(rev.body.rail_outcome, 'failed', 'Q2 · ★★ recorded as `failed` — the ARITHMETIC, because the money came back');
    eq(rev.body.rail_state, 'reversed', 'Q3 · ★★★ and carrying `reversed` — the FACT, because it had executed first. `failed` alone would say it never ran');
    eq((await QG('/audit', OPTOKEN)).agents[qg.grant_id].spent, spentBefore - 3000, 'Q4 · the budget came back, exactly once');
    const rj = await QG('/evidence/' + rev.body.receipt_id);
    const rv = receipt.verify(Buffer.from(rj.cose_base64, 'base64'), await QG('/.well-known/jwks.json'));
    eq(rv.payload.rail_state, 'reversed', 'Q5 · ★★ `rail_state` is INSIDE the signed bytes, not only in the HTTP reply');
    eq(rv.payload.rail_outcome, 'failed', 'Q6 · …beside the outcome it was mapped to, so a reader sees both');

    // Every non-terminal Writ in-flight state is reportable as `submitted` and keeps the money reserved.
    const r2 = (await qauth(1000, 'q-2')).body;
    const qr = await QP('/settlements/' + r2.authorization_id, { outcome: 'submitted', state: 'held_for_review', tx_id: '0xq' }, railHdr(r2.rail.handoff_token));
    eq(qr.body.rail_state, 'held_for_review', 'Q7 · ★ a non-terminal rail state — held for review, still in flight — rides on `submitted` and keeps its own word');
    ok(qr.body.reservation_deadline > r2.expires_at, 'Q8 · …and still extends the reservation, because the payment is not over');

    // A state Cosmos was never told about is carried, not rejected. Cosmos does not police a rail's words.
    const r3 = (await qauth(1000, 'q-3')).body;
    eq((await QP('/settlements/' + r3.authorization_id, { outcome: 'settled', state: 'some_future_writ_state', tx_id: '0xf' }, railHdr(r3.rail.handoff_token))).body.rail_state,
       'some_future_writ_state', 'Q9 · ★★ an UNKNOWN state is carried verbatim — a rail may add states without Cosmos shipping a release, and validating a vocabulary that is not ours would break the seam for no gain');
    // …but `outcome` IS ours, and stays closed.
    eq((await QP('/settlements/' + r3.authorization_id, { outcome: 'reversed', tx_id: '0xz' }, railHdr(r3.rail.handoff_token))).body.error, 'INVALID_OUTCOME',
       'Q10 · ★★ `reversed` is NOT a Cosmos outcome and is refused as one — the closed set stays closed; it belongs in `state`');

    // The two state machines agree where it matters most, and this is the reassuring half of the finding.
    const r4 = (await qauth(1000, 'q-4')).body;
    await QP('/settlements/' + r4.authorization_id, { outcome: 'settled', state: 'settled', tx_id: '0xs' }, railHdr(r4.rail.handoff_token));
    eq((await QP('/settlements/' + r4.authorization_id, { outcome: 'failed', state: 'reversed' }, railHdr(r4.rail.handoff_token))).body.error, 'ALREADY_REPORTED',
       'Q11 · ★★★ settled cannot later be reversed — and Writ forbids the same transition (`settled: []`, terminal is immutable). Two independently written state machines, same rule');
    ok(!('rail_state' in (await QG('/evidence/' + r1.authorization_id)).payload_unverified) ||
       (await QG('/evidence/' + r1.authorization_id)).payload_unverified.rail_state === null,
       'Q12 · ★ an ALLOW receipt carries no rail state — a decision still never implies an outcome');
    await close(q);
  }

  console.log('\nrail (handoff): ' + pass + ' passed, ' + fail + ' failed');
  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch (_) {}
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); process.exit(1); });
