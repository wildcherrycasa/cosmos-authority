// ═══ API END-TO-END — the three calls, against a real server on a real log ═════════════════════════════
//
// Day 3's acceptance criteria, frozen so day 4 cannot silently break them. Everything here was first
// proven by hand with curl; this file exists so it stays proven.
//
// Deterministic by construction: no sleeps. The TTL sweep is unit-tested against a pure function with an
// explicit `now` rather than by waiting for a clock.
'use strict';
process.env.COSMOS_RESERVATION_TTL_MS = '60000';   // long, so nothing expires mid-test

const fs = require('fs'), os = require('os'), path = require('path');
const replay = require('../core/replay');
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

const LOG = path.join(os.tmpdir(), 'cosmos-api-test-' + process.pid + '.jsonl');
try { fs.unlinkSync(LOG); } catch (_) {}

function listen(file) {
  return new Promise((resolve) => {
    const h = start({ port: 0, file, quiet: true });
    h.server.on('listening', () => resolve(Object.assign(h, { port: h.server.address().port })));
  });
}
// closeAllConnections() is required: node:http keeps fetch's keep-alive sockets open, so server.close()
// alone never fires its callback and the test hangs until the harness kills it.
const close = (h) => new Promise((r) => {
  h.store.close();
  if (h.server.closeAllConnections) h.server.closeAllConnections();
  h.server.close(() => r());
});

(async () => {
  let h = await listen(LOG);
  const B = () => 'http://localhost:' + h.port;
  const post = (p, o) => fetch(B() + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(o) })
    .then(async (r) => ({ status: r.status, body: await r.json() }));
  const get = (p) => fetch(B() + p).then(async (r) => ({ status: r.status, body: await r.json() }));

  console.log('\n── A · POST /grants ───────────────────────────────────────────────────────────────────────');
  const mk = (over) => Object.assign({
    org_id: 'o1', agent_id: 'a1', currency: 'USD', budget_minor: 50000,
    per_payment_cap_minor: 1700, daily_cap_minor: 5000, allowed_categories: ['api', 'cloud'],
    approval_threshold_minor: 1500,
  }, over || {});

  const g = await post('/grants', mk());
  eq(g.status, 201, 'A1 · a valid grant is created');
  const GID = g.body.grant_id;
  ok(/^grn_[0-9a-f]{20}$/.test(GID), 'A2 · ★ the grant id is 24 chars (replay G6 needs ≥13)');
  ok(/^[0-9a-f]{64}$/.test(g.body.capability_root), 'A3 · ★ a capability root is committed over the categories');
  ok(/^[0-9a-f]{64}$/.test(g.body.policy_hash), 'A4 · the policy is hashed');
  eq(g.body.status, 'active', 'A5 · status active');

  for (const [over, code] of [
    [{ budget_minor: 0 }, 'INVALID_BUDGET_MINOR'], [{ budget_minor: 1.5 }, 'INVALID_BUDGET_MINOR'],
    [{ currency: 'usd' }, 'INVALID_CURRENCY'], [{ currency: 'DOLLAR' }, 'INVALID_CURRENCY'],
    [{ allowed_categories: [] }, 'INVALID_ALLOWED_CATEGORIES'], [{ org_id: '' }, 'ORG_ID_REQUIRED'],
    [{ per_payment_cap_minor: -1 }, 'INVALID_PER_PAYMENT_CAP_MINOR'],
  ]) {
    const r = await post('/grants', mk(over));
    eq(r.status + ':' + r.body.error, '400:' + code, 'A · ' + JSON.stringify(over) + ' → ' + code);
  }

  console.log('\n── B · POST /authorize — the decision matrix ──────────────────────────────────────────────');
  const auth = (o) => post('/authorize', Object.assign({ grant_id: GID, currency: 'USD', category: 'api' }, o));

  let r = await auth({ amount_minor: 1200, idempotency_key: 'k1' });
  const K1_AUTH = r.body.authorization_id;          // captured for the idempotency check in §C
  eq(r.body.decision, 'ALLOW', 'B1 · ★ $12.00 within every cap → ALLOW');
  eq(r.body.signed, true, 'B2 · ★ decisions are signed (COSE_Sign1) — see test/evidence.test.js for the proof');
  ok(/^auth_[0-9a-f]{20}$/.test(r.body.authorization_id), 'B3 · ★ authorization id is 25 chars (replay G6)');
  ok(/^[0-9a-f]{64}$/.test(r.body.envelope_hash), 'B4 · ★ an envelope hash is bound to the decision');
  ok(r.body.expires_at > r.body.decided_at, 'B5 · ★ an ALLOW carries a reservation TTL');
  eq(r.body.checks[0].name, 'Currency matches grant', 'B6 · ★ the adapter check is PREPENDED to guardrails\' own');
  eq(r.body.checks.length, 7, 'B7 · 1 adapter check + 6 guardrails checks');

  r = await auth({ amount_minor: 3000, idempotency_key: 'k2' });
  eq(r.body.decision + '/' + r.body.reason, 'DENY/PER_PAYMENT_LIMIT', 'B8 · ★ over the per-payment cap → DENY');
  eq(r.status, 200, 'B9 · ★★ a DENY is HTTP 200 — a well-formed question got a real answer');
  eq(r.body.expires_at, null, 'B10 · a DENY reserves nothing');

  r = await auth({ amount_minor: 1600, idempotency_key: 'k3' });
  eq(r.body.decision + '/' + r.body.reason, 'ESCALATE/APPROVAL_REQUIRED', 'B11 · ★ over the approval line → ESCALATE');
  eq(r.body.expires_at, null, 'B12 · ★ an ESCALATE reserves nothing either');

  r = await auth({ amount_minor: 100, category: 'gambling', idempotency_key: 'k4' });
  eq(r.body.reason, 'CATEGORY_NOT_ALLOWED', 'B13 · a category outside the grant → DENY');
  r = await auth({ amount_minor: 100, currency: 'JPY', idempotency_key: 'k5' });
  eq(r.body.reason, 'CURRENCY_MISMATCH', 'B14 · ★ currency is checked — guardrails alone is currency-blind');

  for (const [amt, code] of [[0, 'INVALID_AMOUNT_MINOR'], [-5, 'INVALID_AMOUNT_MINOR'], [12.5, 'INVALID_AMOUNT_MINOR'], ['1200', 'INVALID_AMOUNT_MINOR']]) {
    const x = await auth({ amount_minor: amt, idempotency_key: 'bad-' + amt });
    eq(x.status + ':' + x.body.error, '400:' + code,
       'B · amount ' + JSON.stringify(amt) + ' → 400, NOT a decision (envelope would throw)');
  }
  eq((await auth({ amount_minor: 100 })).body.error, 'IDEMPOTENCY_KEY_REQUIRED', 'B19 · ★ the idempotency key is mandatory');
  eq((await post('/authorize', { grant_id: 'grn_nope', amount_minor: 1, currency: 'USD', idempotency_key: 'x' })).status, 404,
     'B20 · an unknown grant → 404');

  console.log('\n── C · IDEMPOTENCY (replay does not dedupe — E1) ──────────────────────────────────────────');
  const first = await auth({ amount_minor: 1200, idempotency_key: 'k1' });
  eq(first.body.idempotent_replay, true, 'C1 · ★ a repeated key is flagged as a replay');
  eq(first.body.authorization_id, K1_AUTH,
     'C2 · ★ the ORIGINAL authorization id comes back, not a new one');
  eq((await get('/audit')).body.agents[GID].spent, 1200, 'C3 · ★★ the replay did NOT reserve a second time');

  console.log('\n── D · DAILY CAP — the fold replay.js does not do (Gap 2) ────────────────────────────────');
  eq((await auth({ amount_minor: 1400, idempotency_key: 'd1' })).body.decision, 'ALLOW', 'D1 · 1200+1400 under the 5000 daily cap');
  eq((await auth({ amount_minor: 1400, idempotency_key: 'd2' })).body.decision, 'ALLOW', 'D2 · 2600+1400 still under');
  const d3 = await auth({ amount_minor: 1400, idempotency_key: 'd3' });
  eq(d3.body.decision + '/' + d3.body.reason, 'DENY/DAILY_LIMIT', 'D3 · ★★ 4000+1400 exceeds it → DENY');
  eq((await get('/audit')).body.agents[GID].spent, 4000, 'D4 · spend is exactly 1200+1400+1400');

  console.log('\n── E · CONCURRENCY — the double-spend the product exists to prevent ───────────────────────');
  const rg = (await post('/grants', mk({ agent_id: 'race', budget_minor: 5000, daily_cap_minor: 1000000, approval_threshold_minor: null }))).body;
  const burst = await Promise.all(Array.from({ length: 10 }, (_, i) =>
    post('/authorize', { grant_id: rg.grant_id, amount_minor: 1700, currency: 'USD', category: 'api', idempotency_key: 'race-' + i })));
  const allowed = burst.filter((x) => x.body.decision === 'ALLOW').length;
  eq(allowed, 2, 'E1 · ★★ 10 simultaneous $17 requests on a $50 budget → exactly 2 ALLOW');
  const racedSpent = (await get('/audit')).body.agents[rg.grant_id].spent;
  eq(racedSpent, 3400, 'E2 · ★★ spend is 3400, not 17000 — the per-grant mutex held');
  ok(racedSpent <= rg.budget_minor, 'E3 · ★★ spend never exceeded the budget');

  console.log('\n── F · AUDIT — live state vs a fresh fold of the log on disk ──────────────────────────────');
  const fromDisk = fs.readFileSync(LOG, 'utf8').split('\n').filter((s) => s.trim()).map((s) => JSON.parse(s));
  const v = replay.verify(fromDisk, (await get('/audit')).body);
  eq(v.ok, true, 'F1 · ★★ zero diffs — the incremental projection matches the fold, via two code paths');
  ok(v.diffs.length === 0, 'F2 · no drift: ' + JSON.stringify(v.diffs));
  ok(fromDisk.length > 20, 'F3 · every event reached disk (' + fromDisk.length + ' lines)');

  console.log('\n── G · RESTART SURVIVAL ───────────────────────────────────────────────────────────────────');
  const beforeSpent = (await get('/audit')).body.agents[GID].spent;
  await close(h);
  h = await listen(LOG);
  const health = (await get('/health')).body;
  eq((await get('/audit')).body.agents[GID].spent, beforeSpent, 'G1 · ★ balances reload from the log');
  ok(health.idempotency_keys > 0, 'G2 · ★ the idempotency index is rehydrated (' + health.idempotency_keys + ' keys)');
  ok(health.pending_approvals >= 1, 'G3 · ★ the pending ESCALATE survived the restart');
  const afterRestart = await auth({ amount_minor: 1200, idempotency_key: 'k1' });
  eq(afterRestart.body.idempotent_replay, true, 'G4 · ★★ a retried key after a RESTART is still a replay…');
  eq(afterRestart.body.authorization_id, K1_AUTH, 'G4b · ★ …returning the id minted before the restart');
  eq((await get('/audit')).body.agents[GID].spent, beforeSpent, 'G5 · ★★ …and still does not double-spend');

  console.log('\n── H · MALFORMED LOG LINES (replay B8: a null entry throws) ───────────────────────────────');
  await close(h);
  fs.appendFileSync(LOG, 'null\n{ not json\n[]\n\n');
  h = await listen(LOG);
  const afterJunk = (await get('/health')).body;
  eq(afterJunk.skipped_lines, 3, 'H1 · ★★ 3 malformed lines skipped — boot survives a corrupted log');
  eq((await get('/audit')).body.agents[GID].spent, beforeSpent, 'H2 · ★ balances are unaffected by the junk');

  console.log('\n── I · RESERVATION TTL SWEEP (pure, no sleeping) ──────────────────────────────────────────');
  const evs = [
    { kind: 'reservation', ts: 1000, authId: 'auth_aaaaaaaaaaaaaaaaaaaa', agentId: 'g1', amount: 500, expiresAt: 2000 },
    { kind: 'reservation', ts: 1000, authId: 'auth_bbbbbbbbbbbbbbbbbbbb', agentId: 'g1', amount: 700, expiresAt: 9000 },
    { kind: 'reservation', ts: 1000, authId: 'auth_cccccccccccccccccccc', agentId: 'g1', amount: 900, expiresAt: 2000 },
    { kind: 'reversal', ts: 1500, authId: 'auth_cccccccccccccccccccc', agentId: 'g1', amount: 900, reason: 'RECONCILED' },
  ];
  const swept = expiredReservations(evs, 'g1', 5000);
  eq(swept.length, 1, 'I1 · ★ exactly one reservation is expired at t=5000');
  eq(swept[0].authId, 'auth_aaaaaaaaaaaaaaaaaaaa', 'I2 · ★ the expired one');
  eq(swept[0].reason, 'RESERVATION_EXPIRED', 'I3 · it is reversed with a reason');
  eq(swept[0].amount, 500, 'I4 · for the full reserved amount');
  eq(expiredReservations(evs, 'g1', 1500).length, 0, 'I5 · ★ nothing expires before its TTL');
  eq(expiredReservations(evs, 'other', 99999).length, 0, 'I6 · ★ another grant\'s reservations are not touched');
  ok(swept[0].kind === 'reversal',
     'I7 · ★★ the sweep emits a REAL reversal event, not a virtual balance — that is why audit stays clean');

  console.log('\n── J · /approvals — resolving an ESCALATE (the fourth route) ──────────────────────────────');
  const jg = (await post('/grants', mk({ agent_id: 'a-j', budget_minor: 10000, daily_cap_minor: 100000 }))).body;
  const jauth = (o) => post('/authorize', Object.assign({ grant_id: jg.grant_id, currency: 'USD', category: 'api' }, o));
  const esc = (await jauth({ amount_minor: 1600, idempotency_key: 'j1' })).body;
  eq(esc.decision, 'ESCALATE', 'J1 · $16 escalates');
  eq((await get('/audit')).body.agents[jg.grant_id].spent, 0, 'J2 · ★ an ESCALATE reserves nothing');
  ok((await get('/approvals')).body.pending.some((p) => p.authorization_id === esc.authorization_id), 'J3 · ★ it is listed as pending');

  let ap = await post('/approvals/' + esc.authorization_id, { decision: 'approve', approver_id: 'a-j' });
  eq(ap.status + ':' + ap.body.error, '400:APPROVER_EQUALS_REQUESTER', 'J4 · ★★ the agent may not approve its own spend');
  ap = await post('/approvals/' + esc.authorization_id, { decision: 'maybe', approver_id: 'ops' });
  eq(ap.body.error, 'INVALID_DECISION', 'J5 · decision must be approve|deny');
  ap = await post('/approvals/auth_00000000000000000000', { decision: 'approve', approver_id: 'ops' });
  eq(ap.status + ':' + ap.body.error, '404:APPROVAL_NOT_PENDING', 'J6 · an unknown id is not pending');

  ap = await post('/approvals/' + esc.authorization_id, { decision: 'approve', approver_id: 'ops-1', channel: 'test' });
  eq(ap.status + ':' + ap.body.decision + '/' + ap.body.reason, '200:ALLOW/APPROVED_BY_HUMAN', 'J7 · ★★ a human approval → ALLOW / APPROVED_BY_HUMAN');
  eq(ap.body.parent_receipt_id, esc.authorization_id, 'J8 · ★★ the resolution receipt points at the ESCALATE receipt');
  eq(ap.body.approver_id + '/' + ap.body.approval_channel, 'ops-1/test', 'J9 · approver and channel are recorded');
  eq(ap.body.signed, true, 'J10 · ★ it is a signed receipt in its own right');
  ok(ap.body.checks[0].name === 'Approver decision' && ap.body.checks[0].pass === true, 'J11 · ★ the approver decision is the first named check');
  eq((await get('/audit')).body.agents[jg.grant_id].spent, 1600, 'J12 · ★★ approving RESERVES the budget');
  ap = await post('/approvals/' + esc.authorization_id, { decision: 'approve', approver_id: 'ops-1' });
  eq(ap.status + ':' + ap.body.error, '404:APPROVAL_NOT_PENDING', 'J13 · ★★ one-shot: a second approval is refused — no double-spend by double-approve');
  ok(!(await get('/approvals')).body.pending.some((p) => p.authorization_id === esc.authorization_id), 'J14 · it is no longer pending');

  const esc2 = (await jauth({ amount_minor: 1600, idempotency_key: 'j2' })).body;
  ap = await post('/approvals/' + esc2.authorization_id, { decision: 'deny', approver_id: 'ops-1' });
  eq(ap.body.decision + '/' + ap.body.reason, 'DENY/DENIED_BY_APPROVER', 'J15 · ★ a human denial → signed DENY / DENIED_BY_APPROVER');
  eq((await get('/audit')).body.agents[jg.grant_id].spent, 1600, 'J16 · ★ a denial reserves nothing');

  // Approval does NOT override policy. Escalate while the budget fits, DRAIN the budget, then approve.
  const esc3 = (await jauth({ amount_minor: 1600, idempotency_key: 'j3' })).body;
  eq(esc3.decision, 'ESCALATE', 'J17 · escalates while 8400 remains');
  for (let i = 0; i < 5; i++) eq((await jauth({ amount_minor: 1500, idempotency_key: 'drain-' + i })).body.decision, 'ALLOW', 'J17.' + i + ' · drain 1500 (under the approval line)');
  eq((await get('/audit')).body.agents[jg.grant_id].spent, 9100, 'J17.x · 900 remains');
  ap = await post('/approvals/' + esc3.authorization_id, { decision: 'approve', approver_id: 'ops-1' });
  eq(ap.body.decision + '/' + ap.body.reason, 'DENY/INSUFFICIENT_BALANCE', 'J18 · ★★ approved by a human, STILL refused by policy — the receipt records both');
  ok(ap.body.checks[0].pass === true && ap.body.checks.some((c) => c.name === 'Sufficient balance' && !c.pass), 'J18b · ★ checks show approver=pass AND balance=fail, side by side');
  eq((await get('/audit')).body.agents[jg.grant_id].spent, 9100, 'J18c · nothing was reserved');

  // Restart: a pending approval survives and can still be resolved.
  const kg = (await post('/grants', mk({ agent_id: 'a-k', budget_minor: 10000, daily_cap_minor: 100000 }))).body;
  const esc4 = (await post('/authorize', { grant_id: kg.grant_id, currency: 'USD', category: 'api', amount_minor: 1600, idempotency_key: 'k4' })).body;
  eq(esc4.decision, 'ESCALATE', 'J18d · a fresh grant escalates');
  await close(h); h = await listen(LOG);
  ok((await get('/approvals')).body.pending.some((p) => p.authorization_id === esc4.authorization_id), 'J19 · ★★ a pending approval survives a restart');
  ap = await post('/approvals/' + esc4.authorization_id, { decision: 'approve', approver_id: 'ops-1' });
  eq(ap.body.decision, 'ALLOW', 'J20 · ★ …and resolves after the restart');
  eq((await get('/evidence/' + ap.body.receipt_id)).body.self_check, 'ok', 'J21 · ★ the approval receipt is served by /evidence and self-verifies');

  // A DECIDED escalation must stay decided across a restart — approved (esc4), denied (esc2) and
  // approved-but-refused-by-policy (esc3) alike. Mutation A4 (rehydrate ignores `approval_decision`) SURVIVED
  // the whole suite on 2026-09-06 because nothing restarted AFTER a decision: every decision would have
  // reopened on the next boot and a second approve would have reserved the budget again.
  await close(h); h = await listen(LOG);
  const reopened = (await get('/approvals')).body.pending.map((p) => p.authorization_id);
  ok(!reopened.includes(esc4.authorization_id), 'J22 · ★★ an APPROVED escalation does not come back pending after a restart');
  ok(!reopened.includes(esc2.authorization_id), 'J23 · ★★ a DENIED escalation does not come back pending after a restart');
  ok(!reopened.includes(esc3.authorization_id), 'J24 · ★★ an approved-but-policy-refused escalation stays decided too');
  ap = await post('/approvals/' + esc4.authorization_id, { decision: 'approve', approver_id: 'ops-1' });
  eq(ap.status + ':' + ap.body.error, '404:APPROVAL_NOT_PENDING', 'J25 · ★★ no double-spend by restart: re-approving after the boot is refused');
  eq((await get('/audit')).body.agents[kg.grant_id].spent, 1600, 'J26 · ★ the budget was reserved exactly once across the restart');

  console.log('\n── K · BOUNDARIES through the API — decided from the spec, then run ───────────────────────');
  // A suite that never spends EXACTLY at a cap proves the checks exist, not that they are correct. Each
  // edge below was decided from DESIGN.md before running (see test/guardrails.test.js for the decisions).
  { // per-payment cap is INCLUSIVE. No approval line on this grant, so the cap is the only edge in play.
    const g1 = (await post('/grants', mk({ agent_id: 'edge-cap', budget_minor: 10000, daily_cap_minor: 100000, approval_threshold_minor: null }))).body;
    const a1 = (o) => post('/authorize', Object.assign({ grant_id: g1.grant_id, currency: 'USD', category: 'api' }, o));
    eq((await a1({ amount_minor: 1700, idempotency_key: 'e1' })).body.decision, 'ALLOW', 'K1 · ★ exactly the per-payment cap (1700 of 1700) is ALLOWED — a cap is inclusive');
    const over = (await a1({ amount_minor: 1701, idempotency_key: 'e2' })).body;
    eq(over.decision + '/' + over.reason, 'DENY/PER_PAYMENT_LIMIT', 'K2 · ★ one unit over the cap → DENY / PER_PAYMENT_LIMIT');
    eq((await a1({ amount_minor: 100, category: 'API', idempotency_key: 'e3' })).body.reason, 'CATEGORY_NOT_ALLOWED', 'K3 · ★ "API" is not "api" — categories are exact, case-sensitive');
  }
  { // daily cap is INCLUSIVE: the day may reach exactly the cap; one more unit is refused.
    const g2 = (await post('/grants', mk({ agent_id: 'edge-daily', budget_minor: 10000, daily_cap_minor: 5000, approval_threshold_minor: null }))).body;
    const a2 = (o) => post('/authorize', Object.assign({ grant_id: g2.grant_id, currency: 'USD', category: 'api' }, o));
    for (const [amt, k] of [[1700, 'd1'], [1650, 'd2']]) eq((await a2({ amount_minor: amt, idempotency_key: k })).body.decision, 'ALLOW', 'K4 · spend ' + amt + ' toward the daily cap');
    eq((await a2({ amount_minor: 1650, idempotency_key: 'd3' })).body.decision, 'ALLOW', 'K5 · ★ reaching EXACTLY the daily cap (1700+1650+1650 = 5000) is ALLOWED');
    const d = (await a2({ amount_minor: 1, idempotency_key: 'd4' })).body;
    eq(d.decision + '/' + d.reason, 'DENY/DAILY_LIMIT', 'K6 · ★ one unit over the daily cap → DENY / DAILY_LIMIT');
  }
  { // the whole remaining budget is spendable; one unit more is not.
    const g3 = (await post('/grants', mk({ agent_id: 'edge-balance', budget_minor: 1700, daily_cap_minor: 100000, approval_threshold_minor: null }))).body;
    const a3 = (o) => post('/authorize', Object.assign({ grant_id: g3.grant_id, currency: 'USD', category: 'api' }, o));
    eq((await a3({ amount_minor: 1700, idempotency_key: 'b1' })).body.decision, 'ALLOW', 'K7 · ★ spending EXACTLY the remaining budget (1700 of 1700) is ALLOWED');
    const b = (await a3({ amount_minor: 1, idempotency_key: 'b2' })).body;
    eq(b.decision + '/' + b.reason, 'DENY/INSUFFICIENT_BALANCE', 'K8 · ★ one unit past the budget → DENY / INSUFFICIENT_BALANCE');
  }
  { // approval line is STRICTLY ABOVE: exactly-at does not escalate; one unit above does.
    const g4 = (await post('/grants', mk({ agent_id: 'edge-approval', budget_minor: 10000, daily_cap_minor: 100000, approval_threshold_minor: 1500 }))).body;
    const a4 = (o) => post('/authorize', Object.assign({ grant_id: g4.grant_id, currency: 'USD', category: 'api' }, o));
    eq((await a4({ amount_minor: 1500, idempotency_key: 'p1' })).body.decision, 'ALLOW', 'K9 · ★ exactly the approval threshold (1500) does NOT escalate — "above this → ESCALATE"');
    eq((await a4({ amount_minor: 1501, idempotency_key: 'p2' })).body.decision, 'ESCALATE', 'K10 · ★ one unit above the threshold ESCALATES');
  }
  { // expiry: a grant whose expires_at is already in the past refuses; one far in the future allows.
    const past = (await post('/grants', mk({ agent_id: 'edge-expired', expires_at: Date.now() - 1000, approval_threshold_minor: null }))).body;
    const x = (await post('/authorize', { grant_id: past.grant_id, amount_minor: 100, currency: 'USD', category: 'api', idempotency_key: 'x1' })).body;
    eq(x.decision + '/' + x.reason, 'DENY/EXPIRED', 'K11 · ★★ an expired grant → DENY / EXPIRED (the suite never exercised expiry before tonight — mutation G6 survived it)');
    const future = (await post('/grants', mk({ agent_id: 'edge-alive', expires_at: Date.now() + 86400000, approval_threshold_minor: null }))).body;
    eq((await post('/authorize', { grant_id: future.grant_id, amount_minor: 100, currency: 'USD', category: 'api', idempotency_key: 'x2' })).body.decision, 'ALLOW', 'K12 · a grant expiring tomorrow allows today');
  }

  await close(h);
  try { fs.unlinkSync(LOG); } catch (_) {}
  console.log('\napi (end-to-end): ' + pass + ' passed, ' + fail + ' failed');
  process.exitCode = fail ? 1 : 0;
})().catch((e) => { console.error('\nFATAL', e); process.exit(1); });   // exit, not exitCode: the open server keeps the loop alive, and a crashed suite that never exits looked like a HUNG runner on 2026-09-06
