// ═══ WRITE AUTHENTICATION — the two paths that create authority, and the four that must stay open ═════
//
// Review finding (Ramu, 2026-09-06): there was no authentication code anywhere in `api/`. These vectors
// pin the smallest fix that is actually safe, and — more importantly — pin what must NOT become protected.
// Locking /authorize or /evidence would break the product: a verifier with no account is the entire claim.
'use strict';
const fs = require('fs'), os = require('os'), path = require('path');
const { start } = require('../api/server');
const auth = require('../api/auth');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };
const eq = (a, e, m) => {
  if (a === e) { pass++; console.log('  ✓ ' + m); return; }
  fail++; console.log('  ✗ ' + m + '\n      expected: ' + JSON.stringify(e) + '\n      actual:   ' + JSON.stringify(a));
};
const throws = (fn, re, m) => {
  try { fn(); fail++; console.log('  ✗ ' + m + '  (did not throw)'); }
  catch (e) { if (re.test(String(e.message))) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m + '\n      threw: ' + e.message); } }
};

const TOKEN = 'a-token-of-at-least-16-chars';

console.log('\n── A · POLICY RESOLUTION — a misconfigured mint must fail at BOOT, not on first write ──────');
eq(auth.resolveWritePolicy({ writeToken: TOKEN }).mode, 'token', 'A1 · a token configures token mode');
eq(auth.resolveWritePolicy({ production: false }).mode, 'open-dev', 'A2 · development with nothing set → open, but named "open-dev"');
throws(() => auth.resolveWritePolicy({ production: true }), /NO_WRITE_TOKEN/,
  'A3 · ★★ PRODUCTION with no token and no explicit opt-out → REFUSES TO START (same fail-closed shape as the signing key)');
eq(auth.resolveWritePolicy({ production: true, allowUnauthenticatedWrites: true }).mode, 'open',
  'A4 · ★ production CAN be open — but only when someone says so explicitly, which is the point');
throws(() => auth.resolveWritePolicy({ writeToken: 'short' }), /WRITE_TOKEN_TOO_SHORT/,
  'A5 · ★ a guessable token is refused — a 5-character secret is not authentication');
ok(/OPEN/.test(auth.describe(auth.resolveWritePolicy({ production: true, allowUnauthenticatedWrites: true }))),
  'A6 · ★ an open production server says so LOUDLY at every startup, not once in a doc');

console.log('\n── B · CONSTANT-TIME COMPARISON ────────────────────────────────────────────────────────────');
ok(auth.tokenMatches(TOKEN, TOKEN) === true, 'B1 · the right token matches');
ok(auth.tokenMatches(TOKEN + 'x', TOKEN) === false, 'B2 · a longer token does not');
ok(auth.tokenMatches(TOKEN.slice(0, -1), TOKEN) === false, 'B3 · ★ a PREFIX does not — the compare is not a startsWith');
ok(auth.tokenMatches('', TOKEN) === false, 'B4 · empty does not');
// Different lengths must not throw: timingSafeEqual does, which is why both sides are hashed first.
ok(auth.tokenMatches('x', TOKEN) === false, 'B5 · ★ a length mismatch returns false instead of throwing (both sides hashed to 32 bytes)');
eq(auth.bearerFrom({ headers: { authorization: 'Bearer  ' + TOKEN + ' ' } }), TOKEN, 'B6 · the bearer parser tolerates extra whitespace');
eq(auth.bearerFrom({ headers: { authorization: 'Basic ' + TOKEN } }), null, 'B7 · ★ Basic is not Bearer');
eq(auth.bearerFrom({ headers: {} }), null, 'B8 · no header → null');

console.log('\n── C · OVER THE WIRE — what is locked, and what must stay open ─────────────────────────────');
(async () => {
  const LOG = path.join(os.tmpdir(), 'cosmos-auth-test-' + process.pid + '.jsonl');
  try { fs.unlinkSync(LOG); } catch (_) {}
  const h = await new Promise((r) => {
    const s = start({ port: 0, file: LOG, quiet: true, writeToken: TOKEN });
    s.server.on('listening', () => r(Object.assign(s, { port: s.server.address().port })));
  });
  const B = 'http://localhost:' + h.port;
  const post = (p, o, tok) => fetch(B + p, { method: 'POST',
    headers: Object.assign({ 'content-type': 'application/json' }, tok ? { authorization: 'Bearer ' + tok } : {}),
    body: JSON.stringify(o) }).then(async (r) => ({ status: r.status, body: await r.json(), hdr: r.headers }));
  const get = (p) => fetch(B + p).then(async (r) => ({ status: r.status, body: await r.json() }));
  const GRANT = { org_id: 'o1', agent_id: 'a1', currency: 'USD', budget_minor: 50000,
    per_payment_cap_minor: 1700, daily_cap_minor: 5000, allowed_categories: ['api'], approval_threshold_minor: 1500 };

  const noTok = await post('/grants', GRANT, null);
  eq(noTok.status + ':' + noTok.body.error, '401:UNAUTHORIZED', 'C1 · ★★ POST /grants with no token → 401, so a stranger cannot mint authority');
  ok(/Bearer/i.test(noTok.hdr.get('www-authenticate') || ''), 'C2 · ★ …with WWW-Authenticate: ' + noTok.hdr.get('www-authenticate'));
  const badTok = await post('/grants', GRANT, 'wrong-token-but-long-enough');
  eq(badTok.status + ':' + badTok.body.error, '401:UNAUTHORIZED', 'C3 · a wrong token → 401');
  eq(JSON.stringify(noTok.body), JSON.stringify(badTok.body),
    'C4 · ★ "no token" and "wrong token" are INDISTINGUISHABLE — telling a prober which half to work on is a gift');

  const good = await post('/grants', GRANT, TOKEN);
  eq(good.status, 201, 'C5 · the right token mints');
  const GID = good.body.grant_id;

  // …and the paths that must NEVER be locked, asserted with NO token at all.
  const a = await post('/authorize', { grant_id: GID, amount_minor: 1200, currency: 'USD', category: 'api', idempotency_key: 'k1' }, null);
  eq(a.status + '/' + a.body.decision, '200/ALLOW', 'C6 · ★★ POST /authorize is NOT locked — an agent asking permission is the product');
  eq((await get(a.body.evidence)).status, 200, 'C7 · ★★ GET /evidence is NOT locked — a verifier with no account is the entire claim');
  eq((await get('/.well-known/jwks.json')).status, 200, 'C8 · ★★ the JWKS is NOT locked — an unreachable key makes every receipt unverifiable');
  eq((await get('/health')).status, 200, 'C9 · /health is NOT locked — a health check nobody can call is not a health check');

  // the second write path
  const esc = (await post('/authorize', { grant_id: GID, amount_minor: 1600, currency: 'USD', category: 'api', idempotency_key: 'k2' }, null)).body;
  eq(esc.decision, 'ESCALATE', 'C10 · over the approval line → ESCALATE');
  const apNo = await post('/approvals/' + esc.authorization_id, { decision: 'approve', approver_id: 'ops-1' }, null);
  eq(apNo.status + ':' + apNo.body.error, '401:UNAUTHORIZED',
    'C11 · ★★ POST /approvals/:id with no token → 401, so a stranger cannot resolve someone else\'s escalation');
  const apYes = await post('/approvals/' + esc.authorization_id, { decision: 'approve', approver_id: 'ops-1' }, TOKEN);
  eq(apYes.status + '/' + apYes.body.decision, '200/ALLOW', 'C12 · with the token it resolves');
  // ★ THE CLAIM THIS FIX MUST NOT ACCIDENTALLY MAKE. The token authenticates the CALLER — it proves
  // whoever posted holds the operator secret. It says NOTHING about whether "ops-1" approved anything.
  // Written to hold on both sides of PR #1 (schema 2), which is deliberately a separate branch: the field
  // is absent here on master and `false` once #1 merges. `true` is wrong in both worlds, and this is the
  // exact wrong turn a future "we have auth now" refactor would take.
  // Degrade instead of dying: under a mutation that opens the guard, C12 above gets a 404 and there is no
  // receipt_id. Crashing here cost the diagnosis for C14 on three of the nine mutations — a suite that
  // dies mid-run reports the first failure and hides the rest.
  const apRec = apYes.body.receipt_id ? (await get('/evidence/' + apYes.body.receipt_id)).body : {};
  const apPayload = apRec.payload_unverified || {};
  ok(apPayload.approver_authenticated !== true,
    'C13 · ★★ holding the write token does NOT mark the approver authenticated (got ' + JSON.stringify(apPayload.approver_authenticated) +
    ' — absent on master, false after PR #1; never true). The token proves the caller has the operator secret, not that "ops-1" approved.');

  console.log('\n── D · OPERATOR READS — /audit discloses every grant, and ranked above the writes ──────────');
  // Review, 2026-09-06: "GET /audit is the one I'd rank above both write paths for confidentiality."
  // Correct. A mint you cannot call is worth less to an attacker than a ledger you can read: /audit returns
  // amounts, caps, merchants, categories and org/agent ids for EVERY grant on the box.
  const getTok = (p, tok) => fetch(B + p, tok ? { headers: { authorization: 'Bearer ' + tok } } : undefined)
    .then(async (r) => ({ status: r.status, body: await r.json() }));

  const auditNo = await getTok('/audit', null);
  eq(auditNo.status + ':' + auditNo.body.error, '401:UNAUTHORIZED', 'D1 · ★★ GET /audit with no token → 401 — the whole grant dataset is not public');
  const auditYes = await getTok('/audit', TOKEN);
  eq(auditYes.status, 200, 'D2 · with the operator token it reads');
  ok(auditYes.body.agents && Object.keys(auditYes.body.agents).length > 0, 'D3 · …and it really is the dataset (' + Object.keys(auditYes.body.agents || {}).length + ' grants)');
  // the leak this closes, stated as data rather than as a worry
  ok(JSON.stringify(auditYes.body).includes(GID), 'D4 · ★ the response names grant ids — which is exactly why it cannot be open');

  eq((await getTok('/approvals', null)).status, 401, 'D5 · ★ GET /approvals with no token → 401 — pending escalations are not public either');
  eq((await getTok('/approvals', TOKEN)).status, 200, 'D6 · with the token it lists');

  // …and the public four are STILL public. Re-asserted here so widening the guard can never go unnoticed.
  eq((await get('/health')).status, 200, 'D7 · ★★ /health is still public after widening the guard');
  { // …and says LESS than it used to. The log path is filesystem topology, handed to anyone who asks.
    const hb = (await get('/health')).body;
    ok(!('log' in hb), 'D7a · ★★ /health does NOT disclose the event-log path to an unauthenticated caller');
    ok(!JSON.stringify(hb).includes('.jsonl') && !/[A-Za-z]:\\|\/tmp\/|\/var\//.test(JSON.stringify(hb)),
      'D7b · ★ …and no filesystem path leaks through any other field: ' + JSON.stringify(hb).slice(0, 120));
    eq(hb.ok, true, 'D7c · it still answers the question a health check asks');
    ok(typeof hb.signing_kid === 'string' && hb.signing_kid.length > 0,
      'D7d · signing_kid is KEPT — it is discoverable from the public JWKS, so withholding it would be ceremony'); }
  eq((await get('/.well-known/jwks.json')).status, 200, 'D8 · ★★ the JWKS is still public');
  eq((await get(a.body.evidence)).status, 200, 'D9 · ★★ /evidence is still public');
  eq((await post('/authorize', { grant_id: GID, amount_minor: 100, currency: 'USD', category: 'api', idempotency_key: 'k3' }, null)).status, 200,
    'D10 · ★★ /authorize is still public — an agent asking permission needs no operator secret');

  await new Promise((r) => { h.store.close(); if (h.server.closeAllConnections) h.server.closeAllConnections(); h.server.close(() => r()); });

  // an OPEN server is still fully usable — the fix must not have broken the dev path
  const h2 = await new Promise((r) => {
    const s = start({ port: 0, file: LOG + '.2', quiet: true, allowUnauthenticatedWrites: true });
    s.server.on('listening', () => r(Object.assign(s, { port: s.server.address().port })));
  });
  const r2 = await fetch('http://localhost:' + h2.server.address().port + '/grants',
    { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(GRANT) });
  eq(r2.status, 201, 'C14 · ★ with writes explicitly open, no token is needed — the demo path still works');
  await new Promise((r) => { h2.store.close(); if (h2.server.closeAllConnections) h2.server.closeAllConnections(); h2.server.close(() => r()); });
  try { fs.unlinkSync(LOG); fs.unlinkSync(LOG + '.2'); } catch (_) {}

  console.log('\nauth (write paths): ' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('\nFATAL', e); process.exit(1); });
