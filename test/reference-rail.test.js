// ═══ THE SEAM, DRIVEN FROM BOTH ENDS ═══════════════════════════════════════════════════════════════════
//
// Every assertion in test/rail.test.js is Cosmos talking to Cosmos. This one puts a SEPARATE PROCESS on
// the other side — examples/reference-rail — and drives the whole thing the way an integrator would: an
// agent asks Cosmos for permission, hands the ALLOW to the rail, the rail executes and reports back, and
// the budget ends up correct without anyone here touching a settlement endpoint directly.
//
// ⚠ WHAT THIS DOES AND DOES NOT SETTLE. It proves the spec is implementable by a program that is not the
// server, and it pins the rules an integrator will get wrong. It does NOT prove anyone chose to implement
// it — I wrote both sides. That distinction is the whole commercial question and no test can close it.
//
// ⛳ §C WAS REWRITTEN 2026-09-09 AFTER A FINDING FROM THE WRIT SESSION, and the old version of it was the
// defect. It asserted that a swallowed report leaves the reservation for the TTL to reverse and called
// that "the fallback doing its job". For a payment that actually SETTLED, the TTL reversing it is not a
// fallback — it returns budget for money that moved, which is the same ledger a malicious `failed` report
// produces. §K of test/rail.test.js exists to stop an attacker reaching that state; §C used to accept an
// outage reaching it. A report must never fail the payment AND must never be lost.
//
// ⛳ §G AND §H WERE ADDED THE SAME DAY, from review. The example used to build its destination out of
// `cosmos.base_url` IN THE PAYMENT REQUEST and post the rail's bearer token to it — SSRF plus credential
// exfiltration, handed to the least-trusted party in the flow, in the one file written to be copied.
'use strict';
process.env.COSMOS_RESERVATION_TTL_MS = '60000';

const fs = require('fs'), os = require('os'), path = require('path');
const { execFile } = require('child_process');
const { start } = require('../api/server');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };
const eq = (a, e, m) => {
  if (a === e) { pass++; console.log('  ✓ ' + m); return; }
  fail++; console.log('  ✗ ' + m);
  console.log('      expected: ' + JSON.stringify(e));
  console.log('      actual:   ' + JSON.stringify(a));
};

const OPTOKEN = 'reference-rail-operator-token';
const RAILTOKEN = 'reference-rail-shared-secret-32ch';
const LOG = path.join(os.tmpdir(), 'cosmos-refrail-' + process.pid + '.jsonl');
const OUTBOX = path.join(os.tmpdir(), 'cosmos-refrail-outbox-' + process.pid + '.jsonl');
const RAILMOD = path.join(__dirname, '..', 'examples', 'reference-rail', 'rail.js');
for (const f of [LOG, OUTBOX]) { try { fs.unlinkSync(f); } catch (_) {} }

const closeSrv = (s) => new Promise((r) => {
  if (s.closeAllConnections) s.closeAllConnections();
  s.close(() => r());
});

// A REAL separate process that requires the rail module and drains its outbox — the honest form of
// "the rail restarted". A queue that only survives inside the memory that created it is not durable.
//
// ⚠ execFile, NOT execFileSync. The restarted Cosmos in §D is served by THIS process's event loop, so a
// synchronous spawn blocks the very server the child is trying to reach: the child waits on a reply the
// parent cannot send until the child exits. It looked exactly like a hung rail and was neither side's bug.
function railRestartAndFlush(endpointsJson) {
  const src = 'const r = require(' + JSON.stringify(RAILMOD) + ');'
    + 'r.flush().then((got) => { console.log("FLUSHED " + JSON.stringify(Object.keys(got)));'
    + ' r.server.close(); process.exit(0); }).catch((e) => { console.error(e); process.exit(1); });';
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ['-e', src], {
      encoding: 'utf8', timeout: 30000,
      env: Object.assign({}, process.env, {
        RAIL_PORT: '0', RAIL_OUTBOX: OUTBOX, RAIL_PROVIDER: 'reference-rail',
        COSMOS_RAIL_TOKEN: RAILTOKEN, COSMOS_ENDPOINTS: endpointsJson,
      }),
    }, (err, stdout, stderr) => (err ? reject(new Error(err.message + ' :: ' + stdout + stderr)) : resolve(stdout)));
  });
}

(async () => {
  // ── Cosmos first, because the rail's allowlist is CONFIGURATION and must exist before the rail runs ──
  // That ordering is the point of §G: a rail that could learn its destination at request time would not
  // need to be configured at all, and that is exactly the hole.
  let h = start({ port: 0, quiet: true, file: LOG, writeToken: OPTOKEN,
                  rail: { provider: 'reference-rail', token: RAILTOKEN } });
  await new Promise((r) => h.server.on('listening', r));
  const PORT = h.server.address().port;
  const C = 'http://localhost:' + PORT;
  const ENDPOINTS = JSON.stringify({ default: C });

  process.env.COSMOS_RAIL_TOKEN = RAILTOKEN;
  process.env.RAIL_PORT = '0';
  process.env.RAIL_PROVIDER = 'reference-rail';
  process.env.RAIL_OUTBOX = OUTBOX;
  process.env.COSMOS_ENDPOINTS = ENDPOINTS;
  const rail = require('../examples/reference-rail/rail');
  await new Promise((r) => { if (rail.server.listening) return r(); rail.server.on('listening', r); });

  const R = 'http://localhost:' + rail.server.address().port;
  const post = (u, o, tok) => fetch(u, {
    method: 'POST',
    headers: Object.assign({ 'content-type': 'application/json' }, tok ? { authorization: 'Bearer ' + tok } : {}),
    body: JSON.stringify(o),
  }).then(async (r) => ({ status: r.status, body: await r.json() }));
  const audit = async () => (await fetch(C + '/audit', { headers: { authorization: 'Bearer ' + OPTOKEN } }).then((r) => r.json()));

  const grant = (await post(C + '/grants', {
    org_id: 'o', agent_id: 'a', currency: 'USD', budget_minor: 50000,
    per_payment_cap_minor: 9000, daily_cap_minor: 40000, allowed_categories: ['api'],
  }, OPTOKEN)).body;

  const ask = (amount, key) => post(C + '/authorize', {
    grant_id: grant.grant_id, amount_minor: amount, currency: 'USD',
    category: 'api', merchant: 'reference.rail', idempotency_key: key,
  });

  // ── §A · the whole loop, exactly as an integrator wires it ────────────────────────────────────────
  console.log('\n§A · agent → Cosmos → rail → Cosmos, end to end');
  const a1 = (await ask(2500, 'ref-1')).body;
  eq(a1.decision, 'ALLOW', 'A1 · Cosmos allows the spend');
  ok(a1.rail && a1.rail.report_to && a1.rail.handoff_token && a1.rail.base_url === undefined,
     'A2 · ★★ the ALLOW hands out a PATH and a token and NO origin — the protocol never asked the caller where to send credentials');

  // THE HANDOFF: the agent passes the ALLOW's rail block straight through. It never invents anything.
  const paid = (await post(R + '/pay', {
    amount_minor: 2500, currency: 'USD',
    cosmos: { report_to: a1.rail.report_to, handoff_token: a1.rail.handoff_token },
  })).body;
  eq(paid.paid, true, 'A3 · the rail executed');
  ok(/^stl_[0-9a-f]{20}$/.test(paid.cosmos_receipt || ''),
     'A4 · ★★★ the RAIL got back a Cosmos receipt id — a program that is not the server closed the loop');
  eq(paid.cosmos_report, 'delivered', 'A5 · …and says so as `delivered`, so a null receipt can never mean two things');

  const ev = await fetch(C + '/evidence/' + paid.cosmos_receipt).then((r) => r.json());
  const p = ev.payload_unverified || {};
  eq(p.rail_outcome, 'settled', 'A6 · Cosmos recorded it settled');
  eq(p.rail_reported_by, 'rail', 'A7 · ★★ by the RAIL credential class, not the operator and not the requester');
  eq(p.parent_receipt_id, a1.authorization_id, 'A8 · chained to the ALLOW it descends from');
  eq(p.rail_state, 'settled', 'A9 · carrying the rail\'s own word for what happened');
  eq((await audit()).agents[grant.grant_id].spent, 2500, 'A10 · the spend stands, exactly once');
  eq(rail.readOutbox().length, 0, 'A11 · the outbox is empty — a delivered report is not left owed');

  // ── §B · the failure path, which an integrator will hit first in the real world ───────────────────
  console.log('\n§B · a payment that fails returns the budget immediately');
  const a2 = (await ask(3000, 'ref-2')).body;
  const before = (await audit()).agents[grant.grant_id].spent;
  const failed = (await post(R + '/pay', {
    amount_minor: 3000, currency: 'USD', simulate_failure: true,
    cosmos: { report_to: a2.rail.report_to, handoff_token: a2.rail.handoff_token },
  })).body;
  eq(failed.paid, false, 'B1 · the rail reports the payment did not happen');
  eq((await audit()).agents[grant.grant_id].spent, before - 3000,
     'B2 · ★★ the budget came back AT ONCE — not after the five-minute TTL');

  // ── §C · THE RULE AN INTEGRATOR IS MOST LIKELY TO BREAK, and the one this file got wrong first ────
  console.log('\n§C · Cosmos is DOWN while a payment settles — best-effort AND durable, not one or the other');
  // Both figures are captured, because the interesting claim is WHICH of the two the ledger ends on.
  // The ALLOW reserves the spend, so settling keeps it and reversing hands it back.
  const spentBeforeAuth = (await audit()).agents[grant.grant_id].spent;
  const a3 = (await ask(1000, 'ref-3')).body;
  const spentReserved = (await audit()).agents[grant.grant_id].spent;
  eq(spentReserved, spentBeforeAuth + 1000, 'C0 · the ALLOW reserved the spend up front');

  h.store.close();
  await closeSrv(h.server);
  ok(!(await fetch(C + '/health').then(() => true).catch(() => false)), 'C1 · Cosmos really is unreachable (the control this section rests on)');

  const orphan = (await post(R + '/pay', {
    amount_minor: 1000, currency: 'USD',
    cosmos: { report_to: a3.rail.report_to, handoff_token: a3.rail.handoff_token },
  })).body;
  eq(orphan.paid, true,
     'C2 · ★★★ the payment STILL SUCCEEDED — a rail that failed real payments because an authority server was down would be worse than no authority server');
  eq(orphan.cosmos_receipt, null, 'C3 · …with no receipt, honestly reported as null rather than faked');
  eq(orphan.cosmos_report, 'queued', 'C4 · and named `queued`, not silently dropped');

  const owed = rail.readOutbox();
  eq(owed.length, 2, 'C5 · ★★ BOTH reports are on DISK, still owed — submitted and settled');
  ok(owed.some((r) => r.body.outcome === 'settled'),
     'C6 · ★★★ the SETTLED report survived the outage. A swallowed one would not, and Cosmos\'s TTL would then hand back budget for money that really moved — the same ledger a malicious `failed` report produces');
  ok(owed.every((r) => r.endpoint === 'default' && !/^https?:/i.test(String(r.report_to))),
     'C7 · ★★ a queued row stores the endpoint NAME and a path, never a URL — so nothing that reaches this file can redirect where the rail token goes');

  // ── §D · the queue outlives the process that made it, which is the whole claim ────────────────────
  console.log('\n§D · Cosmos comes back; a RESTARTED rail delivers what it still owed');
  h = start({ port: PORT, quiet: true, file: LOG, writeToken: OPTOKEN,
              rail: { provider: 'reference-rail', token: RAILTOKEN } });
  await new Promise((r) => h.server.on('listening', r));

  const out = await railRestartAndFlush(ENDPOINTS);
  ok(/FLUSHED \[.*"settled".*\]/.test(out),
     'D1 · ★★★ a SEPARATE PROCESS read the queue off disk and delivered the settlement — the report survived both the outage and the restart');
  ok(!out.includes(RAILTOKEN),
     'D2 · ★★ and the rail token appears NOWHERE in what that process printed — a credential that reaches a log has left the credential store');
  eq(rail.readOutbox().length, 0, 'D3 · the queue is empty afterwards — delivered rows are removed, not re-sent forever');

  const settledSpend = (await audit()).agents[grant.grant_id].spent;
  eq(settledSpend, spentReserved,
     'D4 · ★★ the spend STANDS at the reserved figure — the money moved and the ledger says so');
  ok(settledSpend !== spentBeforeAuth,
     'D5 · ★★★ and it is NOT the pre-authorization figure, which is where a lost report would have left it: budget handed back for a payment that really settled, then spendable a second time');

  // ── §E · the rail cannot skip the second credential ───────────────────────────────────────────────
  console.log('\n§E · the rail\'s own token is not enough on its own');
  const a4 = (await ask(1000, 'ref-4')).body;
  const noHandoff = await fetch(C + a4.rail.report_to, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + RAILTOKEN },
    body: JSON.stringify({ outcome: 'settled', tx_id: '0xnope' }),
  });
  eq(noHandoff.status, 401,
     'E1 · ★★ a rail that reports WITHOUT x-cosmos-handoff is refused — holding the shared secret does not let it settle authorizations it was never given');

  // ── §F · a permanently-refused report must not jam the queue forever ──────────────────────────────
  console.log('\n§F · a 4xx is dropped, not retried until the end of time');
  await rail.reportSafely('default',
    { report_to: a4.rail.report_to, handoff_token: 'not-this-authorizations-token' },
    { outcome: 'settled', tx_id: '0xbad', provider: 'reference-rail' }, 'settled');
  eq(rail.readOutbox().length, 0,
     'F1 · ★★ a report Cosmos will never accept is dropped after one try — a queue that retries a bad credential forever is an outage that never ends');

  // ── §G · ⛔ THE CALLER MAY NOT CHOOSE WHERE THE RAIL SENDS ITS CREDENTIALS ─────────────────────────
  // The request is the least-trusted input in the whole flow. A rail that takes its destination from it
  // is an SSRF probe on request and a credential-exfiltration endpoint on request — and the credential in
  // question is the one the two-token design exists to keep AWAY from the requester.
  console.log('\n§G · a caller-supplied origin is refused outright, before any money moves');
  const a5 = (await ask(1000, 'ref-5')).body;
  const spentBeforeAttack = (await audit()).agents[grant.grant_id].spent;
  const evil = await post(R + '/pay', {
    amount_minor: 1000, currency: 'USD',
    cosmos: { base_url: 'http://attacker.invalid', report_to: a5.rail.report_to, handoff_token: a5.rail.handoff_token },
  });
  eq(evil.status, 400, 'G1 · ★★★ a request carrying its own base_url is REFUSED — not honoured, and not silently ignored either');
  eq(evil.body.error, 'CALLER_SUPPLIED_ORIGIN', 'G2 · by name, so an integrator learns the rule rather than guessing at a 400');
  eq(evil.body.paid, undefined, 'G3 · ★★ and NO payment happened — the check runs before execution, not after');
  eq(rail.readOutbox().length, 0, 'G4 · ★★ nothing was queued, so the attacker\'s address cannot be retried into later either');
  eq((await audit()).agents[grant.grant_id].spent, spentBeforeAttack, 'G5 · the ledger did not move');

  // A metadata endpoint is the canonical SSRF target and the reason "any URL the rail can reach" is worse
  // than it sounds — it needs no credential at all, only the request coming from inside.
  const ssrf = await post(R + '/pay', {
    amount_minor: 100, currency: 'USD',
    cosmos: { base_url: 'http://169.254.169.254', report_to: '/latest/meta-data/', handoff_token: 'x' },
  });
  eq(ssrf.status, 400, 'G6 · ★★ the cloud metadata address is refused by the same rule — an allowlist does not need to enumerate the targets it protects against');

  // ── §H · and the PATH is untrusted too, which is the half an allowlist usually forgets ────────────
  console.log('\n§H · report_to cannot escape the configured origin');
  for (const [bad, why] of [
    ['//attacker.invalid/steal', 'protocol-relative — the classic way past a naive origin + path concatenation'],
    ['https://attacker.invalid/steal', 'an absolute URL where a path was expected'],
    ['/settlements/../../wherever', 'traversal'],
  ]) {
    const r = await post(R + '/pay', { amount_minor: 100, currency: 'USD', cosmos: { report_to: bad, handoff_token: 'x' } });
    eq(r.status, 400, 'H · refused: ' + why);
  }
  ok(rail.resolveReport({ report_to: '/settlements/auth_x', handoff_token: 't' }).url === C + '/settlements/auth_x',
     'H4 · ★ and a legitimate path still resolves against the configured origin, so the guard is not simply refusing everything');

  console.log('\nreference-rail (both sides of the seam): ' + pass + ' passed, ' + fail + ' failed');
  await closeSrv(rail.server);
  h.store.close();
  await closeSrv(h.server);
  for (const f of [LOG, OUTBOX]) { try { fs.unlinkSync(f); } catch (_) {} }
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); process.exit(1); });
