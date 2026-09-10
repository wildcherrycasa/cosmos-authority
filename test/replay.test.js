// ═══ REPLAY — rebuild the whole system from its own history ════════════════════════════════════════════
//
// replay.js is NOT on the request path. It is the AUDIT path: fold the event log and diff the result
// against live state. That separation is the thing Writ got wrong — it conflated the pure record with the
// coupled storage — so the fold staying pure is a load-bearing property, not a stylistic one.
//
// The property Cosmos depends on most: there is NO `default:` case in the switch, so an unknown event kind
// is INERT. That is what lets Cosmos write `approval_request` / `approval_decision` events into the same
// log that replay() folds, and lets replay() carry Writ's rail kinds (submission/settlement) that Cosmos
// will never emit. §B tests it as a guarantee rather than an accident.
'use strict';
const R = require('../core/replay');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };
const eq = (actual, expected, m) => {
  if (actual === expected) { pass++; console.log('  ✓ ' + m); return; }
  fail++; console.log('  ✗ ' + m);
  console.log('      expected: ' + JSON.stringify(expected));
  console.log('      actual:   ' + JSON.stringify(actual));
};
const throws = (fn, m) => {
  try { fn(); fail++; console.log('  ✗ ' + m); console.log('      expected a throw, got none'); }
  catch (_) { pass++; console.log('  ✓ ' + m); }
};

// A realistic Cosmos history in integer minor units: $500 granted, two ALLOWs, one reversed.
const LOG = () => [
  { kind: 'open', ts: 1, agentId: 'agt_1', budget: 50000 },
  { kind: 'decision', ts: 2, authId: 'auth_a', agentId: 'agt_1', amount: 1200, category: 'api',
    merchant: 'api.openai.com', approved: true, checks: [{ name: 'Active', pass: true }],
    idempotencyKey: 'k1' },
  { kind: 'reservation', ts: 3, authId: 'auth_a', agentId: 'agt_1', amount: 1200, merchant: 'api.openai.com' },
  { kind: 'decision', ts: 4, authId: 'auth_b', agentId: 'agt_1', amount: 800, category: 'cloud',
    merchant: 'aws', approved: true, checks: [{ name: 'Active', pass: true }], idempotencyKey: 'k2' },
  { kind: 'reservation', ts: 5, authId: 'auth_b', agentId: 'agt_1', amount: 800, merchant: 'aws' },
  { kind: 'reversal', ts: 6, authId: 'auth_b', agentId: 'agt_1', amount: 800, reason: 'RAIL_FAILED' },
];

console.log('\n── A · DETERMINISM AND PURITY ─────────────────────────────────────────────────────────────────');

eq(JSON.stringify(R.replay(LOG())), JSON.stringify(R.replay(LOG())),
   'A1 · ★ same history → byte-identical reconstruction');
eq(R.isDeterministic(LOG()), true, 'A2 · isDeterministic() agrees');
eq(JSON.stringify(R.replay([])), '{"agents":{},"authorizations":{}}', 'A3 · an empty log folds to empty state');

{ const events = LOG(); const before = JSON.stringify(events);
  R.replay(events);
  eq(JSON.stringify(events), before, 'A4 · ★ replay() does not mutate the events it folds'); }

// ⚠ ALIASING: `t.checks = e.checks || null` stores a REFERENCE, so replayed state shares mutable
// structure with the log. Mutating the projection makes history appear to change.
{ const events = LOG();
  const out = R.replay(events);
  ok(out.authorizations.auth_a.checks === events[1].checks,
     'A5 · ⚠★ the checks array is SHARED BY REFERENCE with the event — the fold is pure, but its OUTPUT ' +
     'aliases the log. Never hand a raw projection to a caller that might mutate it.'); }

console.log('\n── B · UNKNOWN EVENT KINDS ARE INERT (the property Cosmos depends on) ──────────────────────────');

{ const out = R.replay([{ kind: 'open', agentId: 'agt_1', budget: 50000 },
                        { kind: 'nonsense', agentId: 'agt_1', amount: 999999 }]);
  eq(out.agents.agt_1.budget, 50000, 'B1 · ★★ an unknown kind changes nothing — there is no default: case');
  eq(Object.keys(out.agents).length, 1, 'B2 · ★ an unknown kind does not conjure an agent into existence'); }

// Cosmos writes these into the SAME log; approvals.rehydrate() consumes them. replay() must ignore them.
for (const kind of ['approval_request', 'approval_decision', 'command']) {
  const out = R.replay([{ kind: 'open', agentId: 'agt_1', budget: 50000 },
                        { kind, agentId: 'agt_1', commandId: 'c1', amount: 777 }]);
  eq(out.agents.agt_1.budget, 50000, 'B3 · ★ "' + kind + '" is inert in replay (approvals.js owns it)');
}
eq(Object.keys(R.replay([{ kind: 'approval_request', agentId: 'agt_1', amount: 5 }]).agents).length, 0,
   'B6 · ★★ a log of ONLY Cosmos approval events folds to no agents at all — zero interference');

{ const out = R.replay([{}, { kind: undefined }, { kind: '' }, { kind: 'open', agentId: 'a', budget: 1 }]);
  eq(out.agents.a.budget, 1, 'B7 · missing/empty kinds are skipped without disturbing real events'); }

// ⚠ NOT defensive: the fold reads e.kind unguarded, so a null entry crashes. A corrupted log line that
// parses to `null` would take down boot. core/store.js must filter before folding.
throws(() => R.replay([null]), 'B8 · ⚠★ a NULL entry THROWS — replay() is not defensive; store.js must ' +
       'filter malformed lines before folding');
throws(() => R.replay([undefined]), 'B9 · ⚠ an undefined entry throws for the same reason');

console.log('\n── C · BALANCES ───────────────────────────────────────────────────────────────────────────────');

{ const s = R.replay(LOG());
  eq(s.agents.agt_1.budget, 50000, 'C1 · budget comes from open');
  eq(s.agents.agt_1.spent, 1200, 'C2 · ★ spent = 1200 + 800 reserved − 800 reversed');
  eq(s.agents.agt_1.status, 'active', 'C3 · status defaults to active'); }

{ const s = R.replay([{ kind: 'open', agentId: 'a', budget: 100 },
                      { kind: 'open', agentId: 'a', budget: 999999 }]);
  eq(s.agents.a.budget, 100,
     'C4 · ★★ FIRST open wins — a restart that re-emits `open` cannot wipe or inflate funds'); }

{ const s = R.replay([{ kind: 'open', agentId: 'a', budget: 100 }, { kind: 'fund', agentId: 'a', amount: 250 },
                      { kind: 'fund', agentId: 'a', amount: 50 }]);
  eq(s.agents.a.budget, 400, 'C5 · fund accumulates'); }

{ const s = R.replay([{ kind: 'open', agentId: 'a', budget: 0 }]);
  eq(s.agents.a.budget, 0, 'C6 · an open with no budget is 0, not undefined'); }
{ const s = R.replay([{ kind: 'open', agentId: 'a' }]);
  eq(s.agents.a.budget, 0, 'C7 · ⚠ a MISSING budget silently becomes 0 (`e.budget || 0`)'); }
{ const s = R.replay([{ kind: 'open', agentId: 'a', budget: 100 }, { kind: 'reservation', agentId: 'a' }]);
  eq(s.agents.a.spent, 0, 'C8 · ⚠★ a reservation with NO amount silently contributes 0 — a malformed ' +
     'spend event is absorbed rather than rejected'); }

{ const s = R.replay([{ kind: 'freeze', agentId: 'a' }]);
  eq(s.agents.a.status, 'frozen', 'C9 · freeze sets frozen'); }
{ const s = R.replay([{ kind: 'freeze', agentId: 'a' }, { kind: 'unfreeze', agentId: 'a' }]);
  eq(s.agents.a.status, 'active', 'C10 · ★ freeze → unfreeze ends active (last event wins, durable)'); }
{ const s = R.replay([{ kind: 'unfreeze', agentId: 'a' }, { kind: 'freeze', agentId: 'a' }]);
  eq(s.agents.a.status, 'frozen', 'C11 · ★ the reverse order ends frozen — ORDER IS MEANING'); }

// Cosmos uses integer minor units precisely so the .toFixed(6) float path never rounds anything.
{ const many = [{ kind: 'open', agentId: 'a', budget: 1000000 }];
  for (let i = 0; i < 1000; i++) many.push({ kind: 'reservation', agentId: 'a', amount: 1 });
  eq(R.replay(many).agents.a.spent, 1000, 'C12 · ★ 1000 integer reservations sum EXACTLY — no drift'); }
{ const s = R.replay([{ kind: 'open', agentId: 'a', budget: 1 },
                      { kind: 'reservation', agentId: 'a', amount: 0.1 },
                      { kind: 'reservation', agentId: 'a', amount: 0.2 }]);
  eq(s.agents.a.spent, 0.3,
     'C13 · ⚠ floats are rounded to 6dp, so 0.1+0.2 lands on 0.3 — works, but is why Cosmos uses integers'); }
{ const s = R.replay([{ kind: 'open', agentId: 'a', budget: 1 },
                      { kind: 'reservation', agentId: 'a', amount: 0.0000001 }]);
  eq(s.agents.a.spent, 0, 'C14 · ⚠★ a value below 1e-6 rounds AWAY to zero — sub-micro amounts vanish'); }

console.log('\n── D · AUTHORIZATION PROJECTION ───────────────────────────────────────────────────────────────');

{ const t = R.replay(LOG()).authorizations.auth_a;
  eq(t.agentId, 'agt_1', 'D1 · agentId'); eq(t.amount, 1200, 'D2 · amount');
  eq(t.category, 'api', 'D3 · category'); eq(t.merchant, 'api.openai.com', 'D4 · merchant');
  eq(t.approved, true, 'D5 · approved'); eq(t.idempotencyKey, 'k1', 'D6 · ★ idempotency key survives the fold');
  ok(Array.isArray(t.checks) && t.checks.length === 1, 'D7 · ★ the policy-check breakdown is rebuildable'); }

{ const s = R.replay([{ kind: 'decision', authId: 'x', agentId: 'a', amount: 5, approved: false, reason: 'DAILY_LIMIT' }]);
  eq(s.authorizations.x.reason, 'DAILY_LIMIT', 'D8 · a DENY reason is recorded'); }
{ // `if (e.reason)` — a later decision without a reason does NOT clear an earlier one.
  const s = R.replay([{ kind: 'decision', authId: 'x', agentId: 'a', amount: 5, approved: false, reason: 'DAILY_LIMIT' },
                      { kind: 'decision', authId: 'x', agentId: 'a', amount: 5, approved: true }]);
  eq(s.authorizations.x.approved, true, 'D9 · the later decision wins for `approved`…');
  eq(s.authorizations.x.reason, 'DAILY_LIMIT',
     'D10 · ⚠★ …but `reason` is STICKY — an ALLOW after a DENY still shows the old reason'); }

{ const s = R.replay([{ kind: 'reservation', authId: 'x', agentId: 'a', amount: 99, merchant: 'm1' }]);
  eq(s.authorizations.x.amount, 99, 'D11 · a reservation backfills amount when no decision preceded it');
  eq(s.authorizations.x.merchant, 'm1', 'D12 · …and merchant'); }
{ const s = R.replay([{ kind: 'decision', authId: 'x', agentId: 'a', amount: 10, merchant: 'real' },
                      { kind: 'reservation', authId: 'x', agentId: 'a', amount: 99, merchant: 'other' }]);
  eq(s.authorizations.x.amount, 10, 'D13 · ★ the decision amount is NOT overwritten by the reservation');
  eq(s.authorizations.x.merchant, 'real', 'D14 · ★ nor the merchant'); }
{ const s = R.replay([{ kind: 'status', authId: 'x', status: 'settled' },
                      { kind: 'status', authId: 'x', status: 'reversed' }]);
  eq(s.authorizations.x.status, 'reversed', 'D15 · status is last-wins'); }
{ const s = R.replay([{ kind: 'reversal', authId: 'x', agentId: 'a', amount: 5, reason: 'EXPIRED' }]);
  eq(s.authorizations.x.reason, 'EXPIRED', 'D16 · ★ a reversal records WHY the budget came back'); }

console.log('\n── E · ORDER, DUPLICATES, AND APPEND ──────────────────────────────────────────────────────────');

{ const s = R.replay([{ kind: 'open', agentId: 'a', budget: 100 },
                      { kind: 'reservation', agentId: 'a', authId: 'x', amount: 30 },
                      { kind: 'reservation', agentId: 'a', authId: 'x', amount: 30 }]);
  eq(s.agents.a.spent, 60,
     'E1 · ⚠★★ a DUPLICATED reservation DOUBLE-COUNTS — replay does not dedupe by authId. Idempotency is ' +
     'store.js\'s job: the same idempotency key must never append a second reservation.'); }

{ const base = LOG();
  const grown = base.concat([{ kind: 'reservation', ts: 7, authId: 'auth_c', agentId: 'agt_1', amount: 500 }]);
  eq(R.replay(grown).agents.agt_1.spent, 1700, 'E2 · ★ appending an event and re-folding gives the new total');
  eq(R.replay(base).agents.agt_1.spent, 1200, 'E3 · ★ the original log still folds to the original state'); }

{ const s = R.replay([{ kind: 'reservation', agentId: 'a', amount: 50 },
                      { kind: 'open', agentId: 'a', budget: 100 }]);
  eq(s.agents.a.spent, 50, 'E4 · ⚠ a reservation BEFORE its open is still counted…');
  eq(s.agents.a.budget, 100, 'E5 · ⚠ …and the later open still applies (first-open-wins is per replay)'); }

console.log('\n── F · verify() — the audit path ──────────────────────────────────────────────────────────────');

{ const live = { agents: { agt_1: { budget: 50000, spent: 1200 } }, authorizations: {} };
  const v = R.verify(LOG(), live);
  eq(v.ok, true, 'F1 · ★★ live state matching the fold reports ok');
  eq(v.diffs.length, 0, 'F2 · with no diffs');
  ok(v.replay && v.replay.agents.agt_1, 'F3 · verify() returns the reconstruction it used'); }

{ const v = R.verify(LOG(), { agents: { agt_1: { budget: 50000, spent: 9999 } }, authorizations: {} });
  eq(v.ok, false, 'F4 · ★★ a spent mismatch is DETECTED — this is the drift alarm');
  const d = v.diffs.find((x) => x.field === 'spent');
  ok(d && d.live === 9999 && d.replay === 1200, 'F5 · ★ the diff names the field and both values'); }

{ const v = R.verify(LOG(), { agents: { agt_1: { budget: 1, spent: 1200 } }, authorizations: {} });
  ok(v.diffs.some((d) => d.field === 'budget'), 'F6 · a budget mismatch is detected'); }
{ const v = R.verify(LOG(), { agents: {}, authorizations: { auth_a: { status: 'settled' } } });
  ok(v.diffs.some((d) => d.field === 'status' && d.authId === 'auth_a'),
     'F7 · ★ an authorization status mismatch is detected'); }
{ const v = R.verify(LOG(), { agents: { ghost: { budget: 5, spent: 0 } }, authorizations: {} });
  ok(v.diffs.some((d) => d.agentId === 'ghost'),
     'F8 · ★★ an agent that exists LIVE but has NO history is caught — invented balances cannot hide'); }
{ const v = R.verify(LOG(), { agents: { agt_1: { budget: 50000 + 1e-12, spent: 1200 } }, authorizations: {} });
  eq(v.ok, true, 'F9 · a 1e-12 difference is within tolerance (1e-9)'); }
{ const v = R.verify(LOG(), { agents: { agt_1: { budget: 50000 + 1e-6, spent: 1200 } }, authorizations: {} });
  eq(v.ok, false, 'F10 · ★ a 1e-6 difference is NOT — the tolerance is tight'); }
{ const v = R.verify(LOG(), {});
  eq(v.ok, true, 'F11 · verify() against empty live state is vacuously ok (it only checks what live claims)'); }

console.log('\n── G · receipts() ─────────────────────────────────────────────────────────────────────────────');

{ const rs = R.receipts(LOG());
  eq(rs.length, 2, 'G1 · one receipt per authorization in history');
  const a = rs.find((r) => r.authorizationId === 'auth_a');
  ok(a && a.amount === 1200 && a.merchant === 'api.openai.com', 'G2 · ★ receipts reconstruct from events alone');
  ok(a && Array.isArray(a.checks), 'G3 · the check breakdown rides along');
  const b = rs.find((r) => r.authorizationId === 'auth_b');
  eq(b.reason, 'RAIL_FAILED', 'G4 · ★ the reversed authorization carries its reversal reason');
  ok(rs.every((r) => typeof r.receipt === 'string' && r.receipt.startsWith('rcpt_')),
     'G5 · every receipt has an rcpt_ id'); }

{ // ⚠ `a.id.slice(5, 13)` assumes an authId shaped like `auth_XXXXXXXX`. A short id yields a stub.
  const rs = R.receipts([{ kind: 'decision', authId: 'x', agentId: 'a', amount: 1 }]);
  eq(rs[0].receipt, 'rcpt_',
     'G6 · ⚠★ a short authId produces the DEGENERATE id "rcpt_" — Cosmos authIds must be ≥13 chars, or ' +
     'two authorizations collide on one receipt id'); }

console.log('\n── H · WHAT REPLAY DOES NOT DO — Cosmos gaps, pinned ──────────────────────────────────────────');

{ const a = R.replay(LOG()).agents.agt_1;
  ok(!('spentToday' in a),
     'H1 · ★★ `spentToday` is NOT folded, yet guardrails.js needs it for the daily cap. This is DESIGN §5 ' +
     'Gap 2 — core/agent-view.js must fold it separately.');
  eq(Object.keys(a).sort().join(','), 'budget,spent,status',
     'H2 · ★ the agent projection is exactly {budget, spent, status} — nothing else survives the fold'); }

{ const s = R.replay([{ kind: 'submission', authId: 'x', txId: 't1', provider: 'stripe' },
                      { kind: 'settlement', authId: 'x', txId: 't2', provider: 'stripe' }]);
  eq(s.authorizations.x.txId, 't2',
     'H3 · Writ\'s rail kinds still fold — Cosmos never EMITS them (it does not touch money), but ' +
     'carrying them costs nothing and removing them would edit a frozen module'); }

console.log('\nreplay: ' + pass + ' passed, ' + fail + ' failed');
if (fail) process.exit(1);
