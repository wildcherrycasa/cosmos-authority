// ═══ GUARDRAILS + APPROVALS — THE BOUNDARIES, decided from the spec BEFORE running the code ═════════════
//
// guardrails.js is the frozen anchor and had no dedicated Cosmos suite — it was exercised by smoke and the
// end-to-end suites, none of which ever spends EXACTLY at a cap. That proves the checks exist, not that the
// edges are where the product says they are. A boundary assertion written by observing the code is a
// photograph, not a validation (QuickPay, 2026-09-06). So every boundary below was DECIDED first, from
// docs/DESIGN.md and what a customer would reasonably expect, and the decision is written next to the
// assertion. If the code had disagreed, that would have been a found bug, not a test to adjust.
//
// DECISIONS (2026-09-06):
//   caps are INCLUSIVE — a "$17.00 cap" permits a $17.00 payment; $17.01 is refused.
//   the remaining budget is spendable IN FULL — exactly-remaining is allowed.
//   the daily cap is INCLUSIVE — the day may reach exactly the cap; one unit over is refused.
//   the approval line is STRICTLY ABOVE — DESIGN §1: "above this → ESCALATE"; exactly-at does NOT escalate.
//   categories are EXACT, case-sensitive identifiers — "API" is not "api"; "api " is not "api".
//   expiry: the grant is VALID AT the exact expiry instant and expired only strictly after it. ⚠ Pinned AS
//     IMPLEMENTED in the frozen anchor. It diverges from JWT `exp` (RFC 7519 §4.1.4: invalid at or after exp),
//     but Writ uses the same edge in three independent modules — a house convention by consistency, not a
//     recorded decision. A 1 ms window; flagged to the founder; change it only on purpose, in both repos.
'use strict';
const G = require('../core/guardrails');
const A = require('../core/approvals');

let pass = 0, fail = 0;
const eq = (a, e, m) => { if (a === e) { pass++; console.log('  ✓ ' + m); return; } fail++; console.log('  ✗ ' + m); console.log('      expected: ' + JSON.stringify(e)); console.log('      actual:   ' + JSON.stringify(a)); };
const agent = (o) => Object.assign({ status: 'active', expiry: null, budget: 10000, spent: 0, spentToday: 0, perPaymentCap: 1700, dailyCap: 5000, allowedCategories: ['api', 'cloud'], freeRein: false, approvalThreshold: 1500 }, o || {});
const verdict = (a, amt, cat) => { const r = G.evaluate(a, amt, cat === undefined ? 'api' : cat); return r.approved ? 'ALLOW' : r.reason; };

console.log('\n── PER-PAYMENT CAP — inclusive ────────────────────────────────────────────────────────────');
eq(verdict(agent(), 1700), 'ALLOW', 'exactly the cap (1700 of 1700) is ALLOWED — a cap is the maximum, inclusive');
eq(verdict(agent(), 1701), 'PER_PAYMENT_LIMIT', 'one unit over the cap is REFUSED with PER_PAYMENT_LIMIT');
eq(verdict(agent(), 1699), 'ALLOW', 'one under is allowed');

console.log('\n── BALANCE — the whole remaining budget is spendable ──────────────────────────────────────');
eq(verdict(agent({ budget: 10000, spent: 8300 }), 1700), 'ALLOW', 'exactly the remaining budget (1700 of 1700 left) is ALLOWED');
eq(verdict(agent({ budget: 10000, spent: 8300 }), 1701), 'INSUFFICIENT_BALANCE', 'one unit more than remains is REFUSED with INSUFFICIENT_BALANCE (checked before the per-payment cap)');
eq(verdict(agent({ budget: 10000, spent: 10000 }), 1), 'INSUFFICIENT_BALANCE', 'an exhausted budget refuses even 1 unit');

console.log('\n── DAILY CAP — inclusive ──────────────────────────────────────────────────────────────────');
eq(verdict(agent({ spentToday: 3300 }), 1700), 'ALLOW', 'reaching exactly the daily cap (3300 + 1700 = 5000) is ALLOWED');
eq(verdict(agent({ spentToday: 3301 }), 1700), 'DAILY_LIMIT', 'one unit over the daily cap (5001) is REFUSED with DAILY_LIMIT');
eq(verdict(agent({ spentToday: 5000 }), 1), 'DAILY_LIMIT', 'a day already at the cap refuses 1 unit');

console.log('\n── EXPIRY — valid AT the instant, expired strictly after (implemented; diverges from JWT exp) ──');
{ const realNow = Date.now; const T = 1788134400000;
  try {
    Date.now = () => T;
    eq(verdict(agent({ expiry: T }), 100), 'ALLOW', '⚠ at the exact expiry instant (now == expiry) the grant is still VALID — pinned as implemented (Writ house convention; diverges from JWT exp)');
    Date.now = () => T + 1;
    eq(verdict(agent({ expiry: T }), 100), 'EXPIRED', 'one millisecond after expiry → EXPIRED');
    Date.now = () => T - 1;
    eq(verdict(agent({ expiry: T }), 100), 'ALLOW', 'one millisecond before expiry → valid');
  } finally { Date.now = realNow; } }
eq(verdict(agent({ expiry: null }), 100), 'ALLOW', 'no expiry → never expires');

console.log('\n── CATEGORY — exact, case-sensitive identifier ────────────────────────────────────────────');
eq(verdict(agent(), 100, 'api'), 'ALLOW', '"api" is in the set');
eq(verdict(agent(), 100, 'API'), 'CATEGORY_NOT_ALLOWED', '"API" is NOT "api" — no case folding');
eq(verdict(agent(), 100, 'api '), 'CATEGORY_NOT_ALLOWED', '"api " is NOT "api" — no trimming');
eq(verdict(agent(), 100, null), 'ALLOW', 'no category given → the category check does not apply (guardrails.js:19)');

console.log('\n── STATUS and FREE REIN ───────────────────────────────────────────────────────────────────');
eq(verdict(agent({ status: 'frozen' }), 1), 'NOT_ACTIVE', 'a frozen grant refuses everything');
eq(verdict(agent({ freeRein: true }), 9000, 'gambling'), 'ALLOW', 'free_rein bypasses per-payment, daily AND category…');
eq(verdict(agent({ freeRein: true, budget: 100 }), 101), 'INSUFFICIENT_BALANCE', '…but never the balance');

console.log('\n── APPROVAL LINE — strictly above ─────────────────────────────────────────────────────────');
eq(A.needsApproval(agent(), 1500, null), false, 'exactly the approval threshold (1500) does NOT escalate — "above this → ESCALATE"');
eq(A.needsApproval(agent(), 1501, null), true, 'one unit above the threshold ESCALATES');
eq(A.needsApproval(agent({ approvalThreshold: null }), 1e9, null), false, 'no threshold → never escalates (thresholdFor → Infinity)');

console.log('\nguardrails + approvals (boundaries): ' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
