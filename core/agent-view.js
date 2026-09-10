// ═══ AGENT VIEW — the adapter seam ═════════════════════════════════════════════════════════════════════
//
// The ported modules disagree about their own vocabulary. Rather than edit any of them, every mismatch is
// absorbed here. Field names on the right-hand side are dictated by guardrails.js:5-20 and approvals.js:17
// — read those two before changing anything in this file.
//
// Three DESIGN §5 gaps land here:
//   Gap 1 — units. guardrails does float arithmetic; authorization-envelope THROWS on anything but a
//           positive integer. Resolution: integer minor units everywhere, including into evaluate().
//           `.toFixed(6)` on integers is a harmless no-op, and float error disappears entirely.
//   Gap 2 — replay.js does NOT fold spentToday (test/replay.test.js H1), but guardrails.js:18 needs it
//           for the daily cap. Folded here instead.
//   Gap 3 — guardrails is currency-blind: a USD grant would happily authorize a JPY request. Checked
//           here, BEFORE evaluate(), and prepended to the checks array.
'use strict';
const guardrails = require('./guardrails');

const DAY_MS = 86400000;

// DAY BOUNDARY = UTC. Founder default, 2026-09-05. The alternative was a per-grant timezone, which costs
// a grant field and a DST story; UTC is simplest and defensible. Changing it re-buckets every daily cap.
const utcDayStart = (ts) => Math.floor(ts / DAY_MS) * DAY_MS;

// Sum this grant's reservations in the current UTC day, minus reversals in the same window.
function spentToday(events, grantId, now) {
  const start = utcDayStart(now);
  let total = 0;
  for (const e of events) {
    if (!e || e.agentId !== grantId || !(e.ts >= start)) continue;
    if (e.kind === 'reservation') total += e.amount || 0;
    else if (e.kind === 'reversal') total -= e.amount || 0;
  }
  return total > 0 ? total : 0;
}

// grant + folded state -> exactly the shape guardrails.evaluate() and approvals.thresholdFor() expect.
// NOTE: replay keys its `agents` map by the event's `agentId` field, and Cosmos puts the GRANT id there —
// the grant is the budget-bearing entity. The real agent_id lives on the grant and in the receipt.
function agentView(grant, folded, events, now) {
  const a = (folded && folded.agents && folded.agents[grant.grant_id]) || { budget: 0, spent: 0, status: 'active' };
  return {
    status: grant.status === 'active' ? a.status : grant.status,   // a revoked grant overrides the fold
    expiry: grant.expires_at == null ? null : grant.expires_at,
    budget: a.budget,
    spent: a.spent,
    spentToday: spentToday(events, grant.grant_id, now),
    perPaymentCap: grant.per_payment_cap_minor,
    dailyCap: grant.daily_cap_minor,
    allowedCategories: grant.allowed_categories,
    freeRein: !!grant.free_rein,
    approvalThreshold: grant.approval_threshold_minor == null ? null : grant.approval_threshold_minor,
  };
}

// The full policy decision. Returns the SAME shape as guardrails.evaluate(), with the currency check
// prepended — so a receipt's `checks` array is (adapter checks ++ guardrails checks), in that order.
// A verifier must not assume every check came from guardrails.
function decide(grant, view, amountMinor, currency, category) {
  const currencyOk = String(currency) === String(grant.currency);
  const checks = [{ name: 'Currency matches grant', pass: currencyOk }];
  if (!currencyOk) return { approved: false, reason: 'CURRENCY_MISMATCH', checks };
  const g = guardrails.evaluate(view, amountMinor, category);
  const out = checks.concat(g.checks || []);

  // ⛳ GRANT OVERRUN — spent EXCEEDS budget, which `INSUFFICIENT_BALANCE` describes wrongly.
  //
  // Until the rail handoff this state was unreachable: nothing could push `spent` past `budget`, because
  // every reservation was checked against the remaining balance first. A LATE settlement can
  // (api/settlements.js question 2) — the TTL handed budget back on an assumption that turned out false,
  // the money had in fact moved, and the correction re-reserves it. That is the honest record and it can
  // land a grant above its own ceiling.
  //
  // guardrails ALREADY refuses every further spend here — `remaining` is negative, so `amount <= remaining`
  // fails for any positive amount — so this is not a new control, and behaviour does not change. What
  // changes is the NAME. `INSUFFICIENT_BALANCE` reads as "ask for less and it will work"; at negative
  // remaining no amount works and the grant needs an operator, not a smaller request. A reason code that
  // sends a reader down a path with no end is a lie of the same family as a receipt that over-claims.
  //
  // ⛔ NOT fixed in guardrails.js on purpose: it is a FROZEN vendored copy, byte-identical to Writ's
  // (the vendoring manifest), and this is exactly the vocabulary mismatch the adapter seam absorbs.
  if (!g.approved && g.reason === 'INSUFFICIENT_BALANCE' && +view.spent > +view.budget) {
    return { approved: false, reason: 'GRANT_OVERRUN',
             checks: out.concat([{ name: 'Grant not in overrun', pass: false }]) };
  }
  return { approved: !!g.approved, reason: g.reason || null, checks: out };
}

module.exports = { agentView, decide, spentToday, utcDayStart, DAY_MS };
