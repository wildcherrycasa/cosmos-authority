// ═══ RAIL — the handoff, and the thing that closes DESIGN §7 ══════════════════════════════════════════
//
// DESIGN §7 is titled "the hardest thing in the product" and its problem is one sentence: Cosmos cannot
// observe the rail, so an ALLOW that never executes leaks budget, and the only defence is a TTL that
// auto-reverses. The TTL is a GUESS — short leaks less but reverses slow-but-successful payments, long
// ties up budget on payments that already failed. There is no value that is right.
//
// A rail that reports back removes the guess in BOTH directions, which is why this is worth a module:
//   · `submitted` — the rail has it, txId in flight → EXTEND the deadline. A slow success stops racing
//                   a timer it did not know about.
//   · `settled`   — final → the reservation never auto-reverses again. The guess is gone entirely.
//   · `failed`    — the budget comes back NOW instead of at TTL. No five-minute hold on money that
//                   provably did not move.
// The TTL survives untouched as the fallback for a rail that says nothing, which is still every rail
// Cosmos has ever talked to. This does not delete the guess; it makes the guess unnecessary whenever the
// other side is willing to speak.
//
// ⛔ THIS DOES NOT MAKE COSMOS OBSERVE THE RAIL, and no field here should be read as if it did. Decision
// (a) is unchanged: Cosmos never touches money and has no way to check a txId. Everything a report
// carries — the tx id, the provider, the outcome — is ASSERTED by whoever held the capability. What
// Cosmos can prove is narrower and must be stated as such: a report was made, against this authorization,
// by a holder of THIS credential class, at this time. That is the same shape as `approver_authenticated`
// (core/receipt.js) and it is in the signed bytes for the same reason: a caveat that lives in a source
// comment is not a caveat, because nobody reading a receipt reads this file.
//
// ⛳ NO ENV READ HERE, DELIBERATELY — same rule as core/receipt-keystore.js since PR #15. Configuration
// arrives as arguments from api/server.js. A module that resolves its own configuration is a module that
// silently inherits a sibling project's when its own is unset, and that is exactly how Cosmos came to
// sign with Writ's private key. Pinned by test/rail.test.js §H.
'use strict';
const crypto = require('crypto');

// How long a `submitted` report pushes the deadline out from the moment it is received. Deliberately
// larger than the 5-minute reservation TTL: the rail has told us it is working, so the failure mode we
// are now guarding against is a rail that dies mid-flight, not a rail that is merely slow.
const DEFAULT_GRACE_MS = 15 * 60 * 1000;

const OUTCOMES = ['submitted', 'settled', 'failed'];
const TERMINAL = ['settled', 'failed'];

// ── the capability ────────────────────────────────────────────────────────────────────────────────────
// One token, one authorization, minted with the ALLOW and returned exactly once. The OPERATOR token is
// deliberately NOT the credential for this path: it mints grants, and a rail that can mint grants is a
// rail that can raise its own ceiling. This token can do exactly one thing to exactly one authorization.
//
// Only the HASH is durable. The raw token is in the ALLOW response and nowhere else — so an attacker who
// reads the entire event log still cannot forge a report, and neither can Cosmos re-serve a lost token.
// The cost of that property is stated where it bites: api/authorize.js rehydrateIdem().
//
// The hash binds the authId, so a token lifted from one authorization cannot be presented against
// another even if a caller mixes them up or a store lookup is mis-keyed.
function mintCapability(authId, randomBytes) {
  const raw = (randomBytes || crypto.randomBytes(32));
  const token = Buffer.from(raw).toString('base64url');
  return { token, hash: capabilityHash(authId, token) };
}

function capabilityHash(authId, token) {
  return crypto.createHash('sha256').update(String(authId) + '|' + String(token)).digest('hex');
}

// Constant-time over fixed-width digests. Both sides are hashed first because timingSafeEqual throws on a
// length mismatch and the length of a presented secret is itself a signal (api/auth.js makes the same
// choice for the same reason).
function capabilityMatches(authId, presented, storedHash) {
  if (typeof presented !== 'string' || !presented || typeof storedHash !== 'string' || !storedHash) return false;
  const a = crypto.createHash('sha256').update(capabilityHash(authId, presented)).digest();
  const b = crypto.createHash('sha256').update(String(storedHash)).digest();
  return crypto.timingSafeEqual(a, b);
}

// ── the fold ──────────────────────────────────────────────────────────────────────────────────────────
// One pure pass over history for ONE authorization. Both the TTL sweep and the report route read the
// lifecycle through this, so "is this reservation still open?" cannot come to mean two different things
// in two files.
//
// Order within the log is authoritative and the writers depend on it: a LATE settlement appends
// [reservation, settlement, status] in that order, so the re-reservation re-opens the row and the
// settlement immediately closes it as final.
function railState(events, authId) {
  const s = {
    authId, grantId: null, amount: 0, decision: null,
    reserved: false, reversed: false, deadline: 0,
    tokenHash: null, outcome: null, txId: null, provider: null, explorer: null,
    reportedAt: null, reportedBy: null, late: false, settled: false, failed: false,
    reportReceiptId: null,
  };
  for (const e of events) {
    if (!e || e.authId !== authId) continue;
    switch (e.kind) {
      case 'decision':
        s.grantId = e.agentId != null ? e.agentId : s.grantId;
        s.decision = e.decisionKind || (e.approved ? 'ALLOW' : 'DENY');
        if (e.amount) s.amount = e.amount;
        break;
      case 'reservation':
        s.reserved = true; s.reversed = false;
        s.grantId = e.agentId != null ? e.agentId : s.grantId;
        if (e.amount) s.amount = e.amount;
        if (e.expiresAt) s.deadline = e.expiresAt;
        if (e.railTokenHash) s.tokenHash = e.railTokenHash;
        break;
      case 'reversal':
        s.reserved = false; s.reversed = true;
        break;
      case 'submission':
        s.outcome = 'submitted';
        s.txId = e.txId || s.txId; s.provider = e.provider || s.provider; s.explorer = e.explorer || s.explorer;
        s.reportedAt = e.ts != null ? e.ts : s.reportedAt; s.reportedBy = e.reportedBy || s.reportedBy;
        s.reportReceiptId = e.receiptId || s.reportReceiptId;
        if (e.expiresAt && e.expiresAt > s.deadline) s.deadline = e.expiresAt;
        break;
      case 'settlement':
        s.outcome = e.outcome === 'failed' ? 'failed' : 'settled';
        s.settled = s.outcome === 'settled'; s.failed = s.outcome === 'failed';
        s.txId = e.txId || s.txId; s.provider = e.provider || s.provider; s.explorer = e.explorer || s.explorer;
        s.reportedAt = e.ts != null ? e.ts : s.reportedAt; s.reportedBy = e.reportedBy || s.reportedBy;
        s.reportReceiptId = e.receiptId || s.reportReceiptId;
        s.late = !!e.late;
        if (s.settled) s.reserved = true;      // final: the money moved, the spend stands
        break;
    }
  }
  return s;
}

// Is this authorization still exposed to the TTL sweep? A settled one never is — that is the whole point
// of the handoff. A failed or already-reversed one has nothing left to reverse.
function sweepable(s) { return s.reserved && !s.settled && !s.failed; }

// ── report validation ─────────────────────────────────────────────────────────────────────────────────
// Closed set, and a report is refused rather than coerced. `outcome` is the only field Cosmos acts on;
// everything else is recorded verbatim and asserted, never checked.
function validateReport(body) {
  const b = body || {};
  if (typeof b.outcome !== 'string' || OUTCOMES.indexOf(b.outcome) === -1) {
    return { ok: false, code: 'INVALID_OUTCOME', detail: 'one of: ' + OUTCOMES.join(', ') };
  }
  for (const f of ['tx_id', 'provider', 'explorer', 'state']) {
    if (b[f] != null && (typeof b[f] !== 'string' || b[f].length > 512)) {
      return { ok: false, code: 'INVALID_' + f.toUpperCase(), detail: 'a string of at most 512 characters' };
    }
  }
  // A settled payment with no transaction id is a claim with nothing in it to look up later. Cosmos
  // cannot check the id, but it can refuse to sign a settlement that names nothing at all.
  if (b.outcome === 'settled' && !(typeof b.tx_id === 'string' && b.tx_id)) {
    return { ok: false, code: 'TX_ID_REQUIRED', detail: 'a settled report must carry the rail\'s transaction id' };
  }
  return {
    ok: true,
    outcome: b.outcome,
    // ⛳ THE RAIL'S OWN WORD, verbatim, never translated. Three outcomes is all Cosmos's ACCOUNTING needs
    // — extend, finalise, return the budget. A real rail is richer: Writ's engine terminates in
    // settled/failed/REVERSED, and `reversed` has no Cosmos equivalent. Mapping it to `failed` is the
    // right arithmetic (the money came back) and the wrong fact (`failed` never executed; `reversed`
    // executed and was undone). So the outcome drives the ledger and the state records what happened.
    // Unvalidated beyond length — it is the reporter's vocabulary, not ours.
    state: b.state == null ? null : b.state,
    txId: b.tx_id == null ? null : b.tx_id,
    provider: b.provider == null ? null : b.provider,
    explorer: b.explorer == null ? null : b.explorer,
  };
}

// ── the events a report produces ──────────────────────────────────────────────────────────────────────
// Returned rather than appended: the caller owns the lock and the batch, and this stays a pure function
// that a test can drive with an explicit `now`.
//
// THE LATE CASE, which is the second of the three questions that had to be answered before any of this
// was written. A settlement arriving after the TTL already auto-reversed means the rail was slower than
// the guess AND the money moved. History is append-only, so the reversal is not undone — a second
// `reservation` restores the spend and the receipt says `rail_late: true`. Re-reserving can push a grant
// past its own budget. It is allowed to, and the record says so: Cosmos reports what happened, and a
// cap that refuses to record a spend that already occurred is a cap that makes the ledger lie.
function reportEvents(state, report, now, graceMs) {
  const grace = graceMs > 0 ? graceMs : DEFAULT_GRACE_MS;
  const base = { ts: now, authId: state.authId, agentId: state.grantId };
  const meta = { txId: report.txId, provider: report.provider, explorer: report.explorer, reportedBy: report.reportedBy || null, state: report.state || null };
  const out = [];

  if (report.outcome === 'submitted') {
    out.push(Object.assign({ kind: 'submission' }, base, meta, { expiresAt: now + grace }));
    out.push(Object.assign({ kind: 'status' }, base, { status: 'submitted' }));
    return { events: out, late: false, reReserved: false, deadline: now + grace };
  }

  if (report.outcome === 'failed') {
    // Only reverse if something is still reserved. A failure report arriving after the TTL already
    // reversed must NOT reverse again — that would credit the budget twice for one payment.
    const reReserved = false;
    if (state.reserved) out.push(Object.assign({ kind: 'reversal' }, base, { amount: state.amount, reason: 'RAIL_FAILED' }));
    out.push(Object.assign({ kind: 'settlement' }, base, meta, { outcome: 'failed', late: false }));
    out.push(Object.assign({ kind: 'status' }, base, { status: 'failed' }));
    return { events: out, late: false, reReserved, deadline: 0 };
  }

  const late = !state.reserved;                    // the TTL got there first
  if (late) out.push(Object.assign({ kind: 'reservation' }, base, { amount: state.amount, reason: 'LATE_SETTLEMENT' }));
  out.push(Object.assign({ kind: 'settlement' }, base, meta, { outcome: 'settled', late }));
  out.push(Object.assign({ kind: 'status' }, base, { status: 'settled' }));
  return { events: out, late, reReserved: late, deadline: 0 };
}

module.exports = {
  mintCapability, capabilityHash, capabilityMatches,
  railState, sweepable, validateReport, reportEvents,
  OUTCOMES, TERMINAL, DEFAULT_GRACE_MS,
};
