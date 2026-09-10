#!/usr/bin/env node
// ═══ COSMOS AS AN x402 EXTERNAL VERIFIER (EVC) ═════════════════════════════════════════════════════════
//
// x402-foundation/x402#3376 (`authorization-evidence`, open since 2026-09-05) standardises a pre-payment
// authorization gate: before facilitator verification the resource server spawns a configured external
// verifier, writes ONE JSON request to its stdin, and reads ONE closed verdict from its stdout. That
// interface is the distribution surface — an agent's payment is gated by whatever verifier the deployer
// configures, with no permission needed from anyone. This file makes Cosmos one of those verifiers.
//
// ⚠ THE POINT, and the reason this file exists rather than a comment on the thread: their ALLOW carries
// nothing, and their DENY carries `detail`. The closed schema is
//     allow → { verdict, kind?, consume_nonces? }        ← no room for evidence
//     deny  → { verdict, kind?, code, message, detail? } ← `detail` is a free-form object
// So the one verdict with somewhere to put a signed artifact is the refusal. ⚠ NOTE the scope: x402's own
// spec says a receipt is returned "only on success" (extension-offer-and-receipt.md:263), so the gap is real
// HERE — but "nobody signs the refusal" as a general claim is FALSE (Google AP2, Microsoft; see
// docs/PRIOR-ART-2026-09-08.md). This fills the x402-shaped hole: every DENY carries the Cosmos receipt
// id and the path a stranger fetches to verify it offline. An ALLOW cannot carry it without breaking
// their schema, so it does not try — the receipt still exists and is still fetchable by id.
//
// CONTRACT OBLIGATIONS (read from the PR, not assumed — evcHost.ts + specs/extensions/authorization_evidence.md):
//   · exactly one JSON object on stdout, exit 0. A non-zero exit, a second object, unparseable output,
//     a timeout or an out-of-registry code all make the HOST fail closed — the payment is still denied,
//     but our specific reason is lost. So we always emit a verdict and always exit 0.
//   · `code` MUST be one of the closed 15-code registry below; an unknown code fails their schema check
//     and is never relayed.
//   · `kind` is deliberately OMITTED. It is a self-description class ("classical"/"zk"/"external") defined
//     in EVC §3.5, which is not in this PR. Asserting one we cannot read would be guessing.
//
// ⚠ LIMITATION, stated rather than hidden: the spec calls `evidence` an OPERATOR-SIGNED spend mandate.
// Cosmos does not issue signed bearer mandates today, so the bundle here carries a grant id and the trust
// model is "the verifier trusts its configured Cosmos instance". That is weaker than the spec intends.
// Building a signed mandate is a real artifact and nobody has asked for one yet; it is named here so its
// absence cannot read as an oversight.
'use strict';

// The EVC §9 denial-code registry, closed within wire version 1. Copied verbatim from the PR's types.ts.
const EVC_CODES = new Set(['malformed_input', 'unsupported_version', 'invalid_bundle', 'invalid_proof',
  'untrusted_root', 'delegation_invalid', 'invalid_signature', 'request_mismatch', 'model_mismatch',
  'unknown_capability', 'scope_exceeded', 'expired', 'nonce_missing', 'nonce_replayed', 'internal_error']);

// Cosmos reason → EVC code. DECIDED from the two specs before writing the code, never photographed from
// whichever code happened to run. Every reason `core/guardrails.js` and `core/agent-view.js` can emit
// appears here; test §M fails if one does not, so adding a reason without a mapping cannot ship silently.
const REASON_TO_CODE = Object.freeze({
  PER_PAYMENT_LIMIT:    'scope_exceeded',      // the amount is outside the granted scope
  DAILY_LIMIT:          'scope_exceeded',
  INSUFFICIENT_BALANCE: 'scope_exceeded',
  // ⛳ GRANT_OVERRUN is NOT the same fact as INSUFFICIENT_BALANCE and must not be flattened into it, even
  // though both map to the same wire code. The grant carries MORE settled spend than its own budget — a
  // late rail settlement landed after the TTL had already handed the budget back (core/agent-view.js).
  // `scope_exceeded` is the truthful EVC code: the spend is outside what was granted. What differs is the
  // remedy, and the message carries it, because a caller told "insufficient balance" will retry smaller
  // forever — at negative remaining no amount succeeds and only an operator can clear it.
  GRANT_OVERRUN:        'scope_exceeded',
  CATEGORY_NOT_ALLOWED: 'unknown_capability',  // the category IS the capability (capability-commitment.js)
  CURRENCY_MISMATCH:    'request_mismatch',    // the request does not match the mandate's terms
  EXPIRED:              'expired',
  NOT_ACTIVE:           'delegation_invalid',  // the grant is the delegation; revoked or frozen kills it
  NO_AGENT:             'invalid_bundle',      // the bundle names no usable grant
  GRANT_NOT_FOUND:      'invalid_bundle',
  INVALID_AMOUNT:       'malformed_input',
  // ESCALATE. The gate has NO pending state and MUST NOT fail open, so an approval-required spend is a
  // deny here. `scope_exceeded` is the truthful choice: it is outside what may be authorized without a
  // human. The message says so so the caller is not told a flat no.
  APPROVAL_REQUIRED:    'scope_exceeded',
  // Request-validation failures (HTTP 400). Our adapter built a bad request; that is malformed INPUT to
  // the verifier, not an internal fault, and saying so tells the operator where to look. Found by Ramu:
  // section M used to hand-list four extra names and missed these nine, which defaulted to internal_error.
  CURRENCY_REQUIRED:    'malformed_input',
  GRANT_ID_REQUIRED:    'malformed_input',
  IDEMPOTENCY_KEY_REQUIRED: 'malformed_input',
  INVALID_AMOUNT_MINOR: 'malformed_input',
  INVALID_CATEGORY:     'malformed_input',
  INVALID_DESCRIPTION:  'malformed_input',
  INVALID_MERCHANT:     'malformed_input',
  // Cosmos has no signing key (503). The receipt is the product, so an unsigned allow is worth nothing:
  // deny, and never quietly let the payment through because the evidence layer is down.
  RECEIPT_SIGNER_UNAVAILABLE: 'internal_error',
  RESERVATION_EXPIRED:  'internal_error',
});

const deny = (code, message, detail) => {
  const v = { verdict: 'deny', code: EVC_CODES.has(code) ? code : 'internal_error', message: String(message).slice(0, 400) };
  if (detail && typeof detail === 'object' && !Array.isArray(detail)) v.detail = detail;
  return v;
};
const allow = () => ({ verdict: 'allow' });

// amount arrives in the ASSET's base units (USDC has 6 decimals); Cosmos policy is denominated in the
// CURRENCY's minor units (USD has 2). They are not the same number. The divisor is deployment config, and
// a non-integer conversion is REFUSED rather than rounded — there is no float anywhere in this money path.
// The idempotency key Cosmos requires. Two sources, most specific first:
//   1. what the bundle explicitly asked for — the deployer knows their own retry semantics
//   2. the x402 challenge/nonce, single-use per response, exactly the right grain
// Never random: a random key would make every retry a fresh authorization and reserve budget twice.
//
// ⚠ AND THERE IS NO SAFE THIRD FALLBACK. Ramu's catch on the first version, and he is right: hashing the
// request fields (grant, amount, currency, category, payee) uses ONLY what two IDENTICAL LEGITIMATE spends
// also share. The agent buys the same $5 search twice on purpose; both derive the same key; Cosmos returns
// the first receipt and reserves budget ONCE for two real payments. That is an under-reserve — the exact
// mirror of the double-reserve the random-key comment warns about, and §I only tested the different-spend
// direction, so it passed while being blind to this one.
//
// A retry and a second identical purchase are INDISTINGUISHABLE from here. Guessing either way is a money
// error, so this refuses instead. Cosmos fails closed everywhere else; it fails closed here too.
// `nonce_missing` is in the EVC closed registry and means exactly this, and x402 mints a fresh single-use
// nonce per response — so in real x402 traffic the source is always present and this branch never fires.
function idempotencyKey(bundle, ctx) {
  if (typeof bundle.idempotency_key === 'string' && bundle.idempotency_key) return bundle.idempotency_key;
  const nonce = ctx && (ctx.nonce || ctx.challenge);
  if (typeof nonce === 'string' && nonce) return 'x402:' + nonce;
  return null;   // caller MUST deny; see decide()
}

function toMinor(amount, divisor) {
  const n = typeof amount === 'string' && /^\d+$/.test(amount) ? Number(amount) : amount;
  if (!Number.isInteger(n) || n < 0) return null;
  if (!Number.isInteger(divisor) || divisor < 1) return null;
  return n % divisor === 0 ? n / divisor : null;
}

async function decide(request, opts) {
  const cfg = opts || {};
  const divisor = cfg.divisor == null ? 1 : cfg.divisor;
  if (!request || typeof request !== 'object' || Array.isArray(request)) return deny('malformed_input', 'request is not a JSON object');

  const ctx = request.x402_evc;
  if (!ctx || typeof ctx !== 'object' || Array.isArray(ctx)) return deny('malformed_input', 'no x402_evc envelope member');
  const bundle = request.bundle;
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) return deny('invalid_bundle', 'no bundle');
  if (typeof bundle.grant_id !== 'string' || !bundle.grant_id) return deny('invalid_bundle', 'bundle carries no grant_id');
  if (typeof bundle.currency !== 'string' || typeof bundle.category !== 'string') {
    // x402 expresses an asset and a network, never a policy currency or a spend category. Cosmos policy is
    // written in both, so the bundle (verifier-owned, per the spec) is where they must come from.
    return deny('invalid_bundle', 'bundle must carry currency and category; x402 context expresses neither');
  }

  const amountMinor = toMinor(ctx.amount, divisor);
  if (amountMinor == null) return deny('malformed_input', 'amount is not a non-negative integer, or does not divide evenly by ' + divisor);

  // Fail closed rather than guess. Without a nonce or a caller-supplied key, a retry and a second
  // identical purchase are the same bytes, and picking either reading is a money error in one direction.
  const idem = idempotencyKey(bundle, ctx);
  if (!idem) {
    return deny('nonce_missing',
      'no idempotency source: x402_evc carries no nonce or challenge and the bundle no idempotency_key. ' +
      'A retry and a second identical payment are indistinguishable without one, so this refuses rather ' +
      'than risk reserving budget once for two real spends.');
  }

  let res, body;
  try {
    res = await cfg.fetch(cfg.url + '/authorize', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        grant_id: bundle.grant_id, amount_minor: amountMinor, currency: bundle.currency,
        category: bundle.category, merchant: String(ctx.payee || ctx.resource || 'x402'),
        // ⚠ ALWAYS SEND ONE. `/authorize` requires it (IDEMPOTENCY_KEY_REQUIRED) and this used to send
        // `undefined` whenever the bundle omitted it, which JSON drops — so EVERY x402-gated payment came
        // back `malformed_input` and was denied. The unit tests missed it completely because they stub
        // `fetch`; it took running against a real Cosmos on a phone to see it. §I now asserts the body.
        // Derived, not random: x402 mints a fresh single-use `nonce` per response, so keying on it gives
        // exactly the replay semantics both sides already want — the same challenge cannot spend twice,
        // and a retry of the same challenge returns the same receipt instead of reserving budget again.
        idempotency_key: idem,
      }),
    });
    body = await res.json();
  } catch (e) {
    // Cosmos unreachable is NOT an allow. Ever.
    return deny('internal_error', 'cosmos unreachable: ' + (e && e.message ? e.message : e));
  }
  if (!res.ok) {
    const r = body && body.error ? body.error : 'HTTP ' + res.status;
    return deny(REASON_TO_CODE[r] || 'internal_error', 'cosmos refused the request: ' + r);
  }

  const detail = {};
  // ABSOLUTE, not a relative path. The verdict is read by the resource server and its caller, neither of
  // which knows where Cosmos lives, so '/evidence/<id>' is unfetchable by the one audience that matters.
  // COSMOS_PUBLIC_URL is the externally reachable base; it falls back to the URL we call, which on a
  // default install is localhost and therefore honest about being local rather than pretending otherwise.
  if (body.receipt_id) { detail.cosmos_receipt_id = body.receipt_id; detail.cosmos_evidence = (cfg.publicUrl || cfg.url) + '/evidence/' + body.receipt_id; }
  if (body.reason) detail.cosmos_reason = body.reason;
  const failed = (body.checks || []).filter((c) => c && c.pass === false).map((c) => c.name);
  if (failed.length) detail.failed_checks = failed.slice(0, 4);

  if (body.decision === 'ALLOW') return allow();
  if (body.decision === 'DENY' || body.decision === 'ESCALATE') {
    const code = REASON_TO_CODE[body.reason] || 'scope_exceeded';
    const msg = body.decision === 'ESCALATE'
      ? 'this spend requires human approval and cannot be authorized inline; the signed decision is at ' + (detail.cosmos_evidence || 'the evidence endpoint')
      : 'denied by policy: ' + (body.reason || 'unspecified');
    return deny(code, msg, detail);
  }
  return deny('internal_error', 'cosmos returned no recognisable decision');
}

module.exports = { decide, deny, allow, toMinor, REASON_TO_CODE, EVC_CODES };

if (require.main === module) {
  let raw = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (d) => { raw += d; });
  process.stdin.on('end', async () => {
    let out;
    try {
      let req = null;
      try { req = JSON.parse(raw); } catch (_) { req = undefined; }
      out = req === undefined ? deny('malformed_input', 'stdin is not one JSON document')
                              : await decide(req, {
                                  url: (process.env.COSMOS_URL || 'http://localhost:8787').replace(/\/$/, ''),
                                  publicUrl: (process.env.COSMOS_PUBLIC_URL || '').replace(/\/$/, '') || undefined,
                                  divisor: +(process.env.COSMOS_X402_AMOUNT_DIVISOR || 1),
                                  fetch: (u, o) => fetch(u, Object.assign({ signal: AbortSignal.timeout(+(process.env.COSMOS_X402_TIMEOUT_MS || 2000)) }, o)),
                                });
    } catch (e) {
      out = deny('internal_error', 'verifier fault: ' + (e && e.message ? e.message : e));
    }
    // ONE object, then exit 0 — a non-zero exit would still deny, but as `verifier_nonzero_exit`, losing
    // the code and the receipt id that are the entire reason Cosmos is in this position.
    process.stdout.write(JSON.stringify(out) + '\n');
    process.exit(0);
  });
}
