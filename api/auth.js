// ═══ WRITE AUTHENTICATION — the smallest thing that makes the two write paths safe ════════════════════
//
// Review finding (Ramu, 2026-09-06): there was NO authentication code anywhere in `api/`. Not weak — none.
// `POST /grants` mints authority (cap, expiry, categories) and `POST /approvals/:id` resolves an escalation
// while naming any approver it likes. Both were open to anyone who could reach the port.
//
// ⛳ WHAT THIS DELIBERATELY IS NOT. No user model, no per-tenant keys, no rotation endpoint, no sessions,
// no scopes. Cosmos runs on one box for one operator (DESIGN §0.2) and has zero customers; an identity
// system built now would be the breadth-ahead-of-demand this repo has a size guard against. This is one
// shared secret on the two paths that create authority. When a customer needs per-tenant keys, that is a
// deliberate second decision with a real requirement behind it.
//
// ⛳ THE DEFAULT IS THE DESIGN. Three states, and the middle one is the point:
//   · COSMOS_WRITE_TOKEN set          → writes require `Authorization: Bearer <token>`.
//   · production, nothing set         → THE SERVER REFUSES TO START. Same fail-closed shape as the signing
//                                       key: an accidentally-open mint is not a thing you discover later.
//   · COSMOS_ALLOW_UNAUTHENTICATED_WRITES=true → open, and LOUD about it at every startup.
// The explicit opt-out exists because a public demo genuinely wants strangers minting their own grants —
// "try to make it say yes" is the demo. That is a legitimate choice. It is not a legitimate accident.
'use strict';
const crypto = require('crypto');
const { HttpError } = require('./http');

// Constant-time compare over sha256 digests: timingSafeEqual throws on length mismatch, and the LENGTH of
// a secret is itself a leak, so both sides are hashed to a fixed 32 bytes first.
function tokenMatches(presented, expected) {
  const a = crypto.createHash('sha256').update(String(presented)).digest();
  const b = crypto.createHash('sha256').update(String(expected)).digest();
  return crypto.timingSafeEqual(a, b);
}

function bearerFrom(req) {
  const h = (req && req.headers && req.headers.authorization) || '';
  const m = /^Bearer[ ]+(.+)$/.exec(String(h).trim());
  return m ? m[1].trim() : null;
}

// Resolve the policy ONCE at boot, not per request — so a misconfiguration is a startup failure rather
// than a runtime surprise on the first write of the day.
function resolveWritePolicy(opts) {
  opts = opts || {};
  const token = opts.writeToken != null ? opts.writeToken : (process.env.COSMOS_WRITE_TOKEN || null);
  const explicitlyOpen = opts.allowUnauthenticatedWrites != null
    ? !!opts.allowUnauthenticatedWrites
    : process.env.COSMOS_ALLOW_UNAUTHENTICATED_WRITES === 'true';
  const production = opts.production != null ? !!opts.production : process.env.NODE_ENV === 'production';

  if (token) {
    if (String(token).length < 16) throw new Error('WRITE_TOKEN_TOO_SHORT: COSMOS_WRITE_TOKEN must be at least 16 characters — a guessable mint is not protected');
    return { mode: 'token', token: String(token) };
  }
  if (explicitlyOpen) return { mode: 'open' };
  if (production) {
    throw new Error('NO_WRITE_TOKEN: POST /grants and POST /approvals/:id would be open to anyone who can reach this port. ' +
      'Set COSMOS_WRITE_TOKEN (>=16 chars), or set COSMOS_ALLOW_UNAUTHENTICATED_WRITES=true to say you meant it.');
  }
  return { mode: 'open-dev' };
}

// Wrap a route handler so it refuses unauthenticated callers. Applied to the OPERATOR surface:
//   · the two paths that CREATE AUTHORITY — POST /grants, POST /approvals/:id
//   · the two that DISCLOSE THE WHOLE DATASET — GET /audit, GET /approvals   (added 2026-09-06, PR #3)
//
// GET /audit was ranked ABOVE both write paths for confidentiality in review, and that is right: it dumps
// the live projection for every grant — amounts, caps, merchants, categories, org and agent ids. That is
// the entire dataset the product exists to produce, and it was readable by anyone who could reach the port.
// A mint you cannot call is worth less to an attacker than a ledger you can read.
//
// PUBLIC, and asserted to stay that way with no token at all: /authorize (an agent asking permission IS the
// product), /evidence/:id and /.well-known/jwks.json (a verifier with no account is the entire claim), and
// /health (a health check nobody can call is not a health check).
function guardOperator(policy, handler) {
  if (policy.mode !== 'token') return handler;
  return async function guarded(body, params, req) {
    const presented = bearerFrom(req);
    // Same error either way: distinguishing "no token" from "wrong token" tells a prober which half to work on.
    if (!presented || !tokenMatches(presented, policy.token)) {
      throw Object.assign(new HttpError(401, 'UNAUTHORIZED', 'operator path: creates authority or discloses the grant dataset; requires a bearer token'),
        { headers: { 'www-authenticate': 'Bearer realm="cosmos", charset="UTF-8"' } });
    }
    return handler(body, params, req);
  };
}

function describe(policy) {
  if (policy.mode === 'token') return 'operator paths (/grants, /approvals, /audit) require a bearer token';
  if (policy.mode === 'open') return '⚠ OPERATOR PATHS ARE OPEN — COSMOS_ALLOW_UNAUTHENTICATED_WRITES=true; anyone who can reach this port can mint a grant, resolve an approval, and read every grant in /audit';
  return '⚠ operator paths are open (development), including /audit which discloses every grant. Set COSMOS_WRITE_TOKEN before exposing this port.';
}

module.exports = { resolveWritePolicy, guardOperator, tokenMatches, bearerFrom, describe };
