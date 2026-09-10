// ═══ COSMOS SERVER — wiring only ═══════════════════════════════════════════════════════════════════════
// THE THREE CALLS plus the key publication that makes the third one verifiable. /health and /audit are
// operational: /audit exists so `npm run audit:ledger` can diff in-memory state against the log on disk
// from a SEPARATE process.
'use strict';
const { makeStore } = require('../core/store');
const { makeKeystore } = require('../core/receipt-keystore');
const { makeServer, exact, param } = require('./http');
const { makeGrantsRoute, loadGrants } = require('./grants');
const { makeAuthorizeRoute, rehydrateIdem } = require('./authorize');
const { makeEvidenceRoute, makeJwksRoute } = require('./evidence');
const { makeApprovalsRoute, makeApprovalsListRoute } = require('./approvals');
const { makeSettlementsRoute } = require('./settlements');
const { resolveWritePolicy, guardOperator, describe: describePolicy } = require('./auth');
const approvals = require('../core/approvals');

function parseRetired(s) {
  if (!s) return undefined;
  try { const v = JSON.parse(s); return Array.isArray(v) ? v : (v && Array.isArray(v.keys) ? v.keys : undefined); }
  catch (_) { return undefined; }
}

// Keys come from COSMOS_* env, passed EXPLICITLY. ⚠ That used to be the WHOLE defence and it did not work:
// passing explicitly only shadows the fallback when the explicit value is non-empty, so with
// COSMOS_RECEIPT_PRIVATE_KEY unset on a box that also ran Writ, the keystore silently adopted
// WRIT_RECEIPT_PRIVATE_KEY, this guard saw a live signer and let production start, and the warning below
// said "EPHEMERAL dev key" — three wrong signals at once. The env path is now gone from the module itself.
// A dev key is allowed only outside production and only when no key is configured — and it is LOUD,
// because a restart on a dev key orphans every receipt it signed (test/receipt-keystore.test.js A5-A8).
function makeConfiguredKeystore(opts) {
  const pk = opts.privateKeyPkcs8B64 || process.env.COSMOS_RECEIPT_PRIVATE_KEY || undefined;
  const allowDevKey = opts.allowDevKey != null ? opts.allowDevKey : (!pk && process.env.NODE_ENV !== 'production');
  const ks = makeKeystore({
    kid: opts.kid || process.env.COSMOS_RECEIPT_KID || 'cosmos-receipt-2026-09',
    privateKeyPkcs8B64: pk,
    retired: opts.retired || parseRetired(process.env.COSMOS_RECEIPT_RETIRED_KEYS),
    allowDevKey,
  });
  if (!ks.activeKid()) throw new Error('NO_SIGNING_KEY: set COSMOS_RECEIPT_PRIVATE_KEY (see `npm run keygen`)');
  if (!pk && !opts.quiet) console.warn('[cosmos] WARNING: signing with an EPHEMERAL dev key. Every receipt it signs becomes unverifiable on restart. Run `npm run keygen` and set COSMOS_RECEIPT_PRIVATE_KEY.');
  return ks;
}

// The rail configuration, resolved HERE and passed down as arguments. core/rail.js and api/authorize.js
// read no environment of their own — the PR #15 rule, applied before it can be broken rather than after.
// COSMOS_* only: a rail hint is Cosmos's own configuration and must never fall back to a sibling's.
function resolveRail(opts) {
  const o = opts.rail || {};
  return {
    provider: o.provider != null ? o.provider : (process.env.COSMOS_RAIL_PROVIDER || null),
    endpoint: o.endpoint != null ? o.endpoint : (process.env.COSMOS_RAIL_ENDPOINT || null),
    graceMs: o.graceMs != null ? o.graceMs : (+process.env.COSMOS_RAIL_GRACE_MS || 0),
    // The RAIL's own credential, delivered to the rail out of band and NEVER to the caller. It is what
    // separates "the rail says this payment ended" from "the party that asked to spend says so" — see the
    // header of api/settlements.js for why the second one is a double-spend and not merely a false record.
    token: o.token != null ? o.token : (process.env.COSMOS_RAIL_TOKEN || null),
  };
}

function start(opts = {}) {
  const store = makeStore({ file: opts.file || process.env.COSMOS_LOG || undefined });
  const keystore = makeConfiguredKeystore(opts);
  const idemCount = rehydrateIdem(store);
  const { rehydrated } = approvals.rehydrate(store.events());   // pending ESCALATEs survive a restart

  // Resolved before the first request: a misconfigured mint fails at boot, not on the first write.
  const writePolicy = resolveWritePolicy(opts);
  const railCfg = resolveRail(opts);
  // Same shape as COSMOS_WRITE_TOKEN: a guessable secret is not a secret, and finding that out at boot
  // beats finding it out from the first forged settlement.
  if (railCfg.token && String(railCfg.token).length < 16) {
    throw new Error('RAIL_TOKEN_TOO_SHORT: COSMOS_RAIL_TOKEN must be at least 16 characters');
  }

  const routes = [
    // GUARDED = the OPERATOR surface: the two paths that CREATE AUTHORITY (/grants, POST /approvals/:id)
    // and the two that DISCLOSE THE DATASET (/audit, GET /approvals). Everything else stays reachable — a
    // verifier with no account is the product, and /authorize is what an agent calls.
    { method: 'POST', match: exact('/grants'), handler: guardOperator(writePolicy, makeGrantsRoute(store)) },
    { method: 'POST', match: exact('/authorize'), handler: makeAuthorizeRoute(store, keystore, railCfg, opts.reservationTtlMs) },
    { method: 'GET', match: param('/evidence/', 'id'), handler: makeEvidenceRoute(store, keystore) },
    { method: 'GET', match: exact('/.well-known/jwks.json'), handler: makeJwksRoute(keystore) },
    // The fourth route — resolves an ESCALATE. See api/approvals.js for why it exists and what it means.
    { method: 'POST', match: param('/approvals/', 'id'), handler: guardOperator(writePolicy, makeApprovalsRoute(store, keystore)) },
    { method: 'GET', match: exact('/approvals'), handler: guardOperator(writePolicy, makeApprovalsListRoute()) },
    // The fifth route — the rail reports back. NOT wrapped in guardOperator: it authenticates a
    // PER-AUTHORIZATION capability first and accepts the operator token only as a second class, so that a
    // rail able to report a settlement is not thereby able to mint a grant. See api/settlements.js.
    { method: 'POST', match: param('/settlements/', 'id'), handler: makeSettlementsRoute(store, keystore, writePolicy, railCfg) },
    // DELIBERATELY UNAUTHENTICATED, and deliberately narrower than it was. A health endpoint that needs
    // a token stops being used by the thing that is supposed to call it, so the fix is to say less rather
    // than to guard it (review, 2026-09-06).
    //   REMOVED: `log: store.file()` — the absolute path to the event log. That is filesystem topology
    //   handed to any unauthenticated caller, and it is the one field an orchestrator provably does not
    //   need: it is the difference between "this service is up" and "here is where its evidence lives on
    //   disk." It is still on stdout at startup, where the operator reading it already has the box.
    //   KEPT: `signing_kid`, which is discoverable from the public JWKS anyway, so withholding it here
    //   would be ceremony rather than control.
    //   KEPT, WITH A CAVEAT WORTH RE-DECIDING IF THIS EVER FACES THE PUBLIC INTERNET: the counts are a
    //   business-volume leak (how many grants exist, how much traffic). Acceptable on an internal health
    //   check; on a public host, put /health behind the edge instead of behind a token.
    { method: 'GET', match: exact('/health'), handler: async () => ({
        status: 200,
        body: {
          ok: true, events: store.events().length, skipped_lines: store.skippedLines(),
          grants: Object.keys(loadGrants(store.events())).length,
          idempotency_keys: idemCount, pending_approvals: approvals.list().length,
          signing_kid: keystore.activeKid(),
        },
      }) },
    // /audit discloses EVERY grant. Guarded for confidentiality, not for integrity — see api/auth.js.
    { method: 'GET', match: exact('/audit'), handler: guardOperator(writePolicy, async () => ({ status: 200, body: store.live() })) },
  ];

  // `!= null`, NOT `||` — port 0 means "ask the OS for an ephemeral port" and is falsy.
  const port = opts.port != null ? opts.port : (+process.env.PORT || 8787);
  const server = makeServer(routes);
  server.listen(port, () => {
    if (opts.quiet) return;
    console.log('[cosmos] listening on http://localhost:' + (server.address().port) + '  signing kid: ' + keystore.activeKid());
    console.log('[cosmos] ' + describePolicy(writePolicy));
    console.log('[cosmos] rail handoff: ' + (railCfg.provider ? 'provider=' + railCfg.provider + (railCfg.endpoint ? ' endpoint=' + railCfg.endpoint : '') : 'no provider configured (COSMOS_RAIL_PROVIDER unset) — ALLOWs still issue a settlement capability'));
    // Say this at BOOT, not at the first refusal. A settlement path nobody can drive is a safe default and
    // a confusing one; the operator should learn it from the startup line rather than from a 403.
    console.log('[cosmos] settlement reports: ' + (
      railCfg.token ? 'rail token set — the rail may report settled/failed (with x-cosmos-handoff)'
      : writePolicy.mode === 'token' ? '⚠ no COSMOS_RAIL_TOKEN — only the OPERATOR token can report settled/failed; the handoff capability is limited to `submitted`'
      : '⚠ NO terminal reports are possible: neither COSMOS_RAIL_TOKEN nor COSMOS_WRITE_TOKEN is set, so nothing may report settled/failed. The handoff capability alone may only report `submitted`, deliberately — it is returned to the requester, and a requester that can report `failed` gets its budget back and spends the same money twice.'));
    console.log('[cosmos] log: ' + store.file() + '  (' + store.events().length + ' events, ' +
                store.skippedLines() + ' malformed lines skipped, ' + idemCount + ' idempotency keys, ' +
                rehydrated + ' pending approvals rehydrated)');
  });
  return { server, store, keystore };
}

if (require.main === module) start();
module.exports = { start, makeConfiguredKeystore };
