// The library entry point. `require('cosmos-authority')` returned MODULE_NOT_FOUND before this existed —
// there was no `main`, so the package had two working binaries, working deep paths, and a failure on the
// single most obvious line anyone would type. Found in review the hour before the first publish, against
// a real node_modules layout rather than by reading package.json.
//
// ⛳ WHAT THIS EXPOSES, and why it is this and not everything: **verification**. The product claim is that
// a stranger can check a receipt with no account and no relationship with the issuer. The Python verifier
// is that claim's reference implementation; this is the same thing for anyone already in Node — an agent
// framework, a marketplace, an auditor's script. Everything else in the repo is how Cosmos DECIDES, which
// is table stakes and reachable by deep path if you want it.
//
// ⚠ DELIBERATELY NO `exports` MAP. One was suggested and it would be a RESTRICTION: an exports map turns
// every unlisted deep path into an error, so `require('cosmos-authority/core/receipt')` — which works
// today — would start throwing for anyone already doing it. Adding `main` alone is strictly additive.
// The map is a 0.2.0 decision once the public surface is worth freezing, not something to slip into the
// release that first defines it.
'use strict';
const receipt = require('./core/receipt');

module.exports = {
  // ── verify a receipt, offline ──────────────────────────────────────────────────────────────────────
  // verify(coseBytes, jwks) -> { ok, kid, keyStatus, payload } | { ok:false, reason }
  // Checks the Ed25519 signature over the COSE_Sign1 Sig_structure, that the schema is one this build
  // accepts, and that any capability proof reaches the committed root. It makes NO network call: fetch
  // the JWKS however you like, then hand it in.
  verify: receipt.verify,

  // Structural read with NO verification, for display only. Named `open` rather than `parse` because it
  // must never be mistaken for a check — reading a receipt and trusting it are different acts.
  open: receipt.open,

  // Build a resolveKey(kid) from a published JWKS — exactly what a stranger does.
  resolverFromJwks: receipt.resolverFromJwks,

  // The schema this build ISSUES, and the set it ACCEPTS. They are different numbers on purpose: an old
  // verifier must fail closed on a newer receipt, while a newer verifier reading an older one has nothing
  // to under-report. Read both before assuming either.
  SCHEMA: receipt.SCHEMA,
  ACCEPTED_SCHEMAS: receipt.ACCEPTED_SCHEMAS,

  // ── run the authority yourself ─────────────────────────────────────────────────────────────────────
  // Lazy, so importing this package to verify one receipt does not pull in the HTTP server, the store or
  // the keystore. `npx cosmos` is the same thing from a shell.
  get startServer() { return require('./api/server').start; },
};
