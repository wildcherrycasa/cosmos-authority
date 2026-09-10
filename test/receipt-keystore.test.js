// ═══ RECEIPT KEYSTORE — Ed25519 identity, rotation, and the published JWKS ═════════════════════════════
//
// This is the module where a mistake is UNRECOVERABLE. Every other bug can be fixed forward; a receipt
// signed by a key nobody can produce again is permanently unverifiable, and "verifiable offline by a
// stranger" is the entire product. So the hazards get tested as loudly as the happy path:
//
//   §A  the dev-key hazard — an unconfigured process silently signs with an EPHEMERAL key
//   §B  private material never reaches the JWKS
//   §C  sign/verify, and THE PREIMAGE CONTRACT — the exact bytes an offline verifier must reproduce
//   §D  JWKS shape (RFC 8037 OKP) and the offline-rebuild property
//   §E  rotation is persistence-bound, and kid reuse is a trap
//   §F  revocation fails closed
//   §G  restart survival — retired public keys round-trip so OLD receipts keep verifying
//   §H  env vars are WRIT_*-named; Cosmos must pass opts explicitly
'use strict';
const K = require('../core/receipt-keystore');
const crypto = require('crypto');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };
const eq = (actual, expected, m) => {
  if (actual === expected) { pass++; console.log('  ✓ ' + m); return; }
  fail++; console.log('  ✗ ' + m);
  console.log('      expected: ' + JSON.stringify(expected));
  console.log('      actual:   ' + JSON.stringify(actual));
};
const throws = (fn, code, m) => {
  try { fn(); fail++; console.log('  ✗ ' + m); console.log('      expected throw ' + code + ', got none'); }
  catch (e) {
    if (String(e.message).includes(code)) { pass++; console.log('  ✓ ' + m); }
    else { fail++; console.log('  ✗ ' + m); console.log('      expected throw ' + code); console.log('      actual:   ' + e.message); }
  }
};

const ENV_KEYS = ['WRIT_RECEIPT_PRIVATE_KEY', 'WRIT_RECEIPT_RETIRED_KEYS', 'WRIT_RECEIPT_KID'];
const ENV_SNAPSHOT = {};
for (const k of ENV_KEYS) ENV_SNAPSHOT[k] = process.env[k];
for (const k of ENV_KEYS) delete process.env[k];

const genPkcs8 = () => crypto.generateKeyPairSync('ed25519')
  .privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
const pubFromSpkiB64 = (b64) =>
  crypto.createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' });
// The verifier's side of sign(): the preimage is the RAW 32 digest bytes (hex-decoded), not the ASCII hex.
const verifySig = (digest, sigB64, spkiB64) =>
  crypto.verify(null, Buffer.from(digest, 'hex'), pubFromSpkiB64(spkiB64), Buffer.from(sigB64, 'base64'));

const DIGEST = crypto.createHash('sha256').update('a cosmos receipt body').digest('hex');
const PK1 = genPkcs8(), PK2 = genPkcs8();

console.log('\n── A · THE DEV-KEY HAZARD — the one unrecoverable mistake ─────────────────────────────────────');

{ const ks = K.makeKeystore({ allowDevKey: false });
  eq(ks.activeKid(), null, 'A1 · ★ allowDevKey:false with no key supplied leaves NO active key');
  eq(ks._size(), 0, 'A2 · the registry is empty');
  throws(() => ks.sign(DIGEST), 'RECEIPT_SIGNER_UNAVAILABLE',
         'A3 · ★★ sign() FAILS CLOSED — it never invents a key to sign with');
  eq(JSON.stringify(ks.jwks()), '{"keys":[]}', 'A4 · the JWKS is empty rather than absent'); }

{ // The hazard itself: the DEFAULT is to generate an ephemeral key. Two processes booted the same way
  // produce the SAME kid but DIFFERENT keys — so a verifier looks up the right kid and still fails.
  const a = K.makeKeystore(), b = K.makeKeystore();
  eq(a.activeKid(), b.activeKid(), 'A5 · ⚠★ two unconfigured keystores share the SAME kid…');
  ok(a.publicSpkiOf(a.activeKid()) !== b.publicSpkiOf(b.activeKid()),
     'A6 · ⚠★ …but hold DIFFERENT keys — the kid is not a promise about the key');
  const sig = a.sign(DIGEST);
  ok(verifySig(DIGEST, sig.signature, a.publicSpkiOf(sig.kid)) === true,
     'A7 · a receipt verifies against the instance that signed it');
  ok(verifySig(DIGEST, sig.signature, b.publicSpkiOf(sig.kid)) === false,
     'A8 · ⚠★★ THE HAZARD: the SAME receipt fails against a restarted process. In production without ' +
     'a persisted key, every receipt becomes permanently unverifiable. Always set allowDevKey:false.'); }

eq(K.DEFAULT_KID, 'cosmos-receipt-unset',
   'A9 · ★ the default kid is inert and Cosmos-branded. It used to be "writ-receipt-2026-01" read from ' +
   'WRIT_RECEIPT_KID, so a Cosmos receipt could be signed under a Writ kid by an environment variable alone.');

console.log('\n── B · PRIVATE MATERIAL NEVER LEAVES ──────────────────────────────────────────────────────────');

{ const ks = K.makeKeystore({ kid: 'cosmos-1', privateKeyPkcs8B64: PK1 });
  const j = JSON.stringify(ks.jwks());
  ok(!j.includes(PK1), 'B1 · ★★ the JWKS does not contain the private key');
  ok(!/"d"\s*:/.test(j), 'B2 · ★ the JWKS has no "d" member (the OKP private scalar)');
  ok(!JSON.stringify(ks.exportRetiredKeys()).includes(PK1),
     'B3 · exportRetiredKeys() carries no private material');
  ok(Object.keys(ks.jwks().keys[0]).every((k) => ['kty', 'crv', 'use', 'kid', 'x', 'status'].includes(k)),
     'B4 · a JWK exposes only kty/crv/use/kid/x/status'); }

console.log('\n── C · SIGN / VERIFY, AND THE BYTES AN OFFLINE VERIFIER MUST REPRODUCE ────────────────────────');

{ const ks = K.makeKeystore({ kid: 'cosmos-1', privateKeyPkcs8B64: PK1 });
  const sig = ks.sign(DIGEST);
  eq(sig.kid, 'cosmos-1', 'C1 · sign() reports the kid it used');
  ok(typeof sig.signature === 'string' && Buffer.from(sig.signature, 'base64').length === 64,
     'C2 · an Ed25519 signature is 64 bytes, base64-encoded');
  ok(verifySig(DIGEST, sig.signature, ks.publicSpkiOf('cosmos-1')), 'C3 · ★ the signature verifies');
  const flipped = (DIGEST[0] === '0' ? '1' : '0') + DIGEST.slice(1);   // deterministically different
  ok(flipped !== DIGEST && !verifySig(flipped, sig.signature, ks.publicSpkiOf('cosmos-1')),
     'C4 · ★ a one-character change to the digest breaks the signature');
  const other = K.makeKeystore({ kid: 'cosmos-1', privateKeyPkcs8B64: PK2 });
  ok(!verifySig(DIGEST, sig.signature, other.publicSpkiOf('cosmos-1')),
     'C5 · ★ the signature does not verify under a different key with the same kid');

  // ═══ THE PREIMAGE CONTRACT — changed 2026-09-01 from ASCII hex to raw bytes ═══
  // These two vectors ARE the interop spec. A verifier in Python/Go/Rust hex-decodes the digest and
  // verifies over 32 bytes; that is now the correct thing to do, and C9 pins that the old ASCII-hex
  // preimage no longer verifies, so the change cannot silently regress.
  const asciiBytes = Buffer.from(DIGEST);         // 64 bytes of ASCII hex — the OLD preimage
  const rawBytes = Buffer.from(DIGEST, 'hex');    // 32 raw bytes        — the CURRENT preimage
  eq(rawBytes.length, 32, 'C6 · the signed message is the 32 RAW digest bytes…');
  eq(asciiBytes.length, 64, 'C7 · …not the 64 ASCII characters of the hex');
  const pub = pubFromSpkiB64(ks.publicSpkiOf('cosmos-1'));
  ok(crypto.verify(null, rawBytes, pub, Buffer.from(sig.signature, 'base64')),
     'C8 · ★★ INTEROP: the signature covers the RAW digest bytes — hex-decode first, as every other ' +
     'signing stack expects');
  ok(!crypto.verify(null, asciiBytes, pub, Buffer.from(sig.signature, 'base64')),
     'C9 · ★★ the OLD ASCII-hex preimage no longer verifies — the change cannot silently regress');

  // Buffer.from(s,'hex') truncates silently, so a malformed digest would otherwise be signed as an
  // EMPTY message and the resulting signature would verify. The guard exists because of that.
  throws(() => ks.sign('zz'), 'INVALID_BINDING_DIGEST', 'C10 · ★★ a non-hex digest is refused');
  throws(() => ks.sign(''), 'INVALID_BINDING_DIGEST', 'C11 · ★ an empty digest is refused');
  throws(() => ks.sign(DIGEST.slice(0, 62)), 'INVALID_BINDING_DIGEST',
         'C12 · ★ a short (31-byte) digest is refused — length is checked, not just alphabet');
  throws(() => ks.sign(DIGEST.toUpperCase()), 'INVALID_BINDING_DIGEST',
         'C13 · ★ UPPERCASE hex is refused — one canonical form, so the same body never has two digests');
  throws(() => ks.sign(Buffer.from(DIGEST, 'hex')), 'INVALID_BINDING_DIGEST',
         'C14 · ★ a Buffer is refused — the contract is a 64-char lowercase hex string');
  throws(() => ks.sign(null), 'INVALID_BINDING_DIGEST', 'C15 · null is refused');

  { const dead = K.makeKeystore({ allowDevKey: false });
    throws(() => dead.sign('zz'), 'RECEIPT_SIGNER_UNAVAILABLE',
           'C16 · ★ signer availability is checked BEFORE digest shape — the more fundamental failure wins'); } }

console.log('\n── D · JWKS SHAPE (RFC 8037 OKP) AND OFFLINE REBUILD ──────────────────────────────────────────');

{ const ks = K.makeKeystore({ kid: 'cosmos-1', privateKeyPkcs8B64: PK1 });
  const jwk = ks.jwks().keys[0];
  eq(jwk.kty, 'OKP', 'D1 · kty is OKP');
  eq(jwk.crv, 'Ed25519', 'D2 · crv is Ed25519');
  eq(jwk.use, 'sig', 'D3 · use is sig');
  eq(jwk.kid, 'cosmos-1', 'D4 · kid is carried');
  eq(jwk.status, 'active', 'D5 · status is exposed so a verifier can see revocation');
  eq(Buffer.from(jwk.x.replace(/-/g, '+').replace(/_/g, '/'), 'base64').length, 32,
     'D6 · x decodes to a 32-byte raw public key');
  ok(!/[+/=]/.test(jwk.x), 'D7 · ★ x is base64URL — no +, / or = padding');

  // THE PRODUCT PROPERTY: a stranger with only the JWKS can verify a real receipt.
  const rebuiltSpki = K.spkiFromRawB64url(jwk.x);
  eq(rebuiltSpki, ks.publicSpkiOf('cosmos-1'), 'D8 · ★ the JWKS x rebuilds the exact SPKI');
  const sig = ks.sign(DIGEST);
  ok(verifySig(DIGEST, sig.signature, rebuiltSpki),
     'D9 · ★★ a verifier holding ONLY the published JWKS can verify a real signature');

  eq(K.b64url(K.rawPubFromSpki(ks.publicSpkiOf('cosmos-1'))), jwk.x,
     'D10 · rawPubFromSpki + b64url round-trips to the published x');
  throws(() => K.spkiFromRawB64url('c2hvcnQ'), 'BAD_JWK_X', 'D11 · a short x is refused, not padded');
  eq(ks.statusOf('nope'), null, 'D12 · statusOf() on an unknown kid is null');
  eq(ks.publicSpkiOf('nope'), null, 'D13 · publicSpkiOf() on an unknown kid is null'); }

console.log('\n── E · ROTATION IS PERSISTENCE-BOUND ──────────────────────────────────────────────────────────');

{ const ks = K.makeKeystore({ kid: 'cosmos-1', privateKeyPkcs8B64: PK1 });
  throws(() => ks.rotate(), 'ROTATION_KID_REQUIRED', 'E1 · rotate() with no kid is refused');
  throws(() => ks.rotate(''), 'ROTATION_KID_REQUIRED', 'E2 · rotate("") is refused');
  throws(() => ks.rotate('cosmos-2'), 'ROTATION_REQUIRES_PERSISTED_KEY',
         'E3 · ★★ rotate() without a supplied key is REFUSED — a generated key would die with the ' +
         'process and orphan every receipt it signed');
  throws(() => ks.rotate('cosmos-1', { privateKeyPkcs8B64: PK2 }), 'ROTATION_KID_IN_USE',
         'E4 · rotating onto the ACTIVE kid is refused'); }

{ const ks = K.makeKeystore({ kid: 'cosmos-1', privateKeyPkcs8B64: PK1 });
  const before = ks.sign(DIGEST);
  const oldSpki = ks.publicSpkiOf('cosmos-1');
  ks.rotate('cosmos-2', { privateKeyPkcs8B64: PK2 });
  eq(ks.activeKid(), 'cosmos-2', 'E5 · the new kid becomes active');
  eq(ks.statusOf('cosmos-1'), 'retired', 'E6 · ★ the previous key is retired, not deleted');
  eq(ks.statusOf('cosmos-2'), 'active', 'E7 · the new key is active');
  eq(ks.sign(DIGEST).kid, 'cosmos-2', 'E8 · new receipts are signed by the new key');
  ok(ks.jwks().keys.some((k) => k.kid === 'cosmos-1'),
     'E9 · ★ the retired key REMAINS in the JWKS');
  ok(verifySig(DIGEST, before.signature, oldSpki),
     'E10 · ★★ a receipt signed BEFORE rotation still verifies afterwards'); }

{ const ks = K.makeKeystore({ kid: 'cosmos-1', privateKeyPkcs8B64: PK1 });
  ks.rotate('cosmos-2', { allowGeneratedKey: true });
  eq(ks.activeKid(), 'cosmos-2', 'E11 · allowGeneratedKey:true is the dev-only escape hatch'); }

{ // ⚠ TRAP: rotating BACK onto a retired kid is permitted, and it overwrites that kid's public key —
  // silently orphaning every receipt already signed under it.
  const ks = K.makeKeystore({ kid: 'cosmos-1', privateKeyPkcs8B64: PK1 });
  const old = ks.sign(DIGEST); const oldSpki = ks.publicSpkiOf('cosmos-1');
  ks.rotate('cosmos-2', { privateKeyPkcs8B64: PK2 });
  ks.rotate('cosmos-1', { privateKeyPkcs8B64: genPkcs8() });   // reuse a RETIRED kid — allowed
  eq(ks.activeKid(), 'cosmos-1', 'E12 · ⚠ rotating onto a RETIRED kid is allowed');
  ok(ks.publicSpkiOf('cosmos-1') !== oldSpki,
     'E13 · ⚠★ …and it REPLACES that kid\'s public key in the registry');
  ok(!verifySig(DIGEST, old.signature, ks.publicSpkiOf('cosmos-1')),
     'E14 · ⚠★★ TRAP: receipts signed under the original cosmos-1 no longer verify. ' +
     'Cosmos must NEVER reuse a kid — make them monotonic (cosmos-receipt-2026-09, -10, …)'); }

console.log('\n── F · REVOCATION FAILS CLOSED ────────────────────────────────────────────────────────────────');

{ const ks = K.makeKeystore({ kid: 'cosmos-1', privateKeyPkcs8B64: PK1 });
  eq(ks.revoke('cosmos-1'), true, 'F1 · revoke() reports success');
  eq(ks.statusOf('cosmos-1'), 'revoked', 'F2 · the key is marked revoked');
  eq(ks.activeKid(), null, 'F3 · ★ revoking the ACTIVE key clears activeKid');
  throws(() => ks.sign(DIGEST), 'RECEIPT_SIGNER_UNAVAILABLE',
         'F4 · ★★ signing after revocation fails closed');
  const jwk = ks.jwks().keys.find((k) => k.kid === 'cosmos-1');
  ok(jwk && jwk.status === 'revoked',
     'F5 · ★ the revoked key STAYS published as revoked — a verifier gets KEY_REVOKED, not KEY_UNKNOWN');
  eq(ks.revoke('never-existed'), false, 'F6 · revoking an unknown kid returns false'); }

console.log('\n── G · RESTART SURVIVAL — the whole reason exportRetiredKeys() exists ──────────────────────────');

{ const first = K.makeKeystore({ kid: 'cosmos-1', privateKeyPkcs8B64: PK1 });
  const receipt = first.sign(DIGEST);
  first.rotate('cosmos-2', { privateKeyPkcs8B64: PK2 });
  const persisted = first.exportRetiredKeys();

  ok(persisted.length === 1 && persisted[0].kid === 'cosmos-1',
     'G1 · exportRetiredKeys() yields exactly the non-active keys');
  ok(!persisted.some((k) => k.status === 'active'), 'G2 · nothing exported is marked active');

  // "Restart": a brand-new process with only the persisted PUBLIC keys plus the current private key.
  const restarted = K.makeKeystore({ kid: 'cosmos-2', privateKeyPkcs8B64: PK2, retired: persisted });
  eq(restarted.statusOf('cosmos-1'), 'retired', 'G3 · ★ the retired key is reloaded after restart');
  ok(restarted.jwks().keys.some((k) => k.kid === 'cosmos-1'), 'G4 · ★ it is served in the new JWKS');
  ok(verifySig(DIGEST, receipt.signature, restarted.publicSpkiOf('cosmos-1')),
     'G5 · ★★ a receipt signed before the restart STILL VERIFIES — this is the property that makes ' +
     'evidence durable across deploys'); }

{ // _loadRetired must never re-activate: even input claiming to be active comes back retired.
  const first = K.makeKeystore({ kid: 'cosmos-1', privateKeyPkcs8B64: PK1 });
  const x = first.jwks().keys[0].x;
  const ks = K.makeKeystore({ allowDevKey: false, retired: [{ kid: 'cosmos-1', x, status: 'active' }] });
  eq(ks.statusOf('cosmos-1'), 'retired',
     'G6 · ★★ a persisted key claiming status:"active" is loaded as RETIRED — a public-only key can ' +
     'never become the signer');
  eq(ks.activeKid(), null, 'G7 · …and it does not become activeKid');
  throws(() => ks.sign(DIGEST), 'RECEIPT_SIGNER_UNAVAILABLE', 'G8 · so signing still fails closed'); }

{ const first = K.makeKeystore({ kid: 'cosmos-1', privateKeyPkcs8B64: PK1 });
  const x = first.jwks().keys[0].x;
  const ks = K.makeKeystore({ allowDevKey: false, retired: [{ kid: 'cosmos-1', x, status: 'revoked' }] });
  eq(ks.statusOf('cosmos-1'), 'revoked', 'G9 · ★ a revoked status survives export/import'); }

{ const ks = K.makeKeystore({ allowDevKey: false, retired: [
    { x: 'no-kid' }, { kid: '' }, { kid: 'bad-x', x: 'zzz' }, { kid: 'no-material' }, null,
  ] });
  eq(ks._size(), 0, 'G10 · ★ malformed retired entries are skipped, not crashed on');
  eq(K.makeKeystore({ allowDevKey: false, retired: 'not-an-array' })._size(), 0,
     'G11 · a non-array retired value is ignored'); }

console.log('\n── H · ENVIRONMENT — THE MODULE READS NONE. Key material enters only through opts ─────────────');
// ⚠⚠ THIS SECTION USED TO ASSERT THE OPPOSITE, and the old assertions were the bug rather than the guard.
// This module is forked from Writ and resolved its own key material from WRIT_RECEIPT_PRIVATE_KEY,
// WRIT_RECEIPT_RETIRED_KEYS and WRIT_RECEIPT_KID. api/server.js passes COSMOS_* values explicitly and
// carried a comment saying that meant "the module's own WRIT_* env path is never relied on" — which is
// only true when the explicit value is non-empty. With COSMOS_RECEIPT_PRIVATE_KEY unset on a host that
// also runs Writ (the founder's own box runs both), the fallback fired and Cosmos:
//   1. signed Cosmos receipts with WRIT's private key,
//   2. published WRIT's public key in Cosmos's JWKS under a Cosmos kid,
//   3. satisfied the production NO_SIGNING_KEY fail-closed guard, so the server started,
//   4. and printed "signing with an EPHEMERAL dev key", which was false and pointed elsewhere.
// Reproduced before the fix, at both keystore and server level. The env surface is now gone entirely.

{ process.env.WRIT_RECEIPT_PRIVATE_KEY = PK1;
  const ks = K.makeKeystore({ kid: 'from-env', allowDevKey: false });
  eq(ks.activeKid(), null,
     'H1 · ★★ a WRIT-named private key in the environment does NOT become a Cosmos signer — cross-project key adoption is impossible, not merely discouraged');
  const ks2 = K.makeKeystore({ kid: 'from-opts', privateKeyPkcs8B64: PK2, allowDevKey: false });
  eq(ks2.activeKid(), 'from-opts', 'H2 · ★ opts.privateKeyPkcs8B64 is the ONLY way in, and it still works');
  ok(ks2.publicSpkiOf('from-opts') !== K.makeKeystore({ kid: 'x', privateKeyPkcs8B64: PK1, allowDevKey: false }).publicSpkiOf('x'),
     'H2b · the key that got in is the one that was passed, not the one in the environment');
  delete process.env.WRIT_RECEIPT_PRIVATE_KEY; }

{ const first = K.makeKeystore({ kid: 'cosmos-1', privateKeyPkcs8B64: PK1 });
  process.env.WRIT_RECEIPT_RETIRED_KEYS = JSON.stringify(first.jwks());   // a whole JWKS blob
  eq(K.makeKeystore({ allowDevKey: false })._size(), 0,
     'H3 · ★★ WRIT_RECEIPT_RETIRED_KEYS is ignored — it used to load Writ retired PUBLIC keys into the registry, which Cosmos then republished as its own JWKS');
  delete process.env.WRIT_RECEIPT_RETIRED_KEYS;
  eq(K.makeKeystore({ retired: first.jwks(), allowDevKey: false }).statusOf('cosmos-1'), 'retired',
     'H4 · ★ …while a JWKS blob passed through opts.retired is still accepted, so the capability was removed from the environment only'); }

{ process.env.COSMOS_RECEIPT_PRIVATE_KEY = PK1;
  eq(K.makeKeystore({ kid: 'k', allowDevKey: false }).activeKid(), null,
     'H5 · ★★ the module does not read COSMOS_* either. It has NO environment surface at all, so the next project to fork it cannot inherit this bug by renaming the variable.');
  delete process.env.COSMOS_RECEIPT_PRIVATE_KEY; }

// ⚠ DEAD CODE, recorded rather than faked. _add() throws KEY_REQUIRES_PUBLIC_OR_PRIVATE when given
// neither public nor private material — but it is UNREACHABLE through the public API. _loadRetired()
// already `continue`s on a key with no usable material (line 54), and bootstrap() only ever calls _add()
// with a private key. An earlier draft of this test "proved" the throw by throwing it itself; that is a
// decorative test, so it was replaced with the honest assertion: the path cannot be reached.
{ const ks = K.makeKeystore({ allowDevKey: false, retired: [{ kid: 'x', publicSpkiB64: null }] });
  eq(ks._size(), 0,
     'H5 · ⚠★ a retired entry with no key material is SKIPPED, so KEY_REQUIRES_PUBLIC_OR_PRIVATE is ' +
     'unreachable via the public API — dead code, not a guard Cosmos can rely on'); }

for (const k of ENV_KEYS) { if (ENV_SNAPSHOT[k] === undefined) delete process.env[k]; else process.env[k] = ENV_SNAPSHOT[k]; }

console.log('\nreceipt-keystore: ' + pass + ' passed, ' + fail + ' failed');
if (fail) process.exit(1);
