// ═══ WRIT RECEIPT SIGNING KEYSTORE — a DEDICATED Ed25519 identity + rotation registry ══════════════════════════
//
// The receipt-signing identity is SEPARATE from the settlement/general keys and uses NO HMAC/shared-secret path. The
// private key lives only in the keystore (from env WRIT_RECEIPT_PRIVATE_KEY as pkcs8-der base64, a managed-key ref in
// prod, or a generated dev key); it NEVER appears in a receipt or the JWKS. The registry tracks the active signing
// key plus retired keys (still valid for historical verification) and revoked keys (their receipts must fail). The
// JWKS publishes ONLY the public keys, keyed by kid, so an offline verifier trusts what Writ actually published.
//
// ROTATION IS PERSISTENCE-BOUND (PR#65 r2). A rotated-to key that exists only in one process is lost on restart —
// every receipt it signed becomes unverifiable, and the retired key silently drops out of the JWKS so OLD receipts
// start returning KEY_UNKNOWN. So: rotate() REQUIRES an explicitly supplied (already-persisted) private key unless a
// test opts in, and retired PUBLIC keys are loaded at bootstrap from WRIT_RECEIPT_RETIRED_KEYS (or opts.retired) —
// exportRetiredKeys() produces exactly that value, so an operator can persist it after every rotation.
'use strict';
const crypto = require('crypto');

// ⚠ NO ENV READ HERE, DELIBERATELY. This module is forked from Writ and used to resolve its own key
// material from WRIT_RECEIPT_* environment variables. On a host running both projects — which is the
// founder's own box — that let Cosmos pick up WRIT_RECEIPT_PRIVATE_KEY whenever COSMOS_RECEIPT_PRIVATE_KEY
// was unset, then sign Cosmos receipts with Writ's key and publish Writ's public key in Cosmos's JWKS.
// Key material now enters ONLY through opts, so a caller cannot get a signer it did not ask for.
const DEFAULT_KID = 'cosmos-receipt-unset';
const ED_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');   // Ed25519 SubjectPublicKeyInfo prefix (12 bytes) + 32-byte raw key
const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
// raw 32-byte Ed25519 public key from an spki-der (base64) — the JWKS `x` value.
function rawPubFromSpki(spkiDerB64) { const der = Buffer.from(spkiDerB64, 'base64'); return der.subarray(der.length - 32); }
// …and back: an spki-der (base64) from a JWKS `x` (base64url raw key) so a published key can be re-imported.
function spkiFromRawB64url(x) {
  const raw = Buffer.from(String(x).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (raw.length !== 32) throw new Error('BAD_JWK_X');
  return Buffer.concat([ED_SPKI_PREFIX, raw]).toString('base64');
}

function makeKeystore(opts = {}) {
  const registry = new Map();   // kid -> { kid, privateKey: KeyObject|null, publicSpkiB64, status, created_at }
  let activeKid = null;

  function _add({ kid, privateKeyPkcs8B64, publicSpkiB64, status = 'active', createdAt }) {
    let priv = null, pubB64 = publicSpkiB64 || null;
    if (privateKeyPkcs8B64) {
      priv = crypto.createPrivateKey({ key: Buffer.from(privateKeyPkcs8B64, 'base64'), format: 'der', type: 'pkcs8' });
      pubB64 = crypto.createPublicKey(priv).export({ type: 'spki', format: 'der' }).toString('base64');
    }
    if (!pubB64) throw new Error('KEY_REQUIRES_PUBLIC_OR_PRIVATE');
    registry.set(kid, { kid, privateKey: priv, publicSpkiB64: pubB64, status, created_at: createdAt || (opts.now ? opts.now : null) });
    if (status === 'active') activeKid = kid;
    return kid;
  }

  // Load previously-published (retired/revoked) PUBLIC keys so historical receipts still verify after a restart.
  // Accepts JWKS-shaped entries ({ kid, x, status }) or ({ kid, publicSpkiB64, status }).
  function _loadRetired(list) {
    if (!Array.isArray(list)) return;
    for (const k of list) {
      if (!k || typeof k.kid !== 'string' || !k.kid) continue;
      const status = k.status === 'revoked' ? 'revoked' : 'retired';    // never re-activate a persisted key
      let pub = k.publicSpkiB64 || null;
      if (!pub && k.x) { try { pub = spkiFromRawB64url(k.x); } catch (_) { continue; } }
      if (!pub) continue;
      _add({ kid: k.kid, publicSpkiB64: pub, status, createdAt: k.created_at || null });
    }
  }

  // bootstrap: retired/revoked public keys FIRST (never active), then the active signing key.
  (function bootstrap() {
    // Retired keys likewise arrive only through opts. Reading WRIT_RECEIPT_RETIRED_KEYS here used to load
    // Writ's retired public keys into Cosmos's registry, which then published them in Cosmos's JWKS.
    let retired = opts.retired;
    if (retired && !Array.isArray(retired) && Array.isArray(retired.keys)) retired = retired.keys;  // a JWKS blob is fine too
    _loadRetired(retired);
    if (opts.privateKeyPkcs8B64) { _add({ kid: opts.kid || DEFAULT_KID, privateKeyPkcs8B64: opts.privateKeyPkcs8B64 }); return; }
    if (opts.allowDevKey !== false) {   // dev/test: a generated identity (prod injects via env/managed key)
      const { privateKey } = crypto.generateKeyPairSync('ed25519');
      _add({ kid: opts.kid || DEFAULT_KID, privateKeyPkcs8B64: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64') });
    }
    // else: no signer available — sign() will fail closed (RECEIPT_SIGNER_UNAVAILABLE).
  })();

  return {
    activeKid: () => activeKid,
    statusOf: (kid) => { const k = registry.get(kid); return k ? k.status : null; },
    publicSpkiOf: (kid) => { const k = registry.get(kid); return k ? k.publicSpkiB64 : null; },
    // Sign a binding digest with the ACTIVE key → { kid, signature (base64) }. Fails closed.
    //
    // ═══ PREIMAGE CONTRACT — changed 2026-09-01, deliberately, before any receipt existed ═══
    // The signature covers the RAW 32 DIGEST BYTES. It previously signed Buffer.from(hexString), i.e.
    // the 64 ASCII characters of the hex — because Buffer.from(str) with no encoding is UTF-8. Every
    // non-JS verifier gets that wrong: they hex-decode first and then verify over 32 bytes, which fails
    // on every receipt. Raw bytes is what every other signing stack does, and the verifier here is a
    // stranger with no account, so least surprise wins. NOT backward compatible — that is why it was
    // changed while zero receipts existed.
    //
    // The shape is validated because Buffer.from(s, 'hex') TRUNCATES SILENTLY on a malformed string
    // ('zz' yields an EMPTY buffer). Without this guard a bad digest would produce a real signature over
    // the empty message, which verifies. Fail closed instead.
    sign(bindingDigest) {
      const k = registry.get(activeKid);
      if (!k || !k.privateKey) throw new Error('RECEIPT_SIGNER_UNAVAILABLE');
      if (typeof bindingDigest !== 'string' || !/^[0-9a-f]{64}$/.test(bindingDigest)) throw new Error('INVALID_BINDING_DIGEST');
      return { kid: k.kid, signature: crypto.sign(null, Buffer.from(bindingDigest, 'hex'), k.privateKey).toString('base64') };
    },

    // Sign ARBITRARY bytes. Added 2026-09-05 for COSE_Sign1, which signs the ToBeSigned structure directly
    // rather than a digest — Ed25519 hashes internally, so there is no separate digest step and no
    // preimage ambiguity to get wrong. Returns a raw 64-byte Buffer, not base64.
    signBytes(message) {
      const k = registry.get(activeKid);
      if (!k || !k.privateKey) throw new Error('RECEIPT_SIGNER_UNAVAILABLE');
      if (!Buffer.isBuffer(message) && !(message instanceof Uint8Array)) throw new Error('INVALID_SIGN_INPUT');
      return crypto.sign(null, Buffer.isBuffer(message) ? message : Buffer.from(message), k.privateKey);
    },
    // rotate: retire the current active key and activate a NEW one under a new kid. The new key MUST already be
    // persisted by the operator (passed in as privateKeyPkcs8B64) — otherwise it dies with this process and the
    // receipts it signs can never be verified again. allowGeneratedKey:true is a test/dev-only escape hatch.
    // After rotating, persist exportRetiredKeys() into WRIT_RECEIPT_RETIRED_KEYS so old receipts keep verifying.
    rotate(newKid, rotOpts = {}) {
      if (typeof newKid !== 'string' || !newKid) throw new Error('ROTATION_KID_REQUIRED');
      if (registry.has(newKid) && registry.get(newKid).status !== 'retired') throw new Error('ROTATION_KID_IN_USE');
      let pk = rotOpts.privateKeyPkcs8B64;
      if (!pk) {
        if (rotOpts.allowGeneratedKey !== true) throw new Error('ROTATION_REQUIRES_PERSISTED_KEY');
        pk = crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
      }
      if (activeKid && registry.get(activeKid)) registry.get(activeKid).status = 'retired';
      return _add({ kid: newKid, privateKeyPkcs8B64: pk });
    },
    // revoke a kid: its published key stays in the JWKS marked revoked → offline verify returns KEY_REVOKED.
    revoke(kid) { const k = registry.get(kid); if (k) { k.status = 'revoked'; if (activeKid === kid) activeKid = null; } return !!k; },
    // JWKS — PUBLIC keys only (never private material). Active + retired + revoked (with status) for historical verify.
    jwks() {
      return { keys: [...registry.values()].map((k) => ({ kty: 'OKP', crv: 'Ed25519', use: 'sig', kid: k.kid, x: b64url(rawPubFromSpki(k.publicSpkiB64)), status: k.status })) };
    },
    // The value to persist into WRIT_RECEIPT_RETIRED_KEYS: every NON-active published key (public material only), so
    // a restarted process still serves them in its JWKS and old receipts keep verifying.
    exportRetiredKeys() {
      return [...registry.values()].filter((k) => k.status !== 'active')
        .map((k) => ({ kid: k.kid, kty: 'OKP', crv: 'Ed25519', x: b64url(rawPubFromSpki(k.publicSpkiB64)), status: k.status }));
    },
    _size: () => registry.size,
  };
}

module.exports = { makeKeystore, DEFAULT_KID, ED_SPKI_PREFIX, rawPubFromSpki, spkiFromRawB64url, b64url };
