// ═══ CAPABILITY ATTENUATION — proves in-bounds, discloses almost nothing, and cannot be forged ══════
// Verifies: a valid child proves scope⊆parent + req≤limit while the parent's other caps AND exact limit
// stay hidden; a widened scope or over-limit request is rejected; a proof against the wrong root fails; a
// tampered set breaks old proofs; multi-hop can only narrow; and — the honest guardrail — the module never
// claims zero-knowledge. Negative control: without the commitment, delegation ships the whole envelope.
'use strict';
const CC = require('../core/capability-commitment');
const crypto = require('crypto');

// ═══ DOMAIN-SEPARATOR PIN (2026-09-06) ═══ Every grant's capability_root, every receipt's membership
// proof, and verifier/cosmos_verify.py (which reimplements these strings verbatim) depend on the leaf and
// node prefixes being EXACTLY 'cap|' and 'node|'. Writ flagged them for pinning; if a changed version is
// ever ported here, this goes red before any artifact is issued under the wrong prefix.
{
  const H = (s) => crypto.createHash('sha256').update(s).digest('hex');
  const leaf = CC.leafOf({ type: 'category', value: 'api' });
  if (leaf !== H('cap|category|api')) { console.log('  ✗ PIN · leaf prefix is not \'cap|\''); process.exitCode = 1; }
  else console.log('  ✓ PIN · leaf = sha256(\'cap|\' + type + \'|\' + value)');
  const t = CC.buildTree([{ type: 'category', value: 'a' }, { type: 'category', value: 'b' }]);
  const [l, r] = t.leaves;
  if (t.root !== H('node|' + l + '|' + r)) { console.log('  ✗ PIN · node prefix is not \'node|\''); process.exitCode = 1; }
  else console.log('  ✓ PIN · node = sha256(\'node|\' + left + \'|\' + right)');
}
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const KP = { id: 'parent', publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(), privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() };

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };

const PARENT = [
  { type: 'category', value: 'api' }, { type: 'category', value: 'compute' }, { type: 'category', value: 'data' },
  { type: 'merchant', value: 'openai' }, { type: 'merchant', value: 'acme-payroll' },
];
const LIMIT = 8500;
const commit = CC.commitCapabilities(PARENT);
const bands = CC.commitLimit(LIMIT, KP, commit.root, { nonce: 'g1' });

// ── 1 · a valid in-scope capability proves membership ─────────────────────────────────────────────────
{ const p = CC.membershipProof(commit.tree, { type: 'category', value: 'api' });
  ok(p && CC.verifyMembership(commit.root, p) === true, '1 · a capability IN the parent set → membership proof verifies against the root');
}
// ── 2 · ★ the parent's OTHER capabilities are NOT revealed by the proof ────────────────────────────────
{ const att = CC.proveAttenuation(commit.tree, [{ type: 'category', value: 'api' }]);
  const wire = JSON.stringify(att.proofs);
  ok(att.ok && !wire.includes('compute') && !wire.includes('acme-payroll') && !wire.includes('openai'),
    '2 · ★ proving {api} reveals NONE of the parent\'s other cap values (compute/acme-payroll/openai absent)');
}
// ── 3 · ★ a capability NOT in the parent set cannot be proven (no widening) ────────────────────────────
{ const att = CC.proveAttenuation(commit.tree, [{ type: 'merchant', value: 'attacker-wallet' }]);
  ok(att.ok === false && att.reason === 'CAP_NOT_IN_PARENT_SET',
    '3 · ★ a cap OUTSIDE the parent set has no honest proof → CAP_NOT_IN_PARENT_SET (Scope_child ⊆ Scope_parent enforced)');
}
// ── 4 · ★ a forged membership proof against the WRONG root fails ───────────────────────────────────────
{ const p = CC.membershipProof(commit.tree, { type: 'category', value: 'api' });
  ok(CC.verifyMembership('00'.repeat(32), p) === false, '4 · ★ a real proof replayed against the WRONG root → REJECTED');
  const tampered = { cap: p.cap, path: p.path.map((s, i) => i === 0 ? { hash: 'ff'.repeat(32), right: s.right } : s) };
  ok(CC.verifyMembership(commit.root, tampered) === false, '4b · ★ a proof with a swapped sibling hash → REJECTED');
}
// ── 5 · ★ subset with EXACT set + reject a claimed superset ────────────────────────────────────────────
{ const all = CC.proveAttenuation(commit.tree, PARENT);
  ok(all.ok, '5 · disclosing the FULL set still verifies (subset allows equality)');
  const superset = CC.proveAttenuation(commit.tree, PARENT.concat([{ type: 'category', value: 'crypto' }]));
  ok(superset.ok === false, '5b · ★ a SUPERSET (parent caps + one extra) is rejected — cannot claim more than the parent has');
}
// ── 6 · amount within the limit verifies; the EXACT limit stays hidden ────────────────────────────────
{ const bp = CC.proveWithinLimit(40, bands.attestations);
  const v = CC.verifyWithinLimit(40, bp, KP.publicKey, commit.root);
  ok(v.ok && bp.band === 50, '6 · $40 request → smallest covering band $50 → verifies (Req ≤ band ≤ Limit)');
  ok(v.learned === 'limit ≥ 50' && !JSON.stringify(bp).includes(String(LIMIT)),
    '6b · ★ the verifier learns only "limit ≥ 50" — the exact $8500 never appears in the disclosure');
}
// ── 7 · ★ an over-limit request has no covering band → rejected ────────────────────────────────────────
{ const bp = CC.proveWithinLimit(999999, bands.attestations);
  ok(bp === null, '7 · ★ $999,999 (over limit) → no signed band covers it → no proof exists');
  // and even a valid band cannot cover a request above it
  const b50 = CC.proveWithinLimit(40, bands.attestations);
  ok(CC.verifyWithinLimit(51, b50, KP.publicKey, commit.root).ok === false,
    '7b · ★ a $50 band cannot be stretched to authorise $51 → REQ_ABOVE_BAND');
}
// ── 8 · ★ a band signed for one grant cannot be lifted onto a different root ───────────────────────────
{ const bp = CC.proveWithinLimit(40, bands.attestations);
  ok(CC.verifyWithinLimit(40, bp, KP.publicKey, 'someOtherRoot') .ok === false,
    '8 · ★ a band attestation carries its root — replaying it on a DIFFERENT grant → BAND_WRONG_ROOT');
  const forgedSig = Object.assign({}, bp, { signature: Buffer.from('nope').toString('base64') });
  ok(CC.verifyWithinLimit(40, forgedSig, KP.publicKey, commit.root).ok === false,
    '8b · ★ a band with a forged signature → BAND_SIGNATURE_INVALID');
}
// ── 9 · ★ tampering the committed set changes the root → old proofs break ──────────────────────────────
{ const p = CC.membershipProof(commit.tree, { type: 'category', value: 'api' });
  const tamperedSet = CC.commitCapabilities(PARENT.concat([{ type: 'merchant', value: 'attacker-wallet' }]));
  ok(tamperedSet.root !== commit.root && CC.verifyMembership(tamperedSet.root, p) === false,
    '9 · ★ adding a cap to the set changes the root; the old membership proof no longer verifies (commitment is binding)');
}
// ── 10 · ★ MULTI-HOP: a child re-commits a NARROWER set + bands ≤ VERIFIED parent bands ────────────────
const child = crypto.generateKeyPairSync('ed25519');
const CKP = { id: 'child', publicKey: child.publicKey.export({ type: 'spki', format: 'pem' }).toString(), privateKey: child.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() };
const REBASE = { parentTree: commit.tree, parentPublicKey: KP.publicKey, parentRoot: commit.root, parentNonce: 'g1', childKeypair: CKP, nonce: 'g1b' };
{ const re = CC.reCommit(Object.assign({}, REBASE, { parentBands: bands.attestations, childCaps: [{ type: 'category', value: 'api' }] }));
  ok(re.ok && re.bands.reduce((m, b) => Math.max(m, b.band), 0) <= bands.attestations.reduce((m, a) => Math.max(m, a.band), 0),
    '10 · ★ a child re-commits {api} and can only sign bands ≤ the VERIFIED parent bands (limit can only narrow)');
  const gp = CC.proveAttenuation(re.tree, [{ type: 'category', value: 'api' }]);
  ok(gp.ok && CC.verifyAttenuation(re.root, gp.proofs).ok, '10b · the grandchild proves {api} against the child\'s narrower root');
  const widen = CC.reCommit(Object.assign({}, REBASE, { parentBands: bands.attestations, childCaps: [{ type: 'category', value: 'crypto-withdrawal' }] }));
  ok(widen.ok === false && widen.reason === 'CAP_NOT_IN_PARENT_SET',
    '10c · ★ a child cannot WIDEN scope by re-committing a cap outside the parent set → refused');
}

// ── P2 ★ NEGATIVE CONTROL: a FABRICATED parent band widens pre-fix, is REJECTED after the fix ──────────
{ const forged = bands.attestations.concat([{ band: 1000000000 }]);   // no signature, no root, no nonce — an attacker's inflated ceiling
  // teeth: the PRE-FIX logic (max of UNVERIFIED .band) would inflate the ceiling to 1e9 → the widening
  const preFixCeiling = forged.reduce((m, a) => Math.max(m, a.band), 0);
  ok(preFixCeiling === 1000000000,
    'P2-neg · the pre-fix ceiling (max over UNVERIFIED bands) inflates to 1,000,000,000 — that is the widening the old code allowed');
  // POST-FIX: reCommit verifies every band, so the fabricated one is rejected and the ceiling never rises
  const re = CC.reCommit(Object.assign({}, REBASE, { parentBands: forged, childCaps: [{ type: 'category', value: 'api' }] }));
  ok(re.ok === false && re.reason === 'OFF_LADDER_PARENT_BAND',
    'P2-neg · ★ a fabricated { band: 1000000000 } is REJECTED after the fix (OFF_LADDER_PARENT_BAND) — child authority never widens');
}

// ── P2 · reject matrix — every malformed/forged parent band is refused, the ceiling never rises ────────
{ const good = bands.attestations;
  const attacker = crypto.generateKeyPairSync('ed25519');
  const AKP = { publicKey: attacker.publicKey.export({ type: 'spki', format: 'pem' }).toString(), privateKey: attacker.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() };
  // a band signed by a DIFFERENT key over the parent's root+nonce → not issued by the trusted parent
  const notParent = CC.commitLimit(100000, AKP, commit.root, { nonce: 'g1' }).attestations;
  ok(CC.reCommit(Object.assign({}, REBASE, { parentBands: notParent, childCaps: [{ type: 'category', value: 'api' }] })).reason.startsWith('PARENT_BAND_BAND_SIGNATURE'),
    'P2 · bands signed by a NON-parent key → rejected (signature does not verify under the trusted parent key)');
  // a band lifted from ANOTHER grant root
  const wrongRoot = CC.commitLimit(50, KP, 'deadbeef'.repeat(8), { nonce: 'g1' }).attestations;
  ok(CC.reCommit(Object.assign({}, REBASE, { parentBands: good.concat(wrongRoot), childCaps: [{ type: 'category', value: 'api' }] })).reason === 'PARENT_BAND_MIXED_ROOT',
    'P2 · a band from a different grant ROOT → PARENT_BAND_MIXED_ROOT');
  // a band from a different nonce (grant replay)
  const wrongNonce = CC.commitLimit(50, KP, commit.root, { nonce: 'OTHER' }).attestations;
  ok(CC.reCommit(Object.assign({}, REBASE, { parentBands: good.concat(wrongNonce), childCaps: [{ type: 'category', value: 'api' }] })).reason === 'PARENT_BAND_MIXED_NONCE',
    'P2 · a band with a different NONCE → PARENT_BAND_MIXED_NONCE');
  ok(CC.reCommit(Object.assign({}, REBASE, { parentBands: [{ band: '50' }], childCaps: [{ type: 'category', value: 'api' }] })).reason === 'MALFORMED_PARENT_BAND',
    'P2 · a non-numeric band → MALFORMED_PARENT_BAND');
  ok(CC.reCommit(Object.assign({}, REBASE, { parentBands: good.concat([good[0]]), childCaps: [{ type: 'category', value: 'api' }] })).reason === 'DUPLICATE_PARENT_BAND',
    'P2 · a duplicate band → DUPLICATE_PARENT_BAND');
  ok(CC.reCommit({ parentTree: commit.tree, parentBands: good, childCaps: [{ type: 'category', value: 'api' }], childKeypair: CKP }).reason === 'PARENT_TRUST_ANCHOR_REQUIRED',
    'P2 · no parent trust anchor (pubkey/root) → PARENT_TRUST_ANCHOR_REQUIRED (cannot verify → refuse)');
  // valid single-hop proof is preserved (regression): the parent's own bands still verify
  ok(CC.verifyWithinLimit(40, CC.proveWithinLimit(40, good), KP.publicKey, commit.root).ok === true,
    'P2 · valid existing single-hop proofs are PRESERVED (the fix only hardens multi-hop re-commit)');
}
// ── 11 · ★ NEGATIVE CONTROL: without the commitment, the whole envelope is exposed ────────────────────
{ // model the pre-commitment delegation: to prove one spend you ship the full capability list + exact limit
  const legacyEnvelope = JSON.stringify({ categories: PARENT.filter((c) => c.type === 'category').map((c) => c.value), merchants: PARENT.filter((c) => c.type === 'merchant').map((c) => c.value), limit: LIMIT });
  ok(legacyEnvelope.includes('acme-payroll') && legacyEnvelope.includes(String(LIMIT)),
    '11 · NEGATIVE CONTROL — the pre-commitment envelope leaks acme-payroll AND the exact $8500 (the surveillance vector)');
  // with the commitment: the same spend proof leaks neither
  const att = CC.proveAttenuation(commit.tree, [{ type: 'category', value: 'api' }]);
  const bp = CC.proveWithinLimit(40, bands.attestations);
  const disclosed = JSON.stringify({ att: att.proofs, bp });
  ok(!disclosed.includes('acme-payroll') && !disclosed.includes(String(LIMIT)),
    '11b · ★ WITH the commitment the SAME spend leaks neither acme-payroll nor $8500 — same authority, the disclosure is the only difference');
}
// ── 13 · EDGES DECIDED FROM THE SPEC, then run (added 2026-09-06 — mutations C14–C17 survived everything) ──
// DECISIONS, written before the code was read:
//   · The band ladder is INCLUSIVE at the limit and never above it: commitLimit attests exactly the bands
//     b where b <= limit. Inclusive matches the house rule for caps (a $5000 limit permits a $5000 spend);
//     never-above is the whole point — a parent may not hand out authority it does not itself hold.
//   · An EMPTY disclosure is not a proof. verifyAttenuation([]) must be NO_PROOFS, never ok — otherwise
//     "prove nothing" verifies as "proved everything".
//   · A child with no VERIFIED parent band has no ceiling to narrow from, so it may not re-commit at all.
{
  // C16 · the boundary the old suite could not see: LIMIT 8500 sits between ladder rungs, so `<=` vs `<`
  // was invisible. Put the limit EXACTLY on a rung.
  const exact = CC.commitLimit(5000, KP, commit.root, { nonce: 'g1' });
  const attested = exact.attestations.map((a) => a.band);
  ok(attested.includes(5000), '13a · ★ a limit of exactly 5000 ATTESTS the 5000 band — the ladder is inclusive at the limit');
  ok(Math.max(...attested) === 5000, '13b · ★ and attests NOTHING above it (highest band ' + Math.max(...attested) + ') — a parent cannot sign authority beyond its own limit');
  ok(CC.verifyWithinLimit(5000, CC.proveWithinLimit(5000, exact.attestations), KP.publicKey, commit.root).ok === true,
    '13c · ★ a request for exactly the limit is provable (Req = band = Limit)');
  ok(CC.proveWithinLimit(5001, exact.attestations) === null, '13d · ★ one unit above the limit has no covering band');

  // C15 · the same claim stated as an invariant over the whole ladder, so any future ladder change is covered
  const over = CC.DEFAULT_LADDER.filter((b) => b > 8500 && bands.attestations.some((a) => a.band === b));
  ok(over.length === 0, '13e · ★ the $8500 grant attests no band above 8500 (offenders: ' + JSON.stringify(over) + ')');

  // C14 · an empty disclosure is not a proof
  const empty = CC.verifyAttenuation(commit.root, []);
  ok(empty.ok === false && empty.reason === 'NO_PROOFS',
    '13f · ★★ verifyAttenuation over ZERO proofs → NO_PROOFS — disclosing nothing must never verify as in-scope');

  // C17 · no verified parent band → no re-commit
  const noBands = CC.reCommit(Object.assign({}, REBASE, { parentBands: [], childCaps: [{ type: 'category', value: 'api' }] }));
  ok(noBands.ok === false && noBands.reason === 'NO_VERIFIED_PARENT_BANDS',
    '13g · ★★ a child with NO verified parent bands cannot re-commit — there is no ceiling to narrow from');
  const childBands = CC.reCommit(Object.assign({}, REBASE, { parentBands: bands.attestations, childCaps: [{ type: 'category', value: 'api' }] })).bands.map((b) => b.band);
  ok(Math.max(...childBands) <= Math.max(...bands.attestations.map((a) => a.band)) && childBands.length > 0,
    '13h · a child that DOES present verified bands still gets a ladder, capped at the parent ceiling');
}

// ── 12 · determinism + no ZK overclaim in the module's own text ────────────────────────────────────────
{ const r1 = CC.commitCapabilities(PARENT).root, r2 = CC.commitCapabilities(PARENT.slice().reverse()).root;
  ok(r1 === r2 && /^[a-f0-9]{64}$/.test(r1), '12 · deterministic — the same set (any order) yields the same root');
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'core', 'capability-commitment.js'), 'utf8');
  ok(/NOT.{0,4}zero-knowledge/i.test(src) && !/\bis a zero-knowledge\b/i.test(src),
    '12b · ★ HONESTY GUARD — the module states it is NOT zero-knowledge and never claims to be');
}

console.log('\ncapability-commitment: ' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
