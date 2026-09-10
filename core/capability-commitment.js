// ═══ CAPABILITY ATTENUATION WITH SELECTIVE DISCLOSURE ══════════════════════════════════════════════
//
// In a deep swarm (A delegates to B, B to C, …) today's delegation carries the parent's FULL envelope
// down the chain — every allowed category, every merchant, the exact spend limit — so an intermediate
// agent, or anyone watching the hop, learns the parent's entire capability structure and ceiling. Across
// hostile public domains that is an enterprise surveillance vector: the whole treasury's shape leaks to
// prove one small spend is in bounds.
//
// This lets a sub-agent prove the two things that matter — its requested capability is WITHIN the parent's
// set (Scope_child ⊆ Scope_parent), and its amount is WITHIN the parent's limit (Req ≤ Limit) — while
// disclosing only what that one proof needs:
//   · SCOPE: the parent commits to its capability set as a Merkle root. A child reveals a MEMBERSHIP PROOF
//     for just the capability it uses — the parent's OTHER capabilities stay hidden behind their hashes.
//   · LIMIT: the parent signs a monotone ladder of band-attestations ("my limit ≥ this band") for every
//     band its limit covers. A child reveals ONLY the smallest band that covers its request, proving
//     Req ≤ band ≤ Limit — the exact limit and the treasury balance stay hidden.
//
// ★ HONEST LABEL — READ THIS. This is COMMITMENT-BASED SELECTIVE DISCLOSURE, **NOT** zero-knowledge. A
// Merkle proof reveals the sibling hashes on its path and the set size; the band reveals a coarse lower
// bound on the limit. It hides the PREIMAGES of undisclosed capabilities and the EXACT limit — a real,
// useful privacy gain over shipping the whole envelope — but it is not a ZK proof and this module never
// calls it one. A true zero-knowledge version (hiding even the path and the band) requires a vetted
// proving system (Bulletproofs / a SNARK); until one is actually integrated, no ZK claim is made here.
//
// FURTHER PRIVACY LIMITS (do not overstate the hiding): the capability leaves are DETERMINISTIC, UNSALTED
// hashes (leafOf = H("cap|type|value")). So (1) the SAME capability produces the SAME leaf across grants —
// an observer can LINK a capability's presence across different commitments/roots; and (2) a LOW-ENTROPY
// capability value (a short category, a known merchant id) can be DICTIONARY-GUESSED by hashing candidates
// and matching the leaf, so a disclosed sibling hash is only as private as the value's entropy. Salting the
// leaves (per-grant nonce mixed into each leaf) would break linkability + guessing at the cost of
// cross-grant membership proofs; that trade-off is deliberately NOT made here, and the guarantee is stated
// as "hides undisclosed leaves against an observer who cannot guess their low-entropy preimages", not
// "unconditionally private".
//
// It composes delegation.js/authority.js (which still own narrow-never-widen); this is the privacy layer
// over the same attenuation, not a replacement for the authority check.
'use strict';
const crypto = require('crypto');

const H = (s) => crypto.createHash('sha256').update(s).digest('hex');
// a capability is a (type, value) pair — "category:api", "merchant:0xABC", "resource:/data". The leaf is a
// domain-separated hash so a value in one axis can never be replayed as a value in another.
const leafOf = (cap) => H('cap|' + String(cap.type) + '|' + String(cap.value));
const canonicalCap = (cap) => ({ type: String(cap.type), value: String(cap.value) });

// ── MERKLE ACCUMULATOR over the capability set ────────────────────────────────────────────────────────
// Sorted leaves → a deterministic tree, so the same set always yields the same root regardless of input
// order. Odd node is promoted (paired with itself). Proof carries {hash, right} per level.
function buildTree(caps) {
  const leaves = [...new Set((caps || []).map((c) => leafOf(c)))].sort();   // dedup + canonical order
  if (!leaves.length) return { root: H('cap|empty'), levels: [[]], leaves };
  let level = leaves.slice();
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const l = level[i], r = (i + 1 < level.length) ? level[i + 1] : level[i];   // promote odd
      next.push(H('node|' + l + '|' + r));
    }
    levels.push(next); level = next;
  }
  return { root: level[0], levels, leaves };
}
function commitCapabilities(caps) { const t = buildTree(caps); return { root: t.root, tree: t, count: t.leaves.length }; }

// membership proof for ONE capability — the sibling hash at each level (hides every other leaf's preimage)
function membershipProof(tree, cap) {
  const leaf = leafOf(cap);
  let idx = tree.leaves.indexOf(leaf);
  if (idx < 0) return null;                                   // not in the set → no honest proof exists
  const path = [];
  for (let lvl = 0; lvl < tree.levels.length - 1; lvl++) {
    const level = tree.levels[lvl];
    const isRight = idx % 2 === 1;
    const sibIdx = isRight ? idx - 1 : (idx + 1 < level.length ? idx + 1 : idx);   // promote odd → self
    path.push({ hash: level[sibIdx], right: !isRight });     // `right` = sibling is on the right
    idx = Math.floor(idx / 2);
  }
  return { cap: canonicalCap(cap), path };
}
// verify a membership proof against a root — proves cap ∈ the committed set, revealing only the path.
function verifyMembership(root, proof) {
  if (!proof || !proof.cap || !Array.isArray(proof.path)) return false;
  let h = leafOf(proof.cap);
  for (const step of proof.path) {
    if (typeof step.hash !== 'string') return false;
    h = step.right ? H('node|' + h + '|' + step.hash) : H('node|' + step.hash + '|' + h);
  }
  return h === root;
}

// ── SCOPE ATTENUATION: prove Scope_child ⊆ Scope_parent without revealing the parent's other caps ──────
// The parent commits its full set once. The child discloses membership proofs for ONLY the caps it will
// use. verifyAttenuation confirms every disclosed cap is in the parent's set — a subset by construction,
// because a cap NOT in the set has no valid proof. The parent's undisclosed caps never appear.
function proveAttenuation(parentTree, childCaps) {
  const proofs = [];
  for (const c of childCaps || []) { const p = membershipProof(parentTree, c); if (!p) return { ok: false, reason: 'CAP_NOT_IN_PARENT_SET', cap: canonicalCap(c) }; proofs.push(p); }
  return { ok: true, proofs };
}
function verifyAttenuation(parentRoot, proofs) {
  if (!Array.isArray(proofs) || !proofs.length) return { ok: false, reason: 'NO_PROOFS' };
  for (const p of proofs) if (!verifyMembership(parentRoot, p)) return { ok: false, reason: 'MEMBERSHIP_FAILED', cap: p && p.cap };
  return { ok: true, disclosed: proofs.map((p) => p.cap) };
}

// ── LIMIT ATTENUATION: prove Req ≤ Limit while hiding the exact Limit ──────────────────────────────────
// A monotone ladder of bands. The parent signs "limit ≥ band" for every band ≤ its limit, tied to the
// capability root + a nonce so a band cannot be lifted onto a different grant. A child proving a request
// reveals ONLY the smallest signed band ≥ Req.
const DEFAULT_LADDER = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000, 10000, 50000, 100000];
const bandMsg = (band, root, nonce) => Buffer.from('limit_band|' + band + '|' + root + '|' + (nonce || ''));

function commitLimit(limit, keypair, root, opts) {
  opts = opts || {};
  const ladder = opts.ladder || DEFAULT_LADDER;
  const nonce = opts.nonce || null;
  const attestations = ladder.filter((b) => b <= limit).map((band) => ({
    band, root, nonce,
    signature: crypto.sign(null, bandMsg(band, root, nonce), keypair.privateKey).toString('base64'),
  }));
  return { attestations, ladder, nonce };   // NOTE: the exact `limit` is never in the output — only the bands it covers
}
// the child selects the smallest band that covers its request (minimal disclosure)
function proveWithinLimit(req, attestations) {
  const covering = (attestations || []).filter((a) => a.band >= req).sort((a, b) => a.band - b.band);
  return covering.length ? covering[0] : null;   // null → no signed band covers the request (over limit)
}
function verifyWithinLimit(req, attestation, parentPubkey, root) {
  if (!attestation || typeof attestation.band !== 'number') return { ok: false, reason: 'NO_BAND' };
  if (!(req <= attestation.band)) return { ok: false, reason: 'REQ_ABOVE_BAND' };
  if (attestation.root !== root) return { ok: false, reason: 'BAND_WRONG_ROOT' };   // a band can't be lifted onto another grant
  let good = false;
  try { good = crypto.verify(null, bandMsg(attestation.band, attestation.root, attestation.nonce), parentPubkey, Buffer.from(String(attestation.signature), 'base64')); } catch (_) { good = false; }
  if (!good) return { ok: false, reason: 'BAND_SIGNATURE_INVALID' };
  // proven: Req ≤ band ≤ Limit. We learned only the band (a coarse lower bound on Limit), not the exact Limit.
  return { ok: true, band: attestation.band, learned: 'limit ≥ ' + attestation.band };
}

// ── MULTI-HOP: a child re-commits a NARROWER set + re-issues bands ≤ what it received ──────────────────
// Narrow-never-widen at the commitment layer: a child's committed set must be a subset of the parent's
// (each child cap proves membership in the parent), and a child may only sign bands its parent signed to
// it. reCommit refuses to widen either axis.
function reCommit(o) {
  o = o || {};
  const parentTree = o.parentTree, parentBands = o.parentBands || [], childCaps = o.childCaps, childKeypair = o.childKeypair;
  const parentPublicKey = o.parentPublicKey, parentRoot = o.parentRoot;
  const parentNonce = (o.parentNonce != null ? o.parentNonce : null);
  const ladder = o.ladder || DEFAULT_LADDER;
  const childNonce = (o.nonce != null ? o.nonce : null);

  // ── 1 · SCOPE: child ⊆ parent ──────────────────────────────────────────────────────────────────────
  const att = proveAttenuation(parentTree, childCaps);
  if (!att.ok) return { ok: false, reason: att.reason, cap: att.cap };               // child scope ⊄ parent → refuse

  // ── 2 · VERIFY EVERY PARENT BAND before trusting ANY numeric value ──────────────────────────────────
  // THE WIDENING FIX. Previously parentMaxBand = max(band) over UNVERIFIED parentBands, so a fabricated
  // { band: 1000000000 } inflated the ceiling and the child could sign far above the parent's real grant —
  // an authority-widening hole in a system whose whole premise is narrow-never-widen. Now a band counts
  // toward the ceiling ONLY if it (a) is a finite number on the permitted canonical ladder, (b) carries the
  // EXPECTED parent root + grant nonce (no lifting a band from another grant), (c) verifies under the
  // TRUSTED parent public key (issued by that parent, signature valid), and (d) is not a duplicate. Anything
  // else — forged signature, mixed root, mixed nonce, off-ladder, malformed, duplicate, or a band the trusted
  // parent never signed — is rejected outright, and the ceiling never rises from it.
  if (!parentPublicKey || !parentRoot) return { ok: false, reason: 'PARENT_TRUST_ANCHOR_REQUIRED' };
  const ladderSet = new Set(ladder);
  const seenBands = new Set();
  let parentMaxBand = 0, verified = 0;
  for (const a of parentBands) {
    if (!a || typeof a.band !== 'number' || !Number.isFinite(a.band)) return { ok: false, reason: 'MALFORMED_PARENT_BAND' };
    if (!ladderSet.has(a.band)) return { ok: false, reason: 'OFF_LADDER_PARENT_BAND', band: a.band };            // a forged 1e9 dies here
    if (a.root !== parentRoot) return { ok: false, reason: 'PARENT_BAND_MIXED_ROOT', band: a.band };             // mixed roots
    if ((a.nonce != null ? a.nonce : null) !== parentNonce) return { ok: false, reason: 'PARENT_BAND_MIXED_NONCE', band: a.band };  // mixed nonces
    if (seenBands.has(a.band)) return { ok: false, reason: 'DUPLICATE_PARENT_BAND', band: a.band };              // duplicate/conflict
    seenBands.add(a.band);
    const v = verifyWithinLimit(a.band, a, parentPublicKey, parentRoot);   // the signature MUST verify vs the trusted parent key
    if (!v.ok) return { ok: false, reason: 'PARENT_BAND_' + v.reason, band: a.band };   // forged signature / not issued by the parent
    verified++; if (a.band > parentMaxBand) parentMaxBand = a.band;
  }
  if (!verified) return { ok: false, reason: 'NO_VERIFIED_PARENT_BANDS' };

  // ── 3 · child bands can never exceed the highest VERIFIED parent band ───────────────────────────────
  const child = commitCapabilities(childCaps);
  const allowed = ladder.filter((b) => b <= parentMaxBand);
  const bands = allowed.map((band) => ({ band, root: child.root, nonce: childNonce,
    signature: crypto.sign(null, bandMsg(band, child.root, childNonce), childKeypair.privateKey).toString('base64') }));
  return { ok: true, root: child.root, tree: child.tree, bands, parent_membership: att.proofs, verified_parent_bands: verified, parent_max_band: parentMaxBand };
}

module.exports = { H, leafOf, buildTree, commitCapabilities, membershipProof, verifyMembership,
  proveAttenuation, verifyAttenuation, commitLimit, proveWithinLimit, verifyWithinLimit, reCommit,
  DEFAULT_LADDER };
