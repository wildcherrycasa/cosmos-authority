#!/usr/bin/env python3
"""cosmos_verify.py — verify a Cosmos authorization receipt OFFLINE, with no Cosmos account.

    python cosmos_verify.py <receipt.json | receipt.cose> <jwks.json> [--debug]

Exit 0 = VALID. Exit 1 = INVALID (reason printed). Exit 2 = usage / unreadable input.

Deliberately has NO dependency on Cosmos and NO CBOR library: the CBOR decoder and the Sig_structure
encoder below are written from RFC 8949 / RFC 9052 directly, in a different language from the issuer.
If this file and the issuer disagree by one byte, that is the bug we want to find — it is the same class
of interop failure that a JavaScript-only verifier would have hidden. Only dependency: `cryptography`
(pip install cryptography) for Ed25519.

What is checked, in order, and the SPECIFIC reason reported on failure:
  COSE_MALFORMED / COSE_WRONG_TAG      the bytes are not a COSE_Sign1 (tag 18, 4-element array)
  COSE_UNSUPPORTED_ALG                 protected alg is not EdDSA (-8)
  KEY_UNKNOWN                          the kid is not in the JWKS
  KEY_REVOKED                          the JWKS marks the key revoked (a retired key still verifies)
  SIGNATURE_INVALID                    Ed25519 over Sig_structure = ["Signature1", protected, b"", payload]
  UNSUPPORTED_SCHEMA                   payload cosmos_schema is not in ACCEPTED_SCHEMAS
  CAPABILITY_PROOF_INVALID             the Merkle path does not reach capability_root
"""
import base64, hashlib, json, sys

# ACCEPTED is a SET; ISSUED is one number. The two directions are not symmetric. An OLD verifier reading a
# NEW receipt must fail closed, and does - it hardcodes its own number and has never heard of the new one.
# A NEW verifier reading an OLD receipt has nothing to under-report: a schema-2 receipt carries no rail_*
# fields, so there is no claim it could print without its caveat. Refusing it would buy no safety and would
# make every receipt already sitting in someone's audit file unverifiable by the current tool.
#   2  through 2026-09-08: adds approver_authenticated
#   3  adds the rail_* settlement report (see the NOT OBSERVED warning printed below)
#   4  adds rail_state - the rail's own word, which changes how rail_outcome must be read
ACCEPTED_SCHEMAS = (2, 3, 4)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:  # pragma: no cover
    print("needs: pip install cryptography", file=sys.stderr); sys.exit(2)

# ── CBOR decode (RFC 8949) — the subset a receipt uses; indefinite-length is REJECTED (§4.2.1) ─────────
class Tagged:
    def __init__(self, tag, value): self.tag, self.value = tag, value

def _arg(buf, i, ai):
    if ai < 24: return ai, i
    if ai == 24: return buf[i], i + 1
    if ai == 25: return int.from_bytes(buf[i:i+2], "big"), i + 2
    if ai == 26: return int.from_bytes(buf[i:i+4], "big"), i + 4
    if ai == 27: return int.from_bytes(buf[i:i+8], "big"), i + 8
    raise ValueError("CBOR_INDEFINITE_LENGTH_FORBIDDEN" if ai == 31 else "CBOR_MALFORMED")

def _item(buf, i):
    if i >= len(buf): raise ValueError("CBOR_TRUNCATED")
    ib = buf[i]; i += 1; major, ai = ib >> 5, ib & 0x1F
    n, i = _arg(buf, i, ai)
    if major == 0: return n, i
    if major == 1: return -1 - n, i
    if major == 2:
        if i + n > len(buf): raise ValueError("CBOR_TRUNCATED")
        return bytes(buf[i:i+n]), i + n
    if major == 3:
        if i + n > len(buf): raise ValueError("CBOR_TRUNCATED")
        return buf[i:i+n].decode("utf-8"), i + n
    if major == 4:
        out = []
        for _ in range(n): v, i = _item(buf, i); out.append(v)
        return out, i
    if major == 5:
        out = {}
        for _ in range(n):
            k, i = _item(buf, i); v, i = _item(buf, i); out[k] = v
        return out, i
    if major == 6:
        v, i = _item(buf, i); return Tagged(n, v), i
    if major == 7:
        if ai == 20: return False, i
        if ai == 21: return True, i
        if ai == 22: return None, i
        raise ValueError("CBOR_UNSUPPORTED_SIMPLE")
    raise ValueError("CBOR_UNSUPPORTED_MAJOR")

def cbor_decode(buf):
    v, end = _item(buf, 0)
    if end != len(buf): raise ValueError("CBOR_TRAILING_BYTES")
    return v

# ── CBOR encode — ONLY what Sig_structure needs: uint heads, tstr, bstr, array (§4.2.1 shortest form) ──
def _head(major, n):
    mt = major << 5
    if n < 24: return bytes([mt | n])
    if n < 0x100: return bytes([mt | 24, n])
    if n < 0x10000: return bytes([mt | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000: return bytes([mt | 26]) + n.to_bytes(4, "big")
    return bytes([mt | 27]) + n.to_bytes(8, "big")

def cbor_encode(v):
    if isinstance(v, bytes): return _head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8"); return _head(3, len(b)) + b
    if isinstance(v, list): return _head(4, len(v)) + b"".join(cbor_encode(x) for x in v)
    raise ValueError("encoder only supports bytes/str/list (all Sig_structure needs)")

def sig_structure(protected_bstr, payload_bstr):
    # RFC 9052 §4.4: ["Signature1", protected, external_aad (zero-length when absent), payload]
    return cbor_encode(["Signature1", protected_bstr, b"", payload_bstr])

# ── inputs ──────────────────────────────────────────────────────────────────────────────────────────────
def load_receipt(path):
    raw = open(path, "rb").read()
    if raw[:1] == b"{":
        j = json.loads(raw.decode("utf-8"))
        b64 = j.get("cose_base64") or j.get("cose")
        if not b64: raise ValueError("JSON has no cose_base64 field")
        return base64.b64decode(b64)
    return raw

def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def find_key(jwks, kid):
    for k in jwks.get("keys", []):
        if k.get("kid") == kid and k.get("kty") == "OKP" and k.get("crv") == "Ed25519" and k.get("x"):
            return k
    return None

# ── capability proof: sha256 over the same strings capability-commitment.js uses ────────────────────────
def H(s): return hashlib.sha256(s.encode("utf-8")).hexdigest()

def verify_capability(root, proof):
    if not proof: return True
    cap = proof.get("cap") or {}
    h = H("cap|%s|%s" % (cap.get("type"), cap.get("value")))
    for step in proof.get("path") or []:
        sib = step.get("hash")
        if not isinstance(sib, str): return False
        h = H("node|%s|%s" % (h, sib)) if step.get("right") else H("node|%s|%s" % (sib, h))
    return h == root

# ── main ────────────────────────────────────────────────────────────────────────────────────────────────
def verify(cose_bytes, jwks, debug=False):
    try:
        item = cbor_decode(cose_bytes)
    except Exception as e:
        return False, str(e) or "COSE_MALFORMED", None
    if isinstance(item, Tagged):
        if item.tag != 18: return False, "COSE_WRONG_TAG", None
        item = item.value
    if not (isinstance(item, list) and len(item) == 4): return False, "COSE_MALFORMED", None
    protected, _unprotected, payload_bstr, signature = item
    if not all(isinstance(x, bytes) for x in (protected, payload_bstr, signature)): return False, "COSE_MALFORMED", None
    hdr = cbor_decode(protected) if protected else {}
    if hdr.get(1) != -8: return False, "COSE_UNSUPPORTED_ALG", None
    kid_b = hdr.get(4)
    if not isinstance(kid_b, bytes): return False, "COSE_KID_MISSING", None
    kid = kid_b.decode("utf-8")

    key = find_key(jwks, kid)
    if not key: return False, "KEY_UNKNOWN", kid
    if key.get("status") == "revoked": return False, "KEY_REVOKED", kid

    tbs = sig_structure(protected, payload_bstr)
    if debug: print("debug sig_structure hex:", tbs.hex())
    try:
        Ed25519PublicKey.from_public_bytes(b64url_decode(key["x"])).verify(signature, tbs)
    except (InvalidSignature, ValueError):
        return False, "SIGNATURE_INVALID", kid

    payload = cbor_decode(payload_bstr)
    if payload.get("cosmos_schema") not in ACCEPTED_SCHEMAS: return False, "UNSUPPORTED_SCHEMA", kid
    if not verify_capability(payload.get("capability_root"), payload.get("capability_proof")):
        return False, "CAPABILITY_PROOF_INVALID", kid
    return True, key.get("status", "active"), (kid, payload)

def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    debug = "--debug" in argv
    if len(args) != 2:
        print(__doc__); return 2
    try:
        cose_bytes = load_receipt(args[0]); jwks = json.load(open(args[1], "r", encoding="utf-8"))
    except Exception as e:
        print("cannot read inputs:", e); return 2
    ok, info, extra = verify(cose_bytes, jwks, debug)
    if not ok:
        print("INVALID:", info, ("(kid %s)" % extra) if extra else ""); return 1
    kid, p = extra
    print("VALID  kid=%s  key_status=%s" % (kid, info))
    print("  decision=%s reason=%s" % (p.get("decision"), p.get("reason")))
    print("  %s %s at %s for agent %s (grant %s)" % (p.get("amount_minor"), p.get("currency"),
          p.get("merchant"), p.get("agent_id"), p.get("grant_id")))
    print("  decided_at=%s policy=%s/%s" % (p.get("decided_at"), p.get("policy_version"), (p.get("policy_hash") or "")[:12]))
    for c in p.get("checks") or []:
        print("    [%s] %s" % ("pass" if c.get("pass") else "FAIL", c.get("name")))
    if p.get("capability_proof"): print("  capability proof: ok (category in committed set)")
    # An approval is the one field on a receipt that a reader will over-trust. The signature proves the
    # bytes are untampered; it says nothing about whether the named approver really approved. Print the
    # difference every time, loudly, rather than letting a valid signature imply a verified human.
    if p.get("approver_id") is not None:
        auth = p.get("approver_authenticated")
        print("  approver=%s channel=%s" % (p.get("approver_id"), p.get("approval_channel")))
        if auth is True:
            print("    approver identity: AUTHENTICATED by the issuer")
        else:
            print("    !! approver identity: NOT AUTHENTICATED - asserted by the caller and never checked.")
            print("      This signature proves the receipt was not altered. It does NOT prove that")
            print("      '%s' approved anything." % p.get("approver_id"))
    # A RAIL REPORT is the second field a reader will over-trust, and it is worse than the first: a tx id
    # beside a valid signature reads as "this payment settled and Cosmos saw it." Cosmos cannot see a rail
    # and never will - it does not touch money (decision (a)). What it signed is that a report was MADE,
    # against this authorization, by a holder of the credential class named here. Print that gap every
    # time. ASCII only, on purpose: a non-ASCII glyph here crashed this script on Windows cp1252 AFTER it
    # had already printed VALID (2026-09-06), turning a good receipt into a stack trace and exit 1.
    if p.get("rail_outcome") is not None:
        print("  rail report: outcome=%s tx=%s provider=%s" % (p.get("rail_outcome"), p.get("rail_tx_id"), p.get("rail_provider")))
        # The rail's own word for what happened, when it differs from Cosmos's three-outcome vocabulary.
        # Printed SEPARATELY and only when it disagrees, because that disagreement is the informative part:
        # a `reversed` payment is recorded as outcome=failed (the money came back) but the rail's state
        # says it had executed first. Collapsing them would hide the only fact an auditor is looking for.
        st = p.get("rail_state")
        if st is not None and st != p.get("rail_outcome"):
            print("    rail's own state: %s   (Cosmos recorded outcome=%s for accounting)" % (st, p.get("rail_outcome")))
        by = p.get("rail_reported_by")
        print("    reported_by=%s at %s" % (by, p.get("rail_reported_at")))
        print("    !! rail outcome: NOT OBSERVED - asserted by the reporter and never checked by Cosmos.")
        print("      This signature proves a report was made against this authorization by a holder of the")
        print("      '%s' credential. It does NOT prove that any money moved." % by)
        if by == "operator":
            print("      Weaker still: the operator credential can also mint grants, so it is not evidence")
            print("      that the rail itself said anything.")
        if p.get("rail_late"):
            print("    !! LATE: the reservation had already auto-reversed when this settlement arrived.")
            print("      The TTL guessed wrong; the spend was re-reserved and may exceed the grant budget.")
    if p.get("parent_receipt_id"): print("  parent receipt: %s" % p.get("parent_receipt_id"))
    return 0

def cli():
    """console_scripts entry point: `cosmos-verify <receipt> <jwks>`"""
    sys.exit(main(sys.argv))

if __name__ == "__main__":
    sys.exit(main(sys.argv))
