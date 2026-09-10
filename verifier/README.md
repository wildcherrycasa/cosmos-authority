# cosmos-verify

Verify a Cosmos agent-spend authorization receipt **offline** — no account, no network, no Cosmos code.

```bash
# NOT ON PyPI YET — install from source until it is:
pip install ./verifier          # or: pip install -e ./verifier
cosmos-verify receipt.json jwks.json
```

Exit `0` = VALID (decision, reason, amount, and every policy check are printed). Exit `1` = INVALID with the specific reason: `COSE_MALFORMED`, `COSE_WRONG_TAG`, `COSE_UNSUPPORTED_ALG`, `KEY_UNKNOWN`, `KEY_REVOKED`, `SIGNATURE_INVALID`, `UNSUPPORTED_SCHEMA`, `CAPABILITY_PROOF_INVALID`. Exit `2` = unreadable input.

Accepts the JSON envelope served by `GET /evidence/:id` (uses its `cose_base64`) or raw COSE bytes. `jwks.json` is what `GET /.well-known/jwks.json` returns.

What it checks: COSE_Sign1 structure (RFC 9052, tag 18) · protected header `alg` = EdDSA · `kid` present in the JWKS and not revoked · Ed25519 over `Sig_structure = ["Signature1", protected, b"", payload]` · payload schema · the Merkle membership proof against `capability_root`. The CBOR decoder and the Sig_structure encoder are written from the RFCs here, in Python, sharing nothing with the issuer — its signed bytes matched the issuer's byte-for-byte across languages in test.

Only dependency: `cryptography` (for Ed25519). On Android / Termux install it with `pkg install python-cryptography`, not pip — there is no Android wheel and the source build needs Rust.
