# Cosmos demo — verify a receipt with nothing but this folder

Three real, signed receipts and the public key that verifies them. No account, no network, no Cosmos code:

```bash
pip install cryptography
# (on Windows the interpreter is `python`, not `python3`)
python3 ../verifier/cosmos_verify.py deny.json jwks.json
python3 ../verifier/cosmos_verify.py allow.json jwks.json
python3 ../verifier/cosmos_verify.py settled.json jwks.json
```

`deny.json` is the receipt nobody else issues: a signed, offline-verifiable statement that **this spend was refused, under this policy, at this time** — with the failing check named inside. Flip one byte of `cose_base64` and the verifier exits 1 with `SIGNATURE_INVALID`, specifically.

`settled.json` is the other half, and it is the part that makes an ALLOW mean something. `allow.json` says the policy permitted a spend; on its own it cannot tell you whether the money ever moved. `settled.json` is signed by the same key, points back at `allow.json` through `parent_receipt_id`, and carries the transaction id the rail reported. Together they read: **policy allowed this at T1, and the rail reported it settled at T2.**

⛔ **And the verifier says out loud what that does NOT mean.** Cosmos never touches money and never sees a rail, so the transaction id is a CLAIM. Run the command and it prints `rail outcome: NOT OBSERVED` above it, naming which credential made the claim. A receipt that let a valid signature imply "Cosmos watched this settle" would be worth less than no receipt at all.

Format: COSE_Sign1 (RFC 9052), Ed25519, deterministic CBOR (RFC 8949 §4.2), SCITT-shaped (RFC 9943). The signing key was generated for this demo and discarded; the receipts stay verifiable against `jwks.json` forever.

Regenerate: `npm run demo` (new key, new ids, same shape).
