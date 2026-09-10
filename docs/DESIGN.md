# COSMOS — full product design

Written 2026-09-01. Every measurement in this document was produced by a command run in the session that
wrote it; estimates are labelled **(estimate)**. Nothing here is self-graded as done — this is a design,
and the repo currently contains none of it beyond `core/`.

**State when this was written:** 7 modules, 546 lines, `core/` only. `npm test` → smoke 29/29,
capability-commitment 30/30. `npm run audit:size` → 7/25 modules, 546/3000 lines. Working tree clean.

---

## 0 · The boundary, stated once

Cosmos answers one question — *may this agent spend $X at Y for Z?* — and hands back a signed artifact
anyone can verify offline. It never moves money, never holds funds, never touches a rail credential.

Three things follow from that and constrain every decision below:

1. **No custody → no money-transmitter licensing, no KYC/AML, no mainnet gate.** This is the whole reason
   Cosmos can ship where Writ could not. Any design that requires holding a key that can move value is
   out of scope by definition, not by preference.
2. **No discovery → no global state.** A verifier checks a signature locally against a published key. There
   is no registry of agents, no network view, no central party that sees every transaction. Verification
   cost sits with the verifier. This is why Cosmos runs on one box.
3. **Cosmos is not the source of truth about whether money moved.** It is the source of truth about whether
   money was *authorized*. The customer's rail is the source of truth about execution. Section 7 is entirely
   about the seam between those two facts, and it is the hardest unsolved thing in the product.

---

## 1 · The three calls

Complete request/response schemas. Amounts are **integer minor units** everywhere (see §5, Gap 1).

### `POST /grants` — mint authority

```jsonc
// request
{
  "org_id": "org_acme",
  "agent_id": "agt_research_01",
  "currency": "USD",
  "budget_minor": 50000,              // $500.00
  "per_payment_cap_minor": 1700,      // $17.00
  "daily_cap_minor": 5000,            // $50.00
  "allowed_categories": ["api", "cloud", "subscription"],
  "approval_threshold_minor": 2500,   // above this → ESCALATE
  "expires_at": 1788220800000,        // epoch ms, or null
  "free_rein": false                  // true bypasses ALL caps — see §9
}
```

```jsonc
// 201 response
{
  "grant_id": "grn_01J8…",
  "status": "active",
  "capability_root": "9f2c…",         // Merkle root over allowed_categories
  "policy_version": 1,
  "policy_hash": "4ab1…",             // sha256(jcs(policy fields))
  "budget_minor": 50000,
  "spent_minor": 0,
  "created_at": 1788134400000
}
```

`capability_root` is `capability-commitment.commitCapabilities()` over the allowed categories. It lets a
receipt prove *the one category used* without disclosing the whole allowed set (§6).

### `POST /authorize` — the decision

```jsonc
// request
{
  "grant_id": "grn_01J8…",
  "amount_minor": 1200,
  "currency": "USD",
  "merchant": "api.openai.com",
  "category": "api",
  "description": "embeddings batch 4471",
  "idempotency_key": "agt_research_01:req_9931"     // REQUIRED
}
```

```jsonc
// 200 response — the same shape for ALLOW, DENY and ESCALATE
{
  "decision": "ALLOW",                    // ALLOW | DENY | ESCALATE
  "reason": null,                         // guardrails reason code when not ALLOW
  "receipt_id": "rcp_01J8…",
  "expires_at": 1788134700000,            // reservation TTL — see §7
  "checks": [
    { "name": "Currency matches grant", "pass": true },
    { "name": "Active",                 "pass": true },
    { "name": "Not expired",            "pass": true },
    { "name": "Sufficient balance",     "pass": true },
    { "name": "Under per-payment cap",  "pass": true },
    { "name": "Under daily cap",        "pass": true },
    { "name": "Category allowed",       "pass": true }
  ],
  "receipt": { /* the full signed artifact — §6 */ }
}
```

HTTP status is **200 for all three decisions**. A DENY is a successful answer to a well-formed question,
not a client error. 400 is reserved for malformed requests (§5, Gap 4); 404 for an unknown grant.

### `GET /evidence/:receipt_id` — the proof

Returns the signed receipt verbatim, plus the JWKS URL. Content-addressed and immutable: the same
`receipt_id` returns byte-identical JSON forever, or 404.

**Two representations of one artifact (implemented 2026-09-06).** By default the response is the JSON
envelope with `cose_base64`. Under `Accept: application/cose` (RFC 9052 §14.4.1) the response body is the
COSE_Sign1 **bytes themselves**, `content-type: application/cose`, so a verifier written against the RFC
needs no un-wrapping step and no knowledge that this server likes base64. The two are asserted
byte-identical after decoding (`evidence` B2d), not assumed. The raw response carries `x-cosmos-kid` and a
`Link: </.well-known/jwks.json>; rel="jwks"` header, because the key that verifies those bytes is not
inside them. Negotiation is exact-type, not substring: `*/*`, a missing header and `application/json` all
keep JSON — the default may not move under a browser or a bare curl — and `application/cose;q=0` is an
explicit refusal and is honoured. **Errors stay JSON** even when COSE was requested; a 404 whose body is
binary is a worse experience than one that says `RECEIPT_NOT_FOUND`.

### The fourth route, named honestly

`GET /.well-known/jwks.json` is **not a fourth feature**. It is the publication of the public key without
which call #3 is unverifiable and therefore pointless. It ships with `/evidence` or `/evidence` is a lie.
Stated out loud here so it is a deliberate exception rather than the first drift.

---

## 2 · How the seven modules compose

```
POST /authorize
   │
   ├─ 1. validate + parse            api/authorize.js   (400 on malformed — no receipt)
   ├─ 2. load grant + event history  core/store.js
   ├─ 3. fold spentToday             core/agent-view.js (replay.js does NOT track this — Gap 2)
   ├─ 4. project grant → agent shape core/agent-view.js
   ├─ 5. currency check              core/agent-view.js (guardrails is currency-blind — Gap 3)
   ├─ 6. THE DECISION                core/guardrails.js       ← frozen anchor, never edited
   ├─ 7. escalation check            core/approvals.js
   ├─ 8. capability inclusion proof  core/capability-commitment.js
   ├─ 9. build envelope              core/authorization-envelope.js
   ├─ 10. canonicalize + sign        core/jcs.js + core/receipt-keystore.js
   ├─ 11. append events (atomic)     core/store.js
   └─ 12. respond
```

`replay.js` is not on the request path. It is the **audit path**: rebuild all state from events alone and
diff it against live state. That separation is deliberate and is the thing Writ got wrong — it conflated
the pure record with the coupled storage.

### The adapter is the only new concept

`core/agent-view.js` exists because the ported modules disagree about their own vocabulary. It is one
function and it is the seam where every Writ-ism gets translated into Cosmos's:

```js
agentView(grant, events, now) → {
  status, expiry, budget, spent, spentToday,
  perPaymentCap, dailyCap, allowedCategories, freeRein, approvalThreshold
}
```

Every field name on the right is dictated by `guardrails.js:5-20` and `approvals.js:17`. Read those two
before changing this. **No ported module is edited to accommodate Cosmos** — the adapter absorbs all of it.

---

## 3 · Data model

### Grant (projection, not storage)

Grants are not rows. They are a fold over the event log, exactly like everything else. The projection is
cached in memory and rebuildable from `core/store.js` at boot.

### The event log

Append-only JSONL, one file, fsync on append. Event kinds Cosmos writes:

| kind | written when | consumed by |
|---|---|---|
| `open` | grant minted | `replay.js:11` |
| `fund` | budget topped up | `replay.js:12` |
| `decision` | every ALLOW/DENY/ESCALATE | `replay.js:13` |
| `reservation` | an ALLOW commits budget | `replay.js:14` |
| `reversal` | reservation expired or reconciled as failed | `replay.js:15` |
| `freeze` / `unfreeze` | kill switch | `replay.js:17-18` |
| `approval_request` | an ESCALATE pauses | `approvals.js:39` |
| `approval_decision` | a human answers | `approvals.js:36` |

**Cosmos never writes `submission`, `settlement`, or `status`.** Those are rail events — `replay.js:16,19,20`
handles them because Writ executed payments. In Cosmos they are unreachable. That is not dead code to
delete: `replay.js` is a frozen fold whose unknown kinds are deliberately inert, and leaving them costs
nothing. Noted so nobody later "discovers" them and builds a settlement feature.

### Decision receipt — the evidence artifact

```jsonc
{
  "body": {
    "cosmos_schema": 2,
    "receipt_id": "rcp_01J8…",
    "kid": "cosmos-receipt-2026-09",     // inside the signed body, deliberately
    "org_id": "org_acme",
    "grant_id": "grn_01J8…",
    "agent_id": "agt_research_01",
    "decision": "ALLOW",
    "reason": null,
    "checks": [ { "name": "…", "pass": true } ],
    "amount_minor": 1200,
    "currency": "USD",
    "merchant": "api.openai.com",
    "category": "api",
    "intent_hash": "c41d…",              // sha256(jcs(request))
    "envelope_hash": "77e0…",            // authorization-envelope.hashDoc()
    "policy_version": 1,
    "policy_hash": "4ab1…",
    "capability_root": "9f2c…",
    "capability_proof": { "leaf": "…", "path": [ … ] },
    "idempotency_key": "agt_research_01:req_9931",
    "decided_at": 1788134400000,
    "expires_at": 1788134700000
  },
  "binding_digest": "a19f…",             // sha256(jcs(body))
  "signature": "MEUCIQ…"                 // Ed25519 over binding_digest
}
```

`kid` lives **inside** the signed body. If it sat outside, an attacker could swap it — the signature would
fail, so it would be detected, but the verifier would report `KEY_UNKNOWN` instead of the true fault.
Inside the body, tampering surfaces as a digest mismatch, which is the specific, honest error.

---

## 4 · Evidence, signing, and offline verification

**Binding digest:** `sha256(jcs(body))` using `core/jcs.js`. **Signature:** `keystore.sign(binding_digest)`
→ Ed25519, `receipt-keystore.js:82-86`.

**The offline verifier** is a standalone script with no network access and no Cosmos account:

```
1. recompute jcs(body) → sha256 → compare to binding_digest   → DIGEST_MISMATCH
2. look up body.kid in the JWKS                                → KEY_UNKNOWN
3. reject if that key's status is "revoked"                    → KEY_REVOKED
4. crypto.verify(null, hexDecode(binding_digest), spki, signature) → SIGNATURE_INVALID
5. recompute authorization-envelope.hashDoc(fields)            → ENVELOPE_MISMATCH
6. verifyMembership(capability_root, capability_proof)         → CAPABILITY_PROOF_INVALID
```

Step 1 must fail **specifically** on a tampered copy — that is the day-4 acceptance test, and "it fails
somehow" does not count.

#### ✅ THE PREIMAGE CONTRACT — settled 2026-09-01. Signature covers the RAW 32 DIGEST BYTES.

```
binding_digest = sha256(jcs(body))            → a 64-char LOWERCASE hex string
signed message = hexDecode(binding_digest)    → the 32 raw bytes
```

**This was changed, deliberately, while zero receipts existed.** The ported module signed
`Buffer.from(bindingDigest)` — and because `Buffer.from(str)` with no encoding is UTF-8, that signed the
**64 ASCII characters of the hex**, not the digest. Raw bytes is the less surprising preimage, and Cosmos
had no receipts, so the change was free.

> **CORRECTION 2026-09-06.** An earlier revision of this paragraph called Writ's ASCII-hex preimage an
> interop *defect* that "any verifier in Python, Go or Rust would get wrong." **That was wrong.** Writ's
> preimage is documented publicly — <https://writ.money/llms.txt> ("The signed message is the UTF-8
> bytes of that 64-character hex") and <https://writ.money/verify.html> ("the message here is the hex
> STRING, not the raw 32 bytes"), both verified reachable 2026-09-08 — and Writ has an independent Python
> verifier, written from the doc text alone, that verifies
> it TRUE and verifies the raw-bytes guess FALSE as a control. Verified by reading both files in Writ's
> main tree. Cosmos's change stands on its own merits (least surprise, zero receipts), not on Writ being
> broken. **Consequence:** Cosmos and Writ receipts are different formats — Cosmos is COSE_Sign1 since
> 2026-09-05, Writ is JCS + Ed25519 over the hex string — and are **not cross-verifiable**. A Cosmos
> verifier fails on a Writ receipt at CBOR parse, before any signature check. Integration #0 needs no
> cross-verification (Writ carries Cosmos's `receipt_id`; each artifact is verified by its own verifier),
> but two formats in one settlement record is a documentation obligation Cosmos accepts.

The change is **not backward compatible**, which is exactly why it was made now rather than after day 4.

Two consequences, both tested:
- **`sign()` now validates its input** (`INVALID_BINDING_DIGEST`). `Buffer.from(s, 'hex')` truncates
  *silently* on a malformed string — `'zz'` yields an **empty buffer** — so without a guard a bad digest
  would produce a real signature over the empty message, and that signature would verify. It now refuses
  anything that is not a 64-char lowercase hex string: non-hex, empty, short, uppercase, `Buffer`, `null`.
- **Uppercase hex is refused too**, so one body can never have two valid digests.

Vectors C6–C16 pin all of it, and C9 specifically asserts the *old* ASCII-hex preimage no longer verifies —
so a regression cannot pass silently. Reverting the change fails 7 assertions, including D9, E10 and G5,
the three that encode the actual product promise.

### Three more keystore findings the deploy path must respect (`test/receipt-keystore.test.js`, 71 vectors)

1. **The dev-key hazard is real and silent** (A5–A8). Two unconfigured keystores produce the **same kid**
   with **different keys** — so a verifier looks up the right kid and still fails. Production **must** pass
   `allowDevKey: false`; without it a restart orphans every receipt already issued. Confirms §4's earlier
   warning with a test rather than an assertion.
2. **Never reuse a kid** (E12–E14). Rotating onto a *retired* kid is permitted, and it overwrites that
   kid's public key in the registry — silently orphaning every receipt signed under the original. Cosmos
   kids must be monotonic: `cosmos-receipt-2026-09`, `-10`, … and never revisited.
3. **`KEY_REQUIRES_PUBLIC_OR_PRIVATE` is dead code** (H5). `_loadRetired` already skips a key with no
   material and `bootstrap` only ever supplies a private key, so the guard is unreachable through the
   public API. Not a protection Cosmos can rely on.

Confirmed working as documented: the JWKS never carries private material (B1–B4), rotation is
persistence-bound (E3), revocation fails closed and stays published as `revoked` rather than vanishing
(F4, F5), and a receipt signed before a rotation *or* a restart still verifies (E10, G5).

### ✅ The load-bearing module is now covered — `test/jcs.test.js`, 52 vectors, 2026-09-01

`core/jcs.js` is 26 lines and **every signature in the system rests on it**. Writ's certificate suites
executed it constantly but only asserted round-trips through *itself*, which any self-consistent function
passes — including a wrong one. It is now tested against RFC 8785 directly.

The decisive vector is **A4**: RFC 8785 §3.2.3 sorts property names as *arrays of UTF-16 code units*, not
by codepoint, and the two orders disagree for astral characters. Using the RFC's own worked example —
€ (U+20AC), 😀 (U+1F600), דּ (U+FB33) — UTF-16 order is € → 😀 → דּ because the emoji sorts on its lead
surrogate 0xD83D, whereas codepoint order would put it last. JavaScript's default `.sort()` is UTF-16
code-unit order, so `jcs.js` is correct — but that was luck until it was a test.

**Mutation proof** (rule 4): deleting `.sort()` fails 8 named assertions; deleting the `undefined` filter
fails 1; deleting the non-finite guard fails 3. Restore verified byte-identical by sha256
(`90BCF882…50FD56`), 52/52 green after.

#### ⚠️ Correction to an earlier claim in this document

An earlier revision of §4 stated that `jcs.js` is *"not full RFC 8785 for arbitrary floats"*. **That was
wrong.** RFC 8785 §3.2.2.3 requires numbers to be serialized per ECMA-262 §7.1.12.1 (`Number::toString`),
which is exactly what `JSON.stringify` implements for finite doubles. Vectors B5–B11 confirm it against the
RFC's own examples: `1e+30`, `1e-27`, `5e-324`, the `1e20`/`1e21` positional-to-exponent boundary, `-0` → `0`,
and `0.1` in shortest round-trip form. **Cosmos may claim RFC 8785 compliance for finite doubles.**

The real gap is elsewhere, and narrower: `jcs.js:17` accepts `bigint` and emits it verbatim (vector F5).
RFC 8785 requires numbers be "expressible as IEEE 754 double-precision values", which a bigint past 2^53
is not. JSON has no bigint at all, so this is an extension beyond the spec. **Cosmos must never put a
bigint in a receipt** — integer minor units are `number`, and stay well inside 2^53.

Two other divergences are documented rather than fixed, because callers depend on neither: top-level
`undefined` returns `'null'` where `JSON.stringify` returns `undefined` (F1), and functions/symbols are
refused with `JCS_UNSUPPORTED_TYPE` rather than silently dropped (F3, F4).

### What the envelope binds — and five things it does not (`test/authorization-envelope.test.js`, 72 vectors)

The module's central claim holds: **all 31 bound fields change the hash when perturbed** (vector B1, tested
mechanically field-by-field). Unbinding `amount_minor` from `canon()` makes B1 name the colliding field and
flips G4 — a one-cent tamper starts verifying as genuine. The evidence property is real and now pinned.

Five behaviours found while testing that the API layer must design around:

1. **An unbound field is silently unprotected** (B3). `canon()` hashes a fixed list. Any field Cosmos adds
   to the envelope later and forgets to add to `canon()` travels in the artifact but is *not* covered by the
   hash. **Adding a field to the envelope means editing `canon()` in the same commit, or the field is
   decoration.**
2. **The secret guard inspects KEY NAMES only** (C17). `merchant: 'sk-live-REALSECRET'` passes untouched.
   So Cosmos must never place free text it did not generate into `merchant`, `category`, or `vendor_ref` —
   hash the description instead, which §3 already does via `description_hash`.
3. **`"1200"` and `1200` hash identically** (D20, D21) — coercion happens before hashing, so a numeric
   string is accepted. This is why §5 Gap 4's boundary validation is load-bearing rather than cosmetic: the
   envelope will not catch a string amount for you.
4. **Falsy values collide with defaults** (F3–F5). `asset: ''`, `asset: undefined` and `asset: 'USDC'` all
   produce the same hash, and an omitted `destinationFingerprint` collides with `''`. Cosmos must set
   `asset` and `network` **explicitly** on every envelope — a default that silently absorbs empty string is
   not something to rely on.
5. **A comment overstates the code** (E7). The header claims *"approver without an approval requirement …
   is refused"*, but line 46 only implements the `approver === requester` half. An approver on an envelope
   requiring no approval is accepted today. The test pins actual behaviour so the divergence stays visible;
   if Cosmos wants the stricter rule it is a Cosmos-layer check, not an edit to a ported module.

⚠️ **Two canonicalization schemes now exist in one product.** `canon()` uses `JSON.stringify` over a
hand-ordered object literal; the receipt signature uses RFC 8785 via `core/jcs.js`. Both are deterministic,
they are simply not the same function. Do not "unify" them without re-hashing history.

### Key management

`receipt-keystore.js` reads `WRIT_RECEIPT_PRIVATE_KEY`, `WRIT_RECEIPT_KID`, `WRIT_RECEIPT_RETIRED_KEYS`
from env at module load. **Do not rename those variables in the module.** The API layer reads `COSMOS_*`
env vars and passes them explicitly as `makeKeystore({ privateKeyPkcs8B64, kid, retired })`
(`receipt-keystore.js:67`), which bypasses the env path entirely. Zero edits to a ported module.

Production **must** set `allowDevKey: false`. Without it, `receipt-keystore.js:70-73` silently generates an
ephemeral key, and every receipt signed by it becomes permanently unverifiable on restart. That is a
one-line config mistake with unrecoverable consequences, so it belongs in the deploy checklist, not in a
comment.

---

## 5 · Seven integration gaps found by reading the code

These are not hypotheticals. Each was found by reading the ported source this session, and each needs a
decision before an endpoint can be written.

### Gap 1 — units disagree
`guardrails.js:8` does float arithmetic (`+(agent.budget - agent.spent).toFixed(6)`).
`authorization-envelope.js:44` **throws** unless `amountMinor` is a strict positive integer.

**Decision: integer minor units everywhere, including into `evaluate()`.** `evaluate` is generic
arithmetic — feeding it integers is valid, removes float error entirely, and requires no edit to the
frozen anchor. `.toFixed(6)` on integers is a harmless no-op.

### Gap 2 — `spentToday` is not reconstructible
`replay.js` folds `budget`, `spent`, and `status`. It never computes `spentToday`, but `guardrails.js:18`
requires it for the daily cap.

**Decision:** a separate pure fold in `core/agent-view.js` that sums `reservation` events within the
current day, minus `reversal` events in the same window. **Open question for the founder: which day
boundary?** UTC is simplest and defensible; the grant's local timezone is friendlier and needs a tz field
on the grant. Cannot be inferred — see §12.

### Gap 3 — guardrails is currency-blind
Nothing in `evaluate()` looks at currency. A grant funded in USD would happily authorize a JPY request.

**Decision:** the adapter checks currency **before** calling `evaluate`, and prepends
`{ name: 'Currency matches grant', pass }` to the checks array. `CURRENCY_MISMATCH` is a Cosmos reason
code, not a guardrails one. The receipt's `checks` array is therefore `adapter checks ++ guardrails checks`,
in that order — the verifier must not assume checks come only from guardrails.

### Gap 4 — a DENY can be unrepresentable
`authorization-envelope.js:44` throws `INVALID_AMOUNT_MINOR` for `amount <= 0`. So a denial of a zero or
negative amount cannot produce an envelope, and therefore cannot produce evidence.

**Decision:** the HTTP boundary rejects non-positive and non-integer amounts with **400 and no receipt** —
that is a malformed request, not a decision. Consequence: `guardrails.REASONS` includes `INVALID_AMOUNT`
and `NO_AGENT`, and **both become unreachable through the API** (unknown grant → 404). They stay reachable
when calling the module directly. Documented so neither looks like dead code.

### Gap 5 — approvals is a process-global
`approvals.js:12` is a module-level `Map`, and `thresholdFor` (`:17-20`) falls back to
`process.env.APPROVAL_THRESHOLD`.

**Decision:** every grant carries `approval_threshold_minor`, so the adapter always supplies
`approvalThreshold` and the env fallback never fires. The in-memory queue is acceptable on one box because
`approvals.rehydrate(events)` (`:33`) rebuilds it at boot. **This is the module that breaks first if Cosmos
ever runs more than one process** — noted now so that discovery is not a surprise later.

### Gap 6 — the size guard has a loophole
`scripts/size.js:6` scans `['core','api','mcp']` with `readdirSync`, which is **not recursive**, and does
not scan any other directory.

So a `verify/` directory, or `core/sub/`, would be invisible to the ceiling. **Decision: the offline
verifier lives in `core/`, not `verify/`, and no subdirectories are created under the three scanned roots.**
Routing around the guard is the exact drift the guard exists to prevent, and it would be trivially easy to
do by accident.

### Gap 7 — `ledger.js` and `invariants.js` stay out
Confirmed by dependency scan this session: `ledger.js` requires `./ledger-chain`, `./db`, `./bus`,
`./metrics`, `./log`; `invariants.js` requires `./ledger` and `./ledger-chain`. Porting either drags in
Writ's infrastructure. `core/store.js` is designed here on Cosmos's terms instead (§8).

---

## 6 · Capability commitments — the privacy property

`capability-commitment.js` is already ported and has the strongest test coverage of the seven (30/30). Its
test file contains an explicit negative control proving the surveillance vector it removes.

**In v1:** a grant commits `allowed_categories` to a Merkle root. Each receipt carries an inclusion proof
for **only the category actually used**. A verifier confirms the spend was within authorized scope without
learning the rest of the agent's authority. That directly serves decision (b) — verification is local and
discloses nothing extra.

**Deliberately NOT in v1** (both already implemented in the module, both would be scope creep):
- **Attenuated delegation** — sub-agents with narrower authority (`proveAttenuation`, `reCommit`). Real, and
  a genuine differentiator, but no customer has asked and it doubles the API surface.
- **Signed limit bands** (`commitLimit`, `verifyWithinLimit`) — proving *amount ≤ cap* without revealing the
  cap.

Both are written down here so they are recognised as **deferred**, not forgotten, and so nobody rebuilds
them from scratch.

---

## 7 · The reservation problem — the hardest thing in the product

**The handoff never addresses this, and it determines whether "three calls" survives contact with reality.**

Cosmos says ALLOW and decrements the budget. The customer's rail then executes — or doesn't. If it fails
and nothing reverses the reservation, the agent's budget leaks and eventually every request DENYs with
`INSUFFICIENT_BALANCE` despite no money having moved. If Cosmos *doesn't* decrement on ALLOW, two concurrent
requests each see the full budget and double-spend.

Cosmos cannot observe the rail. By decision (a), it never will.

Three options:

| option | cost |
|---|---|
| **A. Reserve permanently** | Simple. Over-counts spend on every failed payment. Budgets drift wrong. Unacceptable. |
| **B. Add `POST /confirm`** | Correct, and honest. But it is a **fourth call**, and it breaks "zero code change for the agent" — the agent must now report back. |
| **C. Reserve with a TTL + piggybacked reconciliation** | Keeps three calls. More design. |

**Recommendation: C.** An ALLOW reserves with an `expires_at` (already a field on the envelope,
`authorization-envelope.js:34`). An unconfirmed reservation **auto-reverses at expiry** via a pure fold over
the event log — no timer, no background job, no fourth endpoint: the reversal is computed at read time by
the same fold that computes `spent`. Confirmation, when available, rides on the *next* `/authorize` call as
an optional `reconcile: [{ receipt_id, outcome }]` field.

Consequences, stated plainly:
- Budget is **eventually** accurate, not instantly accurate. Within a TTL window, a failed payment still
  counts against the budget.
- TTL choice is a real tradeoff: short leaks less budget but risks reversing a slow-but-successful payment;
  long is safer but ties up budget. **Default proposal: 5 minutes.** Not measured against any real rail.
- An agent that never calls `/authorize` again never reconciles. The fold handles this correctly (expiry
  reverses it), which is why the TTL is doing the real work and `reconcile` is only an optimisation.

**This is the single design decision most likely to be wrong, and it is the one to falsify first with a
real rail.** If B turns out to be necessary, take it — a fourth call that is correct beats three calls that
quietly mis-count money.

---

### ✅ RESOLVED 2026-09-08 — and the answer is "C plus a rail that talks back", not C alone

**Built: `core/rail.js` + `api/settlements.js` (`POST /settlements/:authorization_id`), 96 assertions in
`test/rail.test.js`, mutation-proved by `test/mutations/rail.json`.**

The recommendation above was right that the TTL is doing the real work and wrong that the TTL is the whole
answer. C keeps the budget *eventually* accurate; it cannot make it *correct*, because the auto-reversal is
a coin flip on a number nobody has measured. What was missing is that **the report does not have to come
from the agent.** §7 rejected option B on the grounds that a fourth call breaks "zero code change for the
agent" — but the party that knows whether the money moved is the RAIL, which already has to be told what to
execute. The agent still makes one call and changes nothing.

So the TTL stays, unchanged, as the fallback for a rail that says nothing. On top of it, three reports:

| report | effect | what it fixes |
|---|---|---|
| `submitted` | pushes the deadline out (default +15 min from the report) | a slow-but-successful payment stops racing a timer it was never told about |
| `settled` | the row leaves the sweep permanently | a settled spend is never handed back |
| `failed` | reverses **now** | no five-minute hold on money that provably did not move |

**The dormant slots were already there.** `replay.js` has folded `submission` (txId in flight) and
`settlement` (final) since the port from Writ and nothing had ever emitted either — the record was designed
for this and never wired. It is wired now, and `npm run audit:ledger`'s two independent folds still agree
across the new event kinds (`rail` §F).

#### The three questions that had to be answered before writing it

**Who may report** — ⚠ **the first answer to this was wrong and shipped a double-spend. Read the whole
paragraph; the corrected design is at the end of it.**

The first version accepted a per-authorization capability, minted with the ALLOW and stored only as a
`sha256(authId + '|' + token)`. It was rightly not the operator token — that mints grants, so a rail able
to report would be able to raise its own ceiling. **But the capability is returned in the `/authorize`
response, which means it is handed to the REQUESTER: the one party with a motive to lie about whether
money moved.** Found in review (Ramu, 2026-09-08), who named the `settled` direction. The severe direction
is the opposite:

| self-report | effect | severity |
|---|---|---|
| `settled` when nothing moved | consumes the requester's OWN budget | a false record; costs the liar, buys nothing |
| **`failed` when the money DID move** | **the budget comes straight back** | **spend $10, report `failed`, spend the same $10 again — an unbounded double-spend, with a credential Cosmos issued** |

So the capability is **necessary and not sufficient**. Three credential classes, and a TERMINAL outcome
(`settled` / `failed`) requires one the requester cannot hold:

- **`rail`** — `COSMOS_RAIL_TOKEN` (operator-set, delivered to the rail out of band, **never to the
  caller**) **plus** the per-authorization capability in `x-cosmos-handoff`. Two factors answering two
  different questions: the token proves *who* is reporting, the capability proves *which* authorization was
  actually routed to them. A compromised rail still cannot settle one it was never handed.
- **`operator`** — the operator token alone. It can already mint grants, so this is no new power; recorded
  as the weaker claim, because it is not the rail speaking.
- **`allow_holder`** — the handoff token alone → `submitted` **only**. Named for WHO HOLDS IT rather than
  for what it is: the entire defect was that this credential reaches the `/authorize` caller, and
  `capability` described the mechanism while hiding the holder.

**And `failed` is narrower still — not even the operator.** The three outcomes are ordered by what each can
cost somebody else: `submitted` extends the holder's own reservation and moves nothing; `settled` is
conservative, since it can only fix or increase recorded spend, so manual reconciliation stays possible;
`failed` **returns budget**, and every defect found here has pointed that way. Only the rail — or the TTL —
may give money back. The operator can mint a *new* grant but has no route that credits an *existing* one, so
allowing it to reverse would hand it a power it does not otherwise have.

⛔ **Fail closed, and visibly.** With neither token configured, nothing may report a terminal outcome — and
that includes `COSMOS_ALLOW_UNAUTHENTICATED_WRITES=true`. An open mint is a legitimate demo choice; an open
path that can return spent budget is not. The server says so at startup rather than at the first refusal.

⚠ The cost of storing only the hash, stated because it is real: the raw token exists in one HTTP response
and nowhere else, so an `/authorize` replayed after a restart returns the authorization **without** a
usable token. That is the price of the property that a leaked event log cannot forge a settlement.

**A settlement for an already-reversed authorization** — accepted, marked `rail_late`, and the spend
**re-reserved by appending**. History is never rewritten, so the log shows the TTL's wrong guess *and* its
correction. This can push a grant past its own budget, and it is allowed to: a cap that refuses to record a
spend that already happened makes the ledger lie about the world, which is worse than a grant that reads
over-committed and visibly so. The symmetric case is guarded too — a `failed` report arriving after the TTL
already reversed credits **nothing** a second time, which would be a double-spend pointing the other way.

**Recording an overrun must not raise the ceiling, and now it does not read as if a retry would help.** A
grant carrying more settled spend than its own budget refuses everything — `guardrails` already did that,
because `remaining` goes negative and no positive amount fits. What was wrong was the *name*:
`INSUFFICIENT_BALANCE` tells a reader to ask for less, and at negative remaining no amount works; only an
operator can clear it. `GRANT_OVERRUN` is a distinct reason, with `Grant not in overrun` as a failing named
check inside the signed receipt. It lives in `core/agent-view.js` — the adapter seam — and deliberately
**not** in `guardrails.js`, which is a frozen vendored copy byte-identical to Writ's. ⚠ Overrun is narrower
than it first looks: the TTL sweep reclaims anything still open, so reaching it needs real settled spend on
both sides. Boundary, decided before the code was read back: spent *equal* to budget is spent-out, not
overrun.

**Is the report itself receipted** — yes, and it is the whole point. An ALLOW whose evidence stops at the
decision cannot tell a reader whether anything happened next. The settlement receipt carries
`parent_receipt_id` back to the ALLOW and gets its own `stl_` id, so it can never shadow its parent in
`/evidence`. The pair reads: *policy allowed this at T1; the rail reported tx X at T2.*

#### ⛔ What this does NOT change: decision (a) still holds, and the receipt says so out loud

Cosmos still never touches money and still cannot see a rail. `rail_tx_id` is a **claim**. The danger is
precisely that a transaction id beside a valid signature reads as "Cosmos watched this settle", so the
artifact states its own limit three ways: a **failing named check inside the signed bytes** ("Rail outcome
observed by Cosmos: FAIL"), a `rail_reported_by` field naming the credential class, and a Python verifier
that prints `rail outcome: NOT OBSERVED` every time. `SCHEMA` went 2 → 3 for the same reason it went 1 → 2:
the new field changes how an existing one must be read, so an old verifier must fail closed with
`UNSUPPORTED_SCHEMA` rather than under-report.

**But what a verifier ACCEPTS is a different question from what an issuer WRITES, and conflating them was a
second defect (same review).** The directions are not symmetric. An *old* verifier reading a *new* receipt
must fail closed — it does, automatically and forever, because every released verifier hardcodes its own
number. A *new* verifier reading an *old* receipt has nothing to under-report: a schema-2 receipt carries
no `rail_*` fields, so there is no claim it could print without its caveat. Refusing it buys no safety and
orphans every receipt already sitting in someone's audit file. So `ACCEPTED_SCHEMAS = [2, 3]` while
`SCHEMA = 3`: **accept a set, issue one number.** Publishing that rule costs nothing today and would cost a
customer their evidence later. A schema joins the accepted set only if every field a reader could
over-trust in it is still printed with its caveat — a judgement each addition re-makes, not a licence.

#### Still not measured

The +15 minute submission grace is a guess in exactly the way the 5-minute TTL is a guess. It is a *better*
guess — it only applies once a rail has said "I have this" — but no real rail has been timed. Re-decide it
against the first one that reports.

---

## 8 · Persistence and the throughput wall

### Four hard requirements `core/store.js` inherits from `replay` (`test/replay.test.js`, 69 vectors)

The inertness property Cosmos relies on **is** a guarantee, not an accident: there is no `default:` case,
so unknown kinds change nothing. Adding one fails 5 assertions, including a log of only Cosmos
`approval_*` events folding to zero agents. Cosmos can safely share one log between `replay` and
`approvals`. Four things the store must therefore do, each pinned by a test:

1. **Filter malformed lines BEFORE folding** (B8, B9). `replay()` reads `e.kind` unguarded, so a single
   entry that parses to `null` **throws** and takes down boot. A JSONL line reading `null` is enough. The
   fold is not defensive and should not be made so — the store filters.
2. **Idempotency is entirely the store's job** (E1). A duplicated `reservation` **double-counts**; replay
   does not dedupe by `authId`. The `(grant_id, idempotency_key)` index is not a nicety — without it, one
   retried request permanently overstates spend.
3. **Never hand a raw projection to a mutating caller** (A5). `t.checks = e.checks || null` stores a
   *reference*, so the replayed state aliases the log. A caller that mutates `checks` rewrites history.
   Clone on the way out of the API layer.
4. **Authorization ids must be ≥13 characters** (G6). `receipts()` derives its id from `authId.slice(5,13)`,
   so a short id yields the degenerate `"rcpt_"` — and two authorizations then collide on one receipt id.
   Cosmos ids like `auth_01J8ZK3QW…` clear this; a naive `auth_1` does not.

Two smaller behaviours worth knowing: a `reservation` with no `amount` silently contributes 0 rather than
erroring (C8), and `reason` is **sticky** — an ALLOW recorded after a DENY still shows the old reason (D10).
Neither is wrong, both surprise.

Confirmed: first-`open`-wins so a restart cannot wipe or inflate funds (C4), `freeze`/`unfreeze` are
order-sensitive and durable (C10, C11), 1000 integer reservations sum exactly with no float drift (C12),
and `verify()` catches an agent that exists live with no history at all (F8) — invented balances cannot
hide from the audit path.

### `core/store.js` design
Append-only JSONL + in-memory projections + a **per-grant async mutex** serialising the
read-budget → decide → write-spend sequence. Without that mutex, two concurrent requests against one grant
both read the pre-spend budget and both ALLOW — the double-spend the whole product exists to prevent.

Boot: read the log, `replay.replay(events)` for balances, `approvals.rehydrate(events)` for the pending
queue. Both are already-ported pure functions.

Idempotency: a `(grant_id, idempotency_key) → receipt_id` index. A repeat returns the **identical stored
receipt** and writes no second reservation. An agent retrying on a timeout must never double-reserve.

### The wall — measured 2026-09-01, `npm run bench:io`

It is fsync, and it is not close. Intel N150, 4 cores, Node 24.18.1, SATA SSD, 600-byte append:

| | median | p99 | |
|---|---|---|---|
| `guardrails.evaluate` | 0.40 µs | 1.70 µs | |
| Ed25519 sign | 53.10 µs | 459.8 µs | |
| append, no fsync | 10.30 µs | 83.2 µs | |
| **append + fsync** | **876 µs – 1.11 ms** | **5.273 ms** | ← the wall |
| full path, fsync per authorization | 1.087 – 1.427 ms | 8.1 – 9.9 ms | **701–920/sec** |
| full path, group-committed at 128 | **127.7 – 128.5 µs** | 2.9 – 4.2 ms | **7,782–7,831/sec** |

⚠️ **Ranges, not points.** Two runs; the fsync-bound path varied ~25%, the group-committed path was stable
to within 1%. The conclusion is robust; the single-fsync figure is not. Re-run rather than quoting it.

**fsync is 17–21× the signature and >2,000× the decision.**

This falsifies the optimisation CLAUDE.md previously recommended. Signing is ~53 µs against a ~1 ms fsync,
so removing it entirely — while keeping fsync-per-authorization — buys under 5%. **Group commit is the
lever: 8.5–11× while still signing every receipt.** Batch signing is second, worth ~1.7× more, and only
after group commit makes the path CPU-bound again.

fsync is a fixed device round-trip, not throughput-bound: 8 appends cost the same fsync as 1 (860.9 µs vs
876.4 µs). Group commit therefore **self-tunes** — the busier the box, the larger the batch.

### This changes `core/store.js`

The per-grant mutex is necessary but not sufficient. It protects read-budget → decide → write-spend, but
**fsync is a global serialization point across all grants**, so a per-grant design alone would fsync once
per authorization and cap the whole box at well under 1,000/sec.

Revised: per-grant mutex **plus a single-writer append queue with group commit**. One writer drains
whatever accumulated during the previous fsync and flushes it in one call; each caller's promise resolves
when the fsync covering its append returns. This is standard WAL group commit, roughly 40 lines
**(estimate)**, and it is the difference between 920/sec and ~7,800/sec.

**Durability contract, stated explicitly:** an authorization is not acknowledged until the fsync covering
its append has returned. Cosmos never returns ALLOW for a spend that could vanish on power loss.

### Two escape hatches — one demoted, one still parked

- **Batch signing.** Sign one Merkle root over N receipts; hand each caller an inclusion proof.
  `capability-commitment.js` already has inclusion proofs, so this is assembly, not invention.
  **Demoted to second: measured worth is ~1.7× and only after group commit.**
- **Signed leases.** *$X / N calls / T seconds* drawn down locally; Cosmos sees the grant and the
  reconciliation instead of every call. Group commit buys 8.5× for ~40 lines; leases are a much larger
  design. **Trigger raised: only above a sustained ~10k/sec.**

### Caveats on these numbers
Not measured: multi-core scaling, and whether this consumer SATA SSD honours `FlushFileBuffers` through its
volatile write cache. If the drive lies, the durable figure is worse. A datacenter NVMe with power-loss
protection would likely be far faster. **Do not carry these figures to other hardware — re-run
`npm run bench:io` there.**

---

## 9 · `free_rein` — a loaded gun, kept visible

`guardrails.js:16-20` bypasses per-payment, daily, **and** category checks when `agent.freeRein` is true.
Only balance and expiry still apply.

Kept, because an operator sometimes genuinely wants it. Made safe by making it **loud**:
- Never a default; must be explicitly `true` in the grant request.
- `guardrails.js:20` already pushes `{ name: 'Free rein (caps bypassed)', pass: true }` into checks, so it
  appears in the signed receipt. Anyone auditing sees exactly which spends ran uncapped.
- `POST /grants` should log it at warn level.

The design decision is that a dangerous option is acceptable when it is impossible to use invisibly.

---

## 10 · The MCP server — now grounded in the actual spec

The handoff flagged this twice as the least certain estimate, because nobody had read the spec. It has now
been read.

**The spec has moved.** Latest stable is **2025-11-25**; there is a 2026-07-28 release candidate. Most
tutorials still describe 2025-06-18. Build against 2025-11-25.

### What a tool-wrapping server actually requires
Declare the `tools` capability, implement `tools/list` and `tools/call`. A tool is
`{ name, title, description, inputSchema, outputSchema, annotations, icons }` — `title`, `outputSchema`
and `icons` are newer additions. Results carry `content[]`, optional `structuredContent`, and `isError`.

Per the 2025-11-25 changelog, **input validation errors should be returned as tool execution errors
(`isError: true`), not JSON-RPC protocol errors**, so the model can self-correct. A Cosmos DENY is
therefore an `isError: true` result carrying the reason code — not a `-32602`.

### ESCALATE maps onto elicitation — with a catch
`elicitation/create` is exactly the human-in-the-loop primitive ESCALATE needs. Form mode takes a `message`
and a `requestedSchema` restricted to a **flat object of primitives**. The response `action` is
`accept` | `decline` | `cancel` — a three-state answer that maps cleanly onto approve / deny / timeout.

**The catch, which changes the design:** elicitation is a **client** capability. A server **MUST NOT** send
an elicitation request unless the client declared it at initialization. So ESCALATE needs two paths:

- client declared `elicitation` → `elicitation/create`, form mode, with the amount, merchant and reason.
- client did not → return `isError: true` with the reason and an approval URL. Degraded, but honest.

Also relevant, and favourable: the spec **forbids** requesting payment credentials via form mode elicitation
and requires URL mode for anything sensitive. Cosmos elicits an *approval decision*, never a credential —
so the design sits on the correct side of that rule by construction. For out-of-band approval (owner
approves on their phone) the spec provides URL mode plus error `-32042 URLElicitationRequiredError` and a
`notifications/elicitation/complete` notification.

One more requirement to honour: elicitation state **MUST NOT** be keyed on session ID alone; user identity
should derive from the authorization `sub` claim.

### The wedge
`mcp/proxy.js` connects to one or more upstream MCP servers, re-exports their tools verbatim, and for tools
matching a pricing rule runs `/authorize` first. ALLOW → forward. DENY → `isError` with the reason.
ESCALATE → elicit.

The agent changes nothing. It points at Cosmos instead of the upstream server. That is the entire claim,
and it is cheap to falsify by shipping it.

### Zero dependencies, or the SDK?
The core's dependency-free property is what makes it auditable in an afternoon.
**Recommendation: hand-roll JSON-RPC over stdio for v1** — newline-delimited JSON, roughly 150 lines
**(estimate)**. Adopt `@modelcontextprotocol/sdk` when Streamable HTTP and OAuth are needed, where it
clearly earns its weight. Revisit at that point, deliberately.

### ⚠️ The estimate was wrong
One day was never realistic. Proxying upstream servers, negotiating capabilities, and implementing both
elicitation paths is **2 days (estimate)** — and that is with the spec now read rather than guessed.

---

## 11 · Module budget

The ceiling is 25 modules / 3000 lines, currently 7/546. Planned build, **all line counts estimates**:

| module | role | est. lines |
|---|---|---|
| `core/store.js` | append-only log, mutex, idempotency index | 120 |
| `core/agent-view.js` | grant → guardrails shape, spentToday fold, currency check | 60 |
| `core/receipt.js` | build / sign / verify the decision receipt | 90 |
| `core/verify.js` | standalone offline verifier (in `core/` — Gap 6) | 80 |
| `api/http.js` | router, JSON plumbing, error mapping | 80 |
| `api/grants.js` | `POST /grants` | 70 |
| `api/authorize.js` | `POST /authorize` | 120 |
| `api/evidence.js` | `GET /evidence/:id` + JWKS | 60 |
| `mcp/server.js` | stdio JSON-RPC, tools/list, tools/call | 150 |
| `mcp/proxy.js` | upstream proxy, pricing rules, elicitation | 120 |

**Projected total: 17 modules, ~1496 lines** — 68% of the module ceiling, 50% of the line ceiling.

The whole product fits with real headroom. If it doesn't, that is the signal to delete something, not to
raise the ceiling. Raising it is allowed, but only as a deliberate edit to `scripts/size.js` that someone
can be blamed for.

---

## 12 · Revised plan

Day 1 is done. Day 2 order is set by CLAUDE.md's own ranking, which the code reading confirms.

| day | work | done when |
|---|---|---|
| 2 | ✅ **`jcs`** 52 vectors + 3-mutation proof (§4) · ✅ **`authorization-envelope`** 72 + 4-mutation proof · ✅ **`receipt-keystore`** 78 + 5-mutation proof (§4) · ✅ **`replay`** 69 + 5-mutation proof (§8). Next: `approvals`, `guardrails` | each with a mutation proof: mutate → the *named* assertion fails with printed values → restore → sha256 identical |
| 3 | `core/store.js`, `core/agent-view.js`, the three endpoints | a grant is minted, an authorization decided, evidence fetched, and `replay.verify()` shows zero diffs against live state |
| 4 | ✅ preimage settled (§4 — raw bytes). Then `core/receipt.js`, `core/verify.js`, JWKS | a stranger verifies with no account; a tampered copy fails **specifically** on `DIGEST_MISMATCH` |
| 5–6 | MCP server + proxy (**2 days**, §10) | an agent calling a paid tool gets ALLOW/DENY with zero code change on its side |

**Before day 3 designs around storage, run the fsync benchmark (§8).** It is one command and it may
reorder everything after it.

Week 2: deploy, one demo a stranger can run, list on the MCP registry (`server.json` format).

---

## 13 · Decisions the founder owns

Ordered by how much they block.

1. **Day boundary for `spentToday`** (Gap 2) — UTC, or a per-grant timezone? Blocks day 3. UTC is simplest;
   a tz field is friendlier and costs one grant field. Cannot be inferred.
2. **The reservation model** (§7) — recommendation is C (TTL + piggybacked reconciliation) to preserve three
   calls, but B (a fourth `/confirm` call) is more honest if a real rail needs it. **Most consequential
   decision in this document.**
3. **Reservation TTL** — 5 minutes proposed, measured against nothing.
4. **Name.** Cosmos Network / Cosmos SDK is a large existing blockchain ecosystem. Still flagged, still
   unresolved, and it gets more expensive to change after the MCP registry listing.
5. **Pricing** — per-decision or per-seat. Never touching volume means a percentage is unavailable; that
   caps the upside and is the deliberate cost of not being a rail.

---

## 14 · What this document does not claim

- No endpoint exists yet. Nothing in §1–§4 has been built or tested.
- All line counts in §11 are estimates.
- The fsync benchmark **has** been run (§8, `npm run bench:io`, 2026-09-01). Multi-core scaling has not, and
  whether the drive honours `FlushFileBuffers` through its cache has not.
- `jcs.js` **is** RFC 8785 compliant for finite doubles (52 vectors, §4). It is *not* compliant for
  `bigint`, which it accepts as an extension — Cosmos must never put one in a receipt.
- Whether MCP wrapping converts is a hypothesis. It is cheap to falsify: ship it, list it, count installs.

---

## Sources

- [MCP — Tools (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- [MCP — Key Changes, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/changelog)
- [MCP — Elicitation (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation)
- [MCP — Specification index](https://modelcontextprotocol.io/specification/2025-11-25)
</content>
</invoke>
