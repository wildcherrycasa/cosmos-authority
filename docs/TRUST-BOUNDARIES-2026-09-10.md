# Trust boundaries — one pass, 2026-09-10

**Why this exists.** On 2026-09-09 Cosmos shipped three defects in one day. The suite was at 1053 green
assertions and 27 caught mutations at the time, and it saw none of them. Two of the three were found by
other people reading the code.

They shared a shape. Every assertion and every mutation asked **does the mechanism work**. None asked:

1. **Who holds the key?** — which party is in possession of the credential this check reads.
2. **Where do the credentials go?** — who chooses the destination a secret is sent to.
3. **Can this check ever match?** — is there an input for which this assertion fails.

This is one pass over every place data crosses a party, asking those three. It is a **document, not a
change**: no features, no refactors. Findings are recorded with a disposition and stop there.

> The three that prompted it, for calibration:
> · the settlement capability was handed to the **requester** — the one party with a motive to lie (Q1)
> · the reference rail sent its bearer token to a URL **the caller supplied** (Q2)
> · `public-drift` compared against a tree that could not yet match, and read as drift (Q3)

---

## The crossings

| # | crossing | Q1 · who holds the key | Q2 · where do credentials go | Q3 · can the check match | state |
|---|---|---|---|---|---|
| 1 | **agent → Cosmos** `/authorize` | nobody — deliberately unauthenticated; an agent asking permission *is* the product | nothing sent outward | yes — DENY/ESCALATE are exercised on real inputs | ✅ |
| 2 | **operator → Cosmos** `/grants`, `/approvals/:id`, `/audit` | operator, via `COSMOS_WRITE_TOKEN`; compared with `timingSafeEqual` over hashes | nothing outward | yes — `auth` suite drives token/no-token/wrong-token | ✅ |
| 3 | **Cosmos → agent** the ALLOW's `rail` block | Cosmos mints a per-authorization capability, returns it **once** | to the requester — and that is why it may only report `submitted` | yes — §K asserts the refusal | ✅ ① |
| 4 | **rail → Cosmos** `/settlements/:id` | `rail` = operator-set `COSMOS_RAIL_TOKEN` **and** the per-auth capability; `operator` = write token; `allow_holder` = capability alone | nothing outward | yes — a real HTTP client was refused `failed` on the lab phone | ✅ ① |
| 5 | **rail → its own outbox** (example) | the queue file holds handoff tokens | rows store an endpoint **name** and a path, never a URL | yes — mutation M3 caught storing a URL | ✅ ② |
| 6 | **operator config → Cosmos** environment | operator | signing key has **zero** env surface since PR #15 | partially — see **F1** | ⚠ |
| 7 | **repo → npm tarball** | n/a | n/a — but a secret-shaped file would ship | yes — proved red on nine real files, then green | ✅ ③ |
| 8 | **repo → public export** | n/a | n/a | yes — four checks, each proved by finding what the last could not | ✅ |

① The one that was wrong on 2026-09-08 and is the reason rows 3 and 4 are split: a capability that reaches
the requester must not be sufficient for a terminal outcome. `failed` requires the rail class, because
`failed` returns budget and an unbounded double-spend is what that buys.
② The one that was wrong on 2026-09-09, twice — first the destination (SSRF + credential exfiltration),
then durability (a dropped report and a malicious `failed` produce the identical ledger).
③ The rule is **"if it is not in git, it does not ship"**, not a list of known-bad names. The list answered
*is the threat I thought of present*; it never answered *is anything here that simply should not be*.

---

## Findings

| id | crossing | finding | disposition |
|---|---|---|---|
| **F1** | 6 | `core/approvals.js:18` reads **`APPROVAL_THRESHOLD`** — **unprefixed**. Every other product variable is `COSMOS_*`. It is live on the `/authorize` path (`api/authorize.js:97`) and sets the line above which a spend escalates to a human. An unprefixed name is one any other process, deploy script or sibling project on the same box can set or clear. Same shape as the incident where an unset `COSMOS_RECEIPT_PRIVATE_KEY` let Cosmos sign with **Writ's** key: a foreign environment name reaching into Cosmos's decision path. | **Founder decision.** Severity is low — the default is OFF (`Infinity`), and a per-agent `approvalThreshold` overrides it — so the realistic harm is an operator who relies on the variable and has escalation silently stop. But `core/approvals.js` is **vendored from Writ**, so renaming it diverges a tracked copy and needs a manifest row. That is a deliberate edit someone signs for, not a day-end fix. ⚠ It follows that **Writ carries the same unprefixed variable**; routed to the reviewer, not to Writ. |
| **F2** | 5 | The example's outbox is a plaintext file holding handoff tokens, because a retry cannot authenticate without one. | **Accepted, documented.** It is an example with no dependencies; the README says plainly that it is a credential store and not a log, and it is gitignored (pattern proved with `git check-ignore`). A real rail is told to use the durable outbox it already owns. |
| **F3** | 2 | `COSMOS_ALLOW_UNAUTHENTICATED_WRITES=true` opens grant minting, approval resolution and the whole `/audit` grant dataset to anyone who can reach the port. | **Accepted by design.** A public demo genuinely wants strangers minting their own grants. It is loud at every startup, and it does **not** open terminal settlement reports — an open mint is a legitimate choice, an open path that can cancel a budget reversal is not. |
| **F4** | 3 | `approver_id` is client-asserted; holding the operator token does not make it a verified human. | **Fixed and shipped, kept here for completeness.** `approver_authenticated` rides inside the signed payload and the verifier prints the caveat; `SCHEMA` went 1 → 2 so an old verifier fails closed. |
| **F5** | 4 | Cosmos cannot see a rail. A `tx_id` beside a valid signature would read as "Cosmos watched this settle", which is false. | **Fixed and shipped.** The receipt carries a deliberately **failing** named check and the verifier prints `!! rail outcome: NOT OBSERVED` every time. |

---

## What this pass did not cover, said plainly

- **It is a reading, not an audit.** One person, one afternoon, no adversary. Two of the three defects that
  prompted it were found by someone else reading the same code I had already read.
- **No dependency surface**, because there is none — zero runtime dependencies, verified by scan.
- **No transport security.** TLS termination is the operator's; nothing here assumes it.
- **No rate limiting.** `/evidence` is public and unauthenticated, and a **miss** is the most expensive path
  (a full backward walk, measured at 3.57 ms over 200,000 events). That is a load amplifier before it is a
  latency problem. The recorded trigger for building an index is ~200k events **or** exposure to untrusted
  traffic, whichever comes first. Neither is reached, so it is not built.
- **Nothing here is evidence of adoption.** At the time of writing, zero third parties have implemented
  rail reporting and the package has no recorded installs.

**Standing rule this pass leaves behind, and the only durable output of it:** a test proves a mechanism
works. It does not prove the right party is holding the key, that a secret goes only where the operator
chose, or that the assertion could ever have failed. Ask those three separately, out loud, of anything
that crosses a party.
