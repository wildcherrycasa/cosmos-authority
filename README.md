# Cosmos

**A signed, offline-verifiable receipt that an AI agent's spend was authorized — or refused — under a stated policy.**

An agent asks *may I spend $X at Y for Z?* Cosmos answers **ALLOW / DENY / ESCALATE** and returns a COSE_Sign1 receipt anyone can verify with a published key and a 242-line Python script. No account. No network. No Cosmos code.

Cosmos **never moves money.** Your rail — Stripe, your bank, x402, AgentCore — executes. Cosmos is the evidence.

**Signed refusals exist. Refusals a stranger can verify do not.** Google's Agent Payments Protocol already requires one — *"Upon acceptance or rejection of the Mandate, the Verifier MUST return a signed Mandate Receipt"* ([`agent_authorization.md:496`](https://github.com/google-agentic-commerce/AP2/blob/main/docs/ap2/agent_authorization.md)) — and defines **no key discovery at all**: no JWKS, no `/.well-known`, trust established bilaterally with every agent provider. So the receipt is signed and an outsider still cannot check it. Cosmos publishes the key, so anyone can, offline, with no account and no relationship with us.

> ⚠ **Correction, 2026-09-08.** This paragraph used to read *"Nobody signs the refusal… nobody else produces it."* That was **false**, and false before it was written here. See [`docs/PRIOR-ART-2026-09-08.md`](docs/PRIOR-ART-2026-09-08.md) for the four IETF drafts and two shipping systems that already sign refusals, each verified at source.

## Verify a receipt in 30 seconds, without installing Cosmos

```bash
pip install cryptography
python3 verifier/cosmos_verify.py demo/deny.json demo/jwks.json   # Windows: python
```

On **Android / Termux** that first line fails: `cryptography` has no Android wheel on PyPI, so pip builds it from source with maturin and there is no Rust toolchain. Use `pkg install python python-cryptography` instead — then the command above is unchanged. Measured on a Samsung A15, 2026-09-06: `pkg` install succeeds (Python 3.13.13, cryptography 48.0.1) and `pip install cryptography` in a clean venv ends `ERROR: Failed to build 'cryptography' when installing build dependencies`.

```
VALID  kid=cosmos-demo-2026-09  key_status=active
  decision=DENY reason=PER_PAYMENT_LIMIT
  3000 USD at api.openai.com for agent agent_research_01 (grant grn_…)
    [pass] Currency matches grant
    [pass] Active
    [pass] Not expired
    [pass] Sufficient balance
    [FAIL] Under per-payment cap
    [pass] Under daily cap
    [pass] Category allowed
  capability proof: ok (category in committed set)
```

Flip one byte of `cose_base64` and it exits 1 with `SIGNATURE_INVALID` — that specific reason, not a generic failure. The verifier has its own CBOR decoder written from RFC 8949 and shares no code with the issuer; its signing input matched the issuer's byte-for-byte across languages in test.

Failure reasons a verifier reports: `COSE_MALFORMED` · `COSE_WRONG_TAG` · `COSE_UNSUPPORTED_ALG` · `KEY_UNKNOWN` · `KEY_REVOKED` · `SIGNATURE_INVALID` · `UNSUPPORTED_SCHEMA` · `CAPABILITY_PROOF_INVALID`. A retired key still verifies history; only revocation stops it.

## Run it

Zero runtime dependencies. Node ≥ 20.

```bash
npm run keygen            # prints COSMOS_RECEIPT_KID / COSMOS_RECEIPT_PRIVATE_KEY — persist them BEFORE the first receipt
npm start                 # http://localhost:8787
```

**Mint authority** — a grant: budget, caps, categories, approval line. Amounts are integer minor units.

```bash
curl -sX POST localhost:8787/grants -H 'content-type: application/json' -d '{
  "org_id":"acme","agent_id":"research-01","currency":"USD",
  "budget_minor":50000,"per_payment_cap_minor":1700,"daily_cap_minor":5000,
  "allowed_categories":["api","cloud"],"approval_threshold_minor":1500}'
```

**Ask** — every decision is signed inside the same durable write as the decision itself:

```bash
curl -sX POST localhost:8787/authorize -H 'content-type: application/json' -d '{
  "grant_id":"grn_…","amount_minor":1200,"currency":"USD","category":"api",
  "merchant":"api.openai.com","description":"embeddings batch 4471","idempotency_key":"req-9931"}'
```

→ `{"decision":"ALLOW", "receipt_id":"auth_…", "evidence":"/evidence/auth_…", "checks":[…], "signed":true, …}`

A DENY is HTTP 200 — a well-formed question got a real answer. 400 is reserved for malformed requests. The same `idempotency_key` returns the same receipt and reserves nothing twice, before and after a restart.

**Prove** — the receipt and the key that verifies it:

```bash
curl -s localhost:8787/evidence/auth_…            > receipt.json
curl -s localhost:8787/.well-known/jwks.json      > jwks.json

# …or take the COSE_Sign1 bytes themselves — same artifact, no JSON around it, no base64 to undo:
curl -s -H 'accept: application/cose' localhost:8787/evidence/auth_… > receipt.cose
python3 verifier/cosmos_verify.py receipt.json jwks.json
```

**Report back** — the ALLOW response carries a `rail` block: which rail to use, where to report, and a one-shot capability scoped to that single authorization. The rail reports the outcome; Cosmos signs a *second* receipt chained to the first.

```bash
curl -sX POST localhost:8787/settlements/auth_… \n  -H "authorization: Bearer $COSMOS_RAIL_TOKEN" \n  -H "x-cosmos-handoff: $HANDOFF_TOKEN" \n  -d '{"outcome":"settled","tx_id":"0x…","provider":"writ"}'
```

**Two credentials, and the reason is a double-spend.** The rail token says *who* is reporting and reaches only the rail; the handoff token says *which* authorization was routed to them and reaches the agent. The handoff token alone may report `submitted` and nothing else — it is returned to the requester, and a requester able to report `failed` gets its budget back and spends the same money twice. `failed` is narrower still: **only the rail, or the TTL**, may give budget back — not even the operator, which can mint a new grant but has no route that credits an existing one.

This is what makes an ALLOW mean something. On its own an ALLOW says a policy permitted a spend; it cannot tell a reader whether the money moved. `submitted` extends the reservation so a slow-but-successful payment stops racing a timer; `settled` makes it final so it is never auto-reversed; `failed` returns the budget immediately instead of holding it for the TTL. A rail that says nothing still gets the TTL — the handoff removes the *guess*, not the fallback. The protocol, the three design questions it had to answer, and what it still does not prove: [docs/DESIGN.md](docs/DESIGN.md) §7.

**ESCALATE** — a spend over the approval line pauses and reserves nothing. A human resolves it; the resolution is a *second* signed receipt whose `parent_receipt_id` is the first. A human "yes" does not override policy: the spend is re-evaluated with the approval line removed, and if a cap no longer fits the receipt records both *approver: pass* and *balance: fail*.

```bash
curl -s localhost:8787/approvals                                    # pending
curl -sX POST localhost:8787/approvals/auth_… -d '{"decision":"approve","approver_id":"ops-1"}'
```

## Put it in front of a paid tool — zero agent code change

Cosmos ships an MCP server that wraps any upstream MCP server. Point the client at Cosmos instead of the upstream; the upstream's tools are re-exported verbatim. Any tool matching a pricing rule is authorized **first**: ALLOW forwards the call and attaches the receipt under `structuredContent._cosmos`; DENY returns `isError:true` with the reason and receipt id, and the call **never reaches the upstream**. ESCALATE asks the human through MCP elicitation when the client supports it, and refuses with the out-of-band approval URL when it doesn't.

```json
{ "mcpServers": { "cosmos": {
    "command": "npx", "args": ["-y", "-p", "cosmos-authority", "cosmos-mcp"],
    "env": {
      "COSMOS_URL": "http://localhost:8787",
      "COSMOS_GRANT_ID": "grn_…",
      "COSMOS_MCP_UPSTREAM": "npx some-paid-tool-server",
      "COSMOS_MCP_RULES": "[{\"tool\":\"web_search\",\"amount_minor\":50,\"currency\":\"USD\",\"category\":\"api\",\"merchant\":\"search.example\"}]"
    } } } }
```

⚠ **`npx` needs the package published, and it is not yet.** Until then, clone this repo and use `"command": "node", "args": ["mcp/server.js"]` — everything else is identical. `npm run quickstart` starts a server, mints a grant, proves one ALLOW and one DENY, and prints this exact block filled in.

Rules can read the amount from the tool's own arguments (`"amount_arg":"cost"`). Built against MCP **2025-11-25**: validation failures are tool errors so the model can self-correct; unknown tools are protocol errors; elicitation is only ever sent to a client that declared it.

## What it guarantees, and what it doesn't

- An ALLOW is never acknowledged before the fsync covering its decision, reservation, and receipt returns.
- Concurrent requests on one grant cannot double-spend (per-grant mutex; proven with 10 simultaneous requests on a budget that fits 2).
- The whole state is rebuildable from the append-only log; `npm run audit:ledger` diffs the running server against a fresh fold from disk, across two processes.
- A receipt proves the category used **without disclosing the grant's other categories** (Merkle capability commitment).
- **It still cannot see your rail, and the receipt says so.** An ALLOW reserves budget with a TTL and is released if never reconciled. A rail *can* now report back (`POST /settlements/:id`) and that removes the TTL guess in both directions — but a report is a **claim**, not an observation. Cosmos never touches money and never checks a transaction id. So a settlement receipt carries a deliberately *failing* named check, `Rail outcome observed by Cosmos — FAIL`, records which credential class made the claim in `rail_reported_by`, and the verifier prints `!! rail outcome: NOT OBSERVED` every time. Cosmos is the authority record, not the settlement record, and it refuses to let a valid signature imply otherwise.
- **A requester cannot end its own payment.** A terminal report (`settled`/`failed`) needs the rail's own token *plus* the per-authorization capability; the capability alone may only report `submitted`. It is minted with the ALLOW, returned exactly once, and stored only as a hash bound to the authorization id — so a leaked event log cannot forge a settlement, and one authorization's token is refused against another. With neither the rail token nor the operator token set, **nothing** may report a terminal outcome, including when the operator surface is explicitly open: an open mint is a legitimate demo choice, an open path that can return spent budget is not.
- **A grant that ends up over budget says so.** A late settlement records money that really moved and can push a grant past its own ceiling. It never raises the ceiling — every further spend is refused with `GRANT_OVERRUN`, a distinct reason from `INSUFFICIENT_BALANCE`, because at negative remaining no smaller amount works and only an operator can clear it.
- **Bumping the receipt schema does not orphan old receipts.** Cosmos issues one schema and *accepts* a set. An old verifier must fail closed on a new receipt, and does; a new verifier reading an older receipt has no unqualified claim to print, so refusing it would buy no safety and would make evidence already filed unverifiable.
- `approver_id` is client-asserted; the receipt records who *claimed* to approve and via which channel. It does not authenticate them — **and since schema 2 the receipt says so itself**: every approval carries `approver_authenticated`, inside the signed payload, and the verifier prints `⚠ approver identity: NOT AUTHENTICATED` next to the valid signature. A valid signature proves the receipt was not altered; it does not prove the named human approved. Those are different claims and the artifact now distinguishes them instead of leaving it to a source comment.
- The **operator surface** takes a bearer token (`COSMOS_WRITE_TOKEN`): `POST /grants` and `POST /approvals/:id` because they create authority, `GET /audit` and `GET /approvals` because they disclose every grant. In production the server refuses to start without one unless you explicitly declare it open. `/authorize`, `/evidence/:id`, the JWKS and `/health` are never locked. That token authenticates the *caller*, not the approver.

## Which rail

Cosmos never moves money, so it needs one. The reference rail is **[Writ](https://writ.money)** — a live
agent-payments engine, and the one this handoff was designed against:

```bash
COSMOS_RAIL_PROVIDER=writ COSMOS_RAIL_ENDPOINT=https://writ.money npm start
```

Any rail works; Cosmos only ever hands the agent an address and waits to be told what happened.

⚠ **No rail has implemented the reporting side yet, Writ included.** A silent rail still works — the TTL
reverses an unconfirmed reservation by itself. What is missing is the better half: a settled payment
that is never auto-reversed, and a failed one that returns the budget immediately instead of after five
minutes. That is roughly thirty lines on the rail's side, and **building it for any rail is the most
useful contribution this project can take right now.** There is a working one to copy:
[`examples/reference-rail/rail.js`](examples/reference-rail/rail.js) — about 200 lines, driven end to end
against a real Cosmos by `test/reference-rail.test.js`.

## Licence

**Apache-2.0** — see [LICENSE](LICENSE). Chosen over MIT for the explicit **patent grant**: this is
spend-authorization infrastructure in a space where several large companies are actively filing, and an
integrator wiring a payment gate into production should get patent cover along with the copyright
permission, not just the latter.

Copyright 2026 Ramu Thapa.

## Status

Pre-release. Working end to end; not yet listed or deployed. `npm test` runs every suite through an aggregating runner that cannot short-circuit. Product size is guarded: `npm run audit:size` fails the build past 25 modules / 3,000 lines.

Read before contributing: [docs/DESIGN.md](docs/DESIGN.md) — the spec, the data model, and the seven integration gaps it records with a decision against each.

Format: COSE_Sign1 (RFC 9052) · Ed25519 · deterministic CBOR (RFC 8949 §4.2) · SCITT-shaped (RFC 9943). Repo: private until launch.
