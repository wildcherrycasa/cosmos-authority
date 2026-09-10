# Deploy — the hosted demo the outreach messages point at

The same three steps on any host. The host is the founder's choice; nothing here assumes one.

> **A host may already exist.** A sibling project of the founder's already runs a reverse proxy with
> automatic certificates on a shared Docker network, so co-locating is a hostname and a decision rather
> than a project. ⛔ **ARCHIVED 2026-09-08 — read the archived proposal's own header before anything else.**
> It was never executed and never approved, and it is the only path in this repo pointing at a sibling
> project's infrastructure. **The archived proposal holds a ready-to-review compose file, a proposed proxy block and the
> full sequence** — read its README first: it is that project's box, the tradeoff is theirs to accept,
> and the risk runs toward them, not toward Cosmos.
>
> **Redacted 2026-09-08 — pre-publication hygiene, NOT an incident.** This paragraph named the sibling
> project's hostname, address, proxy and Docker network arrangement.
>
> ⚠ **I first called this "severity 1, a public IP disclosure". That was wrong, and the correction matters
> more than the redaction.** Measured afterwards, three independent ways: the hostname resolves to that
> address in public DNS (a local resolver and an independent DNS-over-HTTPS query agree), and the site
> returns its own `Via` header naming its proxy. Anyone who types the hostname gets both. The document
> disclosed nothing a single lookup does not. **I formed the severity by reading a document instead of
> measuring the system it describes** — the exact failure this repo keeps finding in other people's work,
> committed while escalating it to the founder as urgent.
>
> One part genuinely was not public: the Docker network declared `external: true` and shared with sibling
> projects. Topology is not a lookup.
>
> Removed anyway, because another project's host has no business in this project's deploy guide, and
> That proposal is excluded from any public export for the same reason. Hygiene is reason enough; it did
> not need to be an emergency.

## 1. A persisted signing key — before the first receipt, not after

```bash
npm run keygen
```

Prints `COSMOS_RECEIPT_KID` and `COSMOS_RECEIPT_PRIVATE_KEY`. Put them in the host's secret store. **Never** commit them, log them, or paste them into a chat. With `NODE_ENV=production` and no key the server refuses to start — a dev key that dies with the process would orphan every receipt it signed. Kids are monotonic (`cosmos-receipt-2026-09`, `-10`, …) and never reused: rotating onto a retired kid overwrites its public key and orphans its receipts.

## 2. Run it

**Bare Node (any VPS):**
```bash
NODE_ENV=production PORT=8787 COSMOS_RECEIPT_KID=… COSMOS_RECEIPT_PRIVATE_KEY=… \
  COSMOS_WRITE_TOKEN=… node api/server.js
```
Persist `data/cosmos.jsonl` — it is the whole state. `npm run backup` bundles the repo; the log needs its own backup.

**Docker:**
```bash
docker build -t cosmos .
docker run -d -p 8787:8787 -v cosmos-data:/app/data \
  -e COSMOS_RECEIPT_KID=… -e COSMOS_RECEIPT_PRIVATE_KEY=… -e COSMOS_WRITE_TOKEN=… cosmos
```

> ⚠ **All three commands above were missing `COSMOS_WRITE_TOKEN` until 2026-09-06, and all three were run
> and observed failing.** Bare Node and `docker run` exit 1 before listening with
> `NO_WRITE_TOKEN: POST /grants and POST /approvals/:id would be open to anyone who can reach this port`,
> and the `curl` that mints the demo grant returns **401**. The prose below described the token correctly;
> the copy-pasteable lines did not, which is the only half anyone runs. Set it to at least 16 characters,
> or set `COSMOS_ALLOW_UNAUTHENTICATED_WRITES=true` if you genuinely want a public box where strangers can
> mint their own grants — which a throwaway demo host may well want, deliberately.

**Fly / Railway / Render:** point them at the Dockerfile, set the three secrets (kid, private key, write token), attach a volume at `/app/data`, expose 8787. No build step, no dependencies.

Put TLS in front of it (the host's proxy is fine). Cosmos itself speaks plain HTTP.

## 3. Prove it from outside — the stranger's check

From a machine that is not the server:

```bash
curl -s https://<host>/.well-known/jwks.json > jwks.json
curl -s https://<host>/evidence/<receipt_id> > receipt.json
# `pip install cosmos-verify` once it is on PyPI; until then, from a checkout:
python3 verifier/cosmos_verify.py receipt.json jwks.json
```

If that prints `VALID`, the demo is live. That URL is what fills the `[DEMO]` placeholder wherever it appears.

To have something to show, mint one grant and issue one ALLOW and one DENY (the DENY is the receipt nobody else issues):
```bash
curl -sX POST https://<host>/grants -H "authorization: Bearer $COSMOS_WRITE_TOKEN" -H 'content-type: application/json' -d '{"org_id":"demo","agent_id":"agent-01","currency":"USD","budget_minor":50000,"per_payment_cap_minor":1700,"daily_cap_minor":5000,"allowed_categories":["api"]}'
curl -sX POST https://<host>/authorize -H 'content-type: application/json' -d '{"grant_id":"grn_…","amount_minor":3000,"currency":"USD","category":"api","merchant":"api.openai.com","idempotency_key":"demo-deny"}'
```

## Operational notes

- `GET /health` — event count, grants, pending approvals, signing kid. `GET /audit` — live projection; `npm run audit:ledger` diffs it against the log.
- **`COSMOS_WRITE_TOKEN` protects the OPERATOR surface** with `Authorization: Bearer <token>` (minimum 16 chars, constant-time compare): `POST /grants` and `POST /approvals/:id` because they **create authority**, and `GET /audit` and `GET /approvals` because they **disclose the dataset** — `/audit` returns amounts, caps, merchants, categories and org/agent ids for every grant on the box. **In production the server refuses to start** unless you set the token or explicitly set `COSMOS_ALLOW_UNAUTHENTICATED_WRITES=true`; an accidentally-open mint or an open ledger is not something to discover later. `/authorize`, `/evidence/:id`, `/.well-known/jwks.json` and `/health` are never locked — an agent asking permission and a verifier with no account are the product.
- `npm run audit:ledger` reads `/audit`, so run it with the same token: `COSMOS_WRITE_TOKEN=… npm run audit:ledger`. It prints that instruction itself on a 401 rather than failing obscurely.
- The token authenticates the **caller**, not the approver. A receipt still records `approver_id` as client-asserted; holding the operator secret does not make it a verified human.
- The reservation TTL is 5 minutes (`COSMOS_RESERVATION_TTL_MS`). It is a guess, not a measurement against any rail.
