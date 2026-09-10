# Agent tools, proved — exact commands and real output, 2026-09-08

Companion to `PHONE-RUN-2026-09-08.md`, which covered the server and the verifier. This covers the two
surfaces that were listed there as **untested on Android**, plus the one gap that document named honestly
and could not close by itself: **a third-party host**.

**Founder's standard, verbatim:** *"make sure everything worked and is ready for public. cosmos agent cant
fake or decorate it as done. unless everything works like it is intended."*

Three runs. **Two of them failed first and are recorded failing.**

---

## Run 1 — x402 verifier + MCP wrapper on the phone

Payload: `core/ api/ x402/ mcp/ verifier/ package.json` plus the repo's fake upstream, staged from the
workstation over `adb reverse`. Lease claimed and released. Node 26.3.1, Python 3.13.

**First attempt: 10 passed, 5 FAILED.**

```
FAIL under the cap -> verdict allow, got {"verdict":"deny","code":"malformed_input",
      "message":"cosmos refused the request: IDEMPOTENCY_KEY_REQUIRED"}
```

⚠ **The x402 verifier was 100% broken against a real Cosmos.** It sent `idempotency_key: undefined`
whenever the bundle omitted one; `JSON.stringify` drops undefined; `/authorize` requires it. **Every**
x402-gated payment was refused as malformed, never once on policy.

**45 green assertions had missed it, because every one of them stubs `fetch`.** A stub proves the shape of
a *reply*. Nothing had ever looked at the *request*. Fixed in PR #21, with §I asserting the request body.

**After the fix: 15 passed, 0 failed.** The MCP half passed 6/6 on both runs, including the upstream
seeing exactly 1 of 2 paid calls — the refused one never executed.

## Run 2 — the acceptance bar, on the phone

| step | result |
|---|---|
| **persisted** key (`cosmos-phone-2026-09`), not the ephemeral dev key | server started with it |
| agent over MCP, call under the cap | ALLOW, receipt `auth_6e77d1722bebdba74a5e` |
| agent over MCP, call over the cap | DENY / PER_PAYMENT_LIMIT, receipt `auth_bd170ed7ebd526c85f1d` |
| upstream call count | 1 of 2 — the refusal never executed |
| **server restarted**, JWKS re-fetched | **byte-identical** — the key genuinely persisted |
| airplane mode, `curl https://pypi.org` | `net_rc=6`, could not resolve host |
| both receipts, verified on-device | **VALID, exit 0** |

8 passed then 2 passed, 0 failed. Restart is the real test of persistence: an ephemeral key makes every
receipt it signed unverifiable the moment the process dies.

## Run 3 — a REAL third-party host, which is what the other runs could not prove

`PHONE-RUN-2026-09-08.md` said plainly that the client driving those runs was one I wrote, and that this
proves the server speaks the spec *as I read it*, not that a host can use it. That gap is now closed with
actual **Claude Code**, pointed at the server via `--mcp-config` — **ephemeral, no persistent config on the
founder's machine was changed.**

**First attempt: both calls refused, and the host diagnosed it correctly.**

```
Cosmos authorization failed closed: Cosmos 400 INVALID_AMOUNT_MINOR: a positive integer in minor units
```

⚠ **A conformant host validates tool arguments against the published `inputSchema` and DROPS unknown
properties.** The pricing rule prices on `cost`; the re-exported schema declared only `q`; so `cost` never
arrived. A 500 call and a 9000 call produced **byte-identical** errors — the amount had no effect at all.

The repo's own MCP suite passed throughout, because its hand-written client sends whatever it is told to.
**This is the second instance of the same lesson in one day**, after the stubbed `fetch`. Fixed in PR #21:
`tools/list` now declares the priced argument on that tool's schema. §S asserts it, control proved.

**After the fix, same host, same prompt:**

| call | outcome |
|---|---|
| `cost=500` | **ALLOW**, receipt `auth_2f69bdb618db69118b00`, upstream executed and returned its result |
| `cost=9000` | **DENY / PER_PAYMENT_LIMIT**, receipt `auth_13d767fc1e0373603b1c`, upstream **not** executed |

Both fetched and verified: **VALID, exit 0**, kid `cosmos-receipt-2026-09`. The host remarked, unprompted,
that *"the refusal also produced a signed receipt id — the DENY is evidenced, not just returned as an
error."*

The verifier makes no network call: `grep -cE "urllib|requests|http.client|socket|fetch"` over
`cosmos_verify.py` returns **0**.

---

## What is still NOT proved

- Run 3 verified receipts on the workstation with the local verifier. **The airplane-mode control belongs
  to runs 1 and 2**, on the phone. The host run has no network control of its own.
- Still one device, one Android version, one Termux install, one host.
- Neither package is published, so **no registry install has ever been tested**.
- The edge-deployment proposal remains a proposal and has never been executed. Archived 2026-09-08, not deleted.

## The lesson both failures share

A client you wrote proves your server speaks the spec **as you read it**. A stub proves the shape of a
reply. Neither proves a real caller can use the thing. Both defects were invisible to a green suite and
took about a minute to surface against something that did not share my assumptions.
