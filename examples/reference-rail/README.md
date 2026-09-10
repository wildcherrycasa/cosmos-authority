# Reference rail — the other half of the handoff

**Copy `rail.js`. It is about 200 lines and roughly an afternoon of work to adapt** — less if your rail already owns a durable outbox, which is where the reports belong.

Cosmos decides whether a spend is allowed and proves it. It never moves money — a **rail** does that. This
is a working example of the rail side: it takes a payment request, executes, and reports the outcome back
so Cosmos knows whether the money actually moved.

⛔ **It moves no money.** It is a rail-shaped stub. Every line that matters is the *reporting*, because
that is the part nobody has built yet and the part the spec is about.

## Run it

The Cosmos origin is **operator configuration**, set before the rail starts. It is not something a payment
request can supply — see rule 2 below, which is the one that costs you a credential if you get it wrong.

```bash
COSMOS_BASE_URL=http://localhost:8787 \
COSMOS_RAIL_TOKEN=<the token your Cosmos operator gave you> \
node examples/reference-rail/rail.js
```

Serving more than one Cosmos? Name them, and let the request pick one *by name*:

```bash
COSMOS_ENDPOINTS='{"prod":"https://cosmos.example.com","staging":"https://staging.example.com"}'
```

Then hand it a payment with the `cosmos` block straight out of an ALLOW response:

```json
POST /pay
{
  "amount_minor": 2500,
  "currency": "USD",
  "cosmos": {
    "report_to": "/settlements/auth_…",
    "handoff_token": "…",
    "endpoint": "prod"
  }
}
```

`report_to` and `handoff_token` come from the ALLOW verbatim; the agent never invents them. `endpoint` is
optional when only one is configured. **Cosmos never calls the rail** — it hands out a path and waits to be
told.

## Why bother — what reporting buys you

Without it, Cosmos guesses. An ALLOW reserves budget with a five-minute TTL and auto-reverses if nothing
confirms, because it cannot see your rail. That guess is wrong in both directions: too short and a slow
success gets reversed, too long and a failed payment ties up budget.

| you report | Cosmos does | which half of the guess it kills |
|---|---|---|
| `submitted` | pushes the deadline out | a slow success stops racing a timer it was never told about |
| `settled` | the spend is final, never auto-reversed | a real payment is never handed back |
| `failed` | returns the budget **immediately** | no five-minute hold on money that did not move |

A rail that says nothing still works. You just keep the guess.

⚠ **A rail that reports unreliably is worse than one that never reports**, and this is the trap: once
reports arrive, the operator stops expecting the TTL to be the story. A report that goes missing then reads
as "this payment did not happen." Silence is a known unknown; an intermittent report is a wrong answer.

## The four things you will get wrong

**1. Reporting must never fail the payment — AND must never be lost. Both halves, or you get a wrong
ledger.** This is the one an integrator is most likely to get half-right, because half of it is obvious.

The obvious half: if Cosmos is unreachable the money still moved, so a failed report is not a failed
payment. Swallow it. A rail that failed real payments because an authority server was down would be
strictly worse than having no authority server at all.

⛔ **The half that is not obvious, and that the first version of this file got wrong: Cosmos reverses a
reservation when it hears NOTHING.** So a dropped `settled` report is not a missing log line — it is
budget handed back for money that really moved, and then spendable a second time. **A lost report and a
malicious `failed` report produce the identical ledger**, and Cosmos carries three credential classes
specifically to stop the second one.

So: **persist the report before you try to send it, and retry until it lands.** Swallowing is the floor,
not the target. `rail.js` uses a JSONL file so the example has no dependencies; if your rail already owns
a durable outbox — a store-backed at-least-once relay — put the reports through that instead. It is less
new code, not more.

Pinned by `test/reference-rail.test.js` §C and §D: Cosmos is genuinely stopped mid-payment, the payment
still succeeds, the report is written to disk, and **a separate OS process** later reads that queue and
delivers the settlement — after which the spend stands instead of being reversed.

Two details worth copying rather than rediscovering:

- **A 4xx is dropped, not retried forever.** A bad token stays bad, and `409` means Cosmos already holds a
  terminal report — the fact is recorded and the row is done. Only transport failures, `429` and `5xx` are
  worth another attempt. A queue that retries a rejected credential forever is an outage that never ends.
- ⚠ **The queue holds credentials.** Every pending row carries that authorization's handoff token, because
  a retry cannot authenticate without one. A queue of these is a queue of things that can close out
  payments, so it wants the protection of a credential store, not of a log file.

**A late report is still worth sending.** If the TTL already reversed the reservation, Cosmos accepts the
settlement as `rail_late` and re-reserves by appending — history then shows the wrong guess *and* its
correction. Without a durable queue that correction never arrives, and the wrong ledger is permanent.

**2. ⛔ The request must NEVER choose where the rail sends its credentials.** The first version of this
file built the destination from `cosmos.base_url` in the payment request and posted the rail's bearer token
to it. That is two holes in one line, both handed to the least-trusted party in the flow:

- **SSRF** — the caller picks any address the rail can reach. `http://169.254.169.254/latest/meta-data/`
  needs no credential at all, only a request coming from inside.
- **Credential exfiltration** — point it at your own server and the rail posts
  `Authorization: Bearer <rail token>` straight to you. That token is precisely what rule 3 below exists to
  keep away from the requester; with it, plus the handoff token they already hold, they close out their own
  payments.

⛳ **The protocol was never the problem — the example was.** Cosmos's ALLOW returns `report_to` (a rooted
*path*) and `handoff_token`, and has never returned an origin. The origin was invented by this file.

So: origins are operator config, the request selects one **by name**, and an unconfigured name is refused
rather than guessed. The path is untrusted too — `//attacker/x`, an absolute URL, and `..` are all rejected,
and the resolved URL's origin is re-checked against the allowlist afterwards so a later edit to the pattern
cannot quietly reopen it. **Queued rows store the endpoint name and the path, never a URL**, so nothing that
reaches the outbox file can redirect a pending report.

A hostile block refuses the whole request, before execution. That is *not* a violation of rule 1: rule 1 is
about the transport failing, and a request trying to choose where credentials go is not a transport failure.

Pinned by §G and §H, and mutation-proved — restoring the original `base_url` behaviour fails G1, G2, G3 and
G6 by name.

**3. A terminal report needs BOTH credentials.**

```
Authorization: Bearer <rail token>    WHO is reporting — your own secret, from the Cosmos operator
x-cosmos-handoff: <handoff token>     WHICH authorization was routed to you — from the agent
```

The rail token alone is refused (§E). That is deliberate: the handoff token reaches the *requester*, and a
requester that could report `failed` would get its budget back and spend the same money twice.

**4. Your state vocabulary is richer than Cosmos's.** Cosmos has three outcomes because three is all its
accounting needs. Send your own word in `state` — it rides along verbatim into the signed receipt. A
payment that was executed and then reversed is `outcome: "failed"` (the budget comes back) with
`state: "reversed"` (it had run). Collapsing those loses the only fact an auditor cares about.

## ⚠ What this proves, and what it does not

It proves the spec **is implementable** and how much work it is.

It does **not** prove anyone chose to implement it — the same author wrote both sides. Those are different
claims and only the second one matters commercially. Treat this as a starting point to copy, never as
evidence of adoption.
