// ═══ A REFERENCE RAIL — the other half of the handoff, working ════════════════════════════════════════
//
// ⛔ THIS DOES NOT MOVE MONEY. It is a rail-shaped stub: it takes a payment request, pretends to execute,
// and reports the outcome back to Cosmos exactly as a real rail must. Every line that matters is the
// REPORTING, because that is the part nobody has built and the part the spec is about.
//
// ⛳ WHY IT EXISTS. Until now the handoff had one public side. `docs/DESIGN.md` §7 described what a rail
// should do in prose, and prose is something an integrator has to interpret; a file is something they can
// copy. Every assertion in test/rail.test.js was Cosmos talking to Cosmos, so "is this spec implementable
// by someone else" had never been answered by anything but a paragraph.
//
// ⚠ AND WHAT IT STILL DOES NOT PROVE, said here rather than left for someone to discover: I wrote both
// sides. This shows the spec IS implementable and how much work it is. It does NOT show that anyone CHOSE
// to implement it. Those are different claims and only the second one matters commercially. Treat this as
// a starting point to copy, never as evidence of adoption.
//
// Run it:   COSMOS_BASE_URL=http://localhost:8787 node examples/reference-rail/rail.js
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');

// The string '0' is truthy, so this reads it as the number 0; only unset or empty falls through.
const PORT = process.env.RAIL_PORT ? +process.env.RAIL_PORT : 9911;
// The rail's OWN credential, shared with the Cosmos operator out of band and NEVER given to the agent.
// This is the half that stops a requester ending its own payment — see api/settlements.js.
// ⛔ It is never logged, never echoed in a response, and never sent anywhere but a configured origin.
const RAIL_TOKEN = process.env.COSMOS_RAIL_TOKEN || 'reference-rail-token-change-me';
const PROVIDER = process.env.RAIL_PROVIDER || 'reference-rail';

// ═══ THE DESTINATION IS OPERATOR CONFIGURATION, NEVER THE REQUEST ═════════════════════════════════════
//
// ⛔⛔ THE FIRST VERSION OF THIS FILE BUILT THE URL FROM `cosmos.base_url` IN THE PAYMENT REQUEST AND SENT
// THE RAIL BEARER TOKEN TO IT. Found in review 2026-09-09. On a real rail that is two holes at once:
//   · SSRF — the least-trusted party in the flow picks any address the rail can reach, including cloud
//     metadata endpoints and internal services that trust the network rather than a credential;
//   · CREDENTIAL EXFILTRATION — point `base_url` at your own server and the rail posts `Authorization:
//     Bearer <rail token>` straight to you. That token is the exact thing the two-credential design exists
//     to keep away from the requester: with it, plus a handoff token they already hold, they can close out
//     their own payments. My own example handed it to them.
//
// ⛳ AND THE PROTOCOL WAS NEVER THE PROBLEM — the example was. Cosmos's ALLOW returns `report_to` (a rooted
// PATH) and `handoff_token`, and has never returned an origin: see api/authorize.js:193. The origin was
// invented here. Every rail copying this file would have inherited an invention.
//
// So: the operator configures which Cosmos origins exist. The request may SELECT one BY NAME. It may never
// supply, extend, or influence an origin, and a name that is not configured is refused rather than guessed.
const ENDPOINTS = (() => {
  const out = {};
  const exactOrigin = (s, where) => {
    let u;
    try { u = new URL(String(s)); } catch (_) { throw new Error(where + ': not a URL: ' + s); }
    if (!/^https?:$/.test(u.protocol)) throw new Error(where + ': only http/https: ' + s);
    // An "origin" with a path, query or fragment is a half-built URL, and half-built is how a prefix
    // check gets fooled. Require exactly scheme://host[:port].
    if (u.pathname !== '/' || u.search || u.hash || u.username || u.password) {
      throw new Error(where + ': must be scheme://host[:port] with nothing after it: ' + s);
    }
    return u.origin;
  };
  if (process.env.COSMOS_ENDPOINTS) {
    const map = JSON.parse(process.env.COSMOS_ENDPOINTS);
    for (const k of Object.keys(map)) out[k] = exactOrigin(map[k], 'COSMOS_ENDPOINTS.' + k);
  }
  if (process.env.COSMOS_BASE_URL) out.default = exactOrigin(process.env.COSMOS_BASE_URL, 'COSMOS_BASE_URL');
  return out;
})();

function refuse(code, message) { const e = new Error(message); e.code = code; return e; }

// Resolve a report destination. Throws — the caller decides whether that is a 400 or a dropped queue row.
function resolveReport(cosmos) {
  if (!cosmos) throw refuse('NO_COSMOS_BLOCK', 'no cosmos block');
  // Refused LOUDLY rather than ignored. Silently dropping it would leave an integrator believing their
  // origin was honoured, which is the same class of mistake as a control that cannot match.
  if (cosmos.base_url !== undefined) {
    throw refuse('CALLER_SUPPLIED_ORIGIN',
      'the payment request may not choose where the rail sends its credentials; configure the origin on the rail and select it by name with cosmos.endpoint');
  }
  const names = Object.keys(ENDPOINTS);
  if (!names.length) throw refuse('NO_ENDPOINT_CONFIGURED', 'set COSMOS_BASE_URL or COSMOS_ENDPOINTS on the rail');
  const name = cosmos.endpoint || (names.length === 1 ? names[0] : null);
  if (!name) throw refuse('ENDPOINT_NOT_SELECTED', 'several Cosmos endpoints are configured; name one in cosmos.endpoint');
  const origin = Object.prototype.hasOwnProperty.call(ENDPOINTS, name) ? ENDPOINTS[name] : null;
  if (!origin) throw refuse('UNKNOWN_ENDPOINT', 'no Cosmos endpoint named ' + JSON.stringify(String(name)) + ' is configured');

  // `report_to` still comes from the ALLOW, relayed by the agent, so it is untrusted too — an absolute
  // URL or a protocol-relative `//host` here would walk the token straight back out of the allowlist.
  const p = String(cosmos.report_to == null ? '' : cosmos.report_to);
  if (!/^\/[A-Za-z0-9._~\-/]*$/.test(p) || p.startsWith('//') || p.includes('..')) {
    throw refuse('BAD_REPORT_PATH', 'report_to must be a rooted path such as /settlements/auth_…');
  }
  const url = new URL(p, origin);
  // Belt and braces: construct, then CHECK. A future edit to the pattern above cannot quietly re-open it.
  if (url.origin !== origin) throw refuse('ORIGIN_ESCAPE', 'resolved outside the configured origin');
  if (!cosmos.handoff_token) throw refuse('NO_HANDOFF', 'this authorization\'s handoff token is required');
  return { name, url: url.toString() };
}

// ⛳⛳ THE OUTBOX, AND WHY IT IS NOT OPTIONAL POLISH — corrected 2026-09-09 by the Writ session, whose
// engine already carries a durable webhook outbox and who read the first draft of this file.
//
// The first version swallowed a failed report and moved on, on the correct reasoning that reporting must
// never fail a payment. That reasoning is right and the implementation was still wrong, because of what
// sits on the OTHER side of the wire: Cosmos reverses a reservation when it hears NOTHING. So a swallowed
// `settled` is not a dropped log line — it is a payment that really happened, whose budget Cosmos hands
// back on the TTL, which the agent can then spend a second time.
//
// ⛔ A DROPPED REPORT AND A MALICIOUS `failed` REPORT PRODUCE THE SAME LEDGER. One of those is an attack
// this repo built three credential classes to stop; the other used to be an outage.
//
// So the rule has two halves and needs both: never let reporting fail the payment (swallow at the call
// site) AND never let a report be lost (persist before you try). Swallowing alone is the FLOOR, not the
// target. This file uses a JSONL file because an example should run with no dependencies; a real rail
// should put reports through whatever durable outbox it already owns.
//
// ⚠ THE OUTBOX HOLDS CREDENTIALS. Each queued row carries that authorization's handoff token, because a
// retry cannot authenticate without it. It therefore deserves the protection of a credential store, not
// of a log file. Note what it does NOT hold: a URL. Rows keep the endpoint NAME and re-resolve it against
// the allowlist at send time, so a queued row cannot be redirected by anything that reaches the file.
const OUTBOX = process.env.RAIL_OUTBOX || path.join(__dirname, 'rail-outbox.jsonl');

// A 4xx will never become acceptable by being sent again: a bad token stays bad, and 409 means Cosmos
// already has a terminal report for this authorization, so the fact is recorded and the row is done.
// Everything else — network failure, 429, 5xx — is the transport, and the transport is what retries fix.
const permanent = (status) => status >= 400 && status < 500 && status !== 429;

function readOutbox() {
  try {
    return fs.readFileSync(OUTBOX, 'utf8').split('\n').filter(Boolean).map((l) => {
      try { return JSON.parse(l); } catch (_) { return null; }
    }).filter(Boolean);
  } catch (_) { return []; }               // no file yet is the normal empty case, not an error
}
const writeOutbox = (rows) => fs.writeFileSync(OUTBOX, rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : ''));

// PERSIST BEFORE YOU TRY. If the process dies between this line and the POST, the report is still owed
// and the next start will owe it. That ordering is the whole point; reversing it reopens the hole.
function enqueue(endpoint, cosmos, body, label) {
  const rows = readOutbox();
  rows.push({ id: label + ':' + cosmos.report_to, endpoint, report_to: cosmos.report_to,
              handoff_token: cosmos.handoff_token, body, label, attempts: 0 });
  writeOutbox(rows);
}

async function post(url, handoffToken, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: 'Bearer ' + RAIL_TOKEN,   // WHO is reporting — proves this is the rail
      'x-cosmos-handoff': handoffToken,        // WHICH authorization was routed here
    },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

// Drain the queue. Returns the receipt id for any row that landed, so the happy path can still answer the
// caller with one. NEVER THROWS — every exit from this function is a return. Logs a status and an endpoint
// NAME; never a token, and never a header.
async function flush() {
  const rows = readOutbox();
  if (!rows.length) return {};
  const keep = [];
  const receipts = {};
  for (const row of rows) {
    let target;
    try {
      // Re-resolved from configuration on every attempt, so a row that was legal when queued cannot
      // become a redirect later, and a row from an older format is refused rather than trusted.
      target = resolveReport({ endpoint: row.endpoint, report_to: row.report_to, handoff_token: row.handoff_token });
    } catch (e) {
      console.log('  [rail] ' + row.label + ' -> DROPPED (' + e.code + '); it does not resolve to a configured Cosmos');
      continue;
    }
    try {
      const r = await post(target.url, row.handoff_token, row.body);
      if (r.status < 300) {
        if (r.body && r.body.receipt_id) receipts[row.label] = r.body.receipt_id;
        console.log('  [rail] ' + row.label + ' -> ' + r.status + ' ' + (r.body.rail_outcome || ''));
      } else if (permanent(r.status)) {
        console.log('  [rail] ' + row.label + ' -> ' + r.status + ' ' + (r.body.error || '') + ' (permanent; dropped)');
      } else {
        row.attempts++; keep.push(row);
        console.log('  [rail] ' + row.label + ' -> ' + r.status + ' (retryable; still queued)');
      }
    } catch (e) {
      row.attempts++; keep.push(row);
      console.log('  [rail] ' + row.label + ' -> UNREACHABLE at endpoint ' + target.name + '; STILL QUEUED — the payment stands and the report is still owed');
    }
  }
  writeOutbox(keep);
  return receipts;
}

// Queue it, then try it immediately. The try is best-effort; the queue is not.
async function reportSafely(endpoint, cosmos, body, label) {
  try { enqueue(endpoint, cosmos, body, label); } catch (e) {
    // Cannot persist. Say so loudly rather than pretending: from here the report really is best-effort,
    // and this is the one branch where an outage can still cost a wrong reversal.
    console.log('  [rail] ⚠ COULD NOT PERSIST ' + label + ' — falling back to best-effort');
  }
  return flush();
}

const server = http.createServer((req, res) => {
  if (req.method !== 'POST' || req.url !== '/pay') {
    res.writeHead(404, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ error: 'POST /pay' }));
  }
  let raw = '';
  req.on('data', (c) => { raw += c; });
  req.on('end', async () => {
    let body;
    try { body = JSON.parse(raw); } catch (_) {
      res.writeHead(400, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: 'invalid json' }));
    }

    // One optional block, ignored when absent. A payment request without it is a normal payment.
    const cosmos = body.cosmos || null;
    let endpoint = null;
    if (cosmos) {
      // ⛳ RESOLVED BEFORE ANY MONEY MOVES, and a hostile block refuses the whole request. This is NOT the
      // "reporting must never fail the payment" case: that rule is about the TRANSPORT failing, and a
      // request trying to choose where the rail sends its credentials is not a transport failure. Failing
      // it here also means an integrator finds out immediately instead of after a payment.
      try { endpoint = resolveReport(cosmos).name; } catch (e) {
        res.writeHead(400, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: e.code, detail: e.message }));
      }
    }

    const txId = '0x' + Math.abs(Math.round(Number(body.amount_minor) || 0)).toString(16).padStart(8, '0') + Date.now().toString(16);
    console.log('[rail] pay ' + body.amount_minor + ' ' + (body.currency || '') + (cosmos ? '  (cosmos: ' + endpoint + cosmos.report_to + ')' : '  (no cosmos block)'));

    // 1. IN FLIGHT. Tells Cosmos to stop racing its own timer — a slow success is no longer reversed
    //    just because five minutes passed.
    if (cosmos) await reportSafely(endpoint, cosmos, { outcome: 'submitted', tx_id: txId, provider: PROVIDER }, 'submitted');

    // 2. …execute. A real rail does the actual payment here. This one simulates, and `simulate_failure`
    //    exists so the FAILURE path gets exercised as often as the happy one.
    const failed = body.simulate_failure === true;

    // 3. TERMINAL. `settled` fixes the spend forever; `failed` returns the budget immediately instead of
    //    after the TTL. ⚠ `state` carries THIS rail's own word for what happened, unmapped — Cosmos has
    //    three outcomes because three is all its accounting needs, and a real rail has more.
    const terminal = failed
      ? { outcome: 'failed', provider: PROVIDER, state: 'declined_by_issuer' }
      : { outcome: 'settled', tx_id: txId, provider: PROVIDER, state: 'settled',
          explorer: 'https://example.invalid/tx/' + txId };
    const receipts = cosmos ? await reportSafely(endpoint, cosmos, terminal, terminal.outcome) : {};
    const receipt = receipts[terminal.outcome] || null;

    res.writeHead(failed ? 402 : 200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      paid: !failed, tx_id: failed ? null : txId, provider: PROVIDER,
      cosmos_receipt: receipt,
      // Honest about which of the two it was, rather than letting a null receipt mean either.
      cosmos_report: cosmos ? (receipt ? 'delivered' : 'queued') : 'not-requested',
    }));
  });
});

if (require.main === module) {
  // Anything owed from a previous life is owed now. This line is the difference between a durable outbox
  // and a swallowed error, and it is one line.
  flush().then((r) => { const n = Object.keys(r).length; if (n) console.log('[rail] delivered ' + n + ' report(s) owed from a previous run'); });
}

server.listen(PORT, () => {
  console.log('[rail] reference rail on http://localhost:' + PORT + '  provider=' + PROVIDER);
  console.log('[rail] ⛔ THIS MOVES NO MONEY. It reports to Cosmos exactly as a real rail must.');
  console.log('[rail] cosmos endpoints (operator-configured, the ONLY places the rail token is sent):');
  const names = Object.keys(ENDPOINTS);
  if (!names.length) console.log('[rail]   ⚠ NONE — set COSMOS_BASE_URL or COSMOS_ENDPOINTS; every report will be refused');
  for (const n of names) console.log('[rail]   ' + n + ' -> ' + ENDPOINTS[n]);
  console.log('[rail] outbox: ' + OUTBOX);
  if (RAIL_TOKEN === 'reference-rail-token-change-me') {
    console.log('[rail] ⚠ using the default rail token — set COSMOS_RAIL_TOKEN to the value the Cosmos operator gave you');
  }
});

module.exports = { server, post, reportSafely, flush, readOutbox, resolveReport, ENDPOINTS, OUTBOX };
