// ═══ HTTP — router, JSON plumbing, error mapping ═══════════════════════════════════════════════════════
// Zero dependencies: node:http only. The core is auditable in an afternoon and the API layer stays that way.
'use strict';
const http = require('http');

class HttpError extends Error {
  constructor(status, code, detail) { super(code); this.status = status; this.code = code; this.detail = detail || null; }
}

function send(res, status, body) {
  const s = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(s) });
  res.end(s);
}

function readJson(req, limit) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', (c) => {
      n += c.length;
      if (n > limit) { reject(new HttpError(413, 'BODY_TOO_LARGE')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      if (!raw) return resolve({});
      let v;
      try { v = JSON.parse(raw); } catch (_) { return reject(new HttpError(400, 'INVALID_JSON')); }
      if (!v || typeof v !== 'object' || Array.isArray(v)) return reject(new HttpError(400, 'BODY_MUST_BE_OBJECT'));
      resolve(v);
    });
    req.on('error', reject);
  });
}

// Matchers return a params object (possibly empty) on a hit, or null on a miss.
const exact = (p) => (pathname) => (pathname === p ? {} : null);
const param = (prefix, name) => (pathname) =>
  pathname.startsWith(prefix) && pathname.length > prefix.length
    ? { [name]: decodeURIComponent(pathname.slice(prefix.length)) }
    : null;

function makeServer(routes, opts = {}) {
  const limit = opts.bodyLimit || 65536;
  return http.createServer((req, res) => {
    let pathname;
    try { pathname = new URL(req.url, 'http://localhost').pathname; }
    catch (_) { return send(res, 400, { error: 'BAD_URL' }); }

    let hit = null;
    for (const r of routes) {
      if (r.method !== req.method) continue;
      const params = r.match(pathname);
      if (params) { hit = { route: r, params }; break; }
    }
    if (!hit) return send(res, 404, { error: 'NOT_FOUND', detail: req.method + ' ' + pathname });

    Promise.resolve()
      .then(async () => {
        const body = (req.method === 'POST' || req.method === 'PUT') ? await readJson(req, limit) : {};
        const out = await hit.route.handler(body, hit.params, req);
        // A handler may answer with BYTES instead of JSON ({ raw: Buffer, contentType }). Only /evidence
        // does, and only under `Accept: application/cose` — the receipt is a binary artifact, and a
        // verifier written against RFC 9052 should not have to know that this server wraps it in base64.
        if (out.raw) {
          res.writeHead(out.status || 200, Object.assign({ 'content-type': out.contentType || 'application/octet-stream', 'content-length': out.raw.length }, out.headers || {}));
          return res.end(out.raw);
        }
        send(res, out.status || 200, out.body);
      })
      .catch((e) => {
        // An HttpError may carry response headers — a 401 without WWW-Authenticate is not a 401 any
        // standard client understands (RFC 9110 §11.6.1 makes the header mandatory on a 401).
        if (e instanceof HttpError) {
          if (e.headers) for (const [k, v] of Object.entries(e.headers)) res.setHeader(k, v);
          return send(res, e.status, { error: e.code, detail: e.detail });
        }
        // Never leak a stack to a caller; log it where the operator can see it.
        console.error('[cosmos] unhandled', e && e.stack ? e.stack : e);
        send(res, 500, { error: 'INTERNAL' });
      });
  });
}

module.exports = { makeServer, send, readJson, HttpError, exact, param };
