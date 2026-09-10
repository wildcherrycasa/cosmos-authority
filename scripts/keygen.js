// Generate a persisted Ed25519 receipt-signing key. Prints the env lines to set. Never writes a file —
// where the private key lives is the operator's decision, not this script's.
'use strict';
const crypto = require('crypto');
const kid = process.argv[2] || ('cosmos-receipt-' + new Date().toISOString().slice(0, 7));
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
const spki = publicKey.export({ type: 'spki', format: 'der' });
const x = spki.subarray(spki.length - 32).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
console.log('# Cosmos receipt-signing key. Keep the PRIVATE line secret; persist it BEFORE the first receipt.');
console.log('# Kids must be monotonic and never reused (rotating onto a retired kid orphans its receipts).');
console.log('COSMOS_RECEIPT_KID=' + kid);
console.log('COSMOS_RECEIPT_PRIVATE_KEY=' + pkcs8);
console.log('# public (JWKS x): ' + x);
