import { webcrypto } from 'node:crypto';
const { subtle } = webcrypto;

// Generate Ed25519 keypair
const keypair = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
const publicJwk  = await subtle.exportKey('jwk', keypair.publicKey);
const privateJwk = await subtle.exportKey('jwk', keypair.privateKey);

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

async function signJwt(payload, header = {}) {
  const h = b64url(JSON.stringify({ alg: 'EdDSA', ...header }));
  const p = b64url(JSON.stringify({ iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + 60, jti: crypto.randomUUID(), ...payload }));
  const sig = await subtle.sign({ name: 'Ed25519' }, keypair.privateKey, Buffer.from(`${h}.${p}`));
  return `${h}.${p}.${b64url(sig)}`;
}

// Compute host thumbprint (RFC 7638)
const canonical = JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x });
const digest = await subtle.digest('SHA-256', Buffer.from(canonical));
const thumbprint = b64url(digest);

const BASE = 'http://localhost:8787';

// Step 1: Register
const hostJwt = await signJwt(
  { typ: 'host+jwt', iss: thumbprint, aud: BASE, host_public_key: publicJwk }
);
const reg = await fetch(`${BASE}/agent/register`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${hostJwt}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({}),
});
const { agent_id } = await reg.json();
console.log('Registered agent:', agent_id);

// Step 2: Execute capability
const agentJwt = await signJwt(
  { typ: 'agent+jwt', iss: thumbprint, sub: agent_id, aud: `${BASE}/capability/execute` }
);
const exec = await fetch(`${BASE}/capability/execute`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${agentJwt}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ capability: 'ping' }),
});
console.log('Execute result:', await exec.json());