/**
 * End-to-end test against the running auth worker.
 *
 * Usage:
 *   cd auth && pnpm dev          # terminal 1 — start worker on :8787
 *   node test-auth.mjs           # terminal 2
 *   node test-auth.mjs http://localhost:4321  # via site BFF
 */

const BASE = process.argv[2] ?? 'http://localhost:8787';

// ── Crypto helpers ────────────────────────────────────────────────────────────

function b64url(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function generateKeypair() {
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicJwk  = await crypto.subtle.exportKey('jwk', kp.publicKey);
  return { publicJwk, privateKey: kp.privateKey };
}

async function thumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return b64url(digest);
}

async function signJwt(payload, header, privateKey) {
  const h = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'EdDSA', ...header })));
  const p = b64url(new TextEncoder().encode(JSON.stringify({
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60,
    jti: crypto.randomUUID(),
    ...payload,
  })));
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, new TextEncoder().encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(sig)}`;
}

// ── Run ───────────────────────────────────────────────────────────────────────

console.log(`\nTesting against: ${BASE}\n`);

// Step 0 — discovery
console.log('── Step 0: discovery ────────────────────────────────────');
const disc = await fetch(`${BASE}/.well-known/agent-configuration`);
const discBody = await disc.json();
console.log('Status:', disc.status);
console.log('agent_auth_version:', discBody.agent_auth_version);
console.log('supported_algorithms:', discBody.supported_algorithms);
console.log('endpoints:', discBody.endpoints);

// Step 1 — generate two separate keypairs: host and agent
console.log('\n── Step 1: generate host + agent keypairs ───────────────');
const host  = await generateKeypair();
const agent = await generateKeypair();
const hostThumbprint = await thumbprint(host.publicJwk);
console.log('Host thumbprint:', hostThumbprint);
console.log('Agent public key (x):', agent.publicJwk.x);

// Step 2 — register
// typ MUST be in the JWT header, not the payload
// agent_public_key is required — the server stores it to verify agent JWTs later
console.log('\n── Step 2: POST /agent/register ─────────────────────────');
const hostJwt = await signJwt(
  {
    iss: hostThumbprint,
    aud: BASE,
    host_public_key:  host.publicJwk,
    agent_public_key: agent.publicJwk,   // required — separate agent keypair
  },
  { typ: 'host+jwt' },                   // typ in HEADER per spec
  host.privateKey,
);

const reg = await fetch(`${BASE}/agent/register`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${hostJwt}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({}),
});
const regBody = await reg.json();
console.log('Status:', reg.status);
console.log('Response:', JSON.stringify(regBody, null, 2));

const agentId = regBody.agent_id;
if (!agentId) {
  console.error('\nRegistration failed — cannot continue.');
  process.exit(1);
}

// Step 3 — check status
console.log('\n── Step 3: GET /agent/status ────────────────────────────');
const statusJwt = await signJwt(
  { iss: hostThumbprint, aud: BASE, host_public_key: host.publicJwk },
  { typ: 'host+jwt' },
  host.privateKey,
);
const status = await fetch(`${BASE}/agent/status?agent_id=${agentId}`, {
  headers: { Authorization: `Bearer ${statusJwt}` },
});
console.log('Status:', status.status);
console.log('Response:', JSON.stringify(await status.json(), null, 2));

// Step 4 — execute capability
// Agent JWT is signed by the AGENT's private key, not the host's
// iss = host thumbprint, sub = agent ID
console.log('\n── Step 4: POST /capability/execute ─────────────────────');
const agentJwt = await signJwt(
  {
    iss: hostThumbprint,               // identifies the host
    sub: agentId,                      // identifies the agent
    aud: `${BASE}/capability/execute`,
  },
  { typ: 'agent+jwt' },               // typ in HEADER per spec
  agent.privateKey,                   // signed by AGENT key, not host key
);

const exec = await fetch(`${BASE}/capability/execute`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${agentJwt}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ capability: 'ping' }),
});
console.log('Status:', exec.status);
console.log('Response:', JSON.stringify(await exec.json(), null, 2));

// Step 5 — hit the protected resource at /auth
// First without auth (should get 401 + discovery hint), then with a valid agent JWT.
console.log('\n── Step 5a: GET /auth (no auth) ─────────────────────────');
const unauthed = await fetch(`${BASE}/auth`);
console.log('Status:', unauthed.status);
console.log('Response:', JSON.stringify(await unauthed.json(), null, 2));

console.log('\n── Step 5b: GET /auth (with agent JWT) ──────────────────');
const authJwt = await signJwt(
  {
    iss: hostThumbprint,
    sub: agentId,
    aud: `${BASE}/auth`,
  },
  { typ: 'agent+jwt' },
  agent.privateKey,
);
const authed = await fetch(`${BASE}/auth`, {
  headers: { Authorization: `Bearer ${authJwt}` },
});
console.log('Status:', authed.status);
console.log('Response:', JSON.stringify(await authed.json(), null, 2));
