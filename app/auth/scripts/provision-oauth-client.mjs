#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// OAuth 2.0 client provisioner.
//
// Generates a strong client_secret, hashes it with the same PBKDF2-SHA-256
// algorithm the worker uses (oauth-jwt.ts → hashClientSecret), and prints:
//   1. The wrangler kv:key put command to write the client record into AUTH_KV.
//   2. The plaintext client_secret, ONCE. Copy it now; we cannot recover it.
//
// Usage:
//   node scripts/provision-oauth-client.mjs <client_id> [scope1 scope2 ...]
//
// Example:
//   node scripts/provision-oauth-client.mjs demo spec:read mcp:tools
//
// The output is split across stderr (human-readable instructions) and stdout
// (the wrangler command). Pipe stdout into `bash` to apply directly:
//   node scripts/provision-oauth-client.mjs demo spec:read | bash
//
// ─── WARNING: PBKDF2 iteration count must match the worker's ──────────────
// The iteration count in `hashClientSecret` below is an independent constant
// from the one in `app/auth/src/oauth-jwt.ts`. Stored hashes carry no
// iteration metadata, so verification only works when both halves agree. If
// you change the count anywhere, change it everywhere and re-provision every
// existing client record; otherwise `/oauth/token` returns `invalid_client`
// for every previously-provisioned client with no error visible in tail.
// See docs/CHANGELOG-2026-05-14-oauth2-demo-stale-kv-hash-fix.md.
// ─────────────────────────────────────────────────────────────────────────────

import { webcrypto } from 'node:crypto'

const { subtle } = webcrypto

const [,, clientId, ...scopes] = process.argv
if (!clientId) {
  console.error('Usage: node scripts/provision-oauth-client.mjs <client_id> [scope ...]')
  process.exit(1)
}
if (!/^[a-zA-Z0-9_-]{1,64}$/.test(clientId)) {
  console.error('client_id must be 1-64 chars: alphanumeric, dash, underscore')
  process.exit(1)
}

function b64urlEncode(bytes) {
  return Buffer.from(bytes).toString('base64url')
}

async function hashClientSecret(secret) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16))
  const keyMaterial = await subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'PBKDF2' },
    false,
    ['deriveBits'],
  )
  // 100,000 iterations to match the worker's PBKDF2 cap. Cloudflare Workers'
  // Web Crypto rejects iteration counts above 100,000 with NotSupportedError,
  // so the script must use the same ceiling for the hash to be verifiable.
  const derivedBits = await subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
    keyMaterial,
    256,
  )
  const out = new Uint8Array(salt.length + 32)
  out.set(salt, 0)
  out.set(new Uint8Array(derivedBits), salt.length)
  return b64urlEncode(out)
}

const clientSecret = b64urlEncode(webcrypto.getRandomValues(new Uint8Array(32)))
const hashed = await hashClientSecret(clientSecret)

const record = {
  hashed_secret: hashed,
  scopes:        scopes.length > 0 ? scopes : ['spec:read'],
  created_at:    Date.now(),
}

// Human-readable side, stderr.
process.stderr.write(`
─────────────────────────────────────────────────────────────
OAuth 2.0 client provisioned (not yet deployed)
─────────────────────────────────────────────────────────────
  client_id:     ${clientId}
  client_secret: ${clientSecret}
  scopes:        ${record.scopes.join(' ')}
─────────────────────────────────────────────────────────────

COPY THE client_secret NOW. It is only printed once and cannot
be recovered from the hashed value stored in KV.

Run the command on stdout to write the client record:

  $ node scripts/provision-oauth-client.mjs ${clientId} ${scopes.join(' ')} | bash

Or copy and run manually:
`)

// Machine-readable side, stdout: the wrangler command.
// Uses `npx wrangler` so it works without a globally-installed wrangler, the
// v4 subcommand syntax `kv key put` (the v3 form `kv:key put` was removed),
// and `--remote` because wrangler v4 defaults KV operations to a local
// emulator. Without `--remote` the record is written to the operator's
// machine and the deployed worker can't read it.
const recordJson = JSON.stringify(record)
process.stdout.write(
  `npx wrangler kv key put --binding=AUTH_KV --env production --remote "oauth:client:${clientId}" '${recordJson}'\n`,
)
