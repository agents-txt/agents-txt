#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// One-shot ES256 (ECDSA P-256) keypair generator for the OAuth signing key.
//
// Run once per environment (preview, production). Stores the result as the
// `OAUTH_PRIVATE_JWK` wrangler secret on the auth worker. The public half is
// derived at runtime by the worker and served from /.well-known/jwks.json.
//
// Usage:
//   node scripts/generate-oauth-keypair.mjs              # prints both JWKs to stdout
//   node scripts/generate-oauth-keypair.mjs | tee key.json && \
//     wrangler secret put OAUTH_PRIVATE_JWK < key.json   # set as secret (preview)
//
// For production:
//   wrangler secret put OAUTH_PRIVATE_JWK --env production < key.json
//
// The script prints a JSON object with `private` and `public` fields. Pipe the
// `private` field into `wrangler secret put`. Never commit the private JWK; the
// public JWK is safe to publish.
// ─────────────────────────────────────────────────────────────────────────────

import { webcrypto } from 'node:crypto'

const { subtle } = webcrypto

function b64urlEncode(bytes) {
  return Buffer.from(bytes).toString('base64url')
}

async function jwkThumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
  const digest = await subtle.digest('SHA-256', new TextEncoder().encode(canonical))
  return b64urlEncode(new Uint8Array(digest))
}

const keypair = await subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  /* extractable */ true,
  ['sign', 'verify'],
)

const privateJwk = await subtle.exportKey('jwk', keypair.privateKey)
const publicJwk  = await subtle.exportKey('jwk', keypair.publicKey)

// Stamp matching kid on both halves so the deployed worker and the JWKS endpoint
// agree on the identifier without a round-trip.
const kid = await jwkThumbprint(publicJwk)
privateJwk.kid = kid
publicJwk.kid  = kid
privateJwk.use = 'sig'
publicJwk.use  = 'sig'
privateJwk.alg = 'ES256'
publicJwk.alg  = 'ES256'

const out = {
  kid,
  private: privateJwk,
  public:  publicJwk,
  notes: [
    'Store `private` as the OAUTH_PRIVATE_JWK secret on the auth worker.',
    '  wrangler secret put OAUTH_PRIVATE_JWK            (preview)',
    '  wrangler secret put OAUTH_PRIVATE_JWK --env production',
    'When prompted, paste the JSON-stringified `private` value (one line).',
    'The `public` JWK is served automatically from /.well-known/jwks.json at runtime;',
    'no separate deploy step is required for the public half.',
  ],
}

process.stdout.write(JSON.stringify(out, null, 2) + '\n')
