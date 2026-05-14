// ─────────────────────────────────────────────────────────────────────────────
// OAuth 2.0 JWT helpers (ES256 / ECDSA P-256)
//
// Web Crypto only. No npm dependencies. Mirrors the style of `jwt.ts`
// (Ed25519 for agent-auth) so the two protocols sit alongside without sharing
// internal modules.
//
// ES256 chosen because:
//   - Asymmetric, so JWKS is meaningful (resource servers verify with the
//     public key; the private key never leaves the issuer).
//   - Widest OAuth library support (Auth0 / Okta / Google all support ES256).
//   - Web Crypto exposes ECDSA P-256 natively; no shimming.
//
// Wire format: JWT signature is IEEE P1363 r||s (64 bytes), which is what
// Web Crypto returns for ECDSA. No DER wrapping required.
// ─────────────────────────────────────────────────────────────────────────────

/** Base64url-encode without padding. */
function b64urlEncode(bytes: Uint8Array | string): string {
  const arr = typeof bytes === 'string'
    ? new TextEncoder().encode(bytes)
    : bytes;
  let binary = '';
  for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]!);
  return btoa(binary).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/** Base64url-decode to Uint8Array. */
function b64urlDecode(b64url: string): Uint8Array {
  const pad = (s: string) => s + '==='.slice((s.length + 3) % 4);
  const b64 = pad(b64url.replace(/-/g, '+').replace(/_/g, '/'));
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export interface OAuthJwtPayload {
  iss: string;
  sub: string;
  aud: string | string[];
  iat: number;
  exp: number;
  jti: string;
  scope?: string;
  client_id?: string;
  [key: string]: unknown;
}

export interface EcPublicJwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
  use?: 'sig';
  alg?: 'ES256';
  kid?: string;
}

export interface EcPrivateJwk extends EcPublicJwk {
  d: string;
}

/** Strip the private component from an EC JWK so it is safe to publish. */
export function toPublicJwk(privateJwk: EcPrivateJwk, kid?: string): EcPublicJwk {
  return {
    kty: 'EC',
    crv: 'P-256',
    x:   privateJwk.x,
    y:   privateJwk.y,
    use: 'sig',
    alg: 'ES256',
    ...(kid ? { kid } : privateJwk.kid ? { kid: privateJwk.kid } : {}),
  };
}

/**
 * Derive a stable JWK thumbprint per RFC 7638 for use as a `kid`. Lets agents
 * recognize a key across deploys without us hard-coding an arbitrary identifier.
 */
export async function jwkThumbprint(jwk: EcPublicJwk): Promise<string> {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return b64urlEncode(new Uint8Array(digest));
}

let cachedSigningKey: CryptoKey | null = null;
let cachedSigningKid: string | null = null;

async function loadSigningKey(privateJwkJson: string): Promise<{ key: CryptoKey; kid: string }> {
  if (cachedSigningKey && cachedSigningKid) {
    return { key: cachedSigningKey, kid: cachedSigningKid };
  }
  const jwk = JSON.parse(privateJwkJson) as EcPrivateJwk;
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.d) {
    throw new Error('oauth signing key must be an EC P-256 private JWK');
  }
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
  const kid = jwk.kid ?? await jwkThumbprint(toPublicJwk(jwk));
  cachedSigningKey = key;
  cachedSigningKid = kid;
  return { key, kid };
}

let cachedPublicJwk: EcPublicJwk | null = null;

/** Returns the public JWK derived from the configured private key, for /.well-known/jwks.json. */
export async function getPublicJwk(privateJwkJson: string): Promise<EcPublicJwk> {
  if (cachedPublicJwk) return cachedPublicJwk;
  const jwk = JSON.parse(privateJwkJson) as EcPrivateJwk;
  const publicJwk = toPublicJwk(jwk, jwk.kid ?? await jwkThumbprint(toPublicJwk(jwk)));
  cachedPublicJwk = publicJwk;
  return publicJwk;
}

/**
 * Sign an OAuth 2.0 access token (ES256). Returns the compact JWS string.
 * Caller supplies the full payload; this helper does not inject any claims.
 */
export async function signAccessToken(payload: OAuthJwtPayload, privateJwkJson: string): Promise<string> {
  const { key, kid } = await loadSigningKey(privateJwkJson);
  const header = { alg: 'ES256', typ: 'JWT', kid };
  const signingInput = `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(payload))}`;
  const sig = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    new TextEncoder().encode(signingInput),
  ));
  return `${signingInput}.${b64urlEncode(sig)}`;
}

/**
 * Verify and decode an ES256 access token. Returns the decoded payload on
 * success, null on any failure (bad signature, malformed token, wrong alg).
 * Caller is responsible for `iss` / `aud` / `exp` claim validation.
 */
export async function verifyAccessToken(token: string, publicJwk: EcPublicJwk): Promise<OAuthJwtPayload | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts as [string, string, string];
  let header: Record<string, unknown>;
  let payload: OAuthJwtPayload;
  try {
    header  = JSON.parse(new TextDecoder().decode(b64urlDecode(h))) as Record<string, unknown>;
    payload = JSON.parse(new TextDecoder().decode(b64urlDecode(p))) as OAuthJwtPayload;
  } catch {
    return null;
  }
  if (header['alg'] !== 'ES256') return null;
  const key = await crypto.subtle.importKey(
    'jwk',
    publicJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
  const ok = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    b64urlDecode(s),
    new TextEncoder().encode(`${h}.${p}`),
  );
  return ok ? payload : null;
}

/**
 * Hash a client secret with PBKDF2-SHA-256 at 100,000 iterations.
 *
 * Iteration count is the maximum Cloudflare Workers' Web Crypto implementation
 * supports. The runtime throws `NotSupportedError: Pbkdf2 failed: iteration
 * counts above 100000 are not supported` for any value beyond that, so the
 * OWASP 2023 minimum recommendation (600,000) is not reachable in this
 * environment. 100,000 is the binding ceiling and matches what many production
 * OAuth deployments use; it is still resistant to offline brute force for
 * non-trivial passwords. If a stronger hash is required, store credentials in
 * an external service (e.g. Workers KV via a Durable Object with Argon2id
 * implemented in WASM) and call that service from this worker.
 *
 * Output: base64url(salt || derived). Stored as an opaque string; compared in
 * constant time on the next request via `verifyClientSecret`.
 *
 * ─── WARNING: iteration count is part of every stored record's identity ────
 * The stored hash does NOT carry its own iteration count. Verification only
 * succeeds when the worker re-derives PBKDF2 with the SAME count used at write
 * time. Consequences:
 *
 *   - The matching value in `scripts/provision-*.mjs` must equal the value
 *     here. They are independent constants in independent codebases.
 *   - If this value ever changes, every existing KV record at
 *     `oauth:client:*` must be re-provisioned. Stale records produce
 *     `401 invalid_client` on every token request despite the KV key existing.
 *   - The failure mode is silent: `verifyClientSecret` returns `false`,
 *     `authenticateClient` returns `null`, the route emits `invalid_client`.
 *     `wrangler tail` shows no error. Diagnosis requires reproducing the
 *     hash offline against the stored bytes at varying iteration counts.
 *
 * See docs/CHANGELOG-2026-05-14-oauth2-demo-stale-kv-hash-fix.md for the
 * post-mortem that produced this warning.
 */
export async function hashClientSecret(secret: string, saltOverride?: Uint8Array): Promise<string> {
  const salt = saltOverride ?? crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'PBKDF2' },
    false,
    ['deriveBits'],
  );
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
    keyMaterial,
    256,
  );
  const out = new Uint8Array(salt.length + 32);
  out.set(salt, 0);
  out.set(new Uint8Array(derivedBits), salt.length);
  return b64urlEncode(out);
}

/**
 * Constant-time comparison of a candidate client secret against a stored
 * hash produced by hashClientSecret. Resilient to length-leak side channels.
 *
 * If this returns `false` for a candidate the operator knows is correct,
 * the most likely cause is that the stored record was hashed under a
 * different PBKDF2 iteration count than `hashClientSecret` uses today.
 * Re-provision the affected KV record. See the WARNING block on
 * `hashClientSecret` above.
 */
export async function verifyClientSecret(candidate: string, stored: string): Promise<boolean> {
  const decoded = b64urlDecode(stored);
  if (decoded.length !== 48) return false;
  // Copy salt into a fresh standalone Uint8Array. Passing a `.subarray(...)`
  // view over the 48-byte decoded buffer to `crypto.subtle.deriveBits` is
  // technically spec-correct (BufferSource accepts any ArrayBufferView), but
  // some Web Crypto implementations read past the view bounds and use the
  // underlying buffer, which produces a different salt than the script wrote.
  // A fresh copy eliminates the ambiguity.
  const salt = new Uint8Array(16);
  salt.set(decoded.subarray(0, 16));
  const expected = decoded.subarray(16);

  const candidateHashed = b64urlDecode(await hashClientSecret(candidate, salt));
  const candidateBytes = candidateHashed.subarray(16);

  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= (expected[i] ?? 0) ^ (candidateBytes[i] ?? 0);
  return diff === 0;
}

/** Cryptographically strong random identifier for `jti`. */
export function randomJti(): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
}
