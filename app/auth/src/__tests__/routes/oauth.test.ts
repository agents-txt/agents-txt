// ─────────────────────────────────────────────────────────────────────────────
// OAuth 2.0 route tests
//
// Covers the five public endpoints plus introspection:
//   /.well-known/openid-configuration
//   /.well-known/oauth-authorization-server
//   /.well-known/oauth-protected-resource
//   /.well-known/jwks.json
//   /oauth/token
//   /oauth/introspect
//
// Plus the helpers in oauth-jwt.ts (PBKDF2 client secret hashing, ES256 JWT
// sign/verify roundtrip) so unit failures surface before integration ones.
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect, beforeAll } from 'vitest';
import app from '../../index.js';
import { createMockKV } from '../helpers.js';
import { hashClientSecret, verifyClientSecret, signAccessToken, verifyAccessToken, getPublicJwk, toPublicJwk } from '../../oauth-jwt.js';

// ── ES256 keypair (generated once per test run) ─────────────────────────────

let privateJwkJson: string;
let publicJwk: ReturnType<typeof toPublicJwk>;

beforeAll(async () => {
  const keypair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;
  const privateJwk = await crypto.subtle.exportKey('jwk', keypair.privateKey) as Parameters<typeof toPublicJwk>[0] & { d: string };
  privateJwk.kid = 'test-kid';
  privateJwk.alg = 'ES256';
  privateJwk.use = 'sig';
  privateJwkJson = JSON.stringify(privateJwk);
  publicJwk = toPublicJwk(privateJwk);
});

// ── Helper to provision a demo client into the mock KV ──────────────────────

async function provisionClient(kv: ReturnType<typeof createMockKV>, id: string, secret: string, scopes: string[] = ['spec:read']) {
  const record = {
    hashed_secret: await hashClientSecret(secret),
    scopes,
    created_at: Date.now(),
  };
  kv._set(`oauth:client:${id}`, record);
}

function buildEnv(privateJwk?: string) {
  return {
    AUTH_KV: createMockKV(),
    ...(privateJwk ? { OAUTH_PRIVATE_JWK: privateJwk } : {}),
  };
}

// ── Helpers under test ──────────────────────────────────────────────────────

describe('oauth-jwt: client secret hashing', () => {
  it('hash + verify roundtrip succeeds', async () => {
    const hashed = await hashClientSecret('correct-horse-battery-staple');
    expect(await verifyClientSecret('correct-horse-battery-staple', hashed)).toBe(true);
  });

  it('verify rejects wrong secret', async () => {
    const hashed = await hashClientSecret('correct-horse-battery-staple');
    expect(await verifyClientSecret('wrong', hashed)).toBe(false);
  });

  it('hash is non-deterministic across calls (salt varies)', async () => {
    const a = await hashClientSecret('same');
    const b = await hashClientSecret('same');
    expect(a).not.toBe(b);
    expect(await verifyClientSecret('same', a)).toBe(true);
    expect(await verifyClientSecret('same', b)).toBe(true);
  });
});

describe('oauth-jwt: ES256 access token roundtrip', () => {
  it('sign + verify succeeds', async () => {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: 'https://test.example',
      sub: 'demo',
      aud: 'https://test.example',
      iat: now,
      exp: now + 3600,
      jti: 'test-jti',
      scope: 'spec:read',
      client_id: 'demo',
    };
    const token = await signAccessToken(payload, privateJwkJson);
    const decoded = await verifyAccessToken(token, publicJwk);
    expect(decoded).not.toBeNull();
    expect(decoded?.sub).toBe('demo');
    expect(decoded?.scope).toBe('spec:read');
  });

  it('verify rejects a tampered token', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signAccessToken({
      iss: 'https://test.example', sub: 'demo', aud: 'https://test.example',
      iat: now, exp: now + 3600, jti: 'x',
    }, privateJwkJson);
    const tampered = token.slice(0, -4) + 'AAAA';
    expect(await verifyAccessToken(tampered, publicJwk)).toBeNull();
  });

  it('verify rejects a token with wrong alg in header', async () => {
    // Forge an HS256 header to ensure the verifier hard-pins ES256.
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    const payload = btoa(JSON.stringify({ sub: 'forged' })).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    const token = `${header}.${payload}.AAAA`;
    expect(await verifyAccessToken(token, publicJwk)).toBeNull();
  });
});

// ── Discovery endpoints ─────────────────────────────────────────────────────

describe('GET /.well-known/openid-configuration', () => {
  it('returns 200', async () => {
    const env = buildEnv(privateJwkJson);
    const res = await app.request('/.well-known/openid-configuration', {}, env);
    expect(res.status).toBe(200);
  });

  it('contains required OIDC discovery fields', async () => {
    const env = buildEnv(privateJwkJson);
    const res = await app.request('/.well-known/openid-configuration', {}, env);
    const body = await res.json() as Record<string, unknown>;
    expect(body).toHaveProperty('issuer');
    expect(body).toHaveProperty('token_endpoint');
    expect(body).toHaveProperty('jwks_uri');
    expect(body.grant_types_supported).toContain('client_credentials');
    expect(body.id_token_signing_alg_values_supported).toContain('ES256');
    expect(body.token_endpoint_auth_methods_supported).toContain('client_secret_basic');
  });
});

describe('GET /.well-known/oauth-authorization-server', () => {
  it('returns the same payload as openid-configuration (RFC 8414 alias)', async () => {
    const env = buildEnv(privateJwkJson);
    const a = await (await app.request('/.well-known/openid-configuration', {}, env)).json();
    const b = await (await app.request('/.well-known/oauth-authorization-server', {}, env)).json();
    expect(b).toEqual(a);
  });
});

describe('GET /.well-known/oauth-protected-resource (RFC 9728)', () => {
  it('returns required fields', async () => {
    const env = buildEnv(privateJwkJson);
    const res = await app.request('/.well-known/oauth-protected-resource', {}, env);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body).toHaveProperty('resource');
    expect(body).toHaveProperty('authorization_servers');
    expect(Array.isArray(body.authorization_servers)).toBe(true);
    expect(body).toHaveProperty('scopes_supported');
  });
});

describe('GET /.well-known/jwks.json', () => {
  it('returns the public JWK matching the configured private key', async () => {
    const env = buildEnv(privateJwkJson);
    const res = await app.request('/.well-known/jwks.json', {}, env);
    expect(res.status).toBe(200);
    const body = await res.json() as { keys: unknown[] };
    expect(body.keys).toHaveLength(1);
    const key = body.keys[0] as Record<string, unknown>;
    expect(key.kty).toBe('EC');
    expect(key.crv).toBe('P-256');
    expect(key.alg).toBe('ES256');
    expect(key.use).toBe('sig');
    expect(key).toHaveProperty('x');
    expect(key).toHaveProperty('y');
    expect(key).not.toHaveProperty('d');   // private component must not leak
  });

  it('returns 500 when OAUTH_PRIVATE_JWK is unset', async () => {
    const env = buildEnv();   // no OAUTH_PRIVATE_JWK
    const res = await app.request('/.well-known/jwks.json', {}, env);
    expect(res.status).toBe(500);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('configuration_error');
  });
});

// ── Token endpoint ──────────────────────────────────────────────────────────

describe('POST /oauth/token', () => {
  it('issues a token for valid client_credentials (Basic auth)', async () => {
    const env = buildEnv(privateJwkJson);
    await provisionClient(env.AUTH_KV, 'demo', 'top-secret', ['spec:read', 'mcp:tools']);
    const res = await app.request('/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + btoa('demo:top-secret'),
      },
      body: 'grant_type=client_credentials&scope=spec:read',
    }, env);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.token_type).toBe('Bearer');
    expect(body).toHaveProperty('access_token');
    expect(body).toHaveProperty('expires_in');
    expect(body.scope).toBe('spec:read');
    expect(res.headers.get('cache-control')).toBe('no-store');
  });

  it('issues a token for valid client_credentials (form-body auth)', async () => {
    const env = buildEnv(privateJwkJson);
    await provisionClient(env.AUTH_KV, 'demo', 'top-secret');
    const res = await app.request('/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials&client_id=demo&client_secret=top-secret',
    }, env);
    expect(res.status).toBe(200);
  });

  it('issued tokens verify against the JWKS public key', async () => {
    const env = buildEnv(privateJwkJson);
    await provisionClient(env.AUTH_KV, 'demo', 'top-secret');
    const tokenRes = await app.request('/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials&client_id=demo&client_secret=top-secret',
    }, env);
    const { access_token } = await tokenRes.json() as { access_token: string };
    const jwksRes = await app.request('/.well-known/jwks.json', {}, env);
    const { keys } = await jwksRes.json() as { keys: Parameters<typeof verifyAccessToken>[1][] };
    const decoded = await verifyAccessToken(access_token, keys[0]!);
    expect(decoded).not.toBeNull();
    expect(decoded?.client_id).toBe('demo');
  });

  it('rejects unknown client_id with 401 invalid_client', async () => {
    const env = buildEnv(privateJwkJson);
    const res = await app.request('/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + btoa('unknown:secret'),
      },
      body: 'grant_type=client_credentials',
    }, env);
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain('Basic');
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('invalid_client');
  });

  it('rejects wrong client_secret with 401 invalid_client', async () => {
    const env = buildEnv(privateJwkJson);
    await provisionClient(env.AUTH_KV, 'demo', 'right-secret');
    const res = await app.request('/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + btoa('demo:wrong-secret'),
      },
      body: 'grant_type=client_credentials',
    }, env);
    expect(res.status).toBe(401);
  });

  it('rejects unsupported grant_type with 400', async () => {
    const env = buildEnv(privateJwkJson);
    await provisionClient(env.AUTH_KV, 'demo', 'top-secret');
    const res = await app.request('/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + btoa('demo:top-secret'),
      },
      body: 'grant_type=password&username=foo&password=bar',
    }, env);
    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('unsupported_grant_type');
  });

  it('rejects non-form content-type with 400', async () => {
    const env = buildEnv(privateJwkJson);
    const res = await app.request('/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant_type: 'client_credentials' }),
    }, env);
    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('invalid_request');
  });

  it('filters requested scopes to client-granted intersection', async () => {
    const env = buildEnv(privateJwkJson);
    await provisionClient(env.AUTH_KV, 'demo', 'top-secret', ['spec:read']);
    const res = await app.request('/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + btoa('demo:top-secret'),
      },
      body: 'grant_type=client_credentials&scope=spec:read mcp:tools mcp:resources',
    }, env);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    // Only spec:read is in the client's grants and supported; the others drop.
    expect(body.scope).toBe('spec:read');
  });

  it('returns 500 when OAUTH_PRIVATE_JWK is unset', async () => {
    const env = buildEnv();   // no OAUTH_PRIVATE_JWK
    const res = await app.request('/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials&client_id=demo&client_secret=x',
    }, env);
    expect(res.status).toBe(500);
  });
});

// ── Introspection ───────────────────────────────────────────────────────────

describe('POST /oauth/introspect', () => {
  it('reports active=true for a freshly issued token', async () => {
    const env = buildEnv(privateJwkJson);
    await provisionClient(env.AUTH_KV, 'demo', 'top-secret');
    const tokenRes = await app.request('/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials&client_id=demo&client_secret=top-secret',
    }, env);
    const { access_token } = await tokenRes.json() as { access_token: string };
    const introspectRes = await app.request('/oauth/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `client_id=demo&client_secret=top-secret&token=${access_token}`,
    }, env);
    expect(introspectRes.status).toBe(200);
    const body = await introspectRes.json() as Record<string, unknown>;
    expect(body.active).toBe(true);
    expect(body.client_id).toBe('demo');
  });

  it('reports active=false for a revoked token (KV deny set)', async () => {
    const env = buildEnv(privateJwkJson);
    await provisionClient(env.AUTH_KV, 'demo', 'top-secret');
    const tokenRes = await app.request('/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials&client_id=demo&client_secret=top-secret',
    }, env);
    const { access_token } = await tokenRes.json() as { access_token: string };
    // Decode jti out of the token (no verification needed for this side-channel).
    const [, payloadB64] = access_token.split('.');
    const padded = payloadB64! + '==='.slice((payloadB64!.length + 3) % 4);
    const payload = JSON.parse(atob(padded.replace(/-/g, '+').replace(/_/g, '/'))) as { jti: string };
    env.AUTH_KV._set(`oauth:revoked:${payload.jti}`, '1');
    const introspectRes = await app.request('/oauth/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `client_id=demo&client_secret=top-secret&token=${access_token}`,
    }, env);
    const body = await introspectRes.json() as Record<string, unknown>;
    expect(body.active).toBe(false);
  });

  it('reports active=false for an invalid token string', async () => {
    const env = buildEnv(privateJwkJson);
    await provisionClient(env.AUTH_KV, 'demo', 'top-secret');
    const res = await app.request('/oauth/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'client_id=demo&client_secret=top-secret&token=not.a.jwt',
    }, env);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.active).toBe(false);
  });

  it('rejects unauthenticated introspection requests with 401', async () => {
    const env = buildEnv(privateJwkJson);
    const res = await app.request('/oauth/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'token=anything',
    }, env);
    expect(res.status).toBe(401);
  });
});

// ── Helper to silence the unused-import warning for getPublicJwk ──────────
// (Public JWK derivation is exercised indirectly through /.well-known/jwks.json,
// but exercising it directly here keeps the unit-test coverage explicit.)
describe('oauth-jwt: getPublicJwk', () => {
  it('returns a public JWK with the d field stripped', async () => {
    const publicOnly = await getPublicJwk(privateJwkJson);
    expect(publicOnly.kty).toBe('EC');
    expect(publicOnly.crv).toBe('P-256');
    expect(publicOnly).not.toHaveProperty('d');
  });
});
