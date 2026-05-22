// ─────────────────────────────────────────────────────────────────────────────
// OAuth 2.0 routes (RFC 6749 §4.4 client-credentials grant + discovery)
//
// Five public endpoints:
//
//   GET  /.well-known/openid-configuration       — OIDC Discovery 1.0 metadata
//   GET  /.well-known/oauth-authorization-server — RFC 8414 metadata
//   GET  /.well-known/oauth-protected-resource   — RFC 9728 metadata
//   GET  /.well-known/jwks.json                  — JWKS with the OAuth signing public key
//   POST /oauth/token                            — client-credentials grant → ES256 access token
//
// Companion endpoint (RFC 7662):
//
//   POST /oauth/introspect                       — token introspection
//
// Tokens are ES256 JWTs signed with a P-256 private key configured as the
// `OAUTH_PRIVATE_JWK` wrangler secret. Public key is published at
// `/.well-known/jwks.json` and is the only thing resource servers need to
// validate tokens; the secret never leaves the worker.
//
// Clients are stored in the existing AUTH_KV namespace under
// `oauth:client:<client_id>` with shape:
//   { hashed_secret, scopes[], created_at, name? }
// Provisioned out of band via `wrangler kv:key put`; this worker never
// exposes a client-creation endpoint by design (PoC keeps the surface tight).
//
// Issued tokens carry `jti` and are added to a short-lived KV deny set when
// revoked (`oauth:revoked:<jti>` with TTL = token lifetime). Introspection
// honours that set so a revoked token is rejected within the lifetime.
// ─────────────────────────────────────────────────────────────────────────────

import { Hono, type Context } from 'hono';
import type { Env } from '../types.js';
import {
  getPublicJwk,
  signAccessToken,
  verifyAccessToken,
  verifyClientSecret,
  randomJti,
  type OAuthJwtPayload,
} from '../oauth-jwt.js';
import { enforceRateLimit } from '../ratelimit.js';

type OAuthContext = Context<{ Bindings: Env }>;

interface OAuthClient {
  hashed_secret: string;
  scopes:        string[];
  created_at:    number;
  name?:         string;
}

// Short-lived by design. The public `demo-public` client embeds its secret in
// HTML, so any token issued to it is effectively a bearer credential anyone
// can mint. A 60-second TTL caps the window during which a leaked or shared
// token is replayable. Real (non-public) clients on a production deployment
// would typically raise this back to 3600s; do so by environment if it ever
// matters here.
const TOKEN_TTL_SECONDS  = 60;
const SUPPORTED_SCOPES   = ['spec:read', 'mcp:tools', 'mcp:resources'] as const;

function badRequest(c: OAuthContext, error: string, description: string, status: 400 | 401 = 400) {
  return c.json({ error, error_description: description }, status);
}

function parseBasicAuth(header: string | undefined | null): { id: string; secret: string } | null {
  if (!header) return null;
  if (!header.toLowerCase().startsWith('basic ')) return null;
  try {
    const decoded = atob(header.slice(6).trim());
    const colon = decoded.indexOf(':');
    if (colon < 0) return null;
    return { id: decoded.slice(0, colon), secret: decoded.slice(colon + 1) };
  } catch {
    return null;
  }
}

async function readForm(body: string): Promise<URLSearchParams> {
  return new URLSearchParams(body);
}

/**
 * Authenticate a client via either `client_secret_basic` (RFC 6749 §2.3.1)
 * or `client_secret_post` (§2.3.1). Returns the client record on success.
 */
async function authenticateClient(
  env:    Env,
  form:   URLSearchParams,
  header: string | undefined | null,
): Promise<{ id: string; client: OAuthClient } | null> {
  let id:     string | null = null;
  let secret: string | null = null;

  const basic = parseBasicAuth(header);
  if (basic) {
    id = basic.id;
    secret = basic.secret;
  } else {
    const formId     = form.get('client_id');
    const formSecret = form.get('client_secret');
    if (formId && formSecret) {
      id = formId;
      secret = formSecret;
    }
  }
  if (!id || !secret) return null;

  const record = await env.AUTH_KV.get(`oauth:client:${id}`, 'json') as OAuthClient | null;
  if (!record) return null;
  const ok = await verifyClientSecret(secret, record.hashed_secret);
  if (!ok) return null;
  return { id, client: record };
}

/**
 * Filter a requested scope string ("scope1 scope2") down to the intersection
 * with both the client's granted scopes and the server's supported scopes.
 * Returns the space-separated intersection (RFC 6749 §3.3 format) or empty
 * string when no overlap.
 */
function intersectScopes(requested: string | null, clientScopes: string[]): string {
  const askedRaw = requested?.split(/\s+/).filter(Boolean) ?? clientScopes;
  const asked    = new Set(askedRaw);
  const granted  = new Set(clientScopes);
  const out: string[] = [];
  for (const s of SUPPORTED_SCOPES) {
    if (asked.has(s) && granted.has(s)) out.push(s);
  }
  return out.join(' ');
}

export function mountOAuthRoutes(app: Hono<{ Bindings: Env }>) {
  // ─── Discovery: OIDC Discovery 1.0 ──────────────────────────────────────
  // OpenID Connect Discovery 1.0. We do not implement the full OIDC flow
  // (no id_token, no userinfo, no authorization_endpoint); only the subset
  // an OAuth 2.0 client-credentials client needs. Documented as an OAuth 2.0
  // authorization server first; the OIDC endpoint is a courtesy alias for
  // tools that probe it.
  app.get('/.well-known/openid-configuration', (c) => buildDiscoveryDoc(c));
  app.get('/.well-known/oauth-authorization-server', (c) => buildDiscoveryDoc(c));

  // ─── Discovery: OAuth Protected Resource Metadata (RFC 9728) ────────────
  app.get('/.well-known/oauth-protected-resource', (c) => {
    const origin = new URL(c.req.url).origin;
    return c.json({
      resource:                 origin,
      authorization_servers:    [origin],
      scopes_supported:         [...SUPPORTED_SCOPES],
      bearer_methods_supported: ['header'],
      resource_documentation:   `${origin}/spec#11`,
    });
  });

  // ─── JWKS ────────────────────────────────────────────────────────────────
  app.get('/.well-known/jwks.json', async (c) => {
    if (!c.env.OAUTH_PRIVATE_JWK) {
      return c.json({ error: 'configuration_error', error_description: 'OAUTH_PRIVATE_JWK is not configured' }, 500);
    }
    const publicJwk = await getPublicJwk(c.env.OAUTH_PRIVATE_JWK);
    return c.json({ keys: [publicJwk] });
  });

  // ─── Token endpoint (RFC 6749 §4.4) ─────────────────────────────────────
  app.post('/oauth/token', async (c) => {
    const limited = await enforceRateLimit(c, 'oauth_token');
    if (limited) return limited;
    if (!c.env.OAUTH_PRIVATE_JWK) {
      return c.json({ error: 'server_error', error_description: 'OAUTH_PRIVATE_JWK is not configured' }, 500);
    }
    const contentType = c.req.header('content-type') ?? '';
    if (!contentType.includes('application/x-www-form-urlencoded')) {
      return badRequest(c, 'invalid_request', 'Content-Type must be application/x-www-form-urlencoded');
    }
    const form = await readForm(await c.req.text());
    const grantType = form.get('grant_type');
    if (grantType !== 'client_credentials') {
      return badRequest(c, 'unsupported_grant_type', `grant_type must be client_credentials; got ${grantType ?? 'null'}`);
    }
    const usedBasic = !!c.req.header('authorization');
    const auth = await authenticateClient(c.env, form, c.req.header('authorization'));
    if (!auth) {
      // RFC 6749 §5.2: invalid_client → 401. The `WWW-Authenticate: Basic`
      // header is only added when the client attempted Basic auth, so it
      // does not trigger a browser HTTP-Basic dialog on form-body failures.
      return c.json(
        { error: 'invalid_client', error_description: 'Client authentication failed' },
        401,
        usedBasic
          ? { 'WWW-Authenticate': 'Basic realm="agents.txt", error="invalid_client"' }
          : {},
      );
    }
    const scope = intersectScopes(form.get('scope'), auth.client.scopes);
    const now   = Math.floor(Date.now() / 1000);
    const origin = new URL(c.req.url).origin;
    const payload: OAuthJwtPayload = {
      iss:       origin,
      sub:       auth.id,
      aud:       origin,
      iat:       now,
      exp:       now + TOKEN_TTL_SECONDS,
      jti:       randomJti(),
      scope:     scope || undefined,
      client_id: auth.id,
    };
    const token = await signAccessToken(payload, c.env.OAUTH_PRIVATE_JWK);
    return c.json({
      access_token: token,
      token_type:   'Bearer',
      expires_in:   TOKEN_TTL_SECONDS,
      ...(scope ? { scope } : {}),
    }, 200, {
      'Cache-Control': 'no-store',
      'Pragma':        'no-cache',
    });
  });

  // ─── Token introspection (RFC 7662) ─────────────────────────────────────
  // Public per the RFC: requires client authentication. Returns the active
  // status plus the standard introspection fields.
  app.post('/oauth/introspect', async (c) => {
    const limited = await enforceRateLimit(c, 'oauth_introspect');
    if (limited) return limited;
    if (!c.env.OAUTH_PRIVATE_JWK) {
      return c.json({ error: 'server_error' }, 500);
    }
    const form = await readForm(await c.req.text());
    const auth = await authenticateClient(c.env, form, c.req.header('authorization'));
    if (!auth) {
      return c.json({ error: 'invalid_client' }, 401);
    }
    const token = form.get('token');
    if (!token) return c.json({ active: false });
    const publicJwk = await getPublicJwk(c.env.OAUTH_PRIVATE_JWK);
    const payload   = await verifyAccessToken(token, publicJwk);
    if (!payload) return c.json({ active: false });
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number' || payload.exp < now) return c.json({ active: false });
    if (payload.jti && await c.env.AUTH_KV.get(`oauth:revoked:${payload.jti}`)) {
      return c.json({ active: false });
    }
    return c.json({
      active:    true,
      scope:     payload.scope,
      client_id: payload.client_id,
      token_type: 'Bearer',
      exp:       payload.exp,
      iat:       payload.iat,
      sub:       payload.sub,
      aud:       payload.aud,
      iss:       payload.iss,
      jti:       payload.jti,
    });
  });
}

// ── Discovery doc builder (shared by both /.well-known aliases) ─────────────

function buildDiscoveryDoc(c: OAuthContext) {
  const origin = new URL(c.req.url).origin;
  return c.json({
    issuer:                                 origin,
    token_endpoint:                         `${origin}/oauth/token`,
    introspection_endpoint:                 `${origin}/oauth/introspect`,
    jwks_uri:                               `${origin}/.well-known/jwks.json`,
    grant_types_supported:                  ['client_credentials'],
    response_types_supported:               ['token'],
    token_endpoint_auth_methods_supported:  ['client_secret_basic', 'client_secret_post'],
    token_endpoint_auth_signing_alg_values_supported: ['ES256'],
    introspection_endpoint_auth_methods_supported:    ['client_secret_basic', 'client_secret_post'],
    scopes_supported:                       [...SUPPORTED_SCOPES],
    service_documentation:                  `${origin}/spec#11`,
    // OIDC-specific fields included so OIDC-strict clients do not error on
    // their absence even though we do not issue id_tokens. Subject types
    // are `public`; the algorithm advertised matches what we sign with.
    subject_types_supported:                ['public'],
    id_token_signing_alg_values_supported:  ['ES256'],
    code_challenge_methods_supported:       [],
    // auth-md activation block. agents.txt §11.3 advertises `auth-md` in the
    // `Authorization:` directive; this block on the AS metadata is the
    // discovery surface that activates the flow described in /auth.md. Field
    // shape follows the WorkOS auth.md schema. The /agent/auth endpoints are
    // not implemented on this reference deployment yet; the URIs below are
    // the addresses they will live at when wired. Agents that probe them
    // before wiring lands receive 404.
    agent_auth: {
      skill:                       `${origin}/auth.md`,
      register_uri:                `${origin}/agent/auth`,
      claim_uri:                   `${origin}/agent/auth/claim`,
      revocation_uri:              `${origin}/agent/auth/revoke`,
      identity_types_supported:    ['anonymous', 'identity_assertion'],
      anonymous: {
        credential_types_supported: ['api_key'],
      },
      identity_assertion: {
        assertion_types_supported: [
          'urn:ietf:params:oauth:token-type:id-jag',
          'verified_email',
        ],
        credential_types_supported: ['access_token', 'api_key'],
      },
      events_supported: [
        'https://schemas.workos.com/events/agent/auth/identity/assertion/revoked',
      ],
    },
  });
}
