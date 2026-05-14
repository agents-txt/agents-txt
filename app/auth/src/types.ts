/**
 * Cloudflare Workers Rate Limiting binding shape. The runtime injects this for
 * every `ratelimits[]` entry declared in wrangler.jsonc. `.limit({ key })`
 * returns `{ success: boolean }`; a false value means the caller is over the
 * configured (limit, period) for that key and the route should respond 429.
 */
export interface RateLimitBinding {
  limit(opts: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
  AUTH_KV: KVNamespace;
  /**
   * OAuth 2.0 signing key as a JSON-serialized EC P-256 private JWK. Set via
   * `wrangler secret put OAUTH_PRIVATE_JWK` and generated once with the
   * `scripts/generate-oauth-keypair.mjs` helper. Public key is derived at
   * runtime and served from `/.well-known/jwks.json`. When the secret is
   * unset every OAuth route returns 500 with `configuration_error`; the rest
   * of the worker (agent-auth) keeps working independently.
   */
  OAUTH_PRIVATE_JWK?: string;
  /**
   * Per-IP rate limiter for credential-handling and write routes (oauth token
   * + introspect, agent register + revoke, capability execute). Optional so
   * `wrangler dev` and vitest still boot without the binding wired up; routes
   * skip the gate when undefined. Provisioned in wrangler.jsonc.
   */
  RL_AUTH?: RateLimitBinding;
}

export interface HostRecord {
  publicKeyJwk: JsonWebKey;
  createdAt: number;
}

export interface AgentRecord {
  hostThumbprint: string;
  agentPublicKeyJwk: JsonWebKey;
  status: 'active' | 'revoked';
  createdAt: number;
}

export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  iat?: number;
  exp?: number;
  jti?: string;
  typ?: string;
  host_public_key?: JsonWebKey;
  agent_public_key?: JsonWebKey;
  capabilities?: string[];
  [key: string]: unknown;
}
