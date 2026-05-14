// ─────────────────────────────────────────────────────────────────────────────
// Per-route rate limit gate, shared by every credential-handling endpoint in
// the auth worker. Backed by Cloudflare's `ratelimits` binding (declared in
// wrangler.jsonc). One binding (`RL_AUTH`) is keyed by `clientIp:route` so each
// route gets its own counter while sharing the same (limit, period) budget,
// which is enough for a demo deployment. If a future deployment needs per-route
// thresholds, declare additional `ratelimits[]` entries and add a parameter to
// `enforceRateLimit` selecting which binding to call.
//
// The binding is optional: vitest and `wrangler dev` boot without it, in which
// case `enforceRateLimit` is a no-op. This keeps the test suite hermetic and
// avoids a deploy-time chicken-and-egg with namespace_id provisioning.
// ─────────────────────────────────────────────────────────────────────────────

import type { Context } from 'hono';
import type { Env } from './types.js';

/**
 * Returns null when the request is within the rate-limit budget. Returns a
 * 429 Response when over budget; the caller should `return` that Response
 * directly without further work. The Response carries a JSON body shaped like
 * the rest of the auth worker's errors so consumers can parse uniformly.
 *
 * The `route` argument scopes the counter; pick a stable string per endpoint
 * (e.g. 'oauth_token', 'agent_register'). Mixing route names lets one busy
 * route saturate independently of another.
 */
export async function enforceRateLimit(
  c: Context<{ Bindings: Env }>,
  route: string,
): Promise<Response | null> {
  if (!c.env.RL_AUTH) return null;
  // CF-Connecting-IP is set by Cloudflare's edge on every public request and
  // cannot be spoofed by the client (the edge overwrites it). Falling back to
  // 'unknown' keeps the gate functional during local dev where the header is
  // absent; that fallback shares one bucket across every dev request, which is
  // exactly what you want for local testing.
  const ip = c.req.header('cf-connecting-ip') ?? 'unknown';
  const { success } = await c.env.RL_AUTH.limit({ key: `${ip}:${route}` });
  if (success) return null;
  return c.json(
    {
      error:             'rate_limited',
      error_description: 'Too many requests. Slow down and retry shortly.',
    },
    429,
    { 'Retry-After': '60' },
  );
}
