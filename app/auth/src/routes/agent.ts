import { Hono } from 'hono';
import type { Env, HostRecord, AgentRecord } from '../types.js';
import { parseJwt, verifyEd25519, jwkThumbprint, assertClaims } from '../jwt.js';

function err(c: any, status: number, code: string, message: string) {
  return c.json({ error: code, message }, status);
}

async function verifyHostJwt(authHeader: string | undefined, kv: KVNamespace): Promise<
  | { ok: true; hostThumbprint: string; hostJwk: JsonWebKey; payload: import('../types.js').JwtPayload }
  | { ok: false; status: number; code: string; message: string }
> {
  if (!authHeader?.startsWith('Bearer ')) {
    return { ok: false, status: 401, code: 'invalid_request', message: 'Missing Bearer token' };
  }

  const token = authHeader.slice(7);
  const parsed = parseJwt(token);
  if (!parsed) return { ok: false, status: 401, code: 'invalid_jwt', message: 'Malformed JWT' };
  if (parsed.header['typ'] !== 'host+jwt') return { ok: false, status: 401, code: 'invalid_jwt', message: 'Expected host+jwt' };

  const claimErr = assertClaims(parsed.payload);
  if (claimErr) return { ok: false, status: 401, code: 'invalid_jwt', message: claimErr };

  // JTI replay check
  const jti = parsed.payload.jti;
  if (!jti) return { ok: false, status: 401, code: 'invalid_jwt', message: 'Missing jti' };
  const jtiKey = `jti:${jti}`;
  if (await kv.get(jtiKey)) return { ok: false, status: 401, code: 'invalid_jwt', message: 'Token replay detected' };

  // Determine which public key to use for verification
  let hostJwk: JsonWebKey | null = null;
  const thumbprintFromToken = parsed.payload.iss as string | undefined;

  if (thumbprintFromToken) {
    const stored = await kv.get<HostRecord>(`host:${thumbprintFromToken}`, 'json');
    if (stored) hostJwk = stored.publicKeyJwk;
  }

  // First-time registration: key must be inline in the token
  if (!hostJwk) {
    const inlineKey = parsed.payload.host_public_key as JsonWebKey | undefined;
    if (!inlineKey) return { ok: false, status: 401, code: 'invalid_jwt', message: 'Unknown host — provide host_public_key in token' };
    hostJwk = inlineKey;
  }

  const valid = await verifyEd25519(parsed.signedData, parsed.signature, hostJwk);
  if (!valid) return { ok: false, status: 401, code: 'invalid_jwt', message: 'Signature verification failed' };

  // Consume JTI (90s TTL covers the jwt lifetime window)
  await kv.put(jtiKey, '1', { expirationTtl: 90 });

  const thumbprint = await jwkThumbprint(hostJwk);
  return { ok: true, hostThumbprint: thumbprint, hostJwk, payload: parsed.payload };
}

export function mountAgentRoutes(app: Hono<{ Bindings: Env }>) {
  // POST /agent/register — accept Host JWT, auto-approve, create agent record
  app.post('/agent/register', async (c) => {
    const result = await verifyHostJwt(c.req.header('Authorization'), c.env.AUTH_KV);
    if (!result.ok) return err(c, result.status, result.code, result.message);

    const { hostThumbprint, hostJwk } = result;

    // Store host if new
    const hostKey = `host:${hostThumbprint}`;
    if (!await c.env.AUTH_KV.get(hostKey)) {
      const hostRecord: HostRecord = { publicKeyJwk: hostJwk, createdAt: Date.now() };
      await c.env.AUTH_KV.put(hostKey, JSON.stringify(hostRecord));
    }

    // agent_public_key is required — agents sign their own JWTs with their own keypair
    const agentPublicKeyJwk = result.payload.agent_public_key as JsonWebKey | undefined;
    if (!agentPublicKeyJwk) return err(c, 400, 'invalid_request', 'Missing agent_public_key in token payload');

    const agentId = `agt_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
    const agentRecord: AgentRecord = { hostThumbprint, agentPublicKeyJwk, status: 'active', createdAt: Date.now() };
    await c.env.AUTH_KV.put(`agent:${agentId}`, JSON.stringify(agentRecord));

    return c.json({
      agent_id: agentId,
      status: 'active',
      host_id: hostThumbprint,
      granted_capabilities: ['ping'],
      message: 'Agent registered and auto-approved (PoC mode — no user consent required)',
    }, 201);
  });

  // GET /agent/status — return agent status for host
  app.get('/agent/status', async (c) => {
    const result = await verifyHostJwt(c.req.header('Authorization'), c.env.AUTH_KV);
    if (!result.ok) return err(c, result.status, result.code, result.message);

    const agentId = c.req.query('agent_id');
    if (!agentId) return err(c, 400, 'invalid_request', 'Missing agent_id query param');

    const record = await c.env.AUTH_KV.get<AgentRecord>(`agent:${agentId}`, 'json');
    if (!record) return err(c, 404, 'not_found', 'Agent not found');
    if (record.hostThumbprint !== result.hostThumbprint) return err(c, 403, 'forbidden', 'Agent belongs to a different host');

    return c.json({ agent_id: agentId, status: record.status, granted_capabilities: ['ping'] });
  });

  // POST /agent/revoke
  app.post('/agent/revoke', async (c) => {
    const result = await verifyHostJwt(c.req.header('Authorization'), c.env.AUTH_KV);
    if (!result.ok) return err(c, result.status, result.code, result.message);

    const body = await c.req.json<{ agent_id?: string }>();
    if (!body.agent_id) return err(c, 400, 'invalid_request', 'Missing agent_id');

    const record = await c.env.AUTH_KV.get<AgentRecord>(`agent:${body.agent_id}`, 'json');
    if (!record) return err(c, 404, 'not_found', 'Agent not found');
    if (record.hostThumbprint !== result.hostThumbprint) return err(c, 403, 'forbidden', 'Agent belongs to a different host');

    record.status = 'revoked';
    await c.env.AUTH_KV.put(`agent:${body.agent_id}`, JSON.stringify(record));

    return c.json({ agent_id: body.agent_id, status: 'revoked' });
  });
}
