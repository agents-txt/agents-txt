import { describe, it, expect, beforeEach } from 'vitest';
import app from '../../index.js';
import { createMockKV, generateKeypair, makeHostJwt, makeAgentJwt, registerAgent } from '../helpers.js';

async function execute(kv: ReturnType<typeof createMockKV>, agentJwt: string, body: Record<string, unknown> = {}) {
  return app.request('/capability/execute', {
    method: 'POST',
    headers: { Authorization: `Bearer ${agentJwt}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, { AUTH_KV: kv });
}

describe('GET /capability/list', () => {
  it('returns 200 with a non-empty capabilities array', async () => {
    const res = await app.request('/capability/list', {}, { AUTH_KV: createMockKV() });
    expect(res.status).toBe(200);
    const body = await res.json() as { capabilities: Array<{ name: string }> };
    expect(Array.isArray(body.capabilities)).toBe(true);
    expect(body.capabilities.length).toBeGreaterThan(0);
  });

  it('includes the ping capability', async () => {
    const res = await app.request('/capability/list', {}, { AUTH_KV: createMockKV() });
    const { capabilities } = await res.json() as { capabilities: Array<{ name: string }> };
    expect(capabilities.some(c => c.name === 'ping')).toBe(true);
  });

  it('requires no auth', async () => {
    const res = await app.request('/capability/list', {}, { AUTH_KV: createMockKV() });
    expect(res.status).toBe(200);
  });
});

describe('GET /capability/describe', () => {
  it('returns schema for ping', async () => {
    const res = await app.request('/capability/describe?name=ping', {}, { AUTH_KV: createMockKV() });
    expect(res.status).toBe(200);
    const body = await res.json() as { name: string; result: unknown };
    expect(body.name).toBe('ping');
    expect(body).toHaveProperty('result');
  });

  it('returns 404 for an unknown capability', async () => {
    const res = await app.request('/capability/describe?name=transfer_funds', {}, { AUTH_KV: createMockKV() });
    expect(res.status).toBe(404);
  });
});

describe('POST /capability/execute', () => {
  let kv: ReturnType<typeof createMockKV>;
  beforeEach(() => { kv = createMockKV(); });

  it('returns authenticated:true for a valid agent JWT signed by the agent keypair', async () => {
    const { agentId, host, agent } = await registerAgent(kv, app);
    // Agent signs with its own private key — host thumbprint in iss
    const agentJwt = await makeAgentJwt(host.publicJwk, agent.privateKey, agentId);
    const res = await execute(kv, agentJwt, { capability: 'ping' });
    expect(res.status).toBe(200);
    const body = await res.json() as { data: { authenticated: boolean; agent_id: string } };
    expect(body.data.authenticated).toBe(true);
    expect(body.data.agent_id).toBe(agentId);
  });

  it('returns 401 when signed by the host key instead of the agent key', async () => {
    const { agentId, host } = await registerAgent(kv, app);
    // Wrong: signing with host private key, not agent private key
    const agentJwt = await makeAgentJwt(host.publicJwk, host.privateKey, agentId);
    const res = await execute(kv, agentJwt, { capability: 'ping' });
    expect(res.status).toBe(401);
    const body = await res.json() as { message: string };
    expect(body.message).toBe('Signature verification failed');
  });

  it('returns 401 when Authorization header is missing', async () => {
    const res = await app.request('/capability/execute', { method: 'POST' }, { AUTH_KV: kv });
    expect(res.status).toBe(401);
  });

  it('returns 401 for wrong JWT typ (host+jwt instead of agent+jwt)', async () => {
    const { agentId, host, agent } = await registerAgent(kv, app);
    // host+jwt typ in header is wrong for capability/execute which expects agent+jwt
    const wrongJwt = await makeHostJwt(host.publicJwk, host.privateKey, agent.publicJwk);
    const res = await execute(kv, wrongJwt);
    expect(res.status).toBe(401);
    const body = await res.json() as { message: string };
    expect(body.message).toContain('agent+jwt');
  });

  it('returns 401 for an unknown host (iss not in KV)', async () => {
    const unknownHost = await generateKeypair();
    const unknownAgent = await generateKeypair();
    // Never registered — host not in KV
    const agentJwt = await makeAgentJwt(unknownHost.publicJwk, unknownAgent.privateKey, 'agt_fake');
    const res = await execute(kv, agentJwt);
    expect(res.status).toBe(401);
    const body = await res.json() as { message: string };
    expect(body.message).toBe('Unknown host');
  });

  it('returns 404 for an unknown agent_id', async () => {
    const { host, agent } = await registerAgent(kv, app);
    // Valid host, valid signing, but agent_id does not exist
    const agentJwt = await makeAgentJwt(host.publicJwk, agent.privateKey, 'agt_doesnotexist');
    const res = await execute(kv, agentJwt);
    expect(res.status).toBe(404);
  });

  it('returns 403 for a revoked agent', async () => {
    const { agentId, host, agent } = await registerAgent(kv, app);
    // Revoke the agent first
    await app.request('/agent/revoke', {
      method: 'POST',
      headers: { Authorization: `Bearer ${await makeHostJwt(host.publicJwk, host.privateKey)}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_id: agentId }),
    }, { AUTH_KV: kv });

    const agentJwt = await makeAgentJwt(host.publicJwk, agent.privateKey, agentId);
    const res = await execute(kv, agentJwt);
    expect(res.status).toBe(403);
    expect((await res.json() as { error: string }).error).toBe('agent_revoked');
  });

  it('returns 403 for an unknown capability name', async () => {
    const { agentId, host, agent } = await registerAgent(kv, app);
    const agentJwt = await makeAgentJwt(host.publicJwk, agent.privateKey, agentId);
    const res = await execute(kv, agentJwt, { capability: 'transfer_funds' });
    expect(res.status).toBe(403);
    expect((await res.json() as { error: string }).error).toBe('capability_not_granted');
  });

  it('rejects a replayed agent JWT on the second use', async () => {
    const { agentId, host, agent } = await registerAgent(kv, app);
    const agentJwt = await makeAgentJwt(host.publicJwk, agent.privateKey, agentId);

    expect((await execute(kv, agentJwt, { capability: 'ping' })).status).toBe(200);

    const second = await execute(kv, agentJwt, { capability: 'ping' });
    expect(second.status).toBe(401);
    expect((await second.json() as { message: string }).message).toContain('replay');
  });

  it('returns 401 for an expired agent JWT', async () => {
    const { agentId, host, agent } = await registerAgent(kv, app);
    const agentJwt = await makeAgentJwt(host.publicJwk, agent.privateKey, agentId, {
      iat: Math.floor(Date.now() / 1000) - 120,
      exp: Math.floor(Date.now() / 1000) - 60,
    });
    const res = await execute(kv, agentJwt);
    expect(res.status).toBe(401);
    expect((await res.json() as { message: string }).message).toBe('token expired');
  });

  it('succeeds without capability field in body (omitting it defaults to ping)', async () => {
    const { agentId, host, agent } = await registerAgent(kv, app);
    const agentJwt = await makeAgentJwt(host.publicJwk, agent.privateKey, agentId);
    const res = await execute(kv, agentJwt, {});
    expect(res.status).toBe(200);
  });
});
