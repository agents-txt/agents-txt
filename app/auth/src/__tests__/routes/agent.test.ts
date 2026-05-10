import { describe, it, expect, beforeEach } from 'vitest';
import app from '../../index.js';
import { createMockKV, generateKeypair, makeHostJwt, signJwt, thumbprint, registerAgent } from '../helpers.js';

describe('POST /agent/register', () => {
  let kv: ReturnType<typeof createMockKV>;
  beforeEach(() => { kv = createMockKV(); });

  it('returns 201 with agent_id and active status', async () => {
    const { res, body } = await registerAgent(kv, app);
    expect(res.status).toBe(201);
    expect(body).toHaveProperty('agent_id');
    expect(body).toHaveProperty('status', 'active');
    expect((body.agent_id as string).startsWith('agt_')).toBe(true);
  });

  it('stores the host record in KV', async () => {
    const { host } = await registerAgent(kv, app);
    const t = await thumbprint(host.publicJwk);
    const stored = kv._store.get(`host:${t}`);
    expect(stored).toBeDefined();
    expect(JSON.parse(stored!)).toHaveProperty('publicKeyJwk');
  });

  it('stores the agent record with agentPublicKeyJwk in KV', async () => {
    const { body, agent } = await registerAgent(kv, app);
    const stored = JSON.parse(kv._store.get(`agent:${body.agent_id}`)!);
    expect(stored).toHaveProperty('status', 'active');
    expect(stored).toHaveProperty('agentPublicKeyJwk');
    expect(stored.agentPublicKeyJwk.x).toBe(agent.publicJwk.x);
  });

  it('returns 400 when agent_public_key is missing from the token', async () => {
    const host = await generateKeypair();
    // No agent_public_key passed — should be rejected
    const token = await makeHostJwt(host.publicJwk, host.privateKey);
    const res = await app.request('/agent/register', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    }, { AUTH_KV: kv });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe('invalid_request');
  });

  it('returns 401 when Authorization header is missing', async () => {
    const res = await app.request('/agent/register', { method: 'POST' }, { AUTH_KV: kv });
    expect(res.status).toBe(401);
  });

  it('returns 401 for wrong JWT typ', async () => {
    const host = await generateKeypair();
    const agent = await generateKeypair();
    const token = await signJwt(
      { iss: await thumbprint(host.publicJwk), aud: 'http://localhost', host_public_key: host.publicJwk, agent_public_key: agent.publicJwk },
      { typ: 'agent+jwt' },  // wrong typ in header — should be rejected
      host.privateKey,
    );
    const res = await app.request('/agent/register', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    }, { AUTH_KV: kv });
    expect(res.status).toBe(401);
    const body = await res.json() as { error: string };
    expect(body.error).toBe('invalid_jwt');
  });

  it('returns 401 for an expired token', async () => {
    const host = await generateKeypair();
    const agent = await generateKeypair();
    const token = await makeHostJwt(host.publicJwk, host.privateKey, agent.publicJwk, {
      iat: Math.floor(Date.now() / 1000) - 120,
      exp: Math.floor(Date.now() / 1000) - 60,
    });
    const res = await app.request('/agent/register', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    }, { AUTH_KV: kv });
    expect(res.status).toBe(401);
    const body = await res.json() as { message: string };
    expect(body.message).toBe('token expired');
  });

  it('rejects a replayed token (same jti twice)', async () => {
    const host = await generateKeypair();
    const agent = await generateKeypair();
    const jti = crypto.randomUUID();
    const t = await thumbprint(host.publicJwk);
    const token = await signJwt(
      { iss: t, aud: 'http://localhost', host_public_key: host.publicJwk, agent_public_key: agent.publicJwk, jti },
      { typ: 'host+jwt' },
      host.privateKey,
    );
    const makeReq = () => app.request('/agent/register', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    }, { AUTH_KV: kv });

    expect((await makeReq()).status).toBe(201);
    const second = await makeReq();
    expect(second.status).toBe(401);
    expect((await second.json() as { message: string }).message).toContain('replay');
  });

  it('accepts a second registration from the same host with a new agent key', async () => {
    const { host, body: first } = await registerAgent(kv, app);
    const agent2 = await generateKeypair();
    const token2 = await makeHostJwt(host.publicJwk, host.privateKey, agent2.publicJwk);
    const res2 = await app.request('/agent/register', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token2}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    }, { AUTH_KV: kv });
    expect(res2.status).toBe(201);
    const second = await res2.json() as { agent_id: string };
    expect(second.agent_id).not.toBe(first.agent_id);
  });

  it('returns 401 when host JWT signature is tampered', async () => {
    const host = await generateKeypair();
    const agent = await generateKeypair();
    const token = await makeHostJwt(host.publicJwk, host.privateKey, agent.publicJwk);
    const parts = token.split('.');
    const validJsonPayload = btoa(JSON.stringify({ sub: 'tampered' })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const tampered = `${parts[0]}.${validJsonPayload}.${parts[2]}`;
    const res = await app.request('/agent/register', {
      method: 'POST',
      headers: { Authorization: `Bearer ${tampered}` },
    }, { AUTH_KV: kv });
    expect(res.status).toBe(401);
  });
});

describe('GET /agent/status', () => {
  let kv: ReturnType<typeof createMockKV>;
  beforeEach(() => { kv = createMockKV(); });

  it('returns 200 with active status for a registered agent', async () => {
    const { body: reg, host } = await registerAgent(kv, app);
    const token = await makeHostJwt(host.publicJwk, host.privateKey);
    const res = await app.request(`/agent/status?agent_id=${reg.agent_id}`, {
      headers: { Authorization: `Bearer ${token}` },
    }, { AUTH_KV: kv });
    expect(res.status).toBe(200);
    const body = await res.json() as { status: string; agent_id: string };
    expect(body.status).toBe('active');
    expect(body.agent_id).toBe(reg.agent_id);
  });

  it('returns 404 for an unknown agent_id', async () => {
    const { host } = await registerAgent(kv, app);
    const token = await makeHostJwt(host.publicJwk, host.privateKey);
    const res = await app.request('/agent/status?agent_id=agt_doesnotexist', {
      headers: { Authorization: `Bearer ${token}` },
    }, { AUTH_KV: kv });
    expect(res.status).toBe(404);
  });

  it('returns 400 when agent_id query param is missing', async () => {
    const { host } = await registerAgent(kv, app);
    const token = await makeHostJwt(host.publicJwk, host.privateKey);
    const res = await app.request('/agent/status', {
      headers: { Authorization: `Bearer ${token}` },
    }, { AUTH_KV: kv });
    expect(res.status).toBe(400);
  });

  it('returns 403 when agent belongs to a different host', async () => {
    const { body: reg } = await registerAgent(kv, app);
    // Different host registers its own agent first
    const { host: otherHost } = await registerAgent(kv, app);
    const token = await makeHostJwt(otherHost.publicJwk, otherHost.privateKey);
    const res = await app.request(`/agent/status?agent_id=${reg.agent_id}`, {
      headers: { Authorization: `Bearer ${token}` },
    }, { AUTH_KV: kv });
    expect(res.status).toBe(403);
  });
});

describe('POST /agent/revoke', () => {
  let kv: ReturnType<typeof createMockKV>;
  beforeEach(() => { kv = createMockKV(); });

  it('marks the agent as revoked in KV', async () => {
    const { body: reg, host } = await registerAgent(kv, app);
    const token = await makeHostJwt(host.publicJwk, host.privateKey);
    const res = await app.request('/agent/revoke', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_id: reg.agent_id }),
    }, { AUTH_KV: kv });
    expect(res.status).toBe(200);
    expect((await res.json() as { status: string }).status).toBe('revoked');
    expect(JSON.parse(kv._store.get(`agent:${reg.agent_id}`)!).status).toBe('revoked');
  });

  it('returns 403 when revoking an agent owned by a different host', async () => {
    const { body: reg } = await registerAgent(kv, app);
    const { host: otherHost } = await registerAgent(kv, app);
    const token = await makeHostJwt(otherHost.publicJwk, otherHost.privateKey);
    const res = await app.request('/agent/revoke', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_id: reg.agent_id }),
    }, { AUTH_KV: kv });
    expect(res.status).toBe(403);
  });

  it('returns 400 when agent_id is missing from body', async () => {
    const { host } = await registerAgent(kv, app);
    const token = await makeHostJwt(host.publicJwk, host.privateKey);
    const res = await app.request('/agent/revoke', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    }, { AUTH_KV: kv });
    expect(res.status).toBe(400);
  });
});
