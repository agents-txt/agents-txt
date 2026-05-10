import { describe, it, expect } from 'vitest';
import app from '../../index.js';
import { createMockKV } from '../helpers.js';

const env = { AUTH_KV: createMockKV() };

describe('GET /.well-known/agent-configuration', () => {
  it('returns 200', async () => {
    const res = await app.request('/.well-known/agent-configuration', {}, env);
    expect(res.status).toBe(200);
  });

  it('returns correct content-type', async () => {
    const res = await app.request('/.well-known/agent-configuration', {}, env);
    expect(res.headers.get('content-type')).toContain('application/json');
  });

  it('contains required top-level fields', async () => {
    const res = await app.request('/.well-known/agent-configuration', {}, env);
    const body = await res.json() as Record<string, unknown>;
    expect(body).toHaveProperty('issuer');
    expect(body).toHaveProperty('agent_auth_version');
    expect(body).toHaveProperty('supported_modes');
    expect(body).toHaveProperty('supported_algorithms');
    expect(body).toHaveProperty('endpoints');
    expect(body).toHaveProperty('capabilities');
  });

  it('endpoints block contains all required paths', async () => {
    const res = await app.request('/.well-known/agent-configuration', {}, env);
    const { endpoints } = await res.json() as { endpoints: Record<string, string> };
    expect(endpoints).toHaveProperty('register');
    expect(endpoints).toHaveProperty('status');
    expect(endpoints).toHaveProperty('capability_list');
    expect(endpoints).toHaveProperty('capability_execute');
  });

  it('declares agent-auth protocol version', async () => {
    const res = await app.request('/.well-known/agent-configuration', {}, env);
    const body = await res.json() as { agent_auth_version: string };
    expect(body.agent_auth_version).toBe('0.1');
  });

  it('capabilities array contains ping', async () => {
    const res = await app.request('/.well-known/agent-configuration', {}, env);
    const { capabilities } = await res.json() as { capabilities: Array<{ name: string }> };
    expect(Array.isArray(capabilities)).toBe(true);
    expect(capabilities.some(c => c.name === 'ping')).toBe(true);
  });
});
