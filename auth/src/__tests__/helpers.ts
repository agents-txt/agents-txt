import { vi } from 'vitest';

// ── Mock KV ──────────────────────────────────────────────────────────────────

export function createMockKV() {
  const store = new Map<string, string>();
  return {
    get: vi.fn(async (key: string, type?: string) => {
      const val = store.get(key) ?? null;
      if (val === null) return null;
      return type === 'json' ? JSON.parse(val) : val;
    }),
    put: vi.fn(async (key: string, value: string, _opts?: { expirationTtl?: number }) => {
      store.set(key, value);
    }),
    delete: vi.fn(async (key: string) => { store.delete(key); }),
    _store: store,
    _clear: () => store.clear(),
    _set: (key: string, value: unknown) => store.set(key, typeof value === 'string' ? value : JSON.stringify(value)),
  };
}

export type MockKV = ReturnType<typeof createMockKV>;

// ── Ed25519 keypair + JWT helpers ─────────────────────────────────────────────

export async function generateKeypair() {
  const keypair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as CryptoKeyPair;
  const publicJwk  = await crypto.subtle.exportKey('jwk', keypair.publicKey) as JsonWebKey;
  const privateKey = keypair.privateKey;
  return { publicJwk, privateKey };
}

function b64url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function thumbprint(jwk: JsonWebKey): Promise<string> {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return b64url(digest);
}

export async function signJwt(
  payload: Record<string, unknown>,
  header: Record<string, unknown>,
  privateKey: CryptoKey,
): Promise<string> {
  const h = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'EdDSA', ...header })));
  const p = b64url(new TextEncoder().encode(JSON.stringify({
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60,
    jti: crypto.randomUUID(),
    ...payload,
  })));
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, new TextEncoder().encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(sig)}`;
}

// Host JWT — typ in HEADER per spec, signed by host private key
export async function makeHostJwt(
  hostPublicJwk: JsonWebKey,
  hostPrivateKey: CryptoKey,
  agentPublicJwk?: JsonWebKey,
  payloadOverrides: Record<string, unknown> = {},
): Promise<string> {
  const t = await thumbprint(hostPublicJwk);
  return signJwt(
    {
      iss: t,
      aud: 'http://localhost',
      host_public_key: hostPublicJwk,
      ...(agentPublicJwk ? { agent_public_key: agentPublicJwk } : {}),
      ...payloadOverrides,
    },
    { typ: 'host+jwt' },
    hostPrivateKey,
  );
}

// Agent JWT — typ in HEADER per spec, signed by the AGENT's private key (not the host's)
// iss = host thumbprint, sub = agent ID
export async function makeAgentJwt(
  hostPublicJwk: JsonWebKey,
  agentPrivateKey: CryptoKey,
  agentId: string,
  payloadOverrides: Record<string, unknown> = {},
): Promise<string> {
  const t = await thumbprint(hostPublicJwk);
  return signJwt(
    { iss: t, sub: agentId, aud: 'http://localhost/capability/execute', ...payloadOverrides },
    { typ: 'agent+jwt' },
    agentPrivateKey,
  );
}

// Convenience: register a host+agent pair and return everything needed for follow-up calls
export async function registerAgent(kv: MockKV, app: any) {
  const host  = await generateKeypair();
  const agent = await generateKeypair();
  const token = await makeHostJwt(host.publicJwk, host.privateKey, agent.publicJwk as JsonWebKey);
  const res = await app.request('/agent/register', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  }, { AUTH_KV: kv });
  const body = await res.json() as { agent_id: string; status: string };
  return { res, body, host, agent, agentId: body.agent_id };
}
