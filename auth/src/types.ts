export interface Env {
  AUTH_KV: KVNamespace;
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
