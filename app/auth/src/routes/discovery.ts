import { Hono } from 'hono';
import type { Env } from '../types.js';

export function mountDiscoveryRoutes(app: Hono<{ Bindings: Env }>) {
  app.get('/.well-known/agent-configuration', (c) => {
    const origin = new URL(c.req.url).origin;
    return c.json({
      issuer: origin,
      agent_auth_version: '0.1',
      supported_modes: ['autonomous'],
      supported_algorithms: ['EdDSA'],
      approval_methods: [],
      endpoints: {
        register:            `${origin}/agent/register`,
        status:              `${origin}/agent/status`,
        request_capability:  `${origin}/agent/request-capability`,
        revoke:              `${origin}/agent/revoke`,
        capability_list:     `${origin}/capability/list`,
        capability_describe: `${origin}/capability/describe`,
        capability_execute:  `${origin}/capability/execute`,
      },
      capabilities: [
        {
          name: 'ping',
          description: 'Proof-of-authentication capability. Returns authenticated agent identity. No data is gated — this is a PoC.',
          schema: { arguments: {}, result: { authenticated: 'boolean', agent_id: 'string', message: 'string' } },
        },
      ],
    });
  });
}
