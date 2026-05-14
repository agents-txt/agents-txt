import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Env } from './types.js';
import { mountDiscoveryRoutes } from './routes/discovery.js';
import { mountAgentRoutes } from './routes/agent.js';
import { mountCapabilityRoutes, mountProtectedRoutes } from './routes/capability.js';
import { mountOAuthRoutes } from './routes/oauth.js';

const app = new Hono<{ Bindings: Env }>();

app.use('*', cors({
  origin: '*',
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['GET', 'POST', 'OPTIONS'],
}));

mountDiscoveryRoutes(app);
mountAgentRoutes(app);
mountCapabilityRoutes(app);
mountProtectedRoutes(app);
mountOAuthRoutes(app);

app.get('/health', (c) => c.json({ ok: true, service: 'agents-txt-auth', version: '0.1.0' }));

app.notFound((c) => c.json({ error: 'not_found', message: `No route for ${c.req.method} ${new URL(c.req.url).pathname}` }, 404));

export default app;
