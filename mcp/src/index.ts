import mcpHandler, { type Env } from './server.js';

export { AgentsTxtMCP } from './server.js';

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const path = new URL(request.url).pathname;

    if (path === '/' || path === '/health') {
      return Promise.resolve(Response.json({
        ok: true,
        service: 'agents-txt-mcp',
        version: '0.5.0',
        endpoints: { mcp: '/mcp', sse: '/sse' },
      }));
    }

    return Promise.resolve(mcpHandler.fetch(request, env, ctx));
  },
};
