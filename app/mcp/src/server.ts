import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpAgent } from 'agents/mcp';
import { Hono } from 'hono';
import { registerGetSpec } from './tools/get_spec.js';
import { registerGetSkill } from './tools/get_skill.js';
import { registerParseAgentsTxt } from './tools/parse_agents_txt.js';
import { registerValidateAgents } from './tools/validate_agents.js';
import { registerAuditSite } from './tools/audit_site.js';

export type Env = {
  SITE_ORIGIN: string;
  // Optional service binding back to the site worker. audit_site uses it to
  // route fetches whose target origin matches SITE_ORIGIN, bypassing the
  // Cloudflare same-account-subrequest loop that returns 522. Optional so
  // wrangler dev without the binding still boots; safeFetch falls back to
  // plain fetch() in that case.
  SITE?: { fetch: typeof fetch };
};

type State = Record<string, never>;
type Props = Record<string, never>;

// Instructions surfaced to MCP clients on initialize. Lets an agent connecting
// to this server know what it is for before listing tools. Format follows the
// MCP spec's `serverInfo.instructions` field: short prose describing scope,
// the right times to call each tool, and the boundary between this server's
// concerns and adjacent specs. AEO scanners read this field as the "MCP
// server identity" / "when to use" signal.
const SERVER_INSTRUCTIONS = `This server exposes the agents.txt v1.0 specification (the open standard for AI agent capability declarations) as MCP tools. Use it when you need to:

- Read the spec or a specific section ("get_spec")
- Parse a plain-text agents.txt file into structured JSON ("parse_agents_txt")
- Validate an agents.txt or agents.json document against the spec ("validate_agents_txt", "validate_agents_json")
- Audit a live site for full agents.txt compliance, including §4.5 serving headers and cross-file consistency ("audit_site")
- Fetch a skill package by name from the agents.txt skills index ("get_skill")

All tools are read-only and side-effect-free. Out of scope: implementing payment protocols (x402, MPP, AP2), authorization protocols (agent-auth, OAuth 2.0, auth.md), or any runtime behaviour. This server only reads, parses, validates, and audits the discovery files; the protocols those files declare are independent specifications. Live spec and demos at https://agents-txt.com; toolkit (herald) at https://www.npmjs.com/package/@agentstxtdev/herald.`;

export class AgentsTxtMCP extends McpAgent<Env, State, Props> {
  server = new McpServer({
    name: 'agents.txt',
    version: '0.5.0',
    websiteUrl: 'https://agents-txt.com',
  }, {
    instructions: SERVER_INSTRUCTIONS,
  });

  initialState: State = {};

  async init() {
    registerGetSpec(this.server, this.env.SITE_ORIGIN);
    registerGetSkill(this.server, this.env.SITE_ORIGIN);
    registerParseAgentsTxt(this.server);
    registerValidateAgents(this.server);
    registerAuditSite(this.server, this.env);
  }
}

const app = new Hono<{ Bindings: Env }>();

app.all('/mcp', (c) =>
  AgentsTxtMCP.serve('/mcp', { binding: 'AgentsTxtMCP' }).fetch(c.req.raw, c.env, c.executionCtx),
);

app.all('/sse', (c) =>
  AgentsTxtMCP.serveSSE('/sse', { binding: 'AgentsTxtMCP' }).fetch(c.req.raw, c.env, c.executionCtx),
);

app.all('/sse/*', (c) =>
  AgentsTxtMCP.serveSSE('/sse', { binding: 'AgentsTxtMCP' }).fetch(c.req.raw, c.env, c.executionCtx),
);

export default app;
