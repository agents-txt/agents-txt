import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

export type ParsedAgentsTxt = {
  payments?: { protocols: string[]; required?: true };
  authorization?: { protocols: string[]; identity?: 'required' };
  mcp: string[];
  skills: string[];
};

export function parseAgentsTxt(content: string): ParsedAgentsTxt {
  const result: ParsedAgentsTxt = { mcp: [], skills: [] };

  for (const raw of content.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;

    const colon = line.indexOf(':');
    if (colon === -1) continue;

    const key = line.slice(0, colon).trim();
    const value = line.slice(colon + 1).trim();

    switch (key) {
      case 'Payments':
        result.payments ??= { protocols: [] };
        if (value === 'required') result.payments.required = true;
        break;

      case 'Protocols':
        result.payments ??= { protocols: [] };
        result.payments.protocols = value.split(',').map((v) => v.trim()).filter(Boolean);
        break;

      case 'Authorization':
        result.authorization ??= { protocols: [] };
        result.authorization.protocols = value.split(',').map((v) => v.trim()).filter(Boolean);
        break;

      case 'Identity':
        result.authorization ??= { protocols: [] };
        if (value === 'required') result.authorization.identity = 'required';
        break;

      case 'MCP':
        result.mcp.push(value);
        break;

      case 'Skills':
        result.skills.push(value);
        break;
    }
  }

  if (result.payments && result.payments.protocols.length === 0) {
    delete result.payments;
  }

  return result;
}

export function registerParseAgentsTxt(server: McpServer) {
  server.registerTool(
    'parse_agents_txt',
    {
      description:
        'Parse the text content of an agents.txt file into a structured JSON object matching the agents.json schema shape.',
      inputSchema: {
        content: z.string().describe('Raw text content of an agents.txt file'),
      },
    },
    ({ content }: { content: string }) => {
      const parsed = parseAgentsTxt(content);
      return { content: [{ type: 'text' as const, text: JSON.stringify(parsed, null, 2) }] };
    },
  );
}
