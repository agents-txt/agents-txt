import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { BLOCK_OPENERS, BLOCK_BODY_DIRECTIVES } from '../protocols.js';

export type ParsedAgentsTxt = {
  payments?: { protocols: string[]; required?: true };
  authorization?: { protocols: string[]; identity?: 'required' };
  mcp: string[];
  skills: string[];
  a2a: string[];
  /**
   * Unknown directives the parser encountered. Forward-compatible bucket so
   * future block types can be observed without modifying the parser. Each
   * entry preserves the original directive name and its values.
   */
  extensions: Record<string, string[]>;
};

const splitList = (value: string) =>
  value.split(',').map((v) => v.trim()).filter(Boolean);

export function parseAgentsTxt(content: string): ParsedAgentsTxt {
  const result: ParsedAgentsTxt = { mcp: [], skills: [], a2a: [], extensions: {} };

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
        result.payments.protocols = splitList(value);
        break;

      case 'Authorization':
        result.authorization ??= { protocols: [] };
        result.authorization.protocols = splitList(value);
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

      case 'A2A':
        result.a2a.push(value);
        break;

      default:
        // Forward-compatible: capture unknown directives so they can be
        // surfaced by audit tools without failing parse. Known-but-misplaced
        // body directives (e.g. `Identity:` outside an auth block) fall
        // through here too.
        if (key in BLOCK_OPENERS || BLOCK_BODY_DIRECTIVES.has(key)) break;
        (result.extensions[key] ??= []).push(value);
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
