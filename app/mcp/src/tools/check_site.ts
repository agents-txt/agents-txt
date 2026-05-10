import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { parseAgentsTxt } from './parse_agents_txt.js';

type FetchResult = { found: true; content: string; status: number } | { found: false; status: number; error?: string };

async function safeFetch(url: string): Promise<FetchResult> {
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': 'agents-txt-validator/0.5 (https://agentstxt.dev/mcp)' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return { found: false, status: res.status };
    return { found: true, content: await res.text(), status: res.status };
  } catch (err) {
    return { found: false, status: 0, error: String(err) };
  }
}

function normalizeOrigin(input: string): string {
  const s = input.trim();
  const withProto = s.startsWith('http://') || s.startsWith('https://') ? s : `https://${s}`;
  const url = new URL(withProto);
  return url.origin;
}

export function registerCheckSite(server: McpServer) {
  server.registerTool(
    'audit_site',
    {
      description:
        'Fetch and audit a live site\'s agents.txt, agents.json, and robots.txt for agents.txt spec compliance. Parses all three files, validates agents.txt directives, and returns a structured compliance report.',
      inputSchema: {
        url: z.string().describe('Site origin or URL to audit (e.g. "https://example.com" or "example.com")'),
      },
    },
    async ({ url }: { url: string }) => {
      let origin: string;
      try {
        origin = normalizeOrigin(url);
      } catch {
        return {
          content: [{ type: 'text' as const, text: JSON.stringify({ error: `Invalid URL: "${url}"` }, null, 2) }],
          isError: true,
        };
      }

      const [txtResult, jsonResult, robotsResult] = await Promise.all([
        safeFetch(`${origin}/agents.txt`),
        safeFetch(`${origin}/agents.json`),
        safeFetch(`${origin}/robots.txt`),
      ]);

      const report: Record<string, unknown> = { site: origin };

      // agents.txt
      if (txtResult.found) {
        const parsed = parseAgentsTxt(txtResult.content);
        const errors: string[] = [];
        const warnings: string[] = [];

        if (parsed.payments?.enabled && parsed.payments.protocols.length === 0) {
          errors.push('Payments: enabled requires Protocols:');
        }
        for (const u of parsed.mcp) {
          try { new URL(u); } catch { errors.push(`Invalid MCP URL: "${u}"`); }
        }
        for (const u of parsed.skills) {
          try { new URL(u); } catch { errors.push(`Invalid Skills URL: "${u}"`); }
        }

        const hasJsonPointer = txtResult.content.includes('# JSON:');
        if (parsed.mcp.length > 0 || parsed.skills.length > 0) {
          if (!hasJsonPointer) warnings.push('agents.txt has MCP or Skills entries but no "# JSON:" comment pointing to agents.json');
        }

        report.agentsTxt = {
          found: true,
          status: txtResult.status,
          parsed,
          validation: { valid: errors.length === 0, errors, warnings },
        };
      } else {
        report.agentsTxt = { found: false, status: txtResult.status, error: (txtResult as { error?: string }).error };
      }

      // agents.json
      if (jsonResult.found) {
        let parsed: unknown = null;
        let parseError: string | null = null;
        try {
          parsed = JSON.parse(jsonResult.content);
        } catch {
          parseError = 'Invalid JSON';
        }
        report.agentsJson = { found: true, status: jsonResult.status, parsed, parseError };
      } else {
        report.agentsJson = { found: false, status: jsonResult.status };
      }

      // robots.txt — check for Agents-Txt: hint
      if (robotsResult.found) {
        const hasAgentsTxtHint = robotsResult.content.includes('Agents-Txt:');
        report.robotsTxt = { found: true, hasAgentsTxtHint };
      } else {
        report.robotsTxt = { found: false };
      }

      return { content: [{ type: 'text' as const, text: JSON.stringify(report, null, 2) }] };
    },
  );
}
