import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

type SkillEntry = { url: string; description?: string };

async function fetchSkillIndex(siteOrigin: string): Promise<SkillEntry[]> {
  const url = `${siteOrigin.replace(/\/$/, '')}/agents.json`;
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) return [];
  const json = (await res.json()) as { skills?: SkillEntry[] };
  return json.skills ?? [];
}

/**
 * Derive the skill identifier from its URL.
 *
 * Canonical agentskills.io layout is `<base>/<skill-name>/SKILL.md`, so we
 * take the path segment immediately before the trailing `SKILL.md`.
 *
 * Fallback for older single-file packages (`<base>/<skill-name>.md`): strip
 * the trailing `.md` from the filename.
 */
function skillNameFromUrl(url: string): string {
  try {
    const segments = new URL(url).pathname.split('/').filter(Boolean);
    if (segments.length === 0) return '';
    const last = segments[segments.length - 1] ?? '';
    if (last.toUpperCase() === 'SKILL.MD' && segments.length >= 2) {
      return segments[segments.length - 2] ?? '';
    }
    return last.replace(/\.md$/i, '');
  } catch {
    return '';
  }
}

export function registerGetSkill(server: McpServer, siteOrigin: string) {
  server.registerTool(
    'get_skill',
    {
      description:
        'Fetch a skill package by name. Returns the full SKILL.md markdown content. ' +
        'Skill names come from the agents.json skills list; use "list" to see available skills. ' +
        'Companion files (REFERENCE.md, scripts) inside the same skill folder are not fetched ' +
        'here. The agent loads them on demand via the links inside SKILL.md.',
      inputSchema: {
        name: z
          .string()
          .describe('Skill name (e.g. "adopt-agents-txt") or "list" to see all available skills'),
      },
    },
    async ({ name }: { name: string }) => {
      const skills = await fetchSkillIndex(siteOrigin);

      if (name === 'list') {
        if (skills.length === 0) {
          return { content: [{ type: 'text' as const, text: 'No skills found in agents.json' }] };
        }
        const list = skills
          .map((s) => `- ${skillNameFromUrl(s.url)}${s.description ? `: ${s.description}` : ''}`)
          .join('\n');
        return { content: [{ type: 'text' as const, text: `Available skills:\n\n${list}` }] };
      }

      const entry = skills.find((s) => skillNameFromUrl(s.url) === name);

      if (!entry) {
        const available = skills.map((s) => skillNameFromUrl(s.url)).filter(Boolean).join(', ');
        return {
          content: [{ type: 'text' as const, text: `Skill "${name}" not found. Available: ${available || 'none'}` }],
          isError: true,
        };
      }

      // Use the path from the canonical URL but fetch against `siteOrigin`.
      // agents.json advertises absolute URLs against the production origin;
      // when this MCP server is wired up to talk to a non-production deployment
      // (preview, staging, local wrangler dev) the fetch must follow.
      const skillPath = new URL(entry.url).pathname;
      const res = await fetch(`${siteOrigin.replace(/\/$/, '')}${skillPath}`, { signal: AbortSignal.timeout(8000) });
      if (!res.ok) {
        return {
          content: [{ type: 'text' as const, text: `Failed to fetch skill "${name}": HTTP ${res.status}` }],
          isError: true,
        };
      }

      return { content: [{ type: 'text' as const, text: await res.text() }] };
    },
  );
}
