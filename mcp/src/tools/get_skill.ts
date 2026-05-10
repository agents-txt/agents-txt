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

export function registerGetSkill(server: McpServer, siteOrigin: string) {
  server.registerTool(
    'get_skill',
    {
      description:
        'Fetch a skill package by name. Returns the full SKILL.md markdown content. ' +
        'Skill names come from the agents.json skills list — use "list" to see available skills.',
      inputSchema: {
        name: z
          .string()
          .describe('Skill name (e.g. "agents-txt-setup") or "list" to see all available skills'),
      },
    },
    async ({ name }: { name: string }) => {
      const skills = await fetchSkillIndex(siteOrigin);

      if (name === 'list') {
        if (skills.length === 0) {
          return { content: [{ type: 'text' as const, text: 'No skills found in agents.json' }] };
        }
        const list = skills
          .map((s) => `- ${s.url.split('/').pop()?.replace('.md', '')}${s.description ? `: ${s.description}` : ''}`)
          .join('\n');
        return { content: [{ type: 'text' as const, text: `Available skills:\n\n${list}` }] };
      }

      const entry = skills.find((s) => {
        const filename = s.url.split('/').pop()?.replace('.md', '');
        return filename === name;
      });

      if (!entry) {
        const available = skills.map((s) => s.url.split('/').pop()?.replace('.md', '')).join(', ');
        return {
          content: [{ type: 'text' as const, text: `Skill "${name}" not found. Available: ${available || 'none'}` }],
          isError: true,
        };
      }

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
