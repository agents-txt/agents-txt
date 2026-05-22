---
title: agents.txt Directives Registry
shortTitle: Directives
order: 1
specSection: "§17.2"
lastUpdated: 2026-05-19
---

Governs the directive names that may appear in `agents.txt`. Parsers ignore unknown directives per §3.2 of the spec; this registry exists so directive authors have a coordination surface, not so parsers gain new failure modes.

Registration policy is defined in §17.1 of the spec. Provisional identifiers use the `x-` prefix (§3.1) and are not added to the registry until promoted.

| Directive | Block | Role | Value type | Repeatable | Spec § | Status |
|---|---|---|---|---|---|---|
| `Protocols:` | Payments | Block opener | Comma-separated identifier list | No | §3.1, §8 | registered |
| `Payments:` | Payments | Modifier | Enum (`required`) | No | §3.1, §8.4 | registered |
| `Authorization:` | Authorization | Block opener | Comma-separated identifier list | No | §3.1, §11 | registered |
| `Identity:` | Authorization | Modifier | Enum (`required`) | No | §3.1, §11.4 | registered |
| `MCP:` | MCP | Block opener | HTTPS URL | Yes | §3.1, §6 | registered |
| `Skills:` | Skills | Block opener | HTTPS URL | Yes | §3.1, §7 | registered |
| `A2A:` | A2A | Block opener | HTTPS URL | Yes | §3.1, §9 | registered |
| `UCP:` | UCP | Block opener | HTTPS URL | Yes | §3.1, §10 | registered |
| `WebMCP:` | WebMCP | Block opener | HTTPS URL | Yes | §3.1, §6.6 | registered |
