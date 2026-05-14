---
title: agents.json Per-Protocol Shape Registry
shortTitle: JSON shapes
order: 2
specSection: "§17.3"
lastUpdated: 2026-05-14
---

Governs the per-protocol object shapes inside `agents.json` `payments.*` and the top-level array shapes for `mcp[]`, `skills[]`, `a2a[]`, `ucp[]`. The `version`, `standard`, `site`, and `authorization` blocks are fixed by §5.2 of the spec and are not separately registered.

Registration policy is defined in §17.1 of the spec.

| Key | Parent | Required fields | Optional fields | Spec § | Status |
|---|---|---|---|---|---|
| `payments.x402` | `payments` | (none) | `chains[]`, `description` | §5.3 | registered |
| `payments.mpp` | `payments` | (none) | `methods[]`, `description` | §5.3 | registered |
| `payments.ap2` | `payments` | (none) | `presentations[]`, `spec`, `description` | §5.3, §8.3 | registered |
| `mcp[]` | top-level | `url`, `type` | `description` | §5.3 | registered |
| `skills[]` | top-level | `url` | `description` | §5.3 | registered |
| `a2a[]` | top-level | `url` | `description` | §5.3, §9 | registered |
| `ucp[]` | top-level | `url` | `description` | §5.3, §10 | registered |

Per-protocol shapes are emitted only when the corresponding identifier is present in the matching `agents.txt` block. Absence of a `payments.<id>` object means the site does not accept that protocol, regardless of whether the identifier is registered.
