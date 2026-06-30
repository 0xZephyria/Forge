---
name: memory
description: >
  Persistent storage and retrieval of long-term context, facts, and user preferences.
  Use this skill to remember information across conversations or to maintain a coherent
  understanding of complex projects.
---

# Memory Skill — Knowledge Graph and Persistent Context

> **Agent directive**: Use memory to store facts that are likely to be useful in future turns.
> Avoid bloating memory with trivial details.

---

## §1 — Knowledge Structure

The memory uses a knowledge graph approach:
- **Entities**: Represent nouns (e.g., people, projects, technologies).
- **Relations**: Represent predicates (e.g., "works_on", "uses", "depends_on").
- **Observations**: Represent specific facts or snippets of information.

---

## §2 — Usage Guidelines

1. **Active Storage**: When a user provides a fact that seems important for the long term, use `create_entities` and `create_relations`.
2. **Retrieval**: Use `search_nodes` or `read_graph` at the start of complex tasks to recall relevant context.
3. **maintenance**: Use `delete_entities` or `delete_observations` to prune stale or incorrect information.

---

## §3 — Common Patterns

- **Project Kickoff**: Store project name, goals, and key files.
- **User Preferences**: Store preferred coding styles or tools.
- **Bug tracking**: Store symptoms and investigation results for long-running issues.
