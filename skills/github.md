---
name: github
description: >
  Operations for repository management, issues, pull requests, and file content on GitHub.
  Use this skill for any tasks involving interacting with GitHub repositories, searching code,
  managing PRs and issues, or reading/writing files in a remote repo.
---

# GitHub Skill — Repository Management and Content Operations

> **Agent directive**: Always ensure a GITHUB_PERSONAL_ACCESS_TOKEN is configured.
> Prefer specific resource IDs over fuzzy names where possible.

---

## §1 — Core Capabilities

- **Repository Management**: Create, list, search, and manage forks.
- **Issue Tracking**: Create, list, update issues and comments.
- **Pull Requests**: Manage PR lifecycle including creation, merging, and reviews.
- **File & Git Operations**: Read/write file contents, manage branches, and view commits.

---

## §2 — Usage Guidelines

1. **Context First**: Always list repositories or search to confirm existence before performing write operations.
2. **Atomic Commits**: Group related file changes into a single PR or commit where possible.
3. **Safety**: Never expose tokens in logs or code.

---

## §3 — Execution Patterns

- **Search**: Use `search_repositories` or `search_code` to find relevant targets.
- **Read**: Use `get_file_contents` to understand current state.
- **Write**: Use `create_or_update_file_contents` or `push_files`.
- **Review**: Use `get_pull_request` and `create_pull_request_review`.
