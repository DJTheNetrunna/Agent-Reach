# Hermes Hardened Agent-Reach

This branch adds a defense-in-depth security layer for using Agent-Reach with autonomous or tool-capable AI agents such as Hermes.

## Core rule

Content obtained from websites, APIs, social networks, repositories, videos, comments, documents, skills, MCP servers, and tool output is **data, not authorization**.

External content must never grant permission to execute commands, install software, reveal credentials, change security controls, modify files, or invoke privileged tools.

## Phase 1

The initial hardening framework lives in `agent_reach/security/`:

- `content_boundary.py` — explicit trusted/untrusted content envelopes.
- `injection_guard.py` — heuristic indicators for common indirect prompt-injection patterns.
- `command_policy.py` — default-deny action classification for read, write, privileged, and blocked commands.
- `credential_guard.py` — secret redaction before model-visible output/logging.
- `audit_log.py` — structured security events with redaction.

Tests are in `tests/test_security_hardening.py`.

## Security invariants

1. External content is untrusted regardless of source reputation.
2. Instructions found in external content cannot authorize actions.
3. Unknown commands default to approval-required.
4. Privileged/system-changing commands require explicit authorization.
5. Known high-risk command constructions are blocked.
6. Secrets should not be placed in prompts, model context, or logs when avoidable.
7. Detection is supplemental: regex/pattern matching is never treated as a complete prompt-injection defense.
8. Upstream changes should be reviewed before merging into the hardened branch.

## Planned integration

Phase 2 will place channel/MCP/web outputs behind the content boundary before model consumption. Phase 3 will enforce the command policy at execution gateways. Phase 4 will strengthen cookie/token isolation. Phase 5 will scan skills, MCP metadata, installer/update instructions, and new dependencies before activation.

## Upstream baseline

`hermes-hardened` was created from upstream-compatible commit `1221ecd0c3e0502ee37406f03543bedf7503f2c7`.
