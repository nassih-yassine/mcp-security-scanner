# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-26

First release. The CLI is the product; the hosted layer comes later.

### Added

- `mcpscan scan` over the MCP config shapes: Claude Code and Claude Desktop,
  Cursor, VS Code, Windsurf, Zed, and Codex TOML.
- Eleven rules across five families:
  - `mcp-secret-literal`, `mcp-secret-entropy` — credentials in `env`, headers,
    args and URL query strings, with placeholder suppression.
  - `mcp-scope-wildcard`, `mcp-scope-write-when-read`, `mcp-scope-admin` —
    provider scope maps for GitHub, Stripe, Supabase, Google, Slack, Notion and
    Linear.
  - `mcp-tool-injection`, `mcp-tool-invisible-text`, `mcp-tool-schema-mismatch`,
    `mcp-tool-shadowing` — tool descriptions and schemas from `--tools-dir`.
  - `mcp-osv-vulnerable` — pinned server versions against OSV, behind `--online`.
  - `mcp-exfil-path` — egress plus read plus a write or a literal secret.
  - `mcp-url-untrusted-endpoint` — plaintext http, cloud metadata and private
    addresses.
- Four report formats: human, JSON (`schema_version: 1`), SARIF 2.1.0 validated
  against the official schema, and Markdown with a 0-100 score and letter grade.
- Exit codes `0` / `2` / `3`, where `3` means the scan could not complete and is
  never a pass.
- `--allow rule:path=reason` reviewed exceptions that downgrade, never delete.
- Offline by default. The only outbound host is `osv.dev`, only with `--online`.
- Secrets are redacted in every format, including the JSON `servers` block.

### Security

- Scanned servers are never executed and scanned URLs are never fetched.
- A test asserts that a fixture secret appears in no output of any format, and
  another asserts that a scanned command never runs.

### Known limits

- Discovery is per directory, not recursive; pass nested directories explicitly.
- Tool-description rules need schemas via `--tools-dir`.
- Scope rules need a `<PROVIDER>_SCOPES` env var or a recognisable package or URL.
