# mcpscan

CI check that scans your MCP servers, agent configs and tool definitions for
leaked credentials, over-broad permissions and prompt-injection surfaces before
an agent gets them.

```console
$ mcpscan scan .
MCP security scan: 1 server(s), 2 finding(s)

fixtures/demo/.mcp.json
  CRITICAL mcp-secret-literal  literal credential (github-pat) in env-value
    at /mcpServers/github/env/GITHUB_TOKEN:3:15
    evidence: ghp_…uvwx (38)
    fix: Move the credential to an environment variable and rotate it.
  HIGH     mcp-exfil-path  server combines net_egress, fs_read, shell_exec
    at /mcpServers/github:3:15
    fix: Split read and write into different servers, or remove network egress from the one that writes.
```

## Who it is for

Platform and AI-infra engineers who just wired Claude Code, Cursor, Codex or a
custom agent into production systems, and security engineers who get asked "is
this MCP server safe?" and have no tooling for it.

There is no `npm audit` for agent tool permissions. This is that.

## What it checks

| Family | Question it answers |
|---|---|
| `mcp-secret-*` | Is a live credential sitting in a config file? |
| `mcp-scope-*` | Did the server ask for more permission than the task needs? |
| `mcp-tool-*` | Does a tool description try to steer the model, or hide text? |
| `mcp-osv-*` | Is the pinned server package a known-vulnerable version? |
| `mcp-exfil-*` | Can this server reach out, read secrets and write? |

<!-- BEGIN RULES -->
| Rule | Severity | Confidence |
|---|---|---|
| `mcp-exfil-path` | high | high |
| `mcp-osv-vulnerable` | high | high |
| `mcp-scope-admin` | high | high |
| `mcp-scope-wildcard` | high | high |
| `mcp-scope-write-when-read` | medium | high |
| `mcp-secret-entropy` | high | medium |
| `mcp-secret-literal` | critical | high |
| `mcp-tool-injection` | high | high |
| `mcp-tool-invisible-text` | high | high |
| `mcp-tool-schema-mismatch` | medium | medium |
| `mcp-tool-shadowing` | medium | medium |
<!-- END RULES -->


Every rule has a page under [`docs/rules/`](docs/rules/) with an example and a fix.

## Install

```bash
cargo install mcpscan --locked          # from source
cargo binstall mcpscan                  # prebuilt binary
brew install nassih-yassine/tap/mcpscan # Homebrew (once the tap is published)
npx mcpscan                             # Node users
```

## Quickstart

```bash
mcpscan scan                  # current directory, human output
mcpscan scan . --format sarif  # for GitHub code scanning
mcpscan scan . --user          # also per-user Claude/Cursor/Codex configs
mcpscan scan . --online        # also check pinned packages against OSV
mcpscan rules                  # what this build can report
```

Scan a repo in CI:

```yaml
- run: cargo install mcpscan --locked
- run: mcpscan scan . --format sarif --output mcpscan.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: mcpscan.sarif
```

## Output formats

| Format | Use |
|---|---|
| `human` (default) | terminal reading |
| `json` | machine-readable, `schema_version: 1`, no timestamps |
| `sarif` | SARIF 2.1.0, validated against the official schema, GitHub-native severities |
| `markdown` | `security-score.md`: letter grade, score, findings table, fix list |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | clean, or findings below `--fail-on` |
| `2` | findings at or above `--fail-on` (default: `critical`) |
| `3` | the scan could not complete |

`3` is not a pass. A config that exists but cannot be parsed, a missing path, or
a failed advisory check with `--online` all exit `3`, so CI never reports "clean"
for a scan that did not happen.

## Allowlists

A finding you have reviewed can be downgraded — never deleted — with a reason:

```bash
mcpscan scan . --allow "mcp-secret-entropy:fixtures/=test fixture"
```

A missing reason is a usage error (exit `3`). The finding stays visible, marked
`LOW` with the reason attached.

## Privacy and safety

- **No network by default.** Only `--online` reaches out, and only to `osv.dev`.
- **No telemetry.**
- **Scanned servers are never executed.** Config commands are read, never run.
- **Scanned URLs are never fetched.** A config pointing at
  `169.254.169.254` produces a finding, not a request.
- **Secrets are never printed.** Findings carry a redacted shape (first four,
  last four, length). A test fails if a fixture secret reaches any output.

## Scope limits

`mcpscan` reads configs and locally supplied tool schemas. It does not speak MCP
to a server, does not introspect a running server, and does not replace a
runtime agent firewall. A clean scan means the configuration has no known
problem — not that the server is safe to run.

## Documentation

- [`SPEC.md`](SPEC.md) — design decisions and scope
- [`docs/rules/`](docs/rules/) — one page per rule
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — adding a rule, reporting a false positive

## Security

Report vulnerabilities in the scanner privately; see [`SECURITY.md`](SECURITY.md).
Findings `mcpscan` reports about third-party servers belong to those servers'
maintainers.

## License

MIT
