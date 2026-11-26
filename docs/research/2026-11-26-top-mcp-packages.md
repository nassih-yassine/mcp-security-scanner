# Top MCP server packages, scanned with `mcpscan 0.1.0`

**Date:** 2026-11-26
**Tool:** the released `mcpscan 0.1.0` binary, `--online` (OSV), default rules.
**Sample:** 17 published npm MCP server packages, pinned to their current
`latest` (versions resolved from the npm registry that day).

## Result

| Metric | Value |
|---|---|
| Packages scanned | 17 |
| Findings | **0** |
| Servers with a known OSV advisory at `latest` | 0 |
| Control: `lodash@4.17.20` through the same path | 4 advisories, 1 HIGH finding |

The control matters: the OSV path is demonstrably working, so "0 advisories" is
a result, not a broken lookup.

Config shape used, one server per package:

```json
{ "mcpServers": { "github": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@2025.4.8"] } } }
```

## What this says

**Good news for the ecosystem.** The most-installed MCP servers are not shipping
known-vulnerable versions, and none of these 17 leaked a literal credential in
their published install instructions.

**Bad news for the premise.** `AGENT.md` leans on "everyone is installing random
MCP servers with read-write access and no audit". This sample does not support
that. What it supports is narrower:

1. Install instructions are still overwhelmingly unpinned (`npx -y pkg` with no
   version) — 12 of 28 popular repos in the earlier screening. This sample pins
   versions to test advisories, so it cannot measure that.
2. Configs are opaque: the same `npx -y` line says nothing about what the server
   can reach. A security tool has nothing to check unless it knows the package.

**The scanner agreed with "clean" on all 17.** That is a false-negative risk, not
a bug: the common config shape carries no signals the current rules act on.

- `net_egress` is only set by a `url`, an http(s) value, or a `--port` flag. An
  `npx` server that calls the GitHub API has none of those in its config.
- `mcp-scope-*` needs a `<PROVIDER>_SCOPES` env var, which no real config here
  has.
- `mcp-exfil-path` needs egress plus a write leg, so with egress false it can
  never fire.
- `mcp-tool-*` needs tool schemas, which no config carries.

So four of the five rule families are inert on the most common install pattern.
That is the real finding of this exercise.

## Follow-up implemented (0.1.0, same day)

Both recommendations below are in the tree and verified against a mixed config:

- `crates/mcpscan-core/data/rules/remote-packages.json` maps package names to
  egress / fs-read / db-read, so `npx` installs now carry capability signals.
  `@modelcontextprotocol/server-github` gains egress; `server-memory` does not.
- "Egress plus literal secret" left the HIGH `mcp-exfil-path` composite and is
  now the MEDIUM `mcp-secret-to-network`.

Re-running the same 17-package config with the new data still reports 0
findings for those packages — the data changes what the rules *can* see, not
what these particular configs do wrong. On a mixed config the difference is
visible:

| Server | Before | After |
|---|---|---|
| `server-github` + literal token | literal only | literal (CRITICAL) + `mcp-secret-to-network` (MEDIUM, opt-in) |
| `server-postgres --read-write` | nothing | `mcp-exfil-path` (HIGH) |
| `server-memory` | nothing | nothing |

## Recommendation

Two changes, both small and both needing a product call:

1. **Known-remote package data.** A curated list (`data/rules/remote-packages.json`)
   mapping package names to the provider they talk to (github, slack, notion,
   supabase, postgres, filesystem, browser…). `resolve` sets `net_egress` and
   `provider` from it. Without this, capability rules cannot see real configs.
2. **Demote "egress + literal secret".** Today it is one leg of the HIGH
   `mcp-exfil-path`. A token handed to a networked server is normal, not an
   exfiltration path. Make it a MEDIUM finding (`mcp-secret-to-network`) and keep
   `mcp-exfil-path` for egress + local read + write, so it stays rare and true.

Do not publish this sample as "MCP is insecure". Publish it as: "17 of the most
installed MCP servers are clean at latest; the install pattern still tells you
nothing about what they can do." That is defensible and it argues for the tool
without overclaiming.

## Limits

- Pin-to-latest defeats the unpinned-install signal by construction.
- npm only; PyPI and container MCP servers are not represented.
- "0 advisories" is a snapshot. OSV entries appear after disclosure, often
  months later.
- Package selection is judgement, not a ranking: the 17 were chosen by
  recognition, then confirmed to exist. A real study should rank by downloads.
