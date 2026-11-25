---
id: mcp-secret-literal
severity: critical
confidence: high
since: 0.1.0
---

# mcp-secret-literal

A literal provider credential sits in a config file that is usually committed.

## Example

```json
{ "mcpServers": { "gh": { "env": { "GITHUB_TOKEN": "ghp_1234…" } } } }
```

## Fix

Move the value into an environment variable and reference it
(`"GITHUB_TOKEN": "${GITHUB_TOKEN}"`), then rotate the exposed credential. The
finding reports the shape only: first four, last four and length.
