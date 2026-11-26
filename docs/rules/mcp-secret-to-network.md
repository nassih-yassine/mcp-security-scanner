---
id: mcp-secret-to-network
severity: medium
confidence: medium
since: 0.1.0
---

# mcp-secret-to-network

A server that can reach the network is configured with a literal credential.
This is the normal way people wire API tokens, so it is a hygiene finding, not a
verdict: the token's blast radius is whatever the provider granted it.

## Example

```json
{
  "mcpServers": {
    "gh": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github@2025.4.8"],
      "env": { "GITHUB_TOKEN": "ghp_1234…" }
    }
  }
}
```

## Fix

Reference the credential from the environment (`"${GITHUB_TOKEN}"`) and scope
the token to the least access the task needs. Pair it with rotation if the value
was ever committed.

Medium confidence: runs only with `--include-medium`.
