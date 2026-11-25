---
id: mcp-scope-wildcard
severity: high
confidence: high
since: 0.1.0
---

# mcp-scope-wildcard

A declared scope is '*', which usually grants every permission the provider offers.

## Example

```
vulnerable: GITHUB_SCOPES=repo,*.
```

```json
{"mcpServers":{"s":{"command":"npx","args":["-y","some-server"],"env":{"GITHUB_SCOPES":"repo,*"}}}}
```

## Fix

Replace '*' with the narrowest scopes the task needs.
