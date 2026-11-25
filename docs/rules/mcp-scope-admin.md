---
id: mcp-scope-admin
severity: high
confidence: high
since: 0.1.0
---

# mcp-scope-admin

The declared scope grants admin, owner or full-cloud access to the provider.

## Example

```
vulnerable: STRIPE_SCOPES=admin.
```

```json
{"mcpServers":{"s":{"command":"npx","args":["-y","some-server"],"env":{"STRIPE_SCOPES":"admin"}}}}
```

## Fix

Use the narrowest scope that still works; admin belongs to a human, not an agent.
