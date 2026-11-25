---
id: mcp-scope-write-when-read
severity: medium
confidence: high
since: 0.1.0
---

# mcp-scope-write-when-read

The requested scope grants write access while the provider offers an equivalent read-only scope.

## Example

```
vulnerable: GITHUB_SCOPES=repo.
```

```json
{"mcpServers":{"s":{"command":"npx","args":["-y","some-server"],"env":{"GITHUB_SCOPES":"repo"}}}}
```

## Fix

Use the read-only sibling scope (for example public_repo instead of repo).
