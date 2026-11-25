---
id: mcp-osv-vulnerable
severity: high
confidence: high
since: 0.1.0
---

# mcp-osv-vulnerable

The pinned server package version is listed in OSV for a known vulnerability.

## Example

```
vulnerable: an old pinned version; requires --online.
```

```json
{"mcpServers":{"s":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@0.1.0"]}}}
```

## Fix

Upgrade to a fixed version from the advisory, or unpin and take the current release.
