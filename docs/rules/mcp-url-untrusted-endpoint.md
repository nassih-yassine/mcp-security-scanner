---
id: mcp-url-untrusted-endpoint
severity: high
confidence: high
since: 0.1.0
---

# mcp-url-untrusted-endpoint

A remote server endpoint is plaintext, or points at an address an agent should
never reach: a cloud metadata endpoint, a private network, or a link-local host.

## Example

```json
{ "mcpServers": { "s": { "url": "http://169.254.169.254/latest/meta-data" } } }
```

## Fix

Use `https` on a public host. A local server belongs on loopback
(`http://127.0.0.1:3000/mcp`), which this rule allows.
