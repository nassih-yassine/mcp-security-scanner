---
id: mcp-exfil-path
severity: high
confidence: high
since: 0.1.0
---

# mcp-exfil-path

A server can reach the network, read sensitive data and write or execute. That is an exfiltration path.

## Example

```
vulnerable: filesystem server with --allow-write.
```

```json
{"mcpServers":{"s":{"command":"npx","args":["-y","server-filesystem","/data","--allow-write"]}}}
```

## Fix

Split read and write into different servers, or drop egress from the one that can write.
