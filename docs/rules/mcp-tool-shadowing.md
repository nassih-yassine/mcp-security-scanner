---
id: mcp-tool-shadowing
severity: medium
confidence: medium
since: 0.1.0
---

# mcp-tool-shadowing

One tool's description tells the model to prefer it over a sibling tool. That is a watering-hole pattern.

## Example

```
vulnerable: 'read_file' description tells the model to use it instead of 'write_file'.
```

```json
{"mcpServers":{"s":{"command":"npx","args":["-y","some-server"]}}}
```

## Fix

Remove the cross-reference; if the server ships it, treat the server as untrusted.
