---
id: mcp-tool-invisible-text
severity: high
confidence: high
since: 0.1.0
---

# mcp-tool-invisible-text

Zero-width, bidi-control or tag characters appear in a tool description. They render as nothing but reach the model.

## Example

```
vulnerable: description contains U+200B.
```

```json
{"mcpServers":{"s":{"command":"npx","args":["-y","some-server"]}}}
```

## Fix

Reject the server or strip the characters; inspect the raw bytes before trusting the description.
