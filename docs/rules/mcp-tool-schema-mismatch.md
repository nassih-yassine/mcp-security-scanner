---
id: mcp-tool-schema-mismatch
severity: medium
confidence: medium
since: 0.1.0
---

# mcp-tool-schema-mismatch

The description says read-only, lookup or list, while the input schema accepts destructive verbs or fields.

## Example

```
vulnerable: description 'read-only lookup' with a required 'drop' field.
```

```json
{"mcpServers":{"s":{"command":"npx","args":["-y","some-server"]}}}
```

## Fix

Treat the tool as write-capable, or fix the description and schema so they agree.
