---
id: mcp-secret-entropy
severity: high
confidence: medium
since: 0.1.0
---

# mcp-secret-entropy

A config value has the shape of a random credential but no known provider
prefix.

## Example

```json
{ "mcpServers": { "s": { "env": { "SERVICE_VALUE": "Zx9Qm2Lp7Rt4Vb8Nc3…" } } } }
```

## Fix

If the value is a credential, move it out of the config and rotate it. If it is
not, ignore the finding once or disable the rule with `--allow`.

Medium confidence: this rule is heuristic and does not run unless
`--include-medium` is passed.
