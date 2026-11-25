# mcpscan

CI check that scans your MCP servers, agent configs and tool definitions for
leaked credentials, over-broad permissions and prompt-injection surfaces before
an agent gets them.

> Early development. The working scanner lands in this repository; see
> `SPEC.md` for the design and `docs/superpowers/plans/` for the build order.

## What it will do

1. Credential exposure in `mcp.json`, `.cursor/mcp.json`,
   `claude_desktop_config.json`, `.env` and shell history.
2. Scope creep: wildcard or admin scopes where read-only would do.
3. Tool poisoning: instruction-override text, hidden Unicode, description/schema
   mismatch, tool shadowing.
4. Known-vulnerable server packages, via OSV.
5. Exfiltration paths: egress plus read access plus write capability.

Output: human, JSON, SARIF and Markdown. Exit `0` clean, `2` findings, `3` could
not complete.

## Safety statement

`mcpscan` never executes a scanned server and never fetches a scanned URL. It is
offline by default and has no telemetry.

## License

MIT
