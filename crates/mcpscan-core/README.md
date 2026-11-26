# mcpscan-core

Scanner core for [`mcpscan`](https://github.com/nassih-yassine/mcp-security-scanner):
parses every MCP/agent config shape into a normalized `ServerSpec`, derives
capabilities, runs the rule registry, scores findings and renders reports.

Side-effect free by design: no argv, no process exit, no network without an
injected client. The unstable pre-1.0 API is for integrators; the CLI is the
supported surface.
