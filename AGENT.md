# MCP / Agent-Tool Security Scanner

**One-liner:** CI check that scans your MCP servers, agent configs and tool
definitions for leaked credentials, over-broad permissions and prompt-injection
surfaces before an agent gets them.

## Target audience

- **Primary:** platform/AI-infra engineers at 20-500 person startups who just
  wired Claude Code, Cursor, or a custom agent into production systems.
- **Secondary:** security engineers at those companies who get asked "is this
  MCP server safe?" and have no tooling.
- **Tertiary:** agencies shipping agent integrations to clients.
- **Where they are:** Hacker News (MCP threads hit 600-850 points repeatedly),
  r/ExperiencedDevs, r/cybersecurity, MCP Discord/Slack communities, GitHub
  `awesome-mcp-servers`.

## The pain

- HN: *"Supabase MCP can leak your entire SQL database"* — 848 points. A
  misconfigured MCP server handed an agent full table access.
- HN: *"The 'S' in MCP Stands for Security"* — 730 points.
- HN: *"A critical look at MCP"* — 623 points. *"Everything wrong with MCP"* —
  516 points.
- HN: *"MCP server that reduces Claude Code context consumption by 98%"* — 570
  points. People are installing random MCP servers by the dozen.

The pattern: everyone is adding MCP servers pulled from GitHub, with
long-lived API keys in config files, `read-write` DB access, and tool
descriptions that an attacker can poison. There is no `npm audit` for this.

## What it does

Scans a repo or a live machine and reports, per finding:

1. **Credential exposure** — API keys/tokens in `mcp.json`, `.cursor/mcp.json`,
   `claude_desktop_config.json`, `.env`, shell history; entropy + provider
   prefix detection (sk-, ghp_, xoxb-, AKIA...).
2. **Scope creep** — MCP server requests `*` or `admin` scopes where read-only
   would do (Stripe, GitHub, Supabase, Google Workspace).
3. **Tool poisoning** — tool descriptions containing instructions aimed at the
   model ("ignore previous instructions", "exfiltrate", hidden Unicode, base64
   blobs), plus description/schema mismatch.
4. **Known-vulnerable servers** — pinned version matches an advisory in OSV.
5. **Data-exfil paths** — a server with both network egress and read access to
   sensitive paths/DBs.

Output: SARIF + a PR comment + a `security-score.md` badge. CI fails on
`critical`.

## Public APIs / data sources

| Purpose | Source |
|---|---|
| Advisory lookup | `https://api.osv.dev/v1/query` (POST, free, no key) |
| Package/version metadata for MCP servers | `https://registry.npmjs.org/{pkg}`, `https://pypi.org/pypi/{pkg}/json` |
| Server inventory | GitHub code search API (authenticated), `https://api.github.com/search/code` |
| Registry of known servers | `awesome-mcp-servers` lists, `modelcontextprotocol/servers` repo |
| Secret pattern sets | gitleaks rules (MIT), trufflehog detectors (AGPL — check license before reuse) |
| SARIF schema | `https://json.schemastore.org/sarif-2.1.0.json` |

All free. The IP is your ruleset and your scoring, not the data.

## MVP (3 weeks)

1. Week 1: static scanner CLI. Parse the 4 common MCP config shapes, run secret
   detection, emit SARIF. Open-source the CLI — distribution engine.
2. Week 2: OSV lookups + permission lint (map known providers' scope models).
3. Week 3: GitHub App that comments on PRs, hosted dashboard, paid tier.

## Pricing

- **CLI: free and open source.** Non-negotiable — this is the funnel.
- **Team — $49/mo:** hosted dashboard, private repos, 10 seats, weekly scan.
- **Business — $199/mo:** unlimited repos, policy enforcement (block PRs),
  audit log export, SSO.
- **Enterprise:** $1-3k/mo, annual, for on-prem scanning of agent fleets.

Why they pay: passing a security review or a SOC2 auditor's question about
"agent access" costs more than a year of Business.

## Distribution: first 10 customers

1. Open-source the CLI, post as "Show HN: I scanned the top 100 MCP servers —
   37 had issues". Publish the aggregate findings (responsibly, no exploits).
2. Comment in the recurring HN MCP threads with the actual data.
3. Ship a GitHub Action so it appears in marketplace search.
4. DM the maintainers of popular MCP servers with a free scan report.

## Why it's defensible

- Security tooling is trust-based; being the first credible name in a category
  is most of the moat.
- Rulesets improve with real-world findings; that's a data flywheel.
- Category is new — no incumbent has MCP support beyond generic SAST.

## Risks

- **False positives destroy trust faster here than anywhere.** Ship
  high-confidence rules only; every rule needs a documented example.
- Security buying is slow and needs a human. Offset with a self-serve tier.
- MCP may be replaced by another standard in 18 months. Mitigate: the core is
  "agent tool permissions", not MCP specifically.
- Don't publish exploit details for named companies — legal and reputational.

## Kill criteria

- 100 CLI installs and zero requests for the hosted version after 60 days →
  the funnel doesn't work, stop.
- More than 30% of findings marked "won't fix / false positive" → rules are bad.

## Cheapest validation (before writing code)

Scan 30 popular MCP servers by hand with grep + a checklist. Publish the
aggregate count in a blog post. If it lands, you have a product and a mailing
list. Cost: 2 days.

## Open questions for you

- Do you want to run the hosted scanner (you hold customers' repo access), or
  stay local-only CLI + paid ruleset? Hosted pays more, costs trust.
- Will you write rules yourself or curate community rules with a review gate?
