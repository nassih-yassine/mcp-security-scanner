# Phase 0 — MCP server screening

**Date:** 2026-11-26
**Method:** mechanical screening, not a full manual audit.
**Scope:** 28 popular public MCP server repos (top by GitHub stars, name contains
`mcp`, plus `modelcontextprotocol/servers`), README-level.

## Result

**12 of 28 (43%) document an unpinned `npx` install for the MCP server itself** —
`npx -y @scope/server` with no version, meaning every launch executes whatever
the registry serves today.

Distribution of the flagged rows:

| Repo | unpinned `npx` lines | pinned | non-loopback `http` URL |
|---|---|---|---|
| apify/apify-mcp-server | 8 | 0 | 0 |
| microsoft/playwright-mcp | 8 | 0 | 0 |
| mobile-next/mobile-mcp | 11 | 0 | 0 |
| firecrawl/firecrawl-mcp-server | 8 | 0 | 0 |
| makenotion/notion-mcp-server | 11 | 0 | 0 |
| executeautomation/mcp-playwright | 4 | 0 | 0 |
| Pimzino/spec-workflow-mcp | 4 | 0 | 0 |
| mcp-use/mcp-use | 5 | 0 | 0 |
| BrowserMCP/mcp | 2 | 0 | 0 |
| getsentry/MobileBuildMCP | 2 | 0 | 0 |
| AgentDeskAI/browser-tools-mcp | 1 | 0 | 0 |
| idosal/git-mcp | 1 | 0 | 0 |

The other 16 repos show pinned installs, a container-only install, or no `npx`
install line in the README.

## What this screening did and did not check

Checked, mechanically:

- unpinned `npx` launch of the server package
- `"url": "http://…"` outside loopback
- provider-shaped literal secrets in the README (`sk-`, `ghp_`, `xoxb-`, `AKIA`)

Not checked (needs a human reading each config, which is the 2-day audit in
`SPEC.md` §6):

- scope creep (wildcard/admin scopes in provider configs)
- tool poisoning (instruction phrases, hidden Unicode, schema/description mismatch)
- known-vulnerable pinned versions (OSV)
- exfil capability combinations

Reproduce with the grep used:

```bash
gh api repos/<owner>/<repo>/readme --jq .content | base64 -d \
  | grep -cE 'npx[[:space:]]+(-y[[:space:]]+)?[^"` ]*mcp[^"` ]*'
```

## Verdict

**Go.** 12/28 clears the plan's 8/30 threshold. The signal found here is also the
dullest one in the product; the three categories that are not mechanical are the
ones a launch post can claim as new information.

Caveat for whoever writes that post: this screening supports "unpinned installs
are the norm", not "37 of the top 100 had issues". The stronger claim needs the
manual pass. Do not publish this table as a security finding about the named
projects — unpinned README install lines are a documentation pattern, not a
vulnerability in the server.
