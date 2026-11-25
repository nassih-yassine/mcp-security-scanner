# AGENTS.md

Rust CLI: scans MCP servers, agent configs and tool definitions for leaked
credentials, scope creep, tool poisoning and known-vulnerable versions. SARIF
out, CI-ready.

## Current state

- `AGENT.md` (singular) = product brief: audience, pricing, kill criteria.
  **Do not rewrite it.**
- `SPEC.md` = engineering spec. **Source of truth for how.**
- Workspace is live: `mcpscan-core` (lib), `mcpscan` (bin), `xtask` (docs).
  10 rules, four report formats, offline by default, OSV behind `--online`.
- Public repo: https://github.com/nassih-yassine/mcp-security-scanner
- `dep-vet` is out of scope: no Cargo dependency on it, no porting its modules.
  Owner decision; revisit only on request (`SPEC.md` §9 Q4).

## Hard constraints

- **Never execute a scanned MCP server** or anything from a scanned config. No
  `Command::new` on scanned input. Static analysis only.
- **Never fetch a scanned `url`.** SSRF surface inside a security tool. One
  allowlisted adapter, `osv.dev` only, https, no userinfo, public IPs only.
- **Offline by default.** `--online` is opt-in. Offline reports OSV as `skipped`,
  never as a pass.
- **Never emit a raw secret.** `Evidence` carries redacted text only (prefix +
  last 4 + length). A test greps every artifact for fixture secrets.
- **No LLM in the scan path.** Output must be byte-identical across reruns.
- Default policy ships `confidence: High` only. False positives are the
  category kill risk (`AGENT.md`).
- `#![forbid(unsafe_code)]` in both crates; `#![deny(missing_docs)]` in core.

## Exit codes — do not invent others

`0` clean · `2` findings at/above `--fail-on` · `3` scan could not complete.

**Never call `Cli::parse()`.** clap exits 2 on usage errors, which means
"findings" here. Use `try_parse()` and remap clap errors to 3.

An incomplete scan is exit 3, never a pass. A missing advisory check must read as
"could not check", not "clean".

## Docs and releases (non-negotiable)

- Generated docs: `cargo xtask gen-docs`. Never hand-edit `docs/generated/`,
  the README rule table, or the README sample output — regenerate them.
  CI runs `gen-docs --check` and fails on drift.
- A behavior change is not done until README, `CHANGELOG.md`, the affected
  `docs/rules/<id>.md`, and the GitHub About description are updated **in the
  same merge**.
- Every rule needs `docs/rules/<id>.md` + `fixtures/<id>/{vulnerable,clean}` +
  `expected.json`, or the build fails. Rule IDs are kebab-case and frozen once
  shipped (SARIF baselines key on them).
- Releases: `docs/RELEASING.md` is the checklist. One version for both crates.
  Publishing jobs declare an environment (`crates-io`, `npm-publish`,
  `release`). Releases are cargo-dist; never hand-build and upload artifacts.
- Conventional commits — `git-cliff` generates the CHANGELOG.

## Commands

```bash
cargo test --locked                                  # all
cargo test -p mcpscan-core rules::secret             # one module
cargo test --test cli                                # one e2e file
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
cargo xtask gen-docs --check                         # generated docs drift
cargo run -q -p mcpscan -- scan fixtures/demo        # dogfood
```

CI order: `fmt → clippy → docs-check → test (3 OS) → build → dogfood`.
Keep `--locked` on clippy and test.

## Traps

- **Tests must not touch the network or the real cache.** Point the OSV base at
  a local `TcpListener` via env override; `--offline` in every other test.
- Parsing spans matter: `jsonc-parser` gives ranges, `toml_edit` gives spans.
  Do not swap in a span-less parser — SARIF locations depend on it.
- Determinism: sort with `BTreeMap`/sorted `Vec` before hashing or serializing.
- VS Code uses `servers`, not `mcpServers`. Zed uses `context_servers`. Codex is
  TOML (`[mcp_servers.*]`). Normalize in `parse.rs`; rules never see editor
  quirks.
- Scoring weights and thresholds live in `score.rs` only; never inline one in a
  rule.
