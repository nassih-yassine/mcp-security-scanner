# Spec — MCP / Agent-Tool Security Scanner

Status: **DRAFT v2 (Rust) — awaiting review. No implementation until §10 is approved.**
Derived from `AGENT.md` (product brief, do not edit that file — see §1).
Owner: `nassih-yassine`

---

## 1. Inputs and definitions

`AGENT.md` is the product brief: audience, pain, features, pricing, distribution,
risks, kill criteria. This spec is the engineering translation. Where they
disagree, `AGENT.md` wins on *what* and *why*; this file wins on *how*.

Scope: repo creation, technology, layout, data model, rules, output, docs policy,
release management, CI/CD, phases.

Not in scope: marketing copy, pricing changes, and any code.

---

## 2. Goals / non-goals / anti-goals

**Goals**

1. `mcpscan` finds real problems in MCP configs, agent configs and tool
   definitions in under 2 seconds.
2. Output drops into CI unchanged: SARIF for GitHub code scanning, plus human
   and Markdown reports.
3. A rule system that is data-driven, documented, and fixture-tested, so false
   positives are cheap to fix.
4. A static binary with release rigor: attested artifacts, crates.io,
   brew/binstall, and npm.
5. Docs, README, CHANGELOG and the About description never lag the shipped
   behavior — enforced by CI, not by memory.

**Non-goals (MVP)**

- No runtime proxy or traffic interception.
- No execution of scanned MCP servers. Static analysis only.
- No generic SAST. Only MCP/agent-tool artifacts.
- No hosted dashboard (phase 4, gated by `AGENT.md` kill criteria).
- No async runtime, no tokio.

**Anti-goals** (a failure even if it "works")

- A finding nobody can act on.
- Silent network calls.
- A raw secret in any output artifact.
- Scores that flip between runs on identical input.
- A release whose README shows output the binary no longer produces.

---

## 3. Repo creation — step by step

Target: `https://github.com/nassih-yassine/mcp-security-scanner`, **public**.
Verified on this machine: `gh` 2.105 authed as `nassih-yassine` (`repo`,
`workflow`, `read:org`, `gist`), `git`, Rust 1.99 with mise, and a working
cargo-dist setup pattern on this machine.

### 3.1 Initialize locally

```bash
cd /home/iomi/Projects/mcp-security-scanner
git init -b main
```

Before the first commit: `LICENSE` (MIT), `README.md`, `SECURITY.md`,
`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.gitignore` (`/target`, `.mcpscan/`),
`rust-toolchain.toml`, `AGENTS.md`.

### 3.2 First commit and public repo

```bash
git add -A
git commit -m "chore: initial commit"
gh repo create nassih-yassine/mcp-security-scanner \
  --public --source=. --remote=origin --push \
  --description "Scan MCP servers, agent configs and tool definitions for leaked credentials, scope creep and tool poisoning. SARIF out, CI-ready."

gh repo edit --add-topic mcp,security,cli,sarif,ai-agents,llm-security
for l in rule bug docs "good first issue" "false positive"; do gh label create "$l" --force; done
```

The `false positive` label is not cosmetic: `AGENT.md` names false positives as
the category kill risk, so rule-FP reports need their own triage path from day one.

### 3.3 Security features (free on public repos)

```bash
gh api -X PATCH repos/nassih-yassine/mcp-security-scanner \
  -F 'security_and_analysis[secret_scanning][status]=enabled' \
  -F 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
gh api -X PUT repos/nassih-yassine/mcp-security-scanner/vulnerability-alerts
```

Also: Dependabot alerts on, private vulnerability reporting on, and a
`SECURITY.md` with a disclosure address and a 90-day window.

### 3.4 Repo settings

- Actions → General: read-only `GITHUB_TOKEN` by default; workflows request more
  explicitly. Allow Actions to create PRs **only** if the data-refresh bot needs
  it.
- Auto-merge on, `delete_branch_on_merge=true`.
- Environments created before the first publish: `crates-io`, `npm-publish`,
  `release`. Every publishing job must declare one, or the channel is invisible
  on the Deployments page.

### 3.5 Branch protection — after the first green CI, not before

House convention is no PRs: work on a branch, merge when green. Protection
therefore does **not** require reviews:

```bash
gh api -X PUT repos/nassih-yassine/mcp-security-scanner/branches/main/protection \
  --input - <<'JSON'
{
  "required_status_checks": { "strict": true, "contexts": ["ci"] },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

Creating a required check that does not exist yet blocks every merge. Push CI,
let it run once, then apply.

### 3.6 Done-when

- [ ] Public URL resolves, `main` pushed
- [ ] LICENSE / README / SECURITY / CONTRIBUTING / AGENTS.md / SPEC.md present
- [ ] Secret scanning + push protection on
- [ ] Topics, labels, environments set
- [ ] CI green on `main`, branch protection active after that

---

## 4. Technology architecture

### 4.1 Decision

**Rust workspace, two crates: `mcpscan-core` (lib) + `mcpscan` (bin).**

Why not the alternatives:

| Option | Verdict |
|---|---|
| TypeScript | Rejected. Its only win was reusing the language for the phase-4 dashboard, which is gated behind kill criteria. Costs a slower cold start, a ReDoS-capable regex engine over attacker-controlled text, and a second release pipeline. |
| Go | Rejected. Viable, and faster to write glue code, but the rules engine is the product and iterating it is slower here; Go also buys nothing on distribution that Rust does not. |
| Rust | Chosen. Compiled distribution matches a security audience, `regex` is linear-time so hostile tool descriptions cannot DoS the scanner, and the author already ships a 34k-line Rust CLI. |
| Rust + TS dashboard | Deferred, not rejected. Phase 4 only, if it happens. |

### 4.2 Stack

| Concern | Choice | Note |
|---|---|---|
| Toolchain | Rust, edition 2024, MSRV 1.88 | stable, wide CI coverage |
| Workspace | `[workspace.package]` + `[workspace.dependencies]` | one version for both crates |
| CLI | `clap` 4 derive | **`try_parse()`, never `parse()`** — see §4.4 |
| Config parsing | `jsonc-parser` (ranges), `toml_edit` (spans) | spans give SARIF line/col |
| YAML | **none** | no scanned format is YAML; scope maps are JSON |
| Serialization | `serde`, `serde_json` | SARIF/JSON built with typed structs |
| Errors | `thiserror` in core, `anyhow` in the bin | typed errors in the lib, context in the CLI |
| Regex | `regex` | linear time; no backreferences, by design |
| Unicode | `unicode-normalization` (NFKC) | zero-width/bidi/homoglyph detection |
| HTTP | `ureq` 3, blocking | no tokio; one adapter, host-allowlisted |
| Hashing | `sha2` | finding fingerprints, checksums |
| Versions | `semver` | OSV range checks |
| Terminal | `owo-colors` | no progress bar in MVP |
| Data | `include_str!` + `OnceLock<serde_json::Value>` | rule data ships in the binary |
| Tests | `cargo test`, `insta`, `assert_cmd`, `predicates`, `tempfile`, `jsonschema` (dev) | |
| Release | `cargo-dist` 0.34, `dist-workspace.toml` | pin action commits in the dist config |
| Lint | `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` | warnings are errors |
| Crypto/dep hygiene | `cargo audit`, `cargo deny` | license + advisory gate |
| Docs sync | `cargo xtask gen-docs --check` | §4.10 |

No async runtime, no YAML crate (a YAML dependency has dragged unmaintained
libyaml code into Rust CLIs before), no LLM in the scan path.

Both crates start with `#![forbid(unsafe_code)]`; core adds
`#![deny(missing_docs)]`.

### 4.3 Layout

```
mcp-security-scanner/
├── Cargo.toml                  # [workspace], workspace.package (version, edition, rust-version)
├── dist-workspace.toml         # cargo-dist; allow-dirty = ["ci"]
├── rust-toolchain.toml
├── deny.toml
├── cliff.toml                  # git-cliff changelog
├── action.yml                  # composite GitHub Action
├── crates/
│   ├── mcpscan-core/src/
│   │   ├── model.rs            # ServerSpec, Capabilities, Finding, ScanReport, Severity
│   │   ├── discover.rs         # candidate paths; pure list, per-platform tests
│   │   ├── parse.rs            # jsonc/toml -> ServerSpec with spans
│   │   ├── resolve.rs          # capability inference, package refs
│   │   ├── rules/mod.rs        # Rule struct + registry
│   │   ├── rules/*.rs          # one file per family
│   │   ├── score.rs            # weights, multipliers, gate
│   │   ├── report/{human,json,sarif,markdown}.rs
│   │   ├── netpolicy.rs        # https, host allowlist, public-IP checks
│   │   ├── osv.rs              # querybatch client, injected base URL
│   │   └── cache.rs            # JSON file cache, 24h TTL, stale disclosure
│   └── mcpscan/src/
│       ├── main.rs             # wiring, color decision, exit codes
│       └── cli.rs              # clap surface
│   └── mcpscan/tests/cli.rs    # assert_cmd against a local fake OSV server
├── crates/xtask/src/main.rs    # gen-docs, gen-completions, release checks
│   │   └── data/rules/        # secret-prefixes.json, scope-maps.json, injection-phrases.json
├── docs/
│   ├── rules/<rule-id>.md      # one page per rule, required
│   ├── RELEASING.md
│   └── generated/              # xtask output: rules index, README sample
├── fixtures/<rule-id>/{vulnerable,clean}.* + expected.json
└── .github/workflows/          # ci, release, cargo-publish, npm-publish, packaging
```

`core` is side-effect free: no `std::env::args`, no `std::process::exit`, no
network without an injected client. Rules are pure functions over `ServerSpec`.

### 4.4 Exit codes

| Code | Meaning |
|---|---|
| 0 | clean, or findings below the fail threshold |
| 2 | findings at or above `--fail-on` (default `critical`) |
| 3 | the scan could not be completed (unreadable config, `--online` failure) |

Two traps that follow:

- **Never call `Cli::parse()`.** clap exits 2 on usage errors, which means
  "findings" here. Use `try_parse()` and remap clap errors to 3.
- **An incomplete scan is never a pass.** Missing OSV data in `--online` mode is
  a disclosed gap (INFO finding + exit 3 if Advisories are required), never
  "no vulnerabilities".

### 4.5 Data model

```rust
pub struct ServerSpec {
    pub id: String,                  // stable hash of source path + name
    pub name: String,
    pub source: Source,              // file, format, json pointer, span
    pub transport: Transport,        // Stdio | Http | Sse
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub url: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub pkg: Option<PackageRef>,     // registry + name + version
    pub tools: Vec<ToolSpec>,        // from local schema files or --tools-dir
    pub declared_scopes: Vec<String>,
    pub capabilities: Capabilities,  // fs_read, fs_write, net_egress, shell_exec,
                                     // db_read, db_write, secret_in_config
}

pub struct Finding {
    pub rule_id: RuleId,             // kebab-case, e.g. "mcp-secret-literal"
    pub severity: Severity,          // Critical | High | Medium | Low
    pub confidence: Confidence,      // High | Medium | Low
    pub message: String,
    pub location: Location,          // file + pointer + optional line/col
    pub evidence: Evidence,          // redacted only, never the raw value
    pub remediation: String,
    pub fingerprint: String,         // sha256(rule|file|normalized evidence)
}
```

`BTreeMap` everywhere and `Vec`s sorted before hashing: determinism is a
requirement, not a nicety (SARIF dedupe, reproducible output).

Discovery targets (read-only, never executed): `mcp.json`, `.mcp.json`,
`~/.claude.json`, `.claude/settings.json`, `claude_desktop_config.json`,
`.cursor/mcp.json`, `~/.cursor/mcp.json`, `.vscode/mcp.json` (`servers` key, not
`mcpServers`), `~/.codeium/windsurf/mcp_config.json`, Zed `settings.json`
(`context_servers`), `~/.codex/config.toml` (`[mcp_servers.*]`), `.env`,
`.env.*`, and shell history only with `--include-history`.

### 4.6 Rules

Kebab-case IDs, not numbers. Readable in SARIF, greppable in allowlists. The
family prefix is the grouping:

| Prefix | Family | Signals |
|---|---|---|
| `mcp-secret-*` | Credential exposure | provider prefixes (`sk-`, `ghp_`, `xoxb-`, `AKIA`…), Shannon entropy > 4.0 at len ≥ 20, placeholder allowlist (`${…}`, `op://`, `YOUR_API_KEY`) |
| `mcp-scope-*` | Scope creep | per-provider maps (github, stripe, supabase, google, slack, linear, notion); wildcard `*`; write/admin where a read-only sibling exists |
| `mcp-tool-*` | Tool poisoning | instruction-override phrases; invisible chars (U+200B–D, U+202A–E, U+2060, U+FEFF, U+E0000–E007F); base64 blobs > 120 chars; description claims read-only while schema has destructive verbs; description names other tools (shadowing) |
| `mcp-osv-*` | Known-vulnerable | `POST /v1/querybatch` with ecosystem/name/version; 24h cache; `--online` only |
| `mcp-exfil-*` | Exfil path | composite: net egress ∧ (fs/db read) ∧ (fs/db write ∨ shell exec), or egress + secret in config |

Shape:

```rust
pub struct Rule {
    pub id: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub since: &'static str,          // version that introduced it
    pub applies_to: fn(&ServerSpec) -> bool,
    pub run: fn(&ServerSpec, &RuleCtx) -> Vec<Finding>,
}
```

Policy: default ships `confidence: High` only (straight from `AGENT.md`'s FP
risk). Medium rules exist behind `--include-medium` and are labeled experimental.
Low-confidence rules do not ship.

Every finding must cite evidence and a remediation; a rule that cannot be linked
does not ship.

Required per rule, enforced by tests, not by review:
`docs/rules/<id>.md` with front-matter (`id`, severity, confidence, since, example),
`fixtures/<id>/vulnerable.*` + `clean.*` + `expected.json`.

### 4.7 Modes

| Mode | Network | Behavior |
|---|---|---|
| `--offline` (default) | none | OSV reported as `skipped`, never "pass" |
| `--online` | osv.dev only | version advisories; failures → exit 3 |

Scanned `url` values are **never** fetched. Outbound traffic goes through one
allowlisted adapter (`osv.dev`), with https-only, no userinfo, default-port and
public-IP-literal checks. Tests point the base URL at a local `TcpListener`; a
test that reaches the real internet is a bug.

### 4.8 Scoring and gate

```
weight = { critical: 40, high: 20, medium: 8, low: 2 }
mult   = { high: 1.0, medium: 0.5, low: 0.25 }
score  = clamp(0, 100, 100 - Σ(weight × mult))   // deduped by fingerprint
A ≥ 90 · B 70–89 · C 50–69 · D 30–49 · F < 30
```

Gate: exit 2 if any finding's severity ≥ `--fail-on` (default `critical`).
Weights and thresholds live in `score.rs` only.

### 4.9 Output

- `human` — grouped by file, colored severity, remediation under each finding.
- `json` — `ScanReport` with `schema_version: 1`, no timestamps.
- `sarif` — SARIF 2.1.0: `tool.driver.{name,version,rules[]}`,
  `results[].{ruleId,level,message,locations,partialFingerprints}`,
  `properties.security-severity` for GitHub-native severity. Critical/High →
  `error`, Medium → `warning`, Low → `note`. Validated against the official
  schema in tests.
- `markdown` — the `security-score.md` report from `AGENT.md`.

`--format` conflicts with `--json`; `-o` writes a file and never changes the
exit code.

### 4.10 Docs stay current — mechanically enforced

Docs drift is a release blocker, not a review comment. Three layers:

1. **`cargo xtask gen-docs`** generates `docs/generated/rules-index.md`, the
   README rule table, the README sample-output block (by running the binary on
   `fixtures/demo/`), and the clap reference. `--check` mode in CI fails on any
   diff. Nobody hand-edits generated files; they regenerate.
2. **Tests assert the invariants**: every registered rule has a docs page and a
   fixture pair; every docs page maps to a registered rule (no orphans);
   front-matter severity/confidence/`since` equals the code; README's rule count
   matches the registry.
3. **`AGENTS.md` working agreement**: a behavior change updates README,
   CHANGELOG, the affected rule page, and the repo About description in the same
   commit/merge. "Not done until the docs no longer state an old limit."

README required sections: one-liner, who it's for, install (cargo/binstall/brew/
npm/action), 30-second quickstart, real sample output, rule table, exit codes,
CI snippet, privacy statement (offline default), security disclosure, license.

`docs/` is tracked and published — these docs are user-facing. A docs site
(mdBook) is phase 3, only if rules exceed ~25.

### 4.11 Release management

Channels, each its own workflow:

| Channel | Trigger | Gate |
|---|---|---|
| GitHub Release + binaries | tag `vX.Y.Z` pushed to `main` | cargo-dist builds 4 native targets (x86_64 linux gnu, both macOS, x86_64 windows), shell+powershell installers, SLSA attestations |
| crates.io | `workflow_run` of Release (token-created releases don't start workflows) | `crates-io` environment with required reviewers; tag must equal `[workspace.package] version` |
| npm (`npx mcpscan`) | deferred | needs platform packages; cargo-dist emits `.tar.xz`, which Node cannot extract without extra deps |
| Homebrew tap / AUR / `.deb`/`.rpm`/`.apk` | phase 3 | nfpm from attested musl archives, no maintainer scripts |
| Docker | phase 3, only on demand | distroless, `--sbom`, `--provenance`, cosign keyless |
| GitHub Action | every release | composite, downloads the pinned release binary, **no third-party actions** |

Versioning and compatibility contract:

- One version for both crates (lockstep). `mcpscan-core` is published for
  integration use and is explicitly **unstable pre-1.0**.
- Pre-1.0: breaking changes allowed in minor, always in CHANGELOG.
- Post-1.0 public contract: CLI flags, JSON `schema_version`, SARIF shape, rule
  IDs. Breaking any of those is a major.
- **Rule IDs are frozen once shipped.** SARIF baselines, PR dismissals and
  allowlists key on them. Renaming/removing a rule ships a mapping table in the
  CHANGELOG; after 1.0 it is a major.
- Severity change on an existing rule = minor (baselines shift).
- New rule = minor. Docs/metadata only = patch.
- Cadence: no schedule. Prereleases `vX.Y.Z-alpha.N` during MVP.
- `docs/RELEASING.md` is the checklist (docs regenerated and checked, CHANGELOG
  written, version bumped, `cargo dist plan` reviewed, tag, artifacts attested,
  publish jobs approved, post-release install smoke test from a clean container,
  About description updated).

CHANGELOG is generated by `git-cliff` from conventional commits, then edited for
user-facing wording. Conventional commit format is enforced by a CI commit-lint
job, not by hope.

### 4.12 Repo operations

- `SECURITY.md`: private disclosure, 90-day window, scope statement (we scan
  configs; report scanner vulns here).
- `CONTRIBUTING.md`: rule submission template = rule + docs page + fixtures +
  expected output; FP reports get the `false positive` label and become
  regression fixtures.
- Issue templates: bug, rule request, **false positive** (with the finding JSON).
- `CODEOWNERS` on `crates/mcpscan-core/data/rules/` and `docs/rules/`.
- Dependabot: cargo, github-actions (ignoring `release.yml`'s pinned actions,
  which are updated in `dist-workspace.toml`), docker.
- `.githooks/pre-commit` = `cargo fmt --check` + `clippy` on changed crates;
  `pre-push` = fmt, clippy, test, docs check. `core.hooksPath` enabled per clone.
- Dogfood job: `mcpscan scan .` on this repo plus every hand-written workflow and
  the local MCP configs. A finding in our own repo fails the build.
---

## 5. Testing

| Level | What |
|---|---|
| Unit | each rule, parser, redaction, scoring, fingerprint stability |
| Fixture | `vulnerable` → exact expected findings; `clean` → zero |
| Contract | SARIF validates against 2.1.0 schema; JSON matches `schema_version` |
| Snapshot | `insta` for human, markdown and SARIF output on seeded fixtures |
| Determinism | same input twice → byte-identical output (own test) |
| Redaction | fixture secrets never appear in any artifact (own test) |
| E2E | `assert_cmd` + local fake OSV over `TcpListener`; env-var base override |
| Docs | §4.10 invariants |

Coverage gate 80% on `mcpscan-core`, none on the bin. CI order:
`fmt → clippy → docs --check → test (3 OS matrix) → build → dogfood`.
CI keeps `--locked` on clippy and test, or it can pass on versions absent from
`Cargo.lock`.

---

## 6. Phases

| Phase | Deliverable | Exit |
|---|---|---|
| 0. Validation (~2 days, no code) | hand-scan 30 popular MCP servers with grep + checklist, publish aggregates | findings are real and non-obvious |
| 1. Walking skeleton (~1 week) | discover + parse + `mcp-secret-*` + human/SARIF output, crates.io publish | `mcpscan scan .` works on all config shapes |
| 2. Substance (~1 week) | `mcp-scope-*`, `mcp-tool-*`, `mcp-osv-*` behind `--online`, scoring, gate | a stranger reproduces the "top 100 servers" run |
| 3. Distribution (~1 week) | `action.yml`, release binaries, README with real output, Show HN draft; brew/npm/nfpm after | Action in Marketplace search |
| 4. Hosted (gated) | GitHub App PR comments, dashboard, paid tier | only after `AGENT.md` kill criteria pass |

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| False positives | high-confidence-only default, mandatory fixtures, `--explain` shows redacted evidence |
| Scanner leaks secrets | redaction at the model boundary; own test greps artifacts |
| SSRF / silent egress | one allowlisted adapter, never fetch scanned URLs |
| ReDoS | `regex` crate only; linear-time by construction |
| Unstable output | sorted `BTreeMap`/`Vec` + fingerprints, determinism test |
| Docs drift | xtask `--check` + invariant tests + AGENTS agreement |
| Release channel breakage | per-channel workflows, environments with reviewers, post-release install smoke test |
| Rust iteration cost | confined to parsing; rules are table-driven data + small functions |

---

## 8. Approval checklist

- [ ] §3 repo `nassih-yassine/mcp-security-scanner`, public, no-PR merge convention
- [ ] §4.1 Rust, two crates
- [ ] §4.4 exit codes 0/2/3 with `try_parse`
- [ ] §4.6 kebab-case rule IDs + high-confidence-only default
- [ ] §4.7 offline by default, osv.dev the only host
- [ ] §4.10 generated docs + `--check` in CI
- [ ] §4.11 channels, lockstep versioning, frozen rule IDs
- [ ] §6 phase order, phase 0 before code
- [ ] §9 questions answered or deferred

## 9. Open questions

1. **Hosted vs local-only** (`AGENT.md`): phase 4 only, does not block MVP.
2. **Rules authorship**: in-house, or community PRs behind a review gate?
3. **License**: MIT assumed. AGPL only if the hosted moat
   matters more than adoption.
4. **Out of scope now**: sharing code with, or depending on, `dep-vet`. Revisit
   only if this repo duplicates the same rule three times.
5. **npm package name**: `mcpscan` available on crates.io/npm? Verify before
   phase 1 publish; fall back to `mcp-security-scanner`.

## 10. Gate

Nothing gets built until §8 is checked off and §9 is answered or explicitly
deferred. Writing product code, scaffolding, `cargo init`, dependency installs
and repo creation are all implementation. Reading, scanning popular servers by
hand, and editing this spec are not.
