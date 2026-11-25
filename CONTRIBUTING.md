# Contributing

## Adding a rule

A rule PR contains all four parts, or it is not reviewable:

1. The rule in `crates/mcpscan-core/src/rules/`, with a kebab-case ID prefixed
   by its family (`mcp-secret-`, `mcp-scope-`, `mcp-tool-`, `mcp-osv-`,
   `mcp-exfil-`).
2. `docs/rules/<id>.md` with front-matter (`id`, `severity`, `confidence`,
   `since`) and an `## Example` / `## Fix` section.
3. `fixtures/<id>/vulnerable.*` and `fixtures/<id>/clean.*`.
4. `fixtures/<id>/expected.json` with the exact findings the vulnerable fixture
   must produce.

Rules that cannot be linked to a documented example do not ship. Default policy
includes high-confidence rules only.

## Reporting a false positive

Open an issue with the `false positive` label and paste the finding JSON from
`mcpscan scan --format json`. That JSON becomes a regression fixture.

## Commits

Conventional commits: `feat:`, `fix:`, `perf:`, `docs:`, `refactor:`, `test:`,
`chore:`, `ci:`.

## Local checks

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo xtask gen-docs --check
```
