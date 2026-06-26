# Memory — Solana Auditor Skill

Durable lessons from the multi-loop build of this skill. Read this before
touching the repo again. These are the things future-me will wish past-me
had written down.

## Current state (v1.4.0 FINAL — world-class complete)

- 11 tags: v1.0.0 through v1.4.0
- 62 integrity check categories (PASS count), all green
- 19 property-based (fuzz) tests using Hypothesis
- 17 security rules (Rules 1-17), up from 12
- 3 vulnerable fixtures: vault (10 VULN) + token-extensions (6 VULN) + real Token-2022 (1 VULN) = 17 total
- 6 commands (added /audit-resume)
- 3 PoC exploit walkthroughs (admin-drain, reinit, flash-loan)
- 5 formal verification invariant patterns (fv-invariant-pattern.ts)
- SARIF export script (scripts/export-sarif.py)
- Concurrent-run lock file + checkpoint/resume system
- 3 CI jobs all green on every commit
- Corporate-grade Python: type hints, magic numbers extracted, utf-8 encoding
- CWE references corrected across Rules 3, 5, 7, 10, 14
- Python 3.9 compatible (no PEP 604 union syntax)
- Bilingual glossary: EN + PT-BR in skill/00-terminology.md

## Toolchain / environment

- **Host**: macOS (26.5.1), user `colbert1`. Working dir on this skill is
  `/Users/colbert1/solana-auditor-skill`. Branch: main → origin/main.
- **Hermes CLI** is the only reliable surface for `~/.hermes/config.yaml`
  writes. Direct file writes get blocked by tirith/defense-in-depth. Use:
  - `hermes config set <key> <value>` for dotted keys (works correctly
    only when each call sets ONE leaf).
  - `hermes chat -q "..." --provider openrouter --model X` to verify
    a model via one-shot before committing to it as default.
  - Avoid JSON-string values via `hermes config set model '{...}'` —
    they end up as a YAML string under `model:` instead of nested keys.
- **9Router** runs at `localhost:20128` and is the `minimax` provider.
  Hangs repeatedly with `tail -f`/interrupted bash; recovery is to
  kill PID + node, restart `9router -t -l &`. Don't `kill -9` Agave.
- **GitHub CLI** (`gh`) is preconfigured. Use `gh api ... --jq ...` for
  pipeline-friendly JSON; `--json field` is the field whitelist.

## Repo conventions

- **Skill name**: `solana-auditor-skill` (everywhere — SKILL.md, install.sh,
  README, CHANGELOG, CLAUDE.md).
- **Workflow file**: `.github/workflows/test.yml`. 3 jobs:
  `skill-integrity`, `anchor-build`, `lint-install`.
- **Integrity script**: `tests/test-skill-integrity.sh` with helpers
  in `tests/severity_counts.py`. Pass/fail tally at end of stdout
  (PASS: N / FAIL: N).
- **Commits must keep CI green**. Subagent findings about CI env are
  not verified — always trigger CI before declaring done.

## Hard-won CI lessons (these bit me at least once each)

1. **`anchor build` alone does NOT produce `target/deploy/<prog>.so` in
   CI on anchor 0.31.1 + Agave solana-cli ≥2.x.** Either run
   `anchor test --skip-local-validator` (which still tries to connect
   to a validator and fails) or use `cargo check` (the strongest
   compile-clean proof that survives CI). Pinned approach:
   `cargo check` in `examples/sample-vulnerable-program/programs/vault/`.

2. **`Swatinem/rust-cache@v2`** does an early `exit(101)` if the
   `workspaces:` path has no Cargo.toml. Anchor projects have the
   Cargo.toml at `programs/<name>/Cargo.toml`, not at the workspace
   root. Use `workspaces: programs/vault -> target` and `cd` into it.

3. **`ubuntu-latest` GitHub Actions runners do NOT ship ripgrep.**
   Subagent reviewer claimed it was preinstalled. It isn't. Always
   `apt-get install -y ripgrep` in the workflow.

4. **Pinned `solana-cli` to v4.0.2** via `release.anza.xyz/v4.0.2/install`.
   `stable` rolls forward and breaks the build.

5. **`examples/sample-vulnerable-program/programs/vault/Cargo.toml`**
   has `solana-program = "2.3"` as a dependency. Anchor 0.31.1 emits a
   warning ("Adding solana-program as a separate dependency might cause
   conflicts") but the build still succeeds.

## Data integrity (v1.2.0–v1.3.1)

The example vault fixture has 10 VULN findings; the Token-2022 fixture has 6.

After v1.3.1:
- **47 PASS / 0 FAIL** integrity checks — every check green
- **19 fuzz tests passing** — CVSS math, severity bins, fixture regression, bidirectional source tag matching
- All vault CVSS scores recomputed from vectors and verified via `tests/severity_counts.py check-cvss-math`
- All Token-2022 CVSS scores verified same way — including methodology-trace.md (fixed from stale 9.3/7.5 to 10.0/8.1)
- Methodology-trace.md CVSS consistency now enforced by integrity Check 19
- Vault severity summary: `CRITICAL=2 HIGH=2 MEDIUM=6 LOW=0`
- Token-2022 severity summary: `CRITICAL=1 HIGH=3 MEDIUM=2 LOW=0`
- Total: `CRITICAL=3 HIGH=5 MEDIUM=8 LOW=0 INFO=0`

## CVSS 3.1 quick reference (for recomputing scores)

```
ISS = 1 - (1 - C) * (1 - I) * (1 - A)
Impact = 6.42 * ISS
Exploitability = 8.22 * AV * AC * PR * UI
Base = roundUp(min(Impact + Exploitability, 10))

AV: N=0.85, A=0.62, L=0.55, P=0.2
AC: L=0.77, H=0.44
UI: N=0.85, R=0.62
PR: N=0.85 always; L=0.62 (Scope U) or 0.68 (Scope C); H=0.5
C/I/A: H=0.56, L=0.22, N=0.0

roundUp(x) = ceil(x * 10) / 10
```

Severity scale (CLAUDE.md):
- CRITICAL ≥ 9.0
- HIGH ≥ 7.0
- MEDIUM ≥ 4.0
- LOW ≥ 0.1

## Subagent-driven development gotchas

- **Subagent reviewer confidence ≠ verified correctness.** Always
  trigger CI after applying reviewer findings.
- **Don't fan out >3 reviewers** — cost grows, conflicts multiply.
- **Save subagent results if context compresses.** Subagent summaries
  arrive as a single message when ALL children finish; if context
  compresses mid-batch, results are lost.
- **Unicode characters in tool calls** — the `→` arrow (U+2192) and
  backtick characters fail silently in str_replace when embedded in
  JSON strings. Use sed via basher or write_file to replace these.
- **Dead code detection false positives** — code-reviewer-deepseek-flash
  flagged `TOKEN_FIXTURE_SOURCE_PATH` as dead code, but it's used by
  P18. Always verify reviewer claims before acting on them.

## Files & purposes

| Path | Purpose | Last touched |
|---|---|---|
| `skill/SKILL.md` | Skill frontmatter + phase routing | v1.1.0 |
| `skill/00-terminology.md` | Glossary (EN + PT-BR) | v1.0.0 |
| `skill/01-recon.md`..`06-remediation.md` | Phase procedures | v1.0.0 |
| `commands/*.md` | 6 slash commands | v1.0.0 |
| `agents/*.md` | 4 specialist agents + AUDIT.md status | v1.0.0 |
| `rules/audit.rules` | 12 path-scoped rules + 24 CWE refs | v1.0.0 |
| `examples/sample-vulnerable-program/programs/vault/` | Anchor vault fixture (VULN-01..10) | v1.2.0 |
| `examples/sample-vulnerable-program/programs/token-extensions/` | Token-2022 fixture (VULN-11..16) | v1.3.0 |
| `templates/poc-template-*` | 3 PoC templates (anchor.rs, typescript.ts, manual.md) | v1.1.1 |
| `tests/test-skill-integrity.sh` | 19-check integrity script with 47 PASS points | v1.3.1 |
| `tests/severity_counts.py` | Python helpers (summary, report, cvss, cvss-math modes) | v1.2.0 |
| `tests/fuzz/test_properties.py` | 19 property-based tests (P1-P19) | v1.3.1 |
| `install.sh` | Copies skill/, commands/, rules/, templates/, CLAUDE.md | v1.2.0 |
| `.github/workflows/test.yml` | 3-job CI, pinned solana v4.0.2 | v1.2.0 |
| `pyproject.toml` | Black, mypy, pytest config (corporate-grade) | v1.3.1 |
| `MEMORY.md` | This file | v1.3.1 |

## Bug classes to watch for

- **Stale doc counts**: any time files are added/removed, CLAUDE.md,
  SKILL.md, README.md, and CHANGELOG.md counts can drift. Check 9
  in `tests/test-skill-integrity.sh` catches agent-list drift.
- **Documentation drift between data files**: findings.json vs
  AUDIT_REPORT.md. Check 8 catches CVSS drift, Check 7 catches
  severity-count drift.
- **Math vs claim**: a method that produces numbers (CVSS, severity,
  etc.) needs an integrity check that recomputes from input data.
  Check 10 catches CVSS math drift.
- **CI tool assumption drift**: things that work locally (ripgrep
  preinstalled, stable solana-cli) may not work in CI. Pin
  everything versioned.
- **Install path drift**: when install.sh copies files, the destination
  directory name MUST match the skill name in SKILL.md. Claude Code
  registers skills by directory name under `~/.claude/skills/<name>/`.
  Copying into `~/.claude/skills/skill/` (literal dir name) or
  `~/.claude/skills/` (no skill subdir) silently breaks the install.
  install.sh:85 was doing this in v1.2.0-v1.2.2 — fixed in v1.2.3.
  Always end-to-end test `bash install.sh -y` against an isolated HOME
  (e.g. `HOME=/tmp/test-home`) and assert files land at the expected
  skill path.
- **Line number drift**: when source code is edited, findings.json
  and AUDIT_REPORT.md line numbers go stale. In v1.2.0 → v1.2.3, 10/10
  findings had drifted by 1-12 lines because the lib.rs grew during
  iterative development but the audit report wasn't re-run. Detection
  by eye is unreliable; a future integrity check (Check 13 candidate)
  could `rg -n "VULN-\d+" examples/.../src/lib.rs` and verify each
  finding's claimed line falls within the VULN's enclosing function.
- **Ghost struct / function references**: when vulnerabilities are
  re-implemented (e.g., VULN-04 was rewritten from `close = user_...`
  to `drain_vault`), description text referencing the original
  implementation can survive. v1.2.3 fixed one instance but the bug
  class recurs.
- **Methodology-trace CVSS drift**: when findings.json CVSS scores
  are corrected, the methodology-trace.md scores must be updated
  in sync. In v1.3.1, VULN-14 (9.3→10.0) and VULN-16 (7.5→8.1)
  were fixed in findings.json and AUDIT_REPORT.md but NOT in
  methodology-trace.md, causing silent data drift. Check 19 now
  catches this.
- **Unicode edge cases in tool calls**: CVSS vector strings contain
  forward slashes and backtick characters that can break str_replace
  when used with JSON parameter encoding. When replacing lines with
  `→` arrows, backticks, or slashes, prefer sed via basher or write
  the entire file with write_file.
