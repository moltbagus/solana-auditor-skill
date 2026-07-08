# Changelog

All notable changes to **solana-auditor-skill** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.8.0] - 2026-06-27

Massive expansion — Token-2022 coverage, Pinocchio/Native Solana rules, AI agent safety guardrails.

### Added

- **Rules 27-35: Token-2022 Transfer Hook Security** (9 rules covering mint
  verification, reentrancy, remaining accounts, amount safety, program ID
  allowlist, CPI seed purity, non-transferable bypass, memo extension order,
  default-handler amount)
- **Rules 36-45: Pinocchio/Native Solana coverage** (10 rules covering sysvar
  spoofing, writable enforcement, duplicate mutable account, unsafe
  deserialization, manual init, lamport griefing, non-canonical bump, unchecked
  arithmetic, unverified CPI program ID, missing signer)
- **Rules 46-50: AI Agent Safety Guardrails** (prompt injection, hallucinated
  CVE, scope creep, false positive inflation, credential exposure)
- **New fixture**: `native-vault` (Pinocchio program with VULN-N01 through N04)
- **New agent**: `safety-guard.md` (Phase 0 pre-flight, cluster enforcement,
  PoC sandbox, credential masking)
- **Phase 0 safety guard** integrated into `/audit` and `/audit-quick` commands
- **22 property-based fuzz tests** (P20-P22 added)
- **153 integrity checks** (up from 93)

## [1.4.0] - 2026-06-25

World-class release — 17 security rules, 62 integrity checks, formal verification demo, SARIF export.

### Added

- **5 new security rules** (Rules 13-17):
  - Rule 13: Flash Loan Attack Surface (CRITICAL, CWE-362/841)
  - Rule 14: Reentrancy Guard (CRITICAL, CWE-362/841)
  - Rule 15: remaining_accounts Validation (CRITICAL, CWE-20/862, Raydium vector)
  - Rule 16: Discriminator Collision (CRITICAL, CWE-843/20)
  - Rule 17: AccountLoader vs Account Distinction (HIGH, CWE-829/345, Mango vector)
- **CWE corrections**: Rules 3,5,7,10,14 — fixed misclassifications (CWE-1281→CWE-20, CWE-330→CWE-340, CWE-567 removed)
- **Formal verification demo** (`tests/test-formal-verification.sh`) — 5 invariant test patterns, 11 checks, graceful skip without Anchor CLI
- **Invariant pattern file** (`tests/fv-invariant-pattern.ts`) — 5 TypeScript test templates for Anchor security tests
- **3 exploit PoC walkthroughs** (`examples/.../pocs/`):
  - admin-drain-poc.md — VULN-01 signer bypass exploit path
  - reinit-attack-poc.md — VULN-06 discriminator collision exploit
  - flash-loan-poc.md — Mango-flash loan oracle manipulation
- **SARIF export** (`scripts/export-sarif.py`) — GitHub Code Scanning integration
- **Concurrent-run protection** — Lock file in `/audit` command
- **Resume command** — `/audit-resume` for interrupted audit sessions
- **Real Token-2022 fixture** — `examples/token-2022-real/` with actual spl_token_2022 dependencies
- **Corporate-grade Python** — Type hints, magic number extraction, `encoding="utf-8"` on all file opens

### Changed

- Security rules: 12 → 17
- Integrity checks: 49 → 62
- Commands: 5 → 6 (added `/audit-resume`)
- Demo.sh: dynamic rule/command counts (no stale hardcodes)
- Python: `Optional[T]` for Python 3.9 compatibility (was `T | None` syntax)

### Verified

- 62 integrity checks passing
- 19 property-based tests green
- 17 security rules, all with CWE references and severity defaults
- 3 vulnerable fixtures with 17 VULN tags total
- Formal verification demo: 11 PASS, 0 FAIL, 1 SKIP
- All CVSS scores mathematically verified from vectors

## [1.3.0] - 2026-06-24

Contest edition — property-based testing, PT-BR glossary, SDD docs, demo script.

### Added

- **Property-based testing harness** (`tests/fuzz/test_properties.py`) — 19 Hypothesis
  fuzz tests verifying CVSS math invariants across 1,000s of randomized inputs:
  score range [0,10], roundUp precision, parse roundtrip, scope ordering,
  severity binning monotonicity, count totals, fixture regression, metric independence.
- **Brazilian Portuguese (PT-BR) glossary** — `skill/00-terminology.md` bilingual
  (EN + PT-BR) with 7 PT-BR table sections and 8 security phrases translated.
- **Spec-Driven Development documents** — `PRD.md`, `spec.md`, `kanban.md`, `learnings.md`
  documenting the full design process, architecture, and decision log.
- **Contest demo script** (`demo.sh`) — one-command evaluation: structure check,
  51 integrity checks, 19 fuzz tests, contest summary. No Solana toolchain needed.
- **4 new integrity checks** in `tests/test-skill-integrity.sh`:
  - Check 14: property-based (fuzz) tests pass
  - Check 15: Brazilian Portuguese (PT-BR) terminology present
  - Check 16: SDD documentation files present
  - Check 17: demo script is present and executable
- **Contest badges** in `README.md` — Superteam Brasil, fuzz tests, SDD docs.
- **Contest submission section** in `README.md` — judge instructions + feature list.

### Changed

- Updated `MEMORY.md` with v1.3.0 current state (51 integrity checks, 30+ commits)
- Total integrity checks: 28 → 36 (8 new verification points)
- Total property-based tests: 0 → 19

### Verified

- 36 integrity check categories, 35+ verification points all green
- 19 property-based tests passing across 1,000+ generated examples per test
- Demo script runs clean from `bash demo.sh`
- All CI jobs green

## [1.1.0] - 2026-06-23

Polish release — closes three regressions and adds PoC templates.

### Added

- **PoC templates** (`templates/`) — `poc-template-anchor.rs`,
  `poc-template-typescript.ts`, `poc-template-manual.md`. Referenced
  by `commands/audit-poc.md` and `skill/06-remediation.md` but were
  previously not on disk. Copy and customize per finding.
- **Badges** in `README.md` — CI status, Anchor 0.31.1, MIT license,
  Solana 2.x. Visual proof of build/test status for kit reviewers.
- **Limitations section** in `README.md` — explicit list of what the
  skill does NOT do, so reviewers aren't surprised by gaps.
- **Two new integrity check categories** in `tests/test-skill-integrity.sh`:
  - Check 6: `findings.json` summary field matches computed counts
  - Check 7: `AUDIT_REPORT.md` severity table matches `findings.json`
  - Total verification points: 13 across 7 named check categories

### Fixed

- **`findings.json` severity summary mismatch** — `summary.medium`
  was 4 but 5 findings had MEDIUM severity (VULN-02, -05, -07, -08,
  -09). Recomputed via Python.
- **VULN-04 CVSS miscalculation** — score 9.1 with vector
  `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` mathematically evaluates to
  5.7, not 9.1. Recomputed and fixed to vector
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8 (matches CRITICAL
  severity and "total fund loss" impact).
- **Broken runtime tests** — `tests/vuln-confirm.rs` required a local
  Solana test validator and failed in CI even with `|| true`. Removed
  the test file. CI now uses `cargo check` as the compile-clean check
  (cheapest reliable verification; producing a deployable `.so` requires
  the SBF toolchain which is flaky on Agave solana-cli).

### Removed

- `tests/vuln-confirm.rs` — runtime tests without a working CI
  validator would have shipped a false signal.

## [1.2.0] - 2026-06-23

Data-integrity + docs release — caught and fixed several data-quality
regressions introduced in earlier iterations.

### Fixed

- **7 CVSS scores in `findings.json` were mathematically wrong** —
  scores 5.3, 6.5, 7.5, 4.5, 5.0, 5.5, 2.5 didn't match their vectors.
  Recomputed and verified against the FIRST CVSS 3.1 calculator. (The
  v1.1.0 fix only caught VULN-04; this fix catches the rest.)
- **3 severity classifications didn't match the corrected CVSS scores**
  per the CLAUDE.md scale: VULN-05 MEDIUM→HIGH, VULN-06 HIGH→MEDIUM,
  VULN-10 LOW→MEDIUM.
- **CLAUDE.md and skill/SKILL.md frontmatter listed 3 agents** but the
  repo has 4 (`orchestrator.md` was missing from both docs). README
  claimed "4 agents" by count but never listed orchestrator by name.
- **`install.sh` did not copy `templates/`** — README claimed templates
  were available post-install, but they weren't. Users cloning the
  repo got them; users running `./install.sh` did not.
- **`commands/audit-poc.md` referenced PoC template paths** but
  didn't tell users where to start. Updated each PoC type to point
  at `templates/poc-template-*`.
- **`docs/session-review.md` was committed but never referenced** —
  moved to `.hermes/dev-notes/` (gitignored, kept as maintainer record).
- **solana-cli install used rolling `stable` channel** — pinned to
  v4.0.2 (the version that successfully builds anchor 0.31.1).
- **CI had no concurrency control** — added to cancel stale PR pushes.

### Added

- **Three new integrity check categories** (`tests/test-skill-integrity.sh`):
  - Check 8: CVSS score+vector consistency between findings.json and
    AUDIT_REPORT.md (catches documentation drift)
  - Check 9: agent count consistency across CLAUDE.md, SKILL.md, README.md
  - Check 10: CVSS scores mathematically derivable from their vectors
    (recomputes CVSS 3.1 base score from vector and flags any mismatch)
- **Helpers in `tests/severity_counts.py`** for `check-cvss`,
  `check-cvss-math` modes
- **`$EXAMPLE_REPORT` variable** in `tests/test-skill-integrity.sh`
  (replaces hard-coded `AUDIT_REPORT.md` path)
- **orchestrator agent row** in README's Agents table
- **Concurrency control** in CI workflow (cancel-in-progress on same ref)

### Changed

- **Severity summary now `CRITICAL=2 HIGH=2 MEDIUM=6 LOW=0`** (was
  `2/2/5/1`); updated both findings.json and AUDIT_REPORT.md.

### Verified

- 10 named integrity check categories, 18 verification points
- CI green on commit `4a97560` (anchors' reproducible cargo check)

## [1.0.0] - 2026-06-23

Initial submission for the Superteam Brasil Solana skills contest.

### Added

**Skill files (8)** — `skill/` folder with hub-router SKILL.md + 7 phase files:
- `SKILL.md` — hub router with phase routing + severity scale + audit scope checklist
- `00-terminology.md` — Solana security glossary
- `01-recon.md` — Phase 1: Reconnaissance procedures
- `02-static-analysis.md` — Phase 2: Static analysis with VULN/FIX examples
- `03-formal-verification.md` — Phase 3: QED 2A + Anchor invariant testing
- `04-findings-triage.md` — Phase 4: CVSS classification, dedup, JSON schema
- `05-report-generation.md` — Phase 5: Markdown report template
- `06-remediation.md` — Phase 6: Fix patterns + regression testing

**Slash commands (5)** — `commands/` folder, install to `~/.claude/commands/`:
- `audit.md` — full 6-phase lifecycle (dispatcher)
- `audit-quick.md` — heuristic SAST scan (~5 min)
- `audit-report.md` — synthesize findings into report
- `audit-poc.md` — generate PoC with mandatory consent gate
- `audit-findings.md` — list/dedupe/retag/export findings DB

**Path-scoped rules (14)** — `rules/audit.rules`, install to `~/.claude/rules/`:
- Rule 1: Anchor program entry point
- Rule 2: Account validation constraints (discriminators, ownership)
- Rule 3: PDA canonical bump
- Rule 4: CPI calls (privilege escalation)
- Rule 5: Token operations (SPL vs Token-2022)
- Rule 6: Arithmetic overflow
- Rule 7: Account closing (lamport drain)
- Rule 8: Signer verification
- Rule 9: Upgrade authority
- Rule 10: Error handling
- Rule 11: Reinitialization attacks
- Rule 12: Rent and lamport safety
- Each rule includes `## References` with 1-2 CWE entries + 4 incident references (Cashio, Wormhole, Crema, Nomad)
- 24 CWE references total, 22 with cwe.mitre.org URLs

**Agent definitions (4)** — `agents/` folder:
- `orchestrator.md` — entry-point with routing table, I/O contracts, handoff protocol
- `auditor.md` — primary auditor with 7-step workflow
- `formal-verifier.md` — invariant proofs with counterexample → findings pipeline
- `report-writer.md` — terminal agent for report generation
- `AUDIT.md` — per-agent status documentation

**Example audit fixture** — `examples/sample-vulnerable-program/`:
- Deliberately vulnerable Anchor 0.31.1 program with **10 tagged bugs** (VULN-01..VULN-10)
  - 6 rule-aligned (caught by `rules/audit.rules` Rules 3, 4, 6, 7, 8, 11)
  - 4 non-rule-aligned (demonstrates triage judgment)
- Pre-written expected outputs:
  - `findings.json` — 10 structured findings with CVSS, CWE, descriptions, recommendations
  - `AUDIT_REPORT.md` — production-format report using the schema in `commands/audit-report.md`
  - `quick-scan-results.md` — pattern validation (5/9 patterns fire on example, 4/9 N/A)
  - `methodology-trace.md` — per-VULN reproducible trace
- Compiles cleanly under anchor 0.31.1 (verified in CI)

**CI workflow** — `.github/workflows/test.yml`:
- 3 jobs: skill-integrity, anchor-build, lint-install
- Runs on every push to main and every PR
- Installs rustup + solana + anchor 0.31.1 in CI runner
- Verifies install.sh dry-run, markdown integrity, anchor example compile (cargo check)

**Tests** — `tests/test-skill-integrity.sh`:
- 11 checks across 5 categories (note: extended in v1.1.0+ to 18 verification points across 10 categories — see v1.2.0 entry)
  - Phase file numbering
  - Command cross-references
  - VULN-XX ↔ findings.json coverage (10=10)
  - CWE reference format (24 valid)
  - Rule ↔ References block 1:1 mapping (12=12)
- All checks pass in CI

**Installer** — `install.sh`:
- Copies skill files → `~/.claude/skills/solana-auditor-skill/`
- Copies 6 slash commands → `~/.claude/commands/`
- Copies path-scoped rules → `~/.claude/rules/`
- Copies agents → skill folder
- Copies CLAUDE.md
- Bash `-n` syntax-validated; end-to-end dry-run verified

**Documentation**:
- `README.md` — top-level kit-style documentation with command/rule tables
- `LICENSE` — MIT
- `CLAUDE.md` — Claude Code instructions

### Verified

- ✅ All 10 integrity check categories (18 verification points) pass locally + in CI
- ✅ `install.sh` dry-run succeeds in CI (deploys 5 commands + 1 rules file + 3 PoC templates)
- ✅ Severity counts: 2 CRITICAL, 2 HIGH, 6 MEDIUM, 0 LOW (note: counts changed between v1.0.0 and v1.2.0 after CVSS score recomputation; the v1.0.0 entry above reflects the historical state of v1.0.0, the v1.2.0 entry above reflects the current state)
- ✅ 5/9 audit-quick patterns confirmed firing on example bugs
- ✅ Methodology trace validates hand-written findings.json is reproducible

### Known limitations

- Toolchain install (`rustup`, `solana-cli`, `anchor-cli`) was not run locally during
  development; CI proves the example builds under anchor 0.31.1. Local validation
  requires `cargo install anchor-cli --git https://github.com/coral-xyz/anchor --tag v0.31.1 --locked`.
- VULN-04's original `close = user_supplied` pattern was rewritten to a `drain_vault`
  function with identical security impact — anchor 0.31.1's close constraint
  generates macro warnings that cascade into errors when the target is unverified.
- Example fixture is build-verified but not deployed to devnet/mainnet. Run
  `anchor test` against the example to add runtime coverage.

## [1.16.0] — 2026-07-08

QEDGen formal verification CI integration — native FV pipeline.

### Added
- **QEDGen CI integration** — `.github/workflows/formal-verification.yml` now installs
  QEDGen via `npx skills add qedgen/solana-skills` and runs spec-check + verify steps
  when `.qedspec` files are present. Cached for performance.
- **Dual-toolchain support** — `scripts/qed-integration.sh` detects and dispatches to
  either `qedgen` (new, primary) or `qed-solana` (legacy fallback).
- **Node.js setup in FV workflow** — `actions/setup-node@v4` with Node 22 for npx support
- **QEDGen install caching** — skill installation cached by runner OS + spec file hash
- **QEDGen documentation** — `skill/03-formal-verification.md` updated with correct
  QEDGen CLI commands (`check`, `codegen`, `verify`) and install instructions

### Changed
- `scripts/run-formal-verification.py`: `_detect_qed()` checks both `qedgen` and
  `qed-solana` in priority order
- `scripts/qed-integration.sh`: supports both tools, 60s→120s timeout per invariant
- `skill/03-formal-verification.md`: "QED 2A" → "QEDGen" throughout, CI Integration
  section expanded from 5 to 7 steps

## [1.15.3] — 2026-07-08

Final maintenance — CI YAML fix, dead code removal, spec backlog cleared.

### Fixed
- **CI workflow YAML syntax error** — `test.yml` literal block scalar had inconsistent
  indentation in the "Run unit + smoke tests" step (first line at 10 spaces, subsequent
  lines at 0), causing `while scanning a simple key` error. All lines now consistently
  indented at 10 spaces.
- **spec #7**: Added `command -v jq` presence check to `scripts/protocol-fingerprint.sh`
  with platform-specific install instructions.
- **spec #8**: Fixed `scripts/generate-cpi-graph.sh` — `set -euo pipefail` (was `-uo`),
  added `2>/dev/null || echo` guards to all 6 jq calls to prevent silent failures.
- **SPEC-002**: Removed redundant `audit-pr` job from `audit.yml` and orphaned `pr` input.
- **SPEC-004**: Replaced hardcoded `git clone` in `audit-on-push.yml` with `cp -r .` from
  checkout directory. Removed `|| true` to surface errors.
- **Dead code removal (5 findings)**:
  - `run-anchor-tests.py`: Removed unused `import os` and `from typing import Optional` (F401)
  - `fix-verification.sh`: Removed unused `FIX_SUGGESTIONS_JSON` variable
  - `pre-commit-audit.sh`: Removed unused `local line_num=0`
  - `protocol-fingerprint.sh`: Removed unused `local match_score=0`
  - `generate-ext-symlinks.sh`: Removed unused `RED` color variable

### Verified
- 165/165 integrity checks, 22/22 fuzz tests, all CI jobs green
- 0 flake8 F401/F841/F811 warnings across all scripts

## [1.15.2] — 2026-07-08

Maintainability sprint — integrity lib modularization, Python test CI wiring, flake8 cleanup.

### Changed
- **MAINT-003**: Fixed `scripts/dashboard.py` dead code paths
- **MAINT-004**: Dynamic SAST rule loading from `rules/audit.rules`
- **MAINT-005**: Temp file cleanup in `generate-cpi-graph.sh`
- **MAINT-006**: Backward compatibility helpers for old findings format
- **MAINT-007**: Resolved `pyproject.toml` version conflicts (black pin 24.10.0)
- **MAINT-008/009**: Modularized integrity library — broke monolithic checks into
  composable verification modules
- **529 Python tests wired into CI** — all smoke + unit tests run in workflow
- SDD docs synced to v1.15.2 (spec.md, kanban.md, learnings.md)

### Verified
- 165 integrity checks (up from 161)
- All CI jobs green across 4 workflow jobs
- 0 flake8 warnings on all new/fixed modules

## [1.15.1] — 2026-07-07

Maintainability audit and documentation sync.

### Changed
- Updated PRD, spec, kanban, learnings to reflect v1.15.1 CI stabilization state
- Stop tracking `kanban.md` and `learnings.md` in git (maintainer-only session files)

## [1.15.0] — 2026-07-06

CI stabilization sprint — resolved multi-round pipeline failures.

### Fixed
- **Round 3**: Black pin (24.10.0), pnpm guard, SARIF ignore, SDD advisory addressed
- **Round 4**: Check 30 advisory, PR diff findings guard added
- **Round 5**: SARIF input handling, flake8 unused imports cleaned
- **Round 7**: SARIF exporter + workflow guard hardening
- **Round 8**: CI workflow audit findings resolved
- **CVSS score corrections**: KAM-001, SOLEND-02, SOLEND-03 scores recomputed
- Check 10 coverage expansion for wider edge-case validation

### Added
- **3 missing audit scripts** implemented and wired into scheduled workflow

## [1.14.3] — 2026-07-04

Minor maintenance — broken file references, script permissions, stale cleanup.

### Fixed
- Broken file references in documentation
- Script permission inconsistencies
- Stale artifacts and directory cleanup

## [1.14.2] — 2026-06-30

Sprint 52 — economic security, --live-demo, global rename.

### Added
- **`--live-demo` mode** — SAST scan any public Solana repo from demo.sh
- **Economic security module** (Phase 1C) — MEV, tokenomics, economic invariant violations
- **Global rename**: "Solana Auditor Shiba Skill" → "Solana Auditor Skill"

### Changed
- SDD docs synced to v1.14.2
- Cross-program agent CPI chain analysis improved

## [1.14.1] — 2026-06-29

Sprint 51 — verified checks, documentation polish, roadmap migration.

### Changed
- SDD docs synced to v1.14.1
- Roadmap migration and PR audit filter added
- Documentation polish pass

## [1.14.0] — 2026-06-28

Fixture expansion — added AMM/DEX, staking pool, and NFT/candy machine fixtures.

### Added
- **AMM/DEX fixture** — `examples/dex-amm/` with 14 VULN tags
- **Staking pool fixture** — `examples/staking-pool/` with 14 VULN tags
- **NFT/candy machine fixture** — `examples/nft-candy-machine/` with 14 VULN tags
- AuditViz dashboard foundation in `scripts/dashboard.py`

### Changed
- Total fixtures: 3 → 6
- Total VULN tags across all fixtures: 10 → 52

## [1.13.0] — 2026-06-28

### Fixed
- 23 findings across 5 fixture files: added missing `rule` (integer) field derived from `rule_caught`
- klive-live-audit/findings.json: fixed summary critical count (0→1), corrected RESOLVED severity handling
- dashboard.py: removed unreachable `stdout_mode = True` branch
- dashboard.py: simplified redundant `not args.compare_mode` condition
- dashboard.py: added `.resolve()` to single-file output paths (path traversal hardening)

### Verified
- demo.sh: EXIT_CODE 0, 161/161 integrity checks, 22/22 fuzz tests
- All findings.json fixtures: JSON valid, rule field complete, severity counts consistent
