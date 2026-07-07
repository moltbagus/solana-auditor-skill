# PRD — Solana Auditor Skill

> **Product Requirements Document**
> _Superteam Brasil Solana Skills Contest — v1.15.2_
> Last updated: 2026-07-07

---

## 1. Vision

Transform Claude Code into the **gold-standard Solana security auditor** — a reproducible, methodology-driven, contest-grade tool that any Solana developer can run against their Anchor programs to get production-quality audit reports with CVSS-scored findings, formal verification integration, and remediation guidance.

## 2. Target Users

| Persona | Need | How the Skill Serves |
|---------|------|---------------------|
| Solana dApp developer | Quick security check before mainnet deploy | `/audit-quick` — 5 min SAST scan |
| Solana audit firm | Structured audit methodology + reporting | `/audit` — 7-phase lifecycle |
| Security researcher | Finding validation + PoC generation | `/audit-poc` — consent-gated exploit |
| Contest judge | Evaluate skill quality + completeness | Demo script, 161 integrity checks, 22 fuzz tests |
| Brazilian dev | Solana security in their native language | PT-BR glossary + terminology |

## 3. Features

### Core (v1.0 — Shipped)
- [x] 6-phase audit lifecycle (Recon → Remediation)
- [x] 9 slash commands (`/audit`, `/audit-quick`, `/audit-resume`, `/audit-report`, `/audit-poc`, `/audit-findings`, `/audit-resume`, and more)
- [x] 50 path-scoped rules (auto-activate on file patterns)
- [x] 7 specialist agents (orchestrator, auditor, formal-verifier, report-writer, cross-program, safety-guard, threat-modeler)
- [x] Dual example fixtures: vault (10 bugs) + token-extensions (6 bugs)
- [x] CVSS 3.1 scoring with math verification
- [x] 62 integrity checks (all passing)
- [x] CI pipeline (3 jobs: integrity + build + lint)

### Enhanced (v1.1–v1.3)
- [x] PoC templates (Anchor, TypeScript, Manual)
- [x] CVSS data integrity: 7 scores recomputed, 3 severities corrected
- [x] Install script copies templates + verifies skill path
- [x] Agent YAML frontmatter for all 6 agents
- [x] Property-based testing harness with Hypothesis fuzz strategies
- [x] Token-2022 example fixture (VULN-11 through VULN-16)
- [x] Brazilian Portuguese terminology support
- [x] Demo/quickstart script for contest judges (`bash demo.sh`)
- [x] SDD documentation (PRD.md, spec.md, kanban.md, learnings.md)

### World-Class (v1.4.0)
- [x] 5 new security rules: flash loan, reentrancy, remaining_accounts, discriminator collision, AccountLoader
- [x] CWE reference corrections across Rules 3, 5, 7, 10, 14
- [x] Formal verification demo with 5 invariant test patterns
- [x] 3 exploit PoC walkthroughs (admin drain, reinit, flash loan)
- [x] SARIF export for GitHub Code Scanning
- [x] Concurrent-run lock file protection
- [x] Resume/checkpoint command (`/audit-resume`)
- [x] Real spl_token_2022 vulnerable program (VULN-17)
- [x] Corporate-grade type hints + Python 3.9 compat
- [x] 62 integrity checks (up from 49)
- [x] Dynamic counts (no stale numbers in demo)

### World-Class v1.7.0
- [x] 50 security rules (up from 26): type confusion, UncheckedAccount, CPI signer propagation, PDA signer confusion, mint authority bypass, delegate authority abuse, close authority drain rev2, token metadata tampering, confidential transfer fee leak, Transfer Hook rules, Pinocchio native coverage, agent safety guardrails, and 38 more
- [x] Phase 0 safety guard: pre-audit safety checks before any analysis runs
- [x] Phase 2B (Runtime Verification): CPI surface graph + runtime analysis
- [x] Two-tier execution model: Tier 1 (SAST-only) vs Tier 2 (full runtime)
- [x] 6 specialist agents: orchestrator, auditor, formal-verifier, report-writer, cross-program, safety-guard
- [x] CPI surface graph output with cross_program_findings.json
- [x] Runtime findings output with runtime_findings.json
- [x] Helius API integration for transaction replay
- [x] cargo-audit integration for dependency vulnerabilities
- [x] QED 2A fallback chain: QED → Anchor test → manual assertion
- [x] Agent safety guardrails: preventing harmful operations during audit
- [x] 75+ integrity checks (up from 62, now 161)
- [x] 50 security rules (up from 26)
- [x] 7 phases (Phase 0 safety guard + Phases 1–6)

### v1.8.1 — Dashboard + Exploit Simulation (2026-06-27)
- [x] HTML audit dashboard: `scripts/dashboard.py` + `templates/dashboard.html`
- [x] demo.sh step 7: generates HTML dashboard automatically
- [x] `/audit-report --html`: generates markdown + HTML in one pass
- [x] `scripts/audit-report.py`: standalone CLI for markdown + HTML generation
- [x] All 9 commands: `name:` frontmatter added for Claude Code registration
- [x] Bug fixes: exit logic, FUZZ_COUNT, heredoc quoting verified clean
- [x] CLAUDE.md rewrite — v1.13.0: correct agent count (10), phase files (12), rule groups, Two-Tier model, fixture schema with rule/recommendation fields, pytest command fix, key gotchas
- [x] Post-contest backlog: 8 gaps identified, 5 priority items planned
- [x] Gap analysis + priority backlog: `docs/superpowers/specs/2026-06-27-gap-analysis.md`
- [x] `docs/superpowers/specs/2026-06-27-priority-backlog.md`: 5 items, 4 new files

### v1.8.0 — Kit Submission (2026-06-26)
- [x] **Solana AI Kit submission repo** at `github.com/moltbagus/solana-auditor-skill`
- [x] Restructured for kit fit: `skill/`, `agents/`, `commands/`, `rules/` at root
- [x] MIT license (clean, permissive)
- [x] Root `SKILL.md` as progressive routing entry point
- [x] Clean `README.md`: what it does, install, quick-start
- [x] `install.sh`: idempotent, installs skill + commands + rules
- [x] `demo.sh`: no toolchain, < 30s, proves it works
- [x] `tests/test-skill-integrity.sh`: 32 kit-relevant checks (structure, routing, agents, commands, rules, license, README)
- [x] `tests/fuzz/test_properties.py`: 22 CVSS property-based tests (port from source)
- [x] CI: lint-install + integrity + fuzz (no anchor build — kit-compatible)
- [x] Phase 0 safety guard as standalone `skill/00-safety-guard.md`
- [x] All 50 rules, 6 agents, 9 commands, 9 phase files preserved

### v1.12.0 — Contest Sprint (2026-06-28)
- [x] pytest invocation fix — 22/22 fuzz tests now run
- [x] README rule descriptions corrected — Rules 27-35 Token-2022, Rules 36-45 Account Validation
- [x] HTML dashboard screenshot — visual proof in README
- [x] PT-BR guide — guides/pt-BR/AUDITORIA_GUIA.md
- [x] Benchmark table — vs solhint, cargo audit, manual review
- [x] GitHub Actions template — .github/workflows/audit-on-push.yml
- [x] Before/After dashboard comparison
- [x] Live exploit audit — historical Solana exploit documented
- [x] CI fuzz tests verified — 22/22 pass in CI


### v1.13.0 — Bug Fix Sprint + CLAUDE.md Rewrite (2026-06-28)
- [x] Post-submission code audit — 4 parallel subagents, demo.sh + all fixtures
- [x] 23 findings fixed: added missing `rule` (integer) field across 5 fixture files
- [x] klive-live-audit summary corrected: critical=0→1, RESOLVED severity preserved
- [x] dashboard.py: removed unreachable stdout_mode branch, simplified condition, added .resolve()
- [x] CLAUDE.md rewrite: fixed stale version/rule counts, added Two-Tier model, correct agent/phase counts, fixture schema with `rule`+`recommendation` fields, pytest command fix, key gotchas
- [x] demo.sh: EXIT 0, 161/161 integrity, 22/22 fuzz — all verified
- [x] SDD docs updated: PRD.md, spec.md, kanban.md, learnings.md → v1.13.0

### v1.14.0 — Fixture Expansion Sprint (2026-06-29)
- [x] AMM/DEX fixture — `examples/dex-amm/`: 14 vulnerabilities across 3 programs (amm, swap, oracle), covering Rules 14, 15, 26, 13, 6, 4, 8, 40, 38, 36, 37
- [x] Staking Pool fixture — `examples/staking-pool/`: 14 vulnerabilities across 3 programs (staking, rewards, delegation), covering Rules 14, 22, 41, 6, 8, 11, 5, 15, 4, 38, 3, 36, 37
- [x] NFT/Candy Machine fixture — `examples/nft-candy-machine/`: 14 vulnerabilities across 3 programs (candy-machine, nft-minter, metadata), covering Rules 16, 40, 2, 8, 6, 14, 5, 33, 22, 38, 27, 39, 4, 37
- [x] All 42 new findings have mathematically verified CVSS 3.1 scores (brute-forced against `severity_counts.py` formula)
- [x] All 42 new findings have correct severity summaries matching actual counts
- [x] All 3 fixtures include findings.json, AUDIT_REPORT.md, methodology-trace.md, quick-scan-results.md


### v1.14.2 — Contest Polish Sprint (2026-06-29)
- [x] OODA loop: parallel subagent audits for structural, competitive, corporate-grade review
- [x] Removed 77 stale files: ext/solana-auditor-shiba/, package/, gan-harness/, benchmarks/, docs/superpowers/, skills/, prompts/bug-fixer-agent.md
- [x] Added skill-registry.json with 4 judging criteria mapped to features
- [x] Removed committed Cargo.lock files from examples/klend/ (added **/Cargo.lock to .gitignore)
- [x] README: added "Why This Wins" section mapping to 4 judging criteria + competitor comparison
- [x] SKILL.md: added Phase 0 routing, version v1.14.2, agents count corrected to 10, Phase 2A entry added
- [x] CLAUDE.md: version v1.14.2
- [x] README.md: fixed safety-anchor.md (non-existent) → safety-guard.md, "8-phase" → "7-phase"
- [x] demo.sh: added visible cat <<EOF commands block; 8-phase → 7-phase
- [x] install.sh: || true silent failures → explicit exit 1; find counts added
- [x] orchestrator.md: malformed response + partial failure handling added to handoff contract
- [x] PRD.md: duplicate v1.14.0 section removed; 07-architecture-review.md → 01B-architecture-review.md
- [x] Git tag v1.14.2 created and pushed
- [x] 161/161 integrity + 22/22 fuzz tests verified clean
- [x] Self-fixing loop: persistent correction rules at ~/.claude/corrections/solana-auditor-skill/

### v1.14.2 Command Audit Sprint (2026-06-30)
- [x] 2 senior engineers audited all 9 commands (Phase 0-3 and Phase 4-6 in parallel)
- [x] 18 issues found across Phase 0-6 commands; 15 were subagent hallucinations
- [x] 3 real HIGH issues verified + fixed:
  - SKILL.md: loop_state.json → phase-state.json (matches audit-resume.md)
  - audit-report.md: dashboard.py invocation wrong (<output-dir>/ → <file>.html)
  - audit-findings.md: search path audit-report/findings.json → audit-output/findings.json
- [x] Key lesson: always test -f before accepting subagent filesystem claims
- [x] README: co-creator credit added — "Co-created by sirshibaninja and Claude Code"
- [x] .gitignore: added `.claude/worktrees/`
- [x] Secrets scan: 0 real secrets — all matches verified safe (public program IDs, Rust seed paths, example placeholders)
- [x] Shiba rename sprint: "Solana Auditor Shiba Skill" → "Solana Auditor Skill" across 7 files (6 repo + PT-BR guide)
- [x] todo.md removed: Kamino-specific content migrated to learnings.md

### v1.14.3 — Repository Hygiene Sprint (2026-07-03)
- [x] Fixed 2 broken file references: SKILL.md (lines 44, 68) and CLAUDE.md (line 54) referenced non-existent `02A-threat-modeling.md` → corrected to `02-threat-modeling.md`
- [x] learnings.md corrected: previous entry dismissed subagent's broken-ref claim as "hallucination" — it was actually a real bug
- [x] `scripts/run-sast.py`: added STALE WARNING — hardcodes 26 rules but `rules/audit.rules` has 50 (Rules 27-50 not covered by automated engine)
- [x] `chmod +x` on `scripts/qed-integration.sh` + 7 Python scripts (only `run-anchor-tests.py` was executable)
- [x] `skill/SPEC-REMEDIATION.md`: marked as Archived — 599-line draft spec from v1.7 never promoted
- [x] Cleaned stale untracked output dir: `examples/sample-vulnerable-program/audit-report/`
- [x] 161/161 integrity checks + 22/22 fuzz tests verified clean post-fixes

### Stretch (Future)
- [x] Line-number drift integrity check (Check 20) — implemented v1.14.2
- [ ] Multi-program audit aggregation
- [ ] Native qed-solana CI integration (dependency of QED 2A)
- [ ] Economic Security module (standalone DeFi attack analysis)
- [x] Architecture Review module (standalone component analysis) — implemented as `skill/01B-architecture-review.md` + `agents/architecture-reviewer.md`

### v1.11.0 — Architecture Review + Report Enhancement (2026-06-27)

Following Loop 3 feedback, added two post-contest backlog items as a single sprint.

- [x] **Architecture Review Module** (`skill/07-architecture-review.md` + `agents/architecture-reviewer.md`) — Standalone component analysis phase using attack surface decomposition: entry point enumeration, trust boundary mapping, component dependency graph, and data flow analysis. Maps findings to architectural layers (instruction dispatch, account validation, state management, CPI interface, token operations).
- [x] **Report Generator Enhancement** — Three missing sections added to `AUDIT_REPORT.md` template: (1) **Executive Summary** with severity-at-a-glance table and risk posture statement, (2) **Methodology Trace** cross-referencing each phase to its output artifact, (3) **Finding Distribution** with severity breakdown table and CVSS vector summary per finding.
- [x] **Architecture-reviewer agent** — 8-step analysis flow: entry point enumeration, trust boundary mapping, component dependency graph, data flow analysis, architectural hotspot identification, architectural weakness assessment, mitigation recommendations, architecture findings export.
- [x] **Phase 7 procedure** (`skill/07-architecture-review.md`) — Phase 7 standalone procedure document covering all 8 analysis steps.
- [x] **Report template** (`templates/report-template.md`) — Updated with Executive Summary, Methodology Trace, Finding Distribution sections.
- [x] **Integrity checks 38–40** — Phase 7 presence check, architecture-reviewer agent check, report template section checks.
- [x] **SDD docs updated** — PRD.md, spec.md, kanban.md, learnings.md updated to v1.11.0.

### v1.10.0 — Remediation Engine Full Upgrade (2026-06-27)

Following the Loop 2 contest judges feedback, the Remediation Engine received a complete overhaul with root cause analysis and regression test support.

- [x] **Phase 6 Root Cause Analysis Layer** — Every fix suggestion now includes a structured `root_cause` field (missing validation, incorrect state transition, unchecked external call, race condition, unchecked arithmetic) with the specific line/function and a plain-language explanation of *why* this code path is dangerous
- [x] **Regression test generation** — `audit-fix-suggestions.py --regression` emits a basic Anchor test stub per finding (if Anchor.toml detected) or a plain Rust test stub (standalone). Each stub includes the exploit precondition, the vulnerable code path commented inline, and an `#[test]` that verifies the fix
- [x] **Fix difficulty rating** — Each finding now carries a `difficulty` field: `trivial` (add one check), `moderate` (restructure logic), `complex` (state machine refactor). Guides operator effort estimation
- [x] **CVSS-adjusted priority ordering** — Remediation suggestions are now sorted by CVSS descending within each severity tier, and severity tiers are sorted CRITICAL > HIGH > MEDIUM > LOW > INFO
- [x] **Integrity checks updated** — Check 17 and Check 20 updated to validate the new fields (`root_cause`, `difficulty`, `regression_test_path`) across all three fixture findings.json files
- [x] **Phase 6 procedure (`06-remediation.md`)** — Updated to document the new remediation metadata fields, the regression test generation flow, and the priority ordering logic

### v1.9.0 — Threat Modeling + Exploit Simulation Framework (2026-06-27)
- [x] **Phase 2A: Threat Modeling** — STRIDE methodology with 6 threat categories (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Privilege Escalation)
- [x] **Threat modeler agent** (`agents/threat-modeler.md`) — 7-step threat identification flow with trust boundary mapping
- [x] **Exploit simulation framework** — Structured PoC metadata per finding with preconditions, steps, expected outcome, actual outcome, exploitability score, and remediation verification
- [x] **3 PoC metadata JSON files** — `examples/vault/exploit-metadata.json`, `examples/token-extensions/exploit-metadata.json`, `examples/token-2022-real/exploit-metadata.json`
- [x] **exploit_metadata schema** — Canonical schema for structured exploit documentation
- [x] **`/audit-poc` enhancements** — `--metadata` flag for structured output, `--full` flag for complete exploit report, `--explain` for step-by-step analysis
- [x] **`06-remediation.md` updates** — exploit_metadata schema documentation, remediation blocks for each exploit metadata field
- [x] **`audit-fix-suggestions.py` updates** — `--explain` flag for root cause + fix rationale, `--metadata` flag for structured output

## 4. Success Metrics

| Metric | Target | Current | How Measured |
|--------|--------|---------|-------------|
| Integrity checks passing | 100% (165+) | 165/165 | `test-skill-integrity.sh` exit 0 |
| Vulnerability coverage | ≥50 classes | 50 rules | `grep "^## Rule " rules/audit.rules` |
| CVSS math accuracy | 100% | 50/50 verified | `check-cvss-math` integrity check |
| Security rules | ≥50 | 50 | `grep "^## Rule " rules/audit.rules` |
| Property-based tests | ≥15 invariants | 22 passing | Fuzz harness results |
| Contest judge clarity | Self-contained demo | `bash demo.sh` < 30s | Run from clean clone |
| CI green on every commit | 100% | ✅ | GitHub Actions status badge |
| Tier 1 SAST coverage | All major vuln classes | 50 rules | Static analysis phase |
| Tier 2 Runtime coverage | CPI + transaction replay | Phase 2B | Cross-program agent |

## 5. Architecture

```
User → Claude Code CLI
  └─ solana-auditor-skill skill
      ├─ agents/orchestrator.md  (router)
      │   ├─ agents/auditor.md           (primary audit, Phase 1, 2, 2B)
      │   ├─ agents/formal-verifier.md   (invariant proofs, Phase 3)
      │   ├─ agents/report-writer.md     (report generation, Phase 5)
      │   └─ agents/cross-program.md      (CPI surface graph, Phase 2B)
      │   └─ agents/safety-guard.md     (agent safety guardrails, Phase 0) [NEW]
      ├─ commands/                       (9 slash commands)
      ├─ rules/                          (50 path-scoped rules) [EXPANDED]
      ├─ skill/                          (8 phase procedures) [EXPANDED]
      │   ├─ skill/00-safety-guard.md   (Phase 0) [NEW]
      │   ├─ skill/01-recon.md           (Phase 1)
      │   ├─ skill/02-static-analysis.md (Phase 2)
      │   ├─ skill/02b-runtime.md        (Phase 2B)
      │   ├─ skill/03-formal-verification.md (Phase 3)
      │   ├─ skill/04-findings-triage.md (Phase 4)
      │   ├─ skill/05-report-generation.md (Phase 5)
      │   └─ skill/06-remediation.md     (Phase 6)
      ├─ tests/                          (75+ integrity checks + 19 fuzz tests)
      ├─ scripts/export-sarif.py          (SARIF export for Code Scanning)
      ├─ scripts/helius-replay.py        (Helius transaction replay) [NEW]
      └─ examples/                       (3 vulnerable fixtures: vault, Token-2022, real Token-2022)
```

### 5.1 Two-Tier Execution

| Tier | Requires Toolchain | Phases Run | Output |
|------|-------------------|------------|--------|
| Tier 1 | No | 1, 2, 4, 5, 6 | findings.json, AUDIT_REPORT.md |
| Tier 2 | Yes (Anchor, Solana CLI) | 1, 2, 2B, 3, 4, 5, 6 | + runtime_findings.json, cross_program_findings.json |

## 6. Non-Goals

- Real exploit execution against mainnet (consent-gated)
- Auto-applying security fixes (operator reviews)
- Native Solana program compilation without toolchain
- Replacing human auditor judgment
- Live deployment or on-chain interaction

## 7. Contest-Specific Goals

For the **Superteam Brasil Solana Skills Contest**:

1. **Judge-ready** — A judge can clone, `./demo.sh`, and evaluate in < 2 min
2. **Brazil-friendly** — Portuguese glossary + PT-BR audit guide for Brazilian devs
3. **Comprehensive** — Covers ALL major Solana vulnerability classes across 3 fixtures
4. **Correct** — All data mathematically verified (CVSS, counts, file references, methodology trace)
5. **Professional** — Production-grade CI, documentation, SRP codebase, maximal test coverage
6. **World-class** — Formal verification demo, PoC exploit walkthroughs, SARIF export, concurrent protection, two-tier execution, CPI surface analysis
7. **Dashboard proof** — HTML dashboard screenshot in README as visual evidence
8. **GH Actions template** — Audit-on-push workflow template for contest submissions
8b. **Why This Wins** — Explicit "Judging criteria mapped to evidence" section in README
9. **Immunefi submissions** — 5 real bugs filed against Kamino Finance and Solend Governance
10. **git tag v1.14.2** — Canonical version pushed to origin/main
9. **Live exploit audit** — Historical Solana exploit documented for real-world context
10. **Benchmarked** — Comparative table vs solhint, cargo audit, and manual review

## 8. New Features in v1.5.0

### 8.1 Phase 2B: Runtime Verification

Phase 2B bridges SAST and dynamic analysis:

1. **CPI Surface Graph** — Enumerate all cross-program invocations
2. **Transaction Replay** — Use Helius API to replay historical transactions
3. **Runtime Assertions** — Verify state transitions against expected invariants
4. **Dependency Scan** — Run `cargo audit` for known vulnerabilities

### 8.2 Cross-Program Agent

Dedicated agent for inter-program security analysis:

- Maps all `invoke`/`invoke_signed` calls
- Identifies privilege escalation paths
- Detects unchecked program IDs
- Tracks signer propagation through CPI chain

### 8.3 CPI Surface Graph

Output format:
```json
{
  "cpi_surface": {
    "total_cpi_calls": 12,
    "programs_invoked": ["TokenkegQ...", "ATokenGPv..."],
    "unchecked_programs": ["MarBms..."],
    "signer_propagation_paths": [
      {"from": "vault", "to": "bridge", "accounts": ["admin_pda"]}
    ]
  }
}
```

### 8.4 QED 2A Fallback Chain

```
┌─────────────┐
│  QED 2A    │──► Primary: Formal invariant proofs
│ (installed) │
└──────┬──────┘
       │ not found
       ▼
┌─────────────┐
│  Anchor     │──► Secondary: Integration test suite
│  (installed)│
└──────┬──────┘
       │ not found
       ▼
┌─────────────┐
│  Manual     │──► Tertiary: Static analysis + assertions
│  Assertions │
└─────────────┘
```

### 8.5 Helius API Integration

Recon phase fetches program accounts and transaction history:

```bash
# Helius Enhanced DPRC
curl -X POST https://mainnet.helius-rpc.com/?key=YOUR_KEY \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"getProgramAccounts","params":[...],"useStakedRPC":true}'
```

### 8.6 cargo-audit Integration

Dependency vulnerability scanning in Recon phase:

```bash
cargo audit 2>/dev/null || echo "No cargo-audit available — skipping dependency scan"
```

---

## v1.15.0 — Current State (2026-07-06)

### Post-contest fork stabilization: 8 rounds of CI fixes

The `moltbagus/solana-auditor-skill` fork on `main` had 10 consecutive red CI runs as of 2026-07-05. Diagnostic + remediation completed 2026-07-06 across 8 atomic commits.

### Headline result

| Run wave | Trigger SHA | Workflows green | Workflows red |
|---|---|---|---|
| Pre-fix baseline | `acfb115f` | 0/10 | 10/10 |
| After round 7 | `78a6967` | 3/3 | 0/3 |
| After round 8 | `491bc09` | **4/4** | **0/4** |

### CI failure root causes addressed

1. **Missing third-party GitHub Actions** — `solana-actions/setup-solana@v1`, `github/code-scanning-action@latest` (both deprecated/removed)
2. **Missing Python scripts** — `find-programs.py`, `run-formal-verification.py`, `triage-findings.py` referenced but never committed
3. **Phantom `hull-scope` Cargo subcommand** — referenced in Phase 2 but doesn't exist in any registry
4. **Wrong SARIF input name** — `if-no-files-found: ignore` is `actions/upload-artifact`-only, not `codeql-action/upload-sarif`
5. **Python env drift** — `pytest` not preinstalled on `ubuntu-latest`; black version drift between local and CI
6. **macOS-only case-insensitivity** — `SPEC.md` matches on local dev but fails on case-sensitive CI filesystem
7. **Recursive `gh workflow run`** — `audit-pr` job ran on `push` events, looping the audit workflow
8. **Python lint drift** — unused imports + untyped code in re-formatted files

### New artifacts

| File | LOC | Purpose |
|---|---|---|
| `scripts/find-programs.py` | 349 | Phase 1: attack-surface recon |
| `scripts/run-formal-verification.py` | 429 | Phase 3: QED/anchor test wrapper |
| `scripts/triage-findings.py` | 527 | Phase 4: severity-rank + CVSS recompute |
| `tests/test_scripts_smoke.py` | 319 | 13 pytest cases for new scripts |

### Backlog for v1.15.x

| Priority | Item | Effort | Status |
|---|---|---|---|
| P1 | Wire `tests/test_scripts_smoke.py` into `test.yml` so smoke tests run on CI | XS | TODO |
| P1 | Replace `[SKIP] hull-scope` placeholder in `audit-scheduled.yml` Phase 2 with a real static-analysis scan (ripgrep-based) — DONE in round 8 | — | ✅ |
| P2 | Decide: keep audit.yml `audit-pr` job (now guarded) or remove as dead code | S | TODO |
| P2 | Migrate `codeql-action/upload-sarif@v4` (v3 deprecation Dec 2026) | XS | DONE |
| P2 | Address Node 20 deprecation warnings (set `ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION=true` or migrate) | XS | TODO |
| P3 | Workflow name collision audit — re-check after rename round 8 | S | DONE |
| P3 | `formal-verification.yml` chained `&&` in `if:` — moved into shell `command -v anchor` | S | DONE |
| P3 | `audit-on-push.yml` hardcoded clone of `moltbagus/solana-auditor-skill` — race with in-repo `skill/` | M | TODO |

### v1.15.1 — CVSS Math Drift Fix + Check 10 Coverage Expansion (2026-07-07)
- [x] CVSS score corrections on 3 live-exploit findings:
  - KAM-001: 9.1→8.8 (PR:L scope-U = 0.62, not 0.50)
  - SOLEND-02: 7.5→6.5 (C:H I:N A:N → ISS = 0.56, not 0.81)
  - SOLEND-03: 7.3→7.5 (C:N I:H A:N → ISS = 0.56, not 0.46)
- [x] Check 10 (CVSS math verification) expanded to cover all 5 fixtures including solend-governance + klive-live-audit — was only running against 3 of 5 fixtures
- [x] Missing-foundation guard: Check 10 now skips absent fixtures (ok) instead of failing — removing an example never breaks CI
- [x] 165/165 integrity checks (up from 161: +4 from extended coverage)
- [x] 22/22 fuzz tests, all CVSS math verified across all 5 fixture dirs

### v1.15.2 — Maintainability Sprint: Refactoring + Test Expansion (2026-07-07)

Following the maintainability audit's 11-item issue catalog, the top 2 P1 items were completed in this sprint.

#### MAINT-001: Split `scripts/audit-fix-suggestions.py` into modules ✅
- **Before**: 3,535 lines, monolithic, 11 flake8 warnings
- **After**: 7 files, clean SRP architecture:
  - `fix_constants.py` (229 lines) — 26 rule metadata tables
  - `fix_models.py` (127 lines) — Dataclasses: FixSuggestion, RemediationBlock, FixSuggestionsOutput
  - `fix_templates.py` (836 lines) — 26 fix templates (before/after code + explanations)
  - `fix_confidence.py` (211 lines) — Confidence scoring, tier classification, CVSS estimation
  - `fix_regression.py` (182 lines) — VULN-specific regression test generators
  - `fix_exploit.py` (114 lines) — Exploit metadata generation + file writing
  - `audit-fix-suggestions.py` (510 lines) — CLI orchestrator (argparse + delegation only)
- **Tests**: 472 tests across 7 test files (test_fix_constants, test_fix_models, test_fix_templates, test_fix_confidence, test_fix_regression, test_fix_exploit, test_fix_orchestrator)

#### MAINT-002: Deduplicate SARIF exporters ✅
- **Before**: `export-sarif.py` (210 lines) + `findings-to-sarif.py` (215 lines) — 90% code duplication
- **After**: `sarif_core.py` (~200 lines) shared module + both scripts as thin CLI wrappers (~60 lines each)
- **Backward compatible**: `export-sarif.py` preserves plain IDs, `findings-to-sarif.py` preserves SHIBA- prefix
- **Tests**: 44 tests in test_sarif_core.py covering all functions + vault fixture integration

#### Validation
- [x] 0 flake8 warnings across all new/changed files
- [x] **516 new unit tests** (472 fix_* + 44 sarif_core) + 13 existing smoke tests = **529 total Python tests**
- [x] 165/165 integrity checks + 22/22 fuzz — all verified clean
- [x] All 4 SDD docs updated to v1.15.2

### Backlog for v1.15.x (updated)

| Priority | Item | Effort | Status |
|---|---|---|---|
| P1 | Wire `tests/test_scripts_smoke.py` into `test.yml` | XS | TODO |
| P1 | Split `scripts/audit-fix-suggestions.py` (>120KB) into modules | M | ✅ DONE |
| P1 | Deduplicate SARIF exporters: `export-sarif.py` ↔ `findings-to-sarif.py` | S | ✅ DONE |
| P2 | Fix `scripts/dashboard.py` dead code + confusing argparse | S | TODO |
| P2 | Migrate `scripts/run-sast.py` to dynamically read patterns from `audit.rules` | M | TODO |
| P3 | Fix temp file cleanup in `scripts/pre-commit-audit.sh` | XS | TODO |
| P3 | Add `bc` check to `scripts/fix-verification.sh` | XS | TODO |
| P3 | Fix `pyproject.toml` version conflicts (py39 vs py310) | XS | TODO |

Full catalog: see learnings.md 2026-07-07 entry.

### Out of scope (intentionally not fixed)

- New bug class: `hull-scope` doesn't exist upstream — fallback uses ripgrep over `rules/audit.rules` instead
- `audit.yml` `audit-tier1` and `audit-quick.yml` duplicate `pre-commit-audit.sh` invocation — both run on push, harmless but wasteful

