# PRD — Solana Auditor Shiba Skill

> **Product Requirements Document**
> _Superteam Brasil Solana Skills Contest — v1.6.0 FINAL_
> Last updated: 2026-06-26

---

## 1. Vision

Transform Claude Code into the **gold-standard Solana security auditor** — a reproducible, methodology-driven, contest-grade tool that any Solana developer can run against their Anchor programs to get production-quality audit reports with CVSS-scored findings, formal verification integration, and remediation guidance.

## 2. Target Users

| Persona | Need | How the Skill Serves |
|---------|------|---------------------|
| Solana dApp developer | Quick security check before mainnet deploy | `/audit-quick` — 5 min SAST scan |
| Solana audit firm | Structured audit methodology + reporting | `/audit` — 6-phase lifecycle |
| Security researcher | Finding validation + PoC generation | `/audit-poc` — consent-gated exploit |
| Contest judge | Evaluate skill quality + completeness | Demo script, 62 integrity checks, 19 fuzz tests |
| Brazilian dev | Solana security in their native language | PT-BR glossary + terminology |

## 3. Features

### Core (v1.0 — Shipped)
- [x] 6-phase audit lifecycle (Recon → Remediation)
- [x] 6 slash commands (`/audit`, `/audit-quick`, `/audit-resume`, `/audit-report`, `/audit-poc`, `/audit-findings`)
- [x] 17 path-scoped rules (auto-activate on file patterns)
- [x] 4 specialist agents (orchestrator, auditor, formal-verifier, report-writer)
- [x] Dual example fixtures: vault (10 bugs) + token-extensions (6 bugs)
- [x] CVSS 3.1 scoring with math verification
- [x] 62 integrity checks (all passing)
- [x] CI pipeline (3 jobs: integrity + build + lint)

### Enhanced (v1.1–v1.3)
- [x] PoC templates (Anchor, TypeScript, Manual)
- [x] CVSS data integrity: 7 scores recomputed, 3 severities corrected
- [x] Install script copies templates + verifies skill path
- [x] Agent YAML frontmatter for all 4 agents
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

### World-Class v1.5
- [x] Phase 2B: Runtime verification with two-tier execution (Tier 1 SAST / Tier 2 full)
- [x] 9 new security rules (Rules 18-26): BorshDeserialize panic, Anchor verify/address bypass, Token-2022 extension ordering, CPI callback reentrancy, init_if_needed + close race, memo CPI injection, remaining_accounts count mismatch, versioned LUT manipulation, cross-program flash loan
- [x] Cross-Program Analysis Agent: CPI graph traversal, flash loan path detection, callback reentrancy
- [x] CPI surface graph generator (scripts/generate-cpi-graph.sh)
- [x] cargo-audit integration for supply chain CVE scanning
- [x] Helius API integration for on-chain program state analysis
- [x] QED 2A fallback chain in Phase 2B
- [x] 81 integrity checks (up from 62)

### World-Class v1.6 Automation
- [x] PR audit command (`/audit-pr`) — diff-based targeting of changed files
- [x] Pre-commit hook (scripts/pre-commit-audit.sh) — blocks commits on HIGH+ findings
- [x] Audit history DB (scripts/audit-history.sh + .audit-history.json) — tracks findings across versions
- [x] Inline fix suggestions (scripts/audit-fix-suggestions.py) — before/after code for each finding

### Stretch (Future)
- [ ] Visual audit report dashboard
- [ ] Multi-program audit aggregation

## 4. Success Metrics

| Metric | Target | Current | How Measured |
|--------|--------|---------|-------------|
| Integrity checks passing | 100% (62+) | 62/62 | `test-skill-integrity.sh` exit code |
| Vulnerability coverage | ≥17 classes | 17 tags (10 vault + 6 Token-2022 + 1 real) | VULN tags in fixtures |
| CVSS math accuracy | 100% | 17/17 verified | `check-cvss-math` integrity check |
| Security rules | ≥15 | 17 | `grep "^## Rule " rules/audit.rules` |
| Property-based tests | ≥15 invariants | 19 passing | Fuzz harness results |
| Contest judge clarity | Self-contained demo | `bash demo.sh` < 30s | Run from clean clone |
| CI green on every commit | 100% | ✅ | GitHub Actions status badge |

## 5. Architecture

```
User → Claude Code CLI
  └─ solana-auditor-shiba skill
      ├─ agents/orchestrator.md  (router)
      │   ├─ agents/auditor.md           (primary audit)
      │   ├─ agents/formal-verifier.md   (invariant proofs)
      │   └─ agents/report-writer.md     (report generation)
      ├─ commands/                       (6 slash commands)
      ├─ rules/                          (17 path-scoped rules)
      ├─ skill/                          (6 phase procedures)
      ├─ tests/                          (62 integrity checks + 19 fuzz tests)
      ├─ scripts/export-sarif.py         (SARIF export for Code Scanning)
      └─ examples/                       (3 vulnerable fixtures: vault, Token-2022, real Token-2022)
```

## 6. Non-Goals

- Real exploit execution against mainnet (consent-gated)
- Auto-applying security fixes (operator reviews)
- Native Solana program compilation without toolchain
- Replacing human auditor judgment

## 7. Contest-Specific Goals

For the **Superteam Brasil Solana Skills Contest**:

1. **Judge-ready** — A judge can clone, `./demo.sh`, and evaluate in < 2 min
2. **Brazil-friendly** — Portuguese glossary for Brazilian devs
3. **Comprehensive** — Covers ALL major Solana vulnerability classes across 3 fixtures
4. **Correct** — All data mathematically verified (CVSS, counts, file references, methodology trace)
5. **Professional** — Production-grade CI, documentation, SRP codebase, maximal test coverage
6. **World-class** — Formal verification demo, PoC exploit walkthroughs, SARIF export, concurrent protection
