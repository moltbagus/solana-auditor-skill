# PRD — Solana Auditor Skill

> **Product Requirements Document**
> _Superteam Brasil Solana Skills Contest — v1.9.0_
> Last updated: 2026-06-27

---

## 1. Vision

Transform Claude Code into the **gold-standard Solana security auditor** — a reproducible, methodology-driven, contest-grade tool that any Solana developer can run against their Anchor programs to get production-quality audit reports with CVSS-scored findings, formal verification integration, and remediation guidance.

## 2. Target Users

| Persona | Need | How the Skill Serves |
|---------|------|---------------------|
| Solana dApp developer | Quick security check before mainnet deploy | `/audit-quick` — 5 min SAST scan |
| Solana audit firm | Structured audit methodology + reporting | `/audit` — 7-phase lifecycle |
| Security researcher | Finding validation + PoC generation | `/audit-poc` — consent-gated exploit |
| Contest judge | Evaluate skill quality + completeness | Demo script, 70+ integrity checks, 19 fuzz tests |
| Brazilian dev | Solana security in their native language | PT-BR glossary + terminology |

## 3. Features

### Core (v1.0 — Shipped)
- [x] 6-phase audit lifecycle (Recon → Remediation)
- [x] 9 slash commands (`/audit`, `/audit-quick`, `/audit-resume`, `/audit-report`, `/audit-poc`, `/audit-findings`, `/audit-resume`, and more)
- [x] 50 path-scoped rules (auto-activate on file patterns)
- [x] 6 specialist agents (orchestrator, auditor, formal-verifier, report-writer, cross-program, safety-guard)
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
- [x] 70+ integrity checks (up from 62)
- [x] 50 security rules (up from 26)
- [x] 8 phases (up from 7)

### v1.8.1 — Dashboard + Exploit Simulation (2026-06-27)
- [x] HTML audit dashboard: `scripts/dashboard.py` + `templates/dashboard.html`
- [x] demo.sh step 7: generates HTML dashboard automatically
- [x] `/audit-report --html`: generates markdown + HTML in one pass
- [x] `scripts/audit-report.py`: standalone CLI for markdown + HTML generation
- [x] All 9 commands: `name:` frontmatter added for Claude Code registration
- [x] Bug fixes: exit logic, FUZZ_COUNT, heredoc quoting verified clean
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

### Stretch (Future)
- [ ] Line-number drift integrity check
- [ ] Multi-program audit aggregation
- [ ] Native qed-solana CI integration (dependency of QED 2A)
- [ ] Economic Security module (standalone DeFi attack analysis)
- [ ] Architecture Review module (standalone component analysis)
- [ ] Remediation Engine full upgrade (root cause + regression tests)

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
| Integrity checks passing | 100% (70+) | 70+/70 | `test-skill-integrity.sh` exit code |
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
      ├─ tests/                          (70+ integrity checks + 19 fuzz tests)
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
2. **Brazil-friendly** — Portuguese glossary for Brazilian devs
3. **Comprehensive** — Covers ALL major Solana vulnerability classes across 3 fixtures
4. **Correct** — All data mathematically verified (CVSS, counts, file references, methodology trace)
5. **Professional** — Production-grade CI, documentation, SRP codebase, maximal test coverage
6. **World-class** — Formal verification demo, PoC exploit walkthroughs, SARIF export, concurrent protection, two-tier execution, CPI surface analysis

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
