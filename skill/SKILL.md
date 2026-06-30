---
name: solana-auditor-skill
description: All-in-one Solana security auditor — recon, static analysis, formal verification, triage, report, and remediation guidance
---

# Solana Auditor Skill (Shiba) v1.14.2

Auditor-lifecycle skill for comprehensive Solana program security review. Runs from initial recon to final report.

**Extends**: solana-dev-skill

**Phases** (7 phases, load progressively):
0. Safety Guard (pre-flight — consent, scope, cluster, credentials)
1. Reconnaissance
2. Static Analysis (SAST — 50 rules)
3. Formal Verification
4. Findings Triage (CVSS 3.1 + 22 fuzz tests)
5. Report Generation
6. Remediation Guidance

**Agents** (10 configs): orchestrator (entry-point router), auditor (primary), architecture-reviewer, economic-security-analyst, threat-modeler, formal-verifier, report-writer, cross-program-agent, safety-guard + AUDIT.md (auto-generated)

**Commands** (9): /audit, /audit-quick, /audit-resume, /audit-report, /audit-poc, /audit-findings, /audit-fix, /audit-history, /audit-pr

**References**: `references/LIMITATIONS.md` — honest coverage ceiling; `skill/00-safety-guard.md` — Phase 0

---

## Skill Files

| Phase | File | When to Load |
|-------|------|-------------|
| Recon | `skill/01-recon.md` | Initial repo/program audit start |
| Architecture Review | `skill/01B-architecture-review.md` | After recon, before static analysis (structural risks) |
| Economic Security Review | `skill/01C-economic-security.md` | After Phase 1B, before static analysis (economic design risks) |
| Static Analysis | `skill/02-static-analysis.md` | After recon, before dynamic testing |
| Threat Modeling (Phase 2A) | `skill/02-threat-modeling.md` | After recon, before static analysis (STRIDE enumeration) |
| Runtime Verification | `skill/02B-runtime-testing.md` | Tier 2 only (anchor + solana toolchain) |
| Formal Verification | `skill/03-formal-verification.md` | When invariants need proof |
| Findings Triage | `skill/04-findings-triage.md` | After finding collection |
| Report Generation | `skill/05-report-generation.md` | Final audit deliverable |
| Remediation | `skill/06-remediation.md` | After triage, during fix verification |
| Reference | `skill/00-terminology.md` | Always available |
| Safety Guard | `skill/00-safety-guard.md` | Phase 0 — always run first |

### Two-Tier Execution Model

| Tier | Capabilities | Trigger |
|------|-------------|---------|
| **TIER1** | SAST-only static analysis | No Anchor/Solana CLI |
| **TIER2** | Full anchor test + BanksClient fuzzing | Anchor + solana available |
| **TIER2-FULL** | TIER2 + QED 2A + advanced fuzzing | Full toolchain installed |

---

## Phase Routing

### User wants to start an audit
→ Load `skill/01-recon.md` first
→ Load `skill/01B-architecture-review.md` for structural threat modeling

### User wants architecture review specifically
→ Load `skill/01B-architecture-review.md` (Phase 1B — runs after recon, before static analysis)
→ Invoke `architecture-reviewer` agent for deployed programs

### User wants economic security review specifically
→ Load `skill/01C-economic-security.md` (Phase 1C — runs after Phase 1B, before static analysis)
→ Invoke `economic-security-analyst` agent for token and DeFi programs

### User mentions finding a specific vulnerability class
→ Load relevant phase skill file

### User wants Tier 2 runtime verification
→ Load `skill/02B-runtime-testing.md` (requires anchor + solana CLI)

### User wants a full audit report
→ Load `skill/05-report-generation.md` + `skill/01-recon.md` + `skill/02-static-analysis.md`

### User wants Phase 2A threat modeling (STRIDE enumeration)
→ Load `skill/02-threat-modeling.md`
→ Invoke `threat-modeler` agent

### User wants Phase 0 safety guard (consent, scope, cluster)
→ Load `skill/00-safety-guard.md`
→ Invoke `safety-guard` agent

### User wants to verify a fix
→ Load `skill/06-remediation.md` + `skill/03-formal-verification.md`

### User asks about severity/criticality of a finding
→ Load `skill/04-findings-triage.md`

---

## Severity Scale

| Level | Description | Example |
|-------|-------------|---------|
| CRITICAL | Total fund loss, authority bypass | `invoke` without signer check, mint freeze authority |
| HIGH | Significant loss, major logic flaw | Integer overflow in amount calc, CPI privilege escalation |
| MEDIUM | Moderate impact, indirect path | Missing owner check on account, weak access control |
| LOW | Minor issue, best practice | Missing `close` authority, error codes not used |
| INFO | Informational | Missing docs, unnecessary complexity |

---

## Solana-Specific Findings Reference

### Anchor Account Discriminators
- Missing `#[account(...)]` constraints → wrong account type accepted
- No `isInitialized` check → uninitialized state accessed
- `init` without `mut` → account exists error on reinit

### CPI Privilege Escalation  
- `invoke` without `remaining_accounts` validation → arbitrary program execution
- Missing `seeds`/`bump` verification on PDA → PDA derivation bypass
- `transfer` from user token account without `owner` check → stolen tokens

### Token Extensions (2022)
- `metadata_pointer` not verified on mint operations → wrong metadata
- `mint_close_authority` not checked → mint can be closed unexpectedly
- `transfer_fee` not accounted in total supply calculations
- `confidential_transfer` fee not extracted from settle

### Sealevel / Runtime
- `invoke` without `is_signer` verification → unsigned transaction execution
- `invoke` without `is_writable` verification → unintended state mutation
- Missing `rent_exempt` validation → account wiped on initialization
- `close` without owner signature verification → fund theft

### Program Derived Addresses
- Hardcoded bump → same seed collision
- Missing bump canonicalization check → address collision attacks
- Bump used in security-critical path without verification → predictable addresses

---

## Agents

| Agent | File | Role |
|-------|------|------|
| orchestrator | `agents/orchestrator.md` | Entry-point router, phase sequencing |
| auditor | `agents/auditor.md` | Primary audit execution, finding generation |
| architecture-reviewer | `agents/architecture-reviewer.md` | Structural architecture review: upgrade authority, token extensions, design-level findings |
| economic-security-analyst | `agents/economic-security-analyst.md` | Economic security review: tokenomics, MEV, staking/LP, governance, invariant enforcement |
| formal-verifier | `agents/formal-verifier.md` | Invariant proofs with QED 2A |
| report-writer | `agents/report-writer.md` | Structured findings to report |
| cross-program-agent | `agents/cross-program-agent.md` | CPI chain analysis, flash loan detection |
| threat-modeler | `agents/threat-modeler.md` | STRIDE threat enumeration, exploit intelligence, Helius API |
| safety-guard | `agents/safety-guard.md` | Phase 0 pre-flight: consent, program identity, cluster boundary |

### Cross-Program Agent

**Trigger**: Phase 4 triage when `cpi_surface.json` exists with `edges.length > 0`

**Capabilities**:
- CPI surface graph analysis
- Unverified privilege escalation detection
- Flash loan path detection (Orca, Raydium, Solend, Marginfi)
- Callback reentrancy detection (CEI pattern violations)
- Cross-program data flow mapping

**Output**: `cross_program_findings.json`, `dataflow_map.json`

## New in v1.7.0

| Feature | Description |
|---------|-------------|
| **50 security rules** | 33 new rules (Rules 27–50): Token-2022 Transfer Hook (27–35), Pinocchio/Native Solana (36–45), AI Agent Safety (46–50) |
| **7 specialist agents** | Added safety-guard for Phase 0 pre-flight (consent, scope, cluster, credentials) |
| **153 integrity checks** | 3× growth from v1.5 (62 → 153) covering Phase 1–3 |
| **22 property-based fuzz tests** | CVSS formula verification, fixture regression guards, Token-2022 rule coverage |
| **3 compile-verified fixtures** | vault (Anchor), token-2022-real (Token Extensions), native-vault (Pinocchio) |
| **Phase 0 Safety Guard** | Pre-flight: consent, program identity, cluster boundary (devnet/localnet only), credential masking |
| **CVSS mathematical verification** | Every score recomputed from vector; Check 10 flags mismatches |
| **References** | `references/LIMITATIONS.md` — honest coverage ceiling |

## Security Rules (50 Path-Scoped, 4 Groups)

| Group | Rules | Coverage |
|-------|-------|----------|
| Anchor Core | 1–26 | Discriminators, CPI, PDA, overflow, reentrancy, signer |
| Token-2022 Transfer Hook | 27–35 | Mint validation, extra_accounts, extension bypass, fee-on-transfer |
| Pinocchio / Native Solana | 36–45 | Sysvar spoofing, runtime, account compression |
| AI Agent Safety | 46–50 | Pre-flight, scope boundary, consent gate, audit trail |

Rules auto-activate on file open. Full rule set in `rules/audit.rules`.

## Audit Scope Checklist

- [ ] Anchor program with `#[program]` mod
- [ ] Token Extensions (2022) mints
- [ ] CPI callers (`invoke`/`invoke_signed`)
- [ ] PDA derivation (`create_program_address` / `find_program_address`)
- [ ] Account validation (`#[account(...)]` constraints)
- [ ] Access control (owner/signer checks)
- [ ] Token transfers (SPL Token vs Token-2022)
- [ ] Rent/exempt validation
- [ ] Error handling completeness
- [ ] Upgradable programs (upgrade authority)
- [ ] CPI surface graph (`cpi_surface.json`)
- [ ] cargo-audit supply chain scan
- [ ] Architecture review: upgrade authority model
- [ ] Architecture review: tokenomics (supply, fees, emissions)
- [ ] Architecture review: shared state / CPI trust chains
- [ ] Architecture review: economic invariants (solvency, liquidity)

---

## Quick Commands

| Command | Use |
|---------|-----|
| `/audit <repo>` | Full lifecycle audit |
| `/audit-quick <repo>` | Fast SAST scan only |
| `/audit-resume` | Resume interrupted audit from `phase-state.json` |
| `/audit-report` | Generate report from findings |
| `/audit-poc <finding>` | Generate proof-of-concept exploit |
| `/audit-findings` | List/manage findings database |

---

⚠️ Always get explicit user consent before executing any exploit PoC code.
⚠️ Never auto-apply fixes — operator reviews and applies remediation.