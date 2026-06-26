---
name: solana-auditor-shiba
description: All-in-one Solana security auditor — recon, static analysis, formal verification, triage, report, and remediation guidance
---

# Solana Auditor Skill (Shiba) v1.5.0

Auditor-lifecycle skill for comprehensive Solana program security review. Runs from initial recon to final report.

**Extends**: solana-dev-skill

**Phases** (7 phases, load progressively):
1. Reconnaissance
2. Static Analysis (2A: SAST)
3. Runtime Verification (2B: Tier 2 only)
4. Formal Verification
5. Findings Triage
6. Report Generation
7. Remediation Guidance

**Agents** (5 specialists): orchestrator (entry-point router), auditor (primary), formal-verifier, report-writer, cross-program-agent

**Commands** (8): /audit, /audit-quick, /audit-resume, /audit-report, /audit-poc, /audit-findings, /audit-history, /audit-pr

---

## Skill Files

| Phase | File | When to Load |
|-------|------|-------------|
| Recon | `skill/01-recon.md` | Initial repo/program audit start |
| Static Analysis | `skill/02A-static-analysis.md` | After recon, before dynamic testing |
| Runtime Verification | `skill/02B-runtime-testing.md` | Tier 2 only (anchor + solana toolchain) |
| Formal Verification | `skill/03-formal-verification.md` | When invariants need proof |
| Findings Triage | `skill/04-findings-triage.md` | After finding collection |
| Report Generation | `skill/05-report-generation.md` | Final audit deliverable |
| Remediation | `skill/06-remediation.md` | After triage, during fix verification |
| Reference | `skill/00-terminology.md` | Always available |

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

### User mentions finding a specific vulnerability class
→ Load relevant phase skill file

### User wants Tier 2 runtime verification
→ Load `skill/02B-runtime-testing.md` (requires anchor + solana CLI)

### User wants a full audit report
→ Load `skill/05-report-generation.md` + `skill/01-recon.md` + `skill/02A-static-analysis.md`

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
| formal-verifier | `agents/formal-verifier.md` | Invariant proofs with QED 2A |
| report-writer | `agents/report-writer.md` | Structured findings to report |
| cross-program-agent | `agents/cross-program-agent.md` | CPI chain analysis, flash loan detection (NEW) |

### Cross-Program Agent

**Trigger**: Phase 4 triage when `cpi_surface.json` exists with `edges.length > 0`

**Capabilities**:
- CPI surface graph analysis
- Unverified privilege escalation detection
- Flash loan path detection (Orca, Raydium, Solend, Marginfi)
- Callback reentrancy detection (CEI pattern violations)
- Cross-program data flow mapping

**Output**: `cross_program_findings.json`, `dataflow_map.json`

## New in v1.5.0

| Feature | Description |
|---------|-------------|
| **Two-tier execution model** | TIER1 (SAST-only) vs TIER2 (full runtime) with auto-detection |
| **Phase 2B runtime verification** | anchor test, BanksClient fuzzing, QED 2A fallback chain |
| **Cross-program analysis agent** | CPI chain analysis, flash loan path detection, callback reentrancy |
| **CPI surface graph generation** | Structured JSON graph of all cross-program invocations |
| **cargo-audit integration** | CVE scanning for supply chain vulnerabilities in Rust deps |
| **Helius API integration** | On-chain state analysis (upgrade authority, bytecode hash, token holders) |
| **QED 2A fallback chain** | Graceful degradation: QED -> anchor invariants -> fuzz -> manual review |
| **26 security rules** | 9 new rules (Rules 18-26) extending coverage beyond original 17 |

## Security Rules (26 Path-Scoped)

| Rule | Triggers | Catches | Default |
|------|----------|---------|---------|
| 1-17 | `programs/**/*.rs` | Core vulnerabilities | CRITICAL→LOW |
| 18-26 | `programs/**/*.rs` | Extended coverage (NEW) | Various |

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

---

## Quick Commands

| Command | Use |
|---------|-----|
| `/audit <repo>` | Full lifecycle audit |
| `/audit-quick <repo>` | Fast SAST scan only |
| `/audit-resume` | Resume interrupted audit from loop_state.json |
| `/audit-report` | Generate report from findings |
| `/audit-poc <finding>` | Generate proof-of-concept exploit |
| `/audit-findings` | List/manage findings database |

---

⚠️ Always get explicit user consent before executing any exploit PoC code.
⚠️ Never auto-apply fixes — operator reviews and applies remediation.