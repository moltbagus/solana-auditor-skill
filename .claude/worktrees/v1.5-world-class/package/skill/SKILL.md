---
name: solana-auditor-shiba
description: All-in-one Solana security auditor — recon, static analysis, formal verification, triage, report, and remediation guidance
---

# Solana Auditor Skill (Shiba)

Auditor-lifecycle skill for comprehensive Solana program security review. Runs from initial recon to final report.

**Extends**: solana-dev-skill

**Phases** (load progressively):
1. Reconnaissance
2. Static Analysis
3. Formal Verification  
4. Findings Triage
5. Report Generation
6. Remediation Guidance

**Agents**: orchestrator (entry-point router), auditor (primary), formal-verifier, report-writer

**Commands**: /audit, /audit-quick, /audit-report, /audit-poc, /audit-findings

---

## Skill Files

| Phase | File | When to Load |
|-------|------|-------------|
| Recon | `skill/01-recon.md` | Initial repo/program audit start |
| Static Analysis | `skill/02-static-analysis.md` | After recon, before dynamic testing |
| Formal Verification | `skill/03-formal-verification.md` | When invariants need proof |
| Findings Triage | `skill/04-findings-triage.md` | After finding collection |
| Report Generation | `skill/05-report-generation.md` | Final audit deliverable |
| Remediation | `skill/06-remediation.md` | After triage, during fix verification |
| Reference | `skill/00-terminology.md` | Always available |

---

## Phase Routing

### User wants to start an audit
→ Load `skill/01-recon.md` first

### User mentions finding a specific vulnerability class
→ Load relevant phase skill file

### User wants a full audit report
→ Load `skill/05-report-generation.md` + `skill/01-recon.md` + `skill/02-static-analysis.md`

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