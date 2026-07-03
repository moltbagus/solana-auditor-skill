---
name: solana-auditor-skill
description: All-in-one Solana security auditor — recon, static analysis, formal verification, triage, report, and remediation guidance for the Solana AI Kit
---

# Solana Auditor Skill

Auditor-lifecycle skill for comprehensive Solana program security review. Runs from initial recon to final report.

**Extends**: `solana-dev-skill`

**Phases** (progressive load — 8 total: Phase 0 + Phases 1–6 + Phase 7):
- Phase 0: Safety Guard (consent, scope, cluster, credentials)
- Phase 1: Reconnaissance
- Phase 1B: Architecture Review (structural topology)
- Phase 1C: Economic Security (tokenomics, MEV, invariants)
- Phase 2: Static Analysis (SAST — 45 rules)
- Phase 2A: Threat Modeling (STRIDE)
- Phase 2B: Runtime Testing
- Phase 3: Formal Verification
- Phase 4: Findings Triage (CVSS 3.1)
- Phase 5: Report Generation
- Phase 6: Remediation Guidance
- Phase 7: Architecture Review (component analysis)

**Agents** (10 specialists): orchestrator, auditor, formal-verifier, report-writer, cross-program-agent, safety-guard, threat-modeler, architecture-reviewer, economic-security-analyst, cross-program

**Rules**: 50 total (45 Solana program security SAST + 5 AI agent safety)

**Commands** (9): `/audit`, `/audit-quick`, `/audit-resume`, `/audit-report`, `/audit-poc`, `/audit-findings`, `/audit-fix`, `/audit-history`, `/audit-pr`

---

## Skill Files

| Phase | File | When to Load |
|-------|------|-------------|
| Safety Guard | `skill/00-safety-guard.md` | Always — Phase 0 pre-flight |
| Terminology | `skill/00-terminology.md` | Always available |
| Recon | `skill/01-recon.md` | Initial audit start |
| Architecture Review | `skill/01B-architecture-review.md` | After recon — structural topology |
| Economic Security | `skill/01C-economic-security.md` | After recon — tokenomics, MEV, invariants |
| Static Analysis | `skill/02-static-analysis.md` | After recon, SAST scan |
| Threat Modeling | `skill/02-threat-modeling.md` | SAST companion — STRIDE enumeration |
| Runtime Testing | `skill/02B-runtime-testing.md` | Tier 2 only (requires Anchor) |
| Formal Verification | `skill/03-formal-verification.md` | Invariant proofs needed |
| Findings Triage | `skill/04-findings-triage.md` | After finding collection |
| Report Generation | `skill/05-report-generation.md` | Final deliverable |
| Remediation | `skill/06-remediation.md` | Fix verification |

### Two-Tier Execution

| Tier | Mode | Phases | Use Case |
|------|------|--------|---------|
| **TIER1** | SAST-only | 0, 1, 1B, 1C, 2, 2A, 4, 5, 6 | Quick audit, no toolchain |
| **TIER2** | Full runtime | 0, 1, 1B, 1C, 2, 2A, 2B, 3, 4, 5, 6 | Comprehensive + validator |

---

## Phase Routing

| User wants | Load |
|------------|------|
| Start an audit | `skill/01-recon.md` |
| Architecture review | `skill/01B-architecture-review.md` |
| Economic security | `skill/01C-economic-security.md` |
| Fast SAST scan | `skill/02-static-analysis.md` |
| Threat modeling | `skill/02-threat-modeling.md` |
| Tier 2 runtime | `skill/02B-runtime-testing.md` |
| Formal verification | `skill/03-formal-verification.md` |
| Full audit report | `skill/05-report-generation.md` + `skill/01-recon.md` |
| Verify a fix | `skill/06-remediation.md` |
| Severity triage | `skill/04-findings-triage.md` |

---

## Severity Scale

| Level | CVSS | Example |
|-------|------|---------|
| CRITICAL | ≥ 9.0 | `invoke` without signer check |
| HIGH | ≥ 7.0 | CPI privilege escalation |
| MEDIUM | ≥ 4.0 | Missing owner check |
| LOW | ≥ 0.1 | Missing `close` authority |
| INFO | < 0.1 | Missing docs |

---

## 50 Security Rules (4 Groups)

| Group | Rules | Coverage |
|-------|-------|----------|
| Anchor Core | 1–26 | Discriminators, CPI, PDA, overflow, signer |
| Token-2022 Transfer Hook | 27–35 | Mint validation, extension bypass, fee-on-transfer |
| Pinocchio / Native Solana | 36–45 | Sysvar spoofing, BPF loader, account compression |
| AI Agent Safety | 46–50 | Pre-flight, scope boundary, consent gate |

Rules auto-activate on file open. Full rule set in `rules/audit.rules`.

---

## Quick Commands

| Command | Use |
|---------|-----|
| `/audit <repo>` | Full lifecycle audit |
| `/audit-quick <repo>` | Fast SAST scan only |
| `/audit-resume` | Resume from `loop_state.json` |
| `/audit-report` | Generate report from findings |
| `/audit-poc <finding>` | Generate exploit PoC |
| `/audit-fix` | Generate inline fix suggestions |

⚠️ Get explicit user consent before executing any exploit PoC code.
⚠️ Never auto-apply fixes — operator reviews and applies.
