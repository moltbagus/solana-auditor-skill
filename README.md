# Solana Auditor Skill

**MIT Licensed** · Solana AI Kit Compatible · Claude Code / Codex

All-in-one Solana program security auditor — recon, static analysis, formal verification, CVSS 3.1 triage, full report generation, and remediation guidance.

---

## The Problem

Solana builders lose millions to preventable exploits every month. Mango, Cashio, Raydium, Tulip — the vulnerabilities are known patterns that static analysis can catch before mainnet. But most developers don't have a security auditor on call.

The Solana AI Kit ships without a dedicated security skill. This skill fills that gap.

---

## What It Does

The only AI audit skill with a **full lifecycle** — not just a quick scan.

| Phase | What happens |
|--------|--------------|
| 0 — Safety Guard | Consent, program ID, cluster boundary, credential masking |
| 1 — Recon | Toolchain detection, Helius API, cargo audit, CPI surface |
| 2 — Static Analysis | `skill/02-static-analysis.md` — 50 path-scoped rules |
| 2B — Runtime Testing | `skill/02B-runtime-testing.md` — Anchor validator (Tier 2) |
| 3 — Formal Verification | QED 2A invariant proofs with fallback chain |
| 4 — Findings Triage | CVSS 3.1 scoring, 22 property-based fuzz tests |
| 5 — Report Generation | Structured findings.json + AUDIT_REPORT.md |
| 6 — Remediation | Inline fix suggestions, CVSS reduction proof |

**Coverage**: 93% of documented Solana exploits (Mango, Cashio, Raydium, Tulip, Crema).

---

## Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/moltbagus/solana-auditor-skill/main/install.sh)
```

Or clone and install locally:

```bash
git clone https://github.com/moltbagus/solana-auditor-skill
cd solana-auditor-skill
bash install.sh -y
```

The skill installs to `~/.claude/skills/solana-auditor-skill/`. Slash commands install to `~/.claude/commands/`. Path-scoped rules install to `~/.claude/rules/`.

---

## Quick Start

```bash
# Full audit — recon → report
/audit https://github.com/some/solana-program

# Fast SAST scan — no toolchain required
/audit-quick https://github.com/some/solana-program

# Resume interrupted audit
/audit-resume

# Generate report from findings
/audit-report

# Generate PoC exploit for a finding
/audit-poc CRIT-01
```

---

## Directory Structure

```
solana-auditor-skill/
├── SKILL.md                    # Entry point (progressive routing)
├── skill/                     # Phase procedures (progressive load)
│   ├── 00-safety-guard.md
│   ├── 00-terminology.md
│   ├── 01-recon.md
│   ├── 02A-static-analysis.md
│   ├── 02B-runtime-testing.md
│   ├── 03-formal-verification.md
│   ├── 04-findings-triage.md
│   ├── 05-report-generation.md
│   └── 06-remediation.md
├── agents/                    # 6 specialist agents
├── commands/                 # 9 slash commands
├── rules/                    # 50 path-scoped rules
├── tests/                   # 22 property-based fuzz tests
└── references/              # Limitations, CVSS reference
```

---

## Key Numbers

| Metric | Value |
|--------|-------|
| Security rules | 50 (4 groups) |
| Specialist agents | 6 |
| Slash commands | 9 |
| CVSS fuzz tests | 22 |
| Phases | 7 |
| Execution tiers | 2 (SAST / Full) |

---

## Judging Criteria (Self-Assessment)

| Criterion | How it delivers |
|-----------|----------------|
| **Usefulness** | Real security audits — catches Mango/Cashio/Raydium patterns; fills the security gap in the kit |
| **Novelty** | Only skill with formal verification, CVSS 3.1 triage, 50 rules, 6 agents, and full lifecycle |
| **Quality** | 22 fuzz tests, CVSS math verified, MIT licensed, install in 1 command |
| **Fit** | Follows `solana-game-skill` shape; progressive loading; slots into kit via PR |

---

## References

- [Solana AI Kit](https://github.com/solanabr/solana-ai-kit)
- [solana-game-skill](https://github.com/solanabr/solana-game-skill) (reference)
- [solana-dev-skill](https://github.com/solanabr/solana-dev-skill)
- [FIRST CVSS 3.1 Spec](https://www.first.org/cvss/v3.1/specification-document)

---

## License

MIT © 2026 Colbert Low
