# Solana Auditor Shiba — AI Kit Extension

This directory is the AI Kit `ext/` package for `solana-auditor-shiba` v1.5.0.

## What It Is

Installable extension for the [Solana AI Kit](https://github.com/solanabr/solana-ai-kit) that adds a world-class Solana program security auditor as a Claude Code skill.

## Quick Install

```bash
# Install via AI Kit skill-registry
bash install.sh --ext-mode

# Or copy ext/solana-auditor-shiba/ into your AI Kit ext/ directory
cp -r ext/solana-auditor-shiba ~/.claude/skills/ext/
```

## What You Get

- **7-phase audit lifecycle** — recon, SAST, runtime verification, formal verification, triage, report, remediation
- **26 path-scoped security rules** — auto-activate on file open (Anchor, Token-2022, CPI, PDA, reentrancy, flash loans, etc.)
- **6 specialist agents** — orchestrator, auditor, formal-verifier, report-writer, cross-program-agent, auditor-agent
- **Two-tier execution** — TIER1 (SAST-only, no toolchain required) and TIER2 (full anchor test + fuzzing)
- **8 slash commands** — `/audit`, `/audit-quick`, `/audit-resume`, `/audit-report`, `/audit-poc`, `/audit-findings`, `/audit-history`, `/audit-pr`
- **Pre-commit hook** — blocks commits on HIGH+ findings
- **CPI surface graph generator** — structured JSON graph of all cross-program invocations
- **SARIF + CVSS scoring** — structured output, mathematically verified severity

## Usage

```bash
# Full lifecycle audit (recommended)
/audit <path-to-solana-program-repo>

# Fast SAST scan (no toolchain needed)
/audit-quick <path-to-solana-program-repo>

# Resume interrupted audit
/audit-resume

# Generate report from findings
/audit-report

# Get PoC for a specific finding
/audit-poc CRIT-01

# View findings database
/audit-findings

# Audit history
/audit-history

# Auto-review a PR for vulnerabilities
/audit-pr <pr-url>
```

## Safety Constraints

| Constraint | Description |
|------------|-------------|
| **PoC consent required** | Explicit user consent before executing any exploit code |
| **No auto-apply fixes** | Operator reviews and applies remediation |
| **No live exploit execution** | Consent gate enforced; mainnet requires owner authorization |

## Directory Structure

```
ext/solana-auditor-shiba/
├── skill-registry.json    # AI Kit catalog entry
├── SKILL.md               # Symlink to skill/SKILL.md
├── README.md              # This file
├── install.sh             # Ext-mode installer
├── skill/                 # Symlinks: skill/*.md
├── agents/                # Symlinks: agents/*.md
├── commands/              # Symlinks: commands/*.md
├── rules/                 # Symlinks: rules/*
├── scripts/               # Symlinks: scripts/*
└── templates/            # Symlinks: templates/*
```

## See Also

- Main README: [README.md](../../README.md)
- Full skill docs: [SKILL.md](../../skill/SKILL.md)
- Solana AI Kit: https://github.com/solanabr/solana-ai-kit
