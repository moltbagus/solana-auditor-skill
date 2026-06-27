---
name: audit
description: Full Solana program security audit — recon, static analysis, formal verification, triage, report
---

# /audit — Full Lifecycle Audit

Run the complete 6-phase audit. Loads phase files progressively; do not embed the procedures inline — reference the skill files.

## Usage

```
/audit <repo-path>               # Full lifecycle
/audit <repo-path> --phase 2   # Start at a specific phase (1-6)
/audit <repo-path> --no-fv     # Skip formal verification (no QED 2A)
/audit <repo-path> --report    # Auto-invoke /audit-report after phase 4
/audit <repo-path> --threat-model  # Run Phase 2A threat modeling (STRIDE) after Phase 1
/audit <repo-path> --architecture  # Run Phase 1B architecture review after Phase 1 recon
/audit <repo-path> --economic      # Run Phase 1C economic security review after Phase 1B
```

If no path given, ask the user before proceeding.

## Phase 0: Safety Guard — Pre-flight (safety-guard agent)

Run the `safety-guard` subagent before any audit phase. If any guardrail fails, block the audit and report to user.

- Validate target program identity (owner verification)
- Confirm consent gate has been passed
- Enforce cluster boundary (devnet/testnet default; mainnet requires explicit flag)
- Scan for credential patterns in scope files
- If any guardrail fails: block audit, report to user

## Phase 1B: Architecture Review (architecture-reviewer agent)

Run the `architecture-reviewer` subagent if `--architecture` flag is set. If omitted, skip entirely.

- Load `skill/01B-architecture-review.md` for architecture review methodology
- Load Phase 1 artifacts: `attack_surface.json`, `cpi_surface.json`, `program_metadata.json`
- Assess upgrade authority type (EOA / multisig / timelock / immutable)
- Evaluate token authorities (mint, freeze, close) on SPL Token and Token-2022 mints
- Detect active Token-2022 extensions and verify program awareness
- Assess CPI surface systemic risk
- Assign architecture rating (CRITICAL / HIGH / MEDIUM / LOW) per program
- Output: `audit-report/architecture/{program}_architecture.json` per program
- Output: design-level findings tagged `code_fixes: false, design_fixes: true` in `audit-report/findings.json`
- Architecture findings feed Phase 4 triage alongside Phase 2 code findings

## Phase 1C: Economic Security Review (economic-security-analyst agent)

Run the `economic-security-analyst` subagent if `--economic` flag is set. If omitted, skip entirely.

- Load `skill/01C-economic-security.md` for economic security methodology
- Load Phase 1B architecture artifacts: `audit-report/architecture/{program}_architecture.json`
- Load Phase 1 artifacts: `token_supply.json`, `attack_surface.json`
- Assess tokenomics integrity (mint authority, supply cap, Token-2022 fee extensions)
- Evaluate MEV exposure (Jito, Light, sandwich attacks, flash loans)
- Assess staking and delegation economics (reward calculations, emission schedules)
- Assess LP token economics (redeemability, reserve invariants, impermanent loss)
- Evaluate governance token security (vote-weight attacks, flash loan governance)
- Verify economic invariant enforcement (solvency, collateralization, no-negative-balance)
- Assign economic security rating (CRITICAL / HIGH / MEDIUM / LOW) per program
- Output: `audit-report/economic/{program}_economic.json` per program
- Output: economic findings tagged `code_fixes` or `design_fixes` in `audit-report/findings.json`
- Economic findings feed Phase 4 triage alongside Phase 2 code findings

## Phase 2A: Threat Modeling (threat-modeler agent)

Run the `threat-modeler` subagent if `--threat-model` flag is set. If omitted, skip entirely.

- Load `skill/02-threat-modeling.md` for STRIDE enumeration procedure
- Load Phase 1 artifacts: `attack_surface.json`, `cpi_surface.json`, `program_metadata.json`
- Invoke `threat-modeler` agent with the audit context
- Output: `audit-report/threats/{program_name}_threats.json` per program
- Threat model feeds Phase 4 triage (cross-reference STRIDE findings with Phase 2 findings)

## Pre-flight

1. **Lock file check** — prevent concurrent runs:
   - Lock path: `<repo>/audit-report/.audit.lock`
   - If lock exists, read the PID from it
   - If the PID is still alive (`kill -0 $PID 2>/dev/null`), abort with error:
     ```
     ERROR: audit already in progress (PID $PID, started $started_at)
     Remove the lock file manually if no audit is running: <repo>/audit-report/.audit.lock
     ```
   - If lock is stale (PID dead), remove it and proceed
   - Create new lock: `{"pid": $$, "started_at": "$(date -Iseconds)", "user": "$USER", "phase": 1}`
   - Set exit trap to remove lock on completion: `trap 'rm -f "$AUDIT_LOCK_FILE"' EXIT`
2. **Confirm scope** — show `skill/SKILL.md` §Audit Scope Checklist.
3. **Consent gate** — print: "PoC exploits require explicit consent before execution. Continue? [y/N]"
4. **Output path** — default `<repo>/audit-report/`.
5. **Workspace** — `mkdir -p <repo>/audit-report/{findings,pocs,screenshots,raw,threats,architecture,economic}`
6. **Abort if** not a Solana program (no `programs/` or `Anchor.toml`).

Update the lock file `phase` field when transitioning between phases (e.g., after phase N completes, update to phase N+1).

## Phase dispatch

Run each phase in order. The command must load (not duplicate) the phase file:

| Phase | Load | Notes |
|-------|------|-------|
| 0 | `skill/00-safety-guard.md` | Pre-flight (safety-guard agent) |
| 1 | `skill/01-recon.md` | Output: `audit-report/raw/recon.md` |
| 1B | `skill/01B-architecture-review.md` | Run if `--architecture`. Output: `audit-report/architecture/{program}_architecture.json` |
| 1C | `skill/01C-economic-security.md` | Run if `--economic`. Output: `audit-report/economic/{program}_economic.json` |
| 2 | `skill/02-static-analysis.md` | One file per finding in `audit-report/findings/` |
| 2A | `skill/02-threat-modeling.md` | Run if `--threat-model`. Output: `audit-report/threats/{program}_threats.json` |
| 3 | `skill/03-formal-verification.md` | Skip if `--no-fv`. Output: `audit-report/raw/formal-verification.md` |
| 4 | `skill/04-findings-triage.md` | Output: `audit-report/findings.json` |
| 5 | `skill/05-report-generation.md` OR invoke `/audit-report` | Output: `audit-report/AUDIT_REPORT.md` |
| 6 | `skill/06-remediation.md` | Reference only — no auto-applied fixes |

The phase files contain the procedure, VULN/FIX examples, and output schemas. Do not re-state them in the command.

## Final output

Print to user:
- Severity counts (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Paths to `audit-report/`, `findings.json`, `AUDIT_REPORT.md`
- Paths to `audit-report/threats/` (if `--threat-model` was used)
- 3 most critical findings (one-line summary each)
- Confirmation that no fixes were auto-applied

## Rules (always apply)

- PoC execution requires explicit consent **every time**, even within an audit.
- Never auto-apply fixes.
- All findings JSON-valid + markdown-formatted.
- CVSS 3.1 classification mandatory for HIGH+.
- QED 2A unavailable → fall back to `anchor test` with property-based fuzzing.
