---
description: Full Solana program security audit — recon, static analysis, formal verification, triage, report
---

# /audit — Full Lifecycle Audit

Run the complete 6-phase audit. Loads phase files progressively; do not embed the procedures inline — reference the skill files.

## Usage

```
/audit <repo-path>           # Full lifecycle
/audit <repo-path> --phase 2 # Start at a specific phase (1-6)
/audit <repo-path> --no-fv   # Skip formal verification (no QED 2A)
/audit <repo-path> --report  # Auto-invoke /audit-report after phase 4
```

If no path given, ask the user before proceeding.

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
5. **Workspace** — `mkdir -p <repo>/audit-report/{findings,pocs,screenshots,raw}`
6. **Abort if** not a Solana program (no `programs/` or `Anchor.toml`).

Update the lock file `phase` field when transitioning between phases (e.g., after phase N completes, update to phase N+1).

## Phase dispatch

Run each phase in order. The command must load (not duplicate) the phase file:

| Phase | Load | Notes |
|-------|------|-------|
| 1 | `skill/01-recon.md` | Output: `audit-report/raw/recon.md` |
| 2 | `skill/02-static-analysis.md` | One file per finding in `audit-report/findings/` |
| 3 | `skill/03-formal-verification.md` | Skip if `--no-fv`. Output: `audit-report/raw/formal-verification.md` |
| 4 | `skill/04-findings-triage.md` | Output: `audit-report/findings.json` |
| 5 | `skill/05-report-generation.md` OR invoke `/audit-report` | Output: `audit-report/AUDIT_REPORT.md` |
| 6 | `skill/06-remediation.md` | Reference only — no auto-applied fixes |

The phase files contain the procedure, VULN/FIX examples, and output schemas. Do not re-state them in the command.

## Final output

Print to user:
- Severity counts (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Paths to `audit-report/`, `findings.json`, `AUDIT_REPORT.md`
- 3 most critical findings (one-line summary each)
- Confirmation that no fixes were auto-applied

## Rules (always apply)

- PoC execution requires explicit consent **every time**, even within an audit.
- Never auto-apply fixes.
- All findings JSON-valid + markdown-formatted.
- CVSS 3.1 classification mandatory for HIGH+.
- QED 2A unavailable → fall back to `anchor test` with property-based fuzzing.
