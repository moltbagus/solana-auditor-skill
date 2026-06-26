---
description: Resume a previously interrupted audit from the last completed phase
---

# /audit-resume — Resume Interrupted Audit

Resume an audit that was interrupted or terminated. Reads the checkpoint state and continues from the last completed phase.

## Usage

```
/audit-resume <repo-path>           # Resume from last checkpoint
/audit-resume <repo-path> --force   # Force resume even if state is corrupt
```

## Pre-flight

1. **Check for state file** — Look for `<repo>/audit-report/phase-state.json`
2. **Abort if no state file** — Error: "No audit state found. Run `/audit <repo>` to start a fresh audit."
3. **Validate state file** — Parse JSON, verify required fields present
4. **Check lock file** — If `.audit.lock` exists and PID is alive, abort with error
5. **Create new lock** — Same as `/audit` lock protocol
6. **Print resume summary** — Show: last completed phase, started_at, phase artifacts

## State File Format

```json
{
  "phase": 3,
  "completed_at": "2024-01-15T14:30:00Z",
  "started_at": "2024-01-15T14:00:00Z",
  "artifacts": [
    "audit-report/raw/recon.md",
    "audit-report/raw/static-analysis.md",
    "audit-report/findings/"
  ],
  "repo": "/path/to/repo",
  "options": {"no_fv": false, "report": true}
}
```

## Resume Logic

| Current Phase | Action |
|---------------|--------|
| 1 | Start from phase 1 (no phases completed) |
| 2 | Skip phase 1, load `skill/01-recon.md` outputs, start phase 2 |
| 3 | Skip phases 1-2, load outputs, start phase 3 |
| 4 | Skip phases 1-3, load outputs, start phase 4 |
| 5 | Skip phases 1-4, load outputs, start phase 5 |
| 6 | Audit already complete — print final output summary |

## Phase Dispatch

Same as `/audit` but skip phases that are already completed (based on state file).

## Final output

Same as `/audit` final output.

## Rules

Same rules as `/audit`. Additionally:
- Do not re-run completed phases
- Verify artifact files exist before skipping a phase
- If artifacts missing for a completed phase, warn and offer to re-run that phase
