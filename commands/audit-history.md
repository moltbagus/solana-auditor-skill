---
name: audit-history
description: View and compare audit history across program versions
agent_type: command
---

# audit-history

View and compare audit history across program versions.

## Usage

```
/audit-history --list <program_id>
/audit-history --diff <program_id> <v1> <v2>
/audit-history --stats
/audit-history --new <program_id> [--version <semver>]
```

## Arguments

| Argument | Description |
|----------|-------------|
| `--list` | List all audited versions for a program |
| `--diff` | Compare findings between two versions |
| `--stats` | Show overall audit statistics |
| `--new` | Start a new audit and save to history |
| `--version` | Optional semantic version for new audit (default: prompts for input) |

## Pre-flight

1. Locate `.audit-history.json` in current directory or parent directories (walk up)
2. Initialize with empty schema if not found
3. Require `jq` for JSON operations

## Command Details

### `/audit-history --list <program_id>`

Lists all audited versions for the specified program.

**Example output:**
```
1.0.0 (2026-06-25T12:00:00Z)
1.1.0 (2026-06-24T09:30:00Z)
1.2.0 (2026-06-23T15:45:00Z)
```

**If no program_id provided:** List all programs with audit counts.

### `/audit-history --diff <program_id> <v1> <v2>`

Compares two audit snapshots and outputs:

1. **Severity breakdown table** (Critical / High / Medium counts per version)
2. **NEW Findings** - Finding IDs present in v2 but not v1
3. **FIXED Findings** - Finding IDs present in v1 but not v2

**Example output:**
```
=== Audit Diff: ExampleToken123... (v1.0.0 -> v1.1.0) ===

--- Severity Breakdown ---
  Version    Crit  High  Med
  v1.0.0        1     3     2
  v1.1.0        0     2     2

--- NEW Findings ---
  VULN-05

--- FIXED Findings ---
  VULN-01
```

### `/audit-history --stats`

Shows aggregate statistics across all audits:

- Total programs audited
- Total audit snapshots
- Finding distribution (Critical / High / Medium / Low)
- Most recent audit details
- Per-program breakdown

### `/audit-history --new <program_id> [--version <semver>]`

Executes a full `/audit` for the program, then saves the results to history.

**Workflow:**

1. Run `/audit <program_id>`
2. After audit completes, extract findings summary
3. Prompt user for version tag (if `--version` not provided)
4. Call `audit_history_add()` to save snapshot
5. Display confirmation with summary

**Prompt template:**
```
Save audit snapshot to history?

Program: {program_id}
Version: {version}
Findings: {critical}C / {high}H / {medium}M / {low}L

Enter version tag or 'skip' to cancel:
```

## Integration Points

### Post-Audit Auto-prompt

After `/audit` completes successfully, automatically prompt:

```
Audit complete for {program_id}

Save to history? This enables future /audit-history --diff comparisons.

[Enter version tag] or [skip]
```

### Report Generation Integration

When `/audit-report` generates a report, check if user wants to save snapshot:

```
Include in audit history? This tracks findings across versions.

/audit-history --new {program_id} --version {version}
```

## File Discovery

History file discovery order:

1. `$AUDIT_HISTORY` environment variable (if set)
2. `.audit-history.json` in current directory
3. Walk up parent directories to find nearest `.audit-history.json`
4. Create in current directory if not found

## Error Handling

| Error | Message | Recovery |
|-------|---------|----------|
| No jq | `jq is required for JSON operations` | Install jq or set `JQ_BIN` path |
| History not found | `No audit history found` | Offer to initialize |
| Program not found | `No audits for program: {id}` | Show available programs |
| Version not found | `No audit for {program_id}@{version}` | Show available versions |
| Same version diff | `Cannot diff identical versions` | Prompt for different versions |

## Finding ID Convention

Finding IDs follow pattern: `{severity}-{NN}`

| Severity | Prefix | Example |
|----------|--------|---------|
| Critical | CRIT | CRIT-01, CRIT-02 |
| High | HIGH | HIGH-01, HIGH-02 |
| Medium | MED | MED-01, MED-02 |
| Low | LOW | LOW-01, LOW-02 |
| Info | INFO | INFO-01, INFO-02 |

## Example Sessions

### Track a program across releases

```markdown
User: /audit ExampleToken111...

[AUDIT COMPLETE]
Found: 1 CRIT, 2 HIGH, 3 MED

User: /audit-history --new ExampleToken111 --version 1.0.0
[SAVED]

[... code changes ...]

User: /audit ExampleToken111...

[AUDIT COMPLETE]
Found: 0 CRIT, 1 HIGH, 3 MED

User: /audit-history --new ExampleToken111 --version 1.1.0
[SAVED]

User: /audit-history --diff ExampleToken111 1.0.0 1.1.0

=== Audit Diff: ExampleToken111... (v1.0.0 -> v1.1.0) ===

--- Severity Breakdown ---
  v1.0.0        1     2     3
  v1.1.0        0     1     3

--- NEW Findings ---
  (none)

--- FIXED Findings ---
  CRIT-01
  HIGH-01
```

### Compare across programs

```markdown
User: /audit-history --stats

=== Audit History Statistics ===

Summary:
  Total programs audited:  3
  Total audit snapshots:   7

Finding Distribution:
  Critical:  2
  High:      8
  Medium:    12
  Low:       5
  Total:     27

Most Recent Audit:
  Program:   VaultProgram222...
  Version:   2.3.1
  Date:      2026-06-25T14:30:00Z
```

## Notes

- History file uses file locking for concurrent safety
- Finding IDs must be stable across versions for accurate diff
- Commit hash is recorded for reproducibility
- Auditor identity defaults to `claude`, configurable via `AUDIT_AUDITOR` env
