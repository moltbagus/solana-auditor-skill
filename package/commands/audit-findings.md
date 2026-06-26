---
description: List, filter, dedupe, retag, export the findings database — pure data manipulation, no analysis
---

# /audit-findings — Findings Database Manager

Query, filter, deduplicate, and export existing findings. No new analysis.

## Usage

```
/audit-findings                          # List all, severity-sorted
/audit-findings --severity CRITICAL      # Filter
/audit-findings --status Open            # Filter
/audit-findings --file programs/foo      # Filter
/audit-findings --dedupe                 # Find near-duplicates (interactive)
/audit-findings --retag <id> <new-sev>   # Reclassify severity
/audit-findings --add                    # Add finding manually (interactive)
/audit-findings --delete <id>            # Delete (confirmation required)
/audit-findings --export json|csv|sarif  # Export
```

## Pre-flight

1. **Locate findings file** — search order:
   - `<cwd>/audit-report/findings.json`
   - `<cwd>/findings.json`
   - `<cwd>/audit-output/findings.json`
   - Ask user if not found.
2. **Validate JSON schema** — abort with parse error on invalid.
3. **Confirm destructive ops** — `--delete`, `--retag` (when downgrading) require explicit confirmation.

## Listing (default)

Print compact table: `ID | Severity | Status | Title | Location`. Plus count summary.

### Filters (compose with AND)

`--severity CRITICAL,HIGH` · `--status Open,Fixed,Verified` · `--file <substring>` · `--id CRIT-01,HIGH-02` · `--has-poc` / `--no-poc` · `--cwe CWE-306`

## Deduplication (`--dedupe`)

Algorithm:
1. Exact title match → flag.
2. Same file + same `#[account(...)]` constraint or same instruction function → flag.
3. Same CWE + same file → flag.
4. Fingerprint hash of `description[:200] + recommendation[:100]` → flag on collision.

For each pair, present actions:
- **[m]** Merge into first (concatenate evidence, keep first ID)
- **[k]** Keep both (mark as related, add `related_to` field)
- **[s]** Skip this pair

**Never auto-merge.** Iterate through all duplicate pairs.

## Retag (`--retag <id> <new-severity>`)

```
HIGH-03 currently HIGH (CVSS 7.5).
Change to MEDIUM? [type the new severity in caps to confirm]
```

- Reject downgrades from CRITICAL/HIGH without CVSS justification in the confirmation.
- Log change with timestamp and reason.
- Renumber IDs by severity after retag; preserve old IDs in `previous_ids`.

## Add (`--add`)

Interactive flow: severity (must justify CRIT/HIGH with impact) → title → location → description → impact → recommendation → CWE (optional) → CVSS vector (optional, defaults) → status (default Open).

Append to `findings.json`, renumber, write back.

## Delete (`--delete <id>`)

```
Delete INFO-07 "<title>"? This cannot be undone.
Type 'delete' to confirm:
```

Never auto-delete. Always require literal word `delete`.

## Export (`--export <format>`)

| Format | Notes |
|--------|-------|
| `json` | Pretty-print `findings.json` (default schema in `skill/04-findings-triage.md` §Findings Database Format) |
| `csv`  | RFC 4180 UTF-8. Columns: `id,severity,cvss,cwe,status,title,file,line,description,recommendation` |
| `sarif` | SARIF 2.1.0 for GitHub Code Scanning. Severity map: CRIT/HIGH → `error`, MEDIUM → `warning`, LOW/INFO → `note` |

If `--output <path>` given, write to file; else stdout.

## Rules

- No code analysis. Pure data manipulation.
- Destructive operations always require explicit confirmation typed in caps.
- Renumber after `--retag`; preserve old IDs in `previous_ids`.
- Atomic writes: write `.tmp`, then `mv` to avoid corruption.
