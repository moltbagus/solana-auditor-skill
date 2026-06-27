---
name: audit-report
description: Synthesize findings.json into a production-grade audit report — markdown + JSON
---

# /audit-report — Generate Audit Report

Take existing findings and produce a final structured report. **No new analysis — synthesis only.**

## Usage

```
/audit-report <findings-json>
/audit-report <findings-json> --output <path>
/audit-report <findings-json> --format json   # JSON-only, normalized schema
/audit-report <findings-json> --format sarif  # SARIF 2.1.0 for GitHub Code Scanning
```

Default output: `<findings-dir>/AUDIT_REPORT.md`.

## Pre-flight

1. Read findings file. If invalid JSON, abort with parse error.
2. Sort by severity (CRITICAL → INFO).
3. If `--output` not given, write to `<findings-dir>/AUDIT_REPORT.md`.

## Required sections (in order)

See `skill/05-report-generation.md` §Report Structure for the full template and example markdown. Summary:

1. **Cover Page** — program, repo, date, methodology, tools
2. **Executive Summary** — 3-6 sentences, lead with severity count
3. **Scope** — files audited, exclusions
4. **Severity Summary Table** — counts by level
5. **Findings** — one section per finding, severity-sorted, with Description/Impact/PoC-reference/Recommendation
6. **Patterns Reviewed, Not Exploited** — builds reviewer trust
7. **Out-of-Scope** — explicit list
8. **Disclaimer** — point-in-time review notice
9. **Appendix — Tools & Methodology**

**Reference, do not paste exploit code** in the report. PoC paths only.

## JSON output schema

```json
{
  "report_version": "1.0",
  "program": "<name>",
  "repo": "<path>",
  "audit_date": "<iso>",
  "executive_summary": "<text>",
  "scope": ["<file>", "..."],
  "severity_summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
  "findings": [{
    "id": "CRIT-01",
    "severity": "CRITICAL",
    "cvss": 9.1,
    "cvss_vector": "CVSS:3.1/...",
    "cwe": "CWE-306",
    "title": "<title>",
    "location": {"file": "...", "line": 42},
    "description": "...",
    "impact": "...",
    "recommendation": "...",
    "poc_path": "<path or null>",
    "status": "Open"
  }],
  "out_of_scope": ["..."]
}
```

Required fields: `id`, `severity`, `title`, `description`, `recommendation`. Warn (don't reject) if `poc_path` missing for CRITICAL/HIGH.

## SARIF output format

For DevSecOps integration with GitHub Code Scanning, use `--format sarif`:

```
/audit-report <findings-json> --format sarif --output results.sarif
```

The SARIF 2.1.0 output includes:
- Severity mapping: CRITICAL/HIGH → error, MEDIUM → warning, LOW/INFO → note
- File and line references from `finding.location`
- CWE and CVSS metadata preserved in result properties
- Rule definitions with default severity levels

### CLI usage (alternative to command)

```bash
python3 scripts/export-sarif.py <findings-json> [--output <file>]
```

Or pipe findings through stdin:
```bash
python3 scripts/export-sarif.py --output results.sarif
```

## Post-write

1. Print path to generated report.
2. Print executive summary inline.
3. Print severity summary table inline.
4. Ask: "Generate PoCs? Run `/audit-poc <finding-id>`."
5. Do NOT auto-open the report.

## Rules

- No new analysis. Preserve operator wording.
- Malformed findings → "Malformed Findings" appendix, don't drop.
- Severity sort + re-number IDs if any were renumbered during triage.
