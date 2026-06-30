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
/audit-report <findings-json> --html          # Markdown report + HTML dashboard
/audit-report <findings-json> --include-architecture  # Include Architecture Review Summary
/audit-report <findings-json> --include-threat-model  # Include Threat Model Summary (STRIDE)
/audit-report <findings-json> --include-economic      # Include Economic Security Analysis
/audit-report <findings-json> --include-all           # Include all three enhanced sections
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
3. **Architecture Review Summary** — program design, account architecture, CPI map, PDAs (if `--include-architecture` or `--include-all`)
4. **Threat Model Summary (STRIDE)** — six-category threat analysis (if `--include-threat-model` or `--include-all`)
5. **Economic Security Analysis** — TVL, attack economics, incentive alignment (if `--include-economic` or `--include-all`)
6. **Scope** — files audited, exclusions
7. **Severity Summary Table** — counts by level
8. **Findings** — one section per finding, severity-sorted, with Description/Impact/PoC-reference/Recommendation
9. **Patterns Reviewed, Not Exploited** — builds reviewer trust
10. **Out-of-Scope** — explicit list
11. **Disclaimer** — point-in-time review notice
12. **Appendix — Tools & Methodology**

**Reference, do not paste exploit code** in the report. PoC paths only.

## Enhanced Sections

### --include-architecture

Adds Section 2: **Architecture Review Summary** containing:

- Program design overview (Anchor version, account count, instruction count)
- Account architecture table (type, purpose, access control)
- Cross-program invocation map (targets, purpose, trust assumptions)
- PDA derivation table (seeds, deriver, access pattern)
- Data flow diagram (text-based)
- Design strengths and concerns

Use when: auditing complex programs with multiple account types and CPI chains.

### --include-threat-model

Adds Section 3: **Threat Model Summary (STRIDE)** containing:

- STRIDE threat breakdown per category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- Per-threat table: affected component, likelihood, impact
- Mitigations in place vs. gaps
- Threat surface summary table

Use when: preparing for formal security review, bug bounty launch, or insurance application.

### --include-economic

Adds Section 4: **Economic Security Analysis** containing:

- TVL and fund flow metrics
- Attack economics table (max extractable, cost, net profit per finding)
- Economic viability assessment per finding
- Incentive alignment analysis per actor type
- Griefing and loss scenarios
- Economic constraint recommendations (immediate/short-term/long-term)

Use when: program manages significant TVL, token reserves, or fee flows.

### --include-all

Shorthand for `--include-architecture --include-threat-model --include-economic`. Adds all three enhanced sections. Use when: full corporate-grade report required.

**Note**: Enhanced sections require manual input for architecture diagrams, threat likelihood ratings, and economic figures. The command will prompt for these if not present in findings.json under the `architecture`, `threat_model`, and `economic` keys.

## JSON output schema

```json
{
  "report_version": "1.0",
  "program": "<name>",
  "repo": "<path>",
  "audit_date": "<iso>",
  "executive_summary": "<text>",
  "scope": ["<file>", "..."],
  "architecture_summary": {"..."},
  "threat_model": {"..."},
  "economic_security": {"..."},
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

## HTML Export

After generating findings.json and AUDIT_REPORT.md, optionally call:

```
python3 scripts/dashboard.py <findings-path> <output-html>
python3 scripts/dashboard.py --compare <before-findings> <after-findings> <output-html>
```

Add a `--html` flag to the audit-report command that triggers this automatically after the markdown report is written.

If `--html` is passed:
1. Locate findings.json (search order: `<repo>/audit-output/findings.json`, `<repo>/findings.json`)
2. Derive output path: `findings.json.with_suffix('.dashboard.html')`
3. Run `python3 scripts/dashboard.py findings.json output.html`
4. Report the dashboard path in the final summary

## Post-write

1. Print path to generated report.
2. Print executive summary inline.
3. Print severity summary table inline.
4. Ask: "Generate PoCs? Run `/audit-poc <finding-id>`."
5. Do NOT auto-open the report.
6. If `--html` was passed, print the dashboard path after the report path.
7. If `--include-architecture`, `--include-threat-model`, `--include-economic`, or `--include-all` was passed, note which enhanced sections were included.

## Rules

- No new analysis. Preserve operator wording.
- Malformed findings → "Malformed Findings" appendix, don't drop.
- Severity sort + re-number IDs if any were renumbered during triage.
- Enhanced sections are omitted unless explicitly requested via flags.
- When `--include-all` is passed, treat as if all three individual flags were passed.