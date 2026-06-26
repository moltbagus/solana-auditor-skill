# Design: Audit Dashboard (HTML Report)

## 2026-06-27

## Overview

Transform `findings.json` into a self-contained HTML file that opens offline in any browser. No server, no CDN, no JavaScript framework. Auto-generated from existing findings schema.

## What gets shown

| Section | Content |
|---------|---------|
| **Header** | Program name, repo, audit date, skill version |
| **Severity bar** | CRITICAL/HIGH/MEDIUM/LOW/INFO counts with color chips |
| **CVSS summary** | Total score, average, worst finding |
| **Findings table** | ID, severity chip, title, CWE, CVSS score, location, rule caught. Sortable by clicking column headers. Click row to expand inline detail. |
| **Finding detail** | Full description, impact, recommendation, poc_status, rule reference |
| **Fix map** | Severity → rule count bar chart (ASCII via CSS) |
| **Metadata footer** | Generator version, file path, generation timestamp |

## Output contract

```
scripts/dashboard.py <findings.json> [output.html]

Default output: <findings.json stem>.dashboard.html
Stdin: can also pipe JSON: cat findings.json | python3 dashboard.py -
```

## Architecture

```
findings.json
    → dashboard.py (reads JSON, renders Jinja2 template)
    → report.html (single file, all CSS inline, no external deps)
```

### dashboard.py

- Pure stdlib Python 3.9+
- `jinja2` required (already a dep? add to requirements-dev.txt if not)
- `argparse` for CLI
- Reads findings.json, computes derived fields (severity counts, CVSS total/avg, rule groups)
- Renders template, writes HTML file
- Error: non-zero exit if JSON unparseable or template missing

### Template: `templates/dashboard.html`

Jinja2 HTML with:
- Inline `<style>` block (no external CSS)
- `<script>` block for sort/expand interaction (vanilla JS, no framework)
- `{{ findings }}`, `{{ summary }}`, `{{ metadata }}` injected
- Responsive: works on mobile for sharing

## Error handling

| Error | Behavior |
|-------|-----------|
| JSON unparseable | Exit 1, print filename + Python exception |
| Template missing | Exit 1, print path |
| Empty findings | Render empty state with message |
| Missing optional fields | Render `N/A` gracefully |

## Testing

- `examples/sample-vulnerable-program/audit-output/findings.json` → generate report → open in browser
- Integrity check: generated HTML contains expected severity counts
- Link check: no `href` to external URLs (offline-safe)

## Integrates with

- `/audit-report` command: call dashboard.py as post-step after JSON generation
- demo.sh: step 4 can open dashboard instead of (or alongside) JSON dump
- `audit-findings`: `--export html` calls dashboard.py

## Scope

DO: single self-contained HTML.  
DON'T: server mode, CDN dependencies, JavaScript framework, dark/light theme variants (single theme), multi-program aggregation.

## Success criteria

```bash
python3 scripts/dashboard.py examples/sample-vulnerable-program/audit-output/findings.json
# produces HTML with correct severity counts, opens in browser offline
```

Judge opens `dashboard.html` from skill install — no additional install needed beyond skill.
