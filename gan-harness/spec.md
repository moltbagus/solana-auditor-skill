# Product Specification: AuditViz — Interactive Solana Audit Dashboard

> Generated from brief: "Build an interactive HTML audit dashboard for the solana-auditor-skill that displays vulnerability findings with severity breakdown, CVSS scoring, and remediation guidance — with a professional dark theme."

## Vision

A cinematic, terminal-inspired audit dashboard that transforms raw vulnerability data into a compelling visual narrative. Think Bloomberg Terminal meets cybersecurity war room — dense with information but surgically organized, where every pixel earns its place. The dashboard should feel like it was built by someone who actually ships security tools, not a generic admin template.

## Design Direction

### Color Palette

| Role | Hex | Usage |
|------|-----|-------|
| Background Deep | `#0a0e17` | Page background |
| Background Surface | `#111827` | Card backgrounds |
| Background Elevated | `#1f2937` | Hover states, raised elements |
| Border Subtle | `#374151` | Dividers, card borders |
| Text Primary | `#f9fafb` | Headings, primary content |
| Text Secondary | `#9ca3af` | Labels, secondary info |
| Text Muted | `#6b7280` | Timestamps, hints |
| Accent Cyan | `#22d3ee` | Primary interactive elements |
| Accent Green | `#34d399` | Success, fixed status |
| Severity CRITICAL | `#ef4444` | Critical vulnerabilities |
| Severity HIGH | `#f97316` | High vulnerabilities |
| Severity MEDIUM | `#eab308` | Medium vulnerabilities |
| Severity LOW | `#3b82f6` | Low vulnerabilities |
| Severity INFO | `#6b7280` | Informational items |

### Typography

- **Headings**: `"Space Grotesk"` (Google Fonts) — geometric, technical, distinctive
- **Body**: `"Inter"` fallback to system-ui — readable at small sizes
- **Code/Data**: `"JetBrains Mono"` — for file paths, CVSS vectors, code snippets
- **Scale**: 11px (labels) / 13px (body) / 15px (card values) / 20px (section titles) / 28px (hero metrics)

### Layout Philosophy

Single-page application with three horizontal zones:

1. **Hero Metrics Strip** — Full-width, immediately visible KPIs (total findings, critical count, average CVSS, worst finding)
2. **Visualization Row** — Three charts side-by-side: severity pie, CVSS distribution histogram, rule coverage
3. **Findings Panel** — Filterable, sortable table with expandable detail rows and remediation guidance

### Visual Identity

- **No gradients** on large surfaces — flat dark surfaces with subtle border luminosity
- **Neon accent lines** — 1px borders using severity colors for visual hierarchy
- **Glassmorphism on charts** — Semi-transparent backgrounds with backdrop blur
- **Terminal aesthetic** — Monospace fonts for paths/codes, subtle scan-line texture on header
- **Depth through layering** — Cards float above background with box-shadow stacking

### Anti-AI-Slop Directives

- NO gradient blobs as backgrounds
- NO rounded-everything uniformity (mix sharp corners for data tables, subtle radius for cards)
- NO generic sans-serif only (JetBrains Mono + Space Grotesk are non-negotiable)
- NO stock chart library defaults (custom SVG charts with brand colors)
- NO flat color dumps (use opacity modulation for hierarchy)

## Features (prioritized)

### Must-Have (Sprint 1-2)

1. **Dark Theme Rendering**
   - Deep navy background (`#0a0e17`)
   - All text accessible (WCAG AA contrast minimum)
   - Severity colors prominently displayed

2. **Hero Metrics Strip**
   - Total findings count (large number, pulsing glow if critical > 0)
   - Critical count (red accent)
   - Average CVSS (with color-coded badge)
   - Worst finding (clickable, scrolls to it)

3. **Severity Breakdown Pie Chart**
   - SVG donut chart with severity segments
   - Hover reveals count + percentage
   - Center shows total or hovered segment value
   - Click filters findings table

4. **CVSS Distribution Histogram**
   - Bar chart showing count per CVSS range (0-4, 4-6, 6-8, 8-10)
   - Color-coded bars matching severity
   - Hover shows exact count

5. **Rule Coverage Chart**
   - Horizontal bar chart
   - Shows which audit rules caught findings
   - Highlights "non-rule-aligned" findings separately

6. **Findings Table**
   - Sortable columns: ID, Severity, Title, CWE, CVSS, Location, Rule
   - Severity pill badges with colors
   - CVSS score badges with color gradient (red=9+, orange=7+, yellow=4+, blue=rest)
   - Click row to expand remediation panel

7. **Remediation Panel (expanded row)**
   - Full description text
   - Impact analysis
   - Step-by-step recommendation
   - Code snippet display (monospace, syntax-aware background)
   - Regression test code block
   - Status badge
   - Copy-to-clipboard for code blocks

### Should-Have (Sprint 3-4)

8. **Filter Controls**
   - Severity multi-select filter (checkboxes)
   - Rule filter dropdown
   - CWE search/filter
   - Text search across title/description

9. **Keyboard Navigation**
   - Arrow keys navigate findings
   - Enter expands/collapses
   - Escape closes expanded row
   - `/` focuses search

10. **Print/Export View**
    - Clean print stylesheet
    - Exclude charts, show data tables instead

11. **Comparison Mode Support**
    - Before/after delta visualization
    - Fixed/unchanged/new status badges
    - CVSS reduction metrics

### Nice-to-Have (Sprint 5+)

12. **Anomaly Highlighting**
    - Pulse animation on CRITICAL findings
    - "Worst" finding badge

13. **Responsive Mobile View**
    - Stacked layout on mobile
    - Collapsible chart section

## Technical Stack

- **Single HTML file** — Self-contained, no build step
- **CSS Variables** — Design tokens for all colors/spacing
- **Vanilla JS** — No framework dependencies
- **SVG Charts** — Hand-crafted, no Chart.js/D3 (keeps bundle small)
- **Google Fonts** — Space Grotesk, JetBrains Mono (loaded async)
- **LocalStorage** — Persist filter/sort preferences

## Data Schema Reference

```json
{
  "findings": [{
    "id": "VULN-01",
    "title": "Admin withdraw lacks signer verification",
    "severity": "CRITICAL",
    "cvss": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-306",
    "location": { "file": "...", "line": 36, "function": "admin_withdraw" },
    "description": "...",
    "impact": "...",
    "recommendation": "...",
    "poc_status": "pending",
    "rule_caught": "Rule 8 — Signer Verification",
    "rule": 8,
    "status": "Open",
    "root_cause": "...",
    "regression_test": "..."
  }],
  "summary": { "critical": 2, "high": 2, "medium": 6, "low": 0, "info": 0, "total": 10 }
}
```

## Evaluation Criteria

See `eval-rubric.md` for the 4-dimension scoring framework.

## Sprint Plan

### Sprint 1: Foundation

- Goals: Dark theme base, hero metrics, severity pie chart
- Features: [#1, #2, #3]
- Definition of done: Page loads with sample data, all 10 findings visible, pie chart interactive

### Sprint 2: Core Visualization

- Goals: CVSS histogram, rule coverage chart, findings table with expand
- Features: [#4, #5, #6, #7]
- Definition of done: All charts render, table sortable, remediation panel shows all fields

### Sprint 3: Interactivity

- Goals: Filters, keyboard nav, comparison mode
- Features: [#8, #9, #10, #11]
- Definition of done: Filters work, keyboard nav functional, comparison mode renders

### Sprint 4: Polish

- Goals: Animation, responsive, anomaly highlighting
- Features: [#12, #13]
- Definition of done: Smooth animations, mobile-usable, critical findings pulse