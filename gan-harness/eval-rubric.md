# Evaluation Rubric: AuditViz Dashboard

**Project**: Interactive Solana Audit Dashboard
**Evaluator**: GAN harness automated checker + human judge
**Scoring**: 1–10 per dimension, weighted total out of 10

---

## Dimension 1: Design Quality (Weight: 25%)

### Score Anchors

| Score | Description |
|-------|-------------|
| **10** | Exceptional visual design. Dark theme executed flawlessly with distinctive typography (Space Grotesk + JetBrains Mono), severity colors used semantically throughout, glassmorphism on charts, proper depth layering. Looks like a professional security tool, not a template. |
| **8** | Strong design with dark theme, proper typography, clear visual hierarchy. Charts are well-styled. Minor polish gaps (some hover states missing, slightly generic spacing). |
| **6** | Functional dark theme but lacks distinctive character. Typography present but mixed inconsistently. Charts work but look like default library output. Some accessibility issues. |
| **4** | Dark theme applied but poorly executed. Inconsistent color usage, awkward spacing, generic card layout. |
| **2** | Barely dark-themed. Light-mode remnants, no visual identity, looks like a stripped Bootstrap. |
| **1** | No dark theme. White background, default system fonts, completely generic. |

### Checkpoints

- [ ] Background is deep navy/black (`#0a0e17` or equivalent)
- [ ] Text is light-colored and readable
- [ ] Severity colors are used consistently (CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue)
- [ ] JetBrains Mono used for code/data display
- [ ] Space Grotesk or equivalent distinctive heading font
- [ ] Cards have proper borders/shadows for depth
- [ ] No jarring bright whites or generic template aesthetics

---

## Dimension 2: Originality (Weight: 20%)

### Score Anchors

| Score | Description |
|-------|-------------|
| **10** | Unique visual identity. Terminal-inspired aesthetic, custom SVG charts with brand styling, innovative data visualization choices, memorable layout that stands apart from generic dashboards. |
| **8** | Distinctive choices in typography, chart styling, or layout. Some creative decisions that elevate beyond defaults. |
| **6** | Acceptable originality. Uses standard dashboard patterns but with some personality (custom colors, thoughtful spacing). |
| **4** | Generic dashboard layout. Standard card grid, common chart types, no memorable design choices. |
| **2** | Nearly identical to common admin templates. No distinctive character. |
| **1** | Copy of existing dashboard.html with only color inversion. |

### Checkpoints

- [ ] Layout is not a standard sidebar+cards grid
- [ ] Charts are custom SVG (not Chart.js defaults)
- [ ] Visual identity feels like a security tool, not a generic admin panel
- [ ] At least one innovative interaction or visualization
- [ ] No gradient blob backgrounds (AI-slop indicator)

---

## Dimension 3: Craft (Weight: 25%)

### Score Anchors

| Score | Description |
|-------|-------------|
| **10** | Flawless HTML/CSS/JS. Zero console errors. Well-organized CSS with custom properties. Semantic HTML. Smooth animations using transform/opacity only. All interactions functional. |
| **8** | Clean code with minor issues. One or two console warnings but no errors. CSS organized well. Animations smooth. |
| **6** | Functional but rough. Some console errors fixed. CSS could be cleaner. Animations janky. |
| **4** | Multiple console errors. Poor CSS organization. Broken interactions. |
| **2** | Major JS errors preventing functionality. Chaotic code structure. |
| **1** | Page doesn't load or completely broken. |

### Checkpoints

- [ ] Zero JavaScript errors in console
- [ ] Zero console warnings about missing resources
- [ ] All buttons/links functional
- [ ] Smooth hover transitions (no layout thrashing)
- [ ] Animations use transform/opacity (compositor-friendly)
- [ ] CSS uses custom properties for consistency
- [ ] No inline styles except dynamic values
- [ ] HTML is semantic (proper heading hierarchy, etc.)

---

## Dimension 4: Functionality (Weight: 30%)

### Score Anchors

| Score | Description |
|-------|-------------|
| **10** | All features work flawlessly. Data loads correctly from findings.json. Charts render with real data. Table sorting works. Expand/collapse works. Filters work. Copy-to-clipboard works. |
| **8** | Core functionality works. Data loads, charts render, table sortable, expand works. Minor edge case issues. |
| **6** | Basic functionality present. Data loads, charts render, table works but sorting/filtering incomplete. |
| **4** | Partial functionality. Charts render but data doesn't match. Table partially sortable. |
| **2** | Minimal functionality. Only static display works. No interactivity. |
| **1** | Broken — data doesn't load, charts don't render, page is static. |

### Checkpoints

- [ ] Page loads successfully
- [ ] All 10 sample findings displayed
- [ ] Severity pie chart renders with correct counts (2 CRIT, 2 HIGH, 6 MEDIUM)
- [ ] CVSS distribution histogram shows correct ranges
- [ ] Finding table is sortable by clicking headers
- [ ] Clicking a row expands to show remediation panel
- [ ] Remediation panel shows: description, impact, recommendation, regression_test
- [ ] Code blocks in remediation use monospace font
- [ ] Copy button on code blocks works
- [ ] Filter controls (if implemented) actually filter results
- [ ] Charts update when filters change (if interactive)

---

## Weighted Total Score Formula

```
total_score = (design_score * 0.25) + (originality_score * 0.20) + (craft_score * 0.25) + (functionality_score * 0.30)
```

**Example**: design=8, originality=6, craft=9, functionality=7 → (8×0.25)+(6×0.20)+(9×0.25)+(7×0.30) = 2.0+1.2+2.25+2.1 = **7.55/10**

---

## Pass Threshold

| Score | Verdict |
|-------|---------|
| 8.0+ | **Gold** — Exceptional, production-ready |
| 6.5+ | **Silver** — Good, minor polish needed |
| 5.0+ | **Bronze** — Functional, needs work |
| <5.0 | **Fail** — Does not meet baseline |

---

## Test Data

The dashboard must correctly render sample data from:
`examples/sample-vulnerable-program/audit-output/findings.json`

Expected findings: 10 total
- CRITICAL: 2 (VULN-01, VULN-04)
- HIGH: 2 (VULN-03, VULN-05)
- MEDIUM: 6 (VULN-02, VULN-06, VULN-07, VULN-08, VULN-09, VULN-10)
- LOW: 0
- INFO: 0

CVSS scores range from 4.3 to 9.8.