---
name: solana-auditor-skill-patterns
description: Coding patterns extracted from solana-auditor-skill — audit skill engineering with spec-driven development, property-based testing, and Claude Code agent orchestration
version: 1.0.0
source: local-git-analysis
analyzed_commits: 92
---

# Solana Auditor Shiba — Patterns

## Commit Conventions

**Strict conventional commits** — every commit typed by scope:

```
feat:       New capability (rules, agents, commands, phases)
fix:        Bug correction (audit findings, docs, CI)
docs:       Documentation only (README, CHANGELOG, inline docs)
test:       Test coverage (property-based, integration, unit)
chore:      Maintenance (deps, config, tooling)
refactor:   Code restructuring (SRP, deduplication)
style:      Formatting (black, ruff, prettier)
perf:       Performance improvement
ci:         CI/CD pipeline changes
```

**Scope conventions:**
- `fix(audit)` — corrections to audit output, findings, submissions
- `fix(docs)` — documentation corrections (counts, versions, links)
- `fix(python)` — Python code fixes (3.9 compat, type hints)
- `fix(demo)` — demo script corrections
- `feat(ruleN)` — new security rule N
- `feat(audit)` — live audit deliverables
- `docs(sdd)` — SDD doc updates (PRD, spec, kanban, learnings)

**Non-negotiable rules:**
1. Version numbers in `fix(docs)` commits must match the actual state (`v1.7` not `v1.5`)
2. Every `feat:` must update `CHANGELOG.md` in the same commit
3. Every PR touching `rules/audit.rules` must run `bash tests/test-skill-integrity.sh` before merge

---

## Code Architecture

### Directory Layout

```
solana-auditor-skill/
├── skill/          Phase procedures (01-recon.md → 06-remediation.md)
├── agents/         Specialist agents (orchestrator, auditor, formal-verifier,
│                   report-writer, cross-program-agent, safety-guard)
├── commands/       Slash commands (/audit, /audit-quick, /audit-resume, etc.)
├── rules/          Path-scoped rules (audit.rules — 50 rules)
├── tests/
│   ├── test-skill-integrity.sh    # 153 shell integrity checks
│   ├── fuzz/
│   │   └── test_properties.py     # 22 property-based Hypothesis tests
│   └── severity_counts.py          # CVSS math verification
├── examples/       Compile-verified vulnerable programs with PoC findings
├── scripts/        Helper scripts (pre-commit, CPI graph, SARIF export)
├── templates/      PoC templates (Anchor, TypeScript, Manual)
├── prompts/        Agent prompt templates
└── references/    Domain reference docs (LIMITATIONS.md, etc.)
```

### File Naming

| Type | Pattern | Example |
|------|---------|---------|
| Phase files | `NN-name.md` | `01-recon.md`, `02B-runtime-testing.md` |
| Agent files | `name.md` | `auditor.md`, `safety-guard.md` |
| Commands | `audit-name.md` | `audit-quick.md`, `audit-pr.md` |
| Rules | Single file `audit.rules` with `## Rule N` headers |
| Fixtures | `/examples/NAME/audit-output/findings.json` |
| Tests | Same dir as code, `test_*.py` or `*_test.sh` |

---

## Key Workflows

### Adding a New Security Rule

1. Add `## Rule N` block to `rules/audit.rules` with:
   - Triggers (file pattern glob)
   - Catches (vulnerability class)
   - CWE reference URL
   - Real exploit example (Wormhole, Cashio, Mango, etc.)
2. Add VULN tag `// VULN-NN:` in the example fixture source
3. Add finding entry to `examples/*/audit-output/findings.json`
4. Update `examples/*/audit-output/AUDIT_REPORT.md`
5. Update `examples/*/audit-output/methodology-trace.md`
6. Run `bash tests/test-skill-integrity.sh` — all 153 must pass
7. Run `python3 tests/fuzz/test_properties.py` — all 22 must pass
8. Update `CHANGELOG.md` (version, rule summary)
9. Update `PRD.md` rules table
10. Update `README.md` rules table

### Bug Fix Workflow

1. **Identify** via integrity check failure, subagent audit, or manual review
2. **Scope** — fix only the broken files; no drive-by changes
3. **Fix** — apply minimal correct change
4. **Verify** — `bash tests/test-skill-integrity.sh`
5. **Commit** — `fix(scope): one-line description (#issue)`

### Live Audit Workflow

1. Clone target repo, run `bash demo.sh` to verify toolchain
2. Run `/audit <repo>` for full lifecycle OR `/audit-quick <repo>` for SAST-only
3. Phase 0 Safety Guard: confirm program ID, cluster, credentials
4. Recon → Static Analysis → Formal Verification → Triage → Report
5. Export findings as JSON + markdown report
6. Write Immunefi submission if High/Critical

---

## Testing Patterns

### Three-Layer Test Pyramid

```
Layer 1: Integrity checks (bash)     — 153 checks, zero deps, CI-fast
Layer 2: Property-based fuzz (Python) — 22 Hypothesis strategies, CVSS math
Layer 3: Manual verification          — judge reads output, runs demo.sh
```

### Integrity Check Convention

Every check has a unique number and a descriptive label:
```
Check 1: skill phase file numbering
Check 2: command cross-references resolve
Check 3: vault fixture VULN-XX ↔ findings.json coverage
...
Check 153: [category-specific]
```

**Check categories:**
- Phase structure (Checks 1, 11)
- Cross-references (Checks 2, 3, 4, 5)
- CVSS math (Checks 6, 7, 8, 9, 10, 19)
- Fixture coverage (Checks 18, 21, 40, 41)
- Agent consistency (Checks 9, 13, 23, 44, 45)
- Token-2022 rules (Checks 36, 38)
- Pinocchio rules (Checks 39, 42, 43)
- PT-BR content (Check 15)
- SDD docs (Check 16)
- Automation scripts (Checks 31, 33, 34)

### CVSS Math Verification

Every finding's score must be recomputable from its vector via the CVSS 3.1 base score formula. `severity_counts.py:check_cvss_math()` verifies this. **Never hand-enter scores.**

### Property-Based Test Convention

Use Hypothesis for general properties, not specific examples:
```python
@given(strategies.sampled_from(ALL_CVSS_METRICS["AV"]))
def test_cvss_score_range(av: str) -> None:
    """AV metric always produces a valid ISS in [0, 1]."""
    ...
```

### Fixture Convention

Every vulnerable program ships with:
- Source with `// VULN-NN:` inline tags
- `findings.json` with 1:1 VULN-to-finding mapping
- `AUDIT_REPORT.md` with severity-graded findings
- `methodology-trace.md` showing rule → finding chain
- `quick-scan-results.md` with heuristic scan output
- `FIX_VERIFICATION.md` proving fix resolves finding

---

## Version Drift Prevention

**The single most-expensive bug class in this repo:** documentation written at one version that became stale when code grew. Cost: 20 bugs found across 4 subagents in one audit pass.

**Prevention rules:**
1. Every count claim (rules, agents, commands, tests) must be dynamically computed from source, not hardcoded in prose
2. `install.sh` prints version from the same source of truth as `SKILL.md`
3. `demo.sh` computes all counts dynamically
4. `CHANGELOG.md` is updated in the same commit as the feature it documents
5. `PRD.md`, `spec.md`, `kanban.md`, `learnings.md` version headers match the current release

**Dynamically computed counts:**
```bash
RULE_COUNT=$(grep -c "^## Rule " rules/audit.rules)
COMMAND_COUNT=$(ls commands/audit-*.md | wc -l)
AGENT_COUNT=$(ls agents/*.md | wc -l)
FUZZ_COUNT=$(grep -c "^def test_" tests/fuzz/test_properties.py)
```

---

## Agent Orchestration

### Specialist Agent Roster

| Agent | Trigger | Output |
|-------|---------|--------|
| `safety-guard` | Always runs first (Phase 0) | Consent, scope, cluster, credentials |
| `orchestrator` | Entry point | Routes to specialists |
| `auditor` | Phase 1, 2, 2B | `findings.json`, `cpi_surface.json` |
| `formal-verifier` | Phase 3 | Invariant proofs, counterexamples |
| `report-writer` | Phase 5 | `AUDIT_REPORT.md`, JSON |
| `cross-program-agent` | Phase 2B (on CPI surface) | `cross_program_findings.json` |

### Handoff Protocol

```json
// Orchestrator → Specialist
{"agent": "auditor", "phase": 2, "input_artifacts": [...], "context": "..."}

// Specialist → Orchestrator
{"status": "ok", "outputs": [...], "next_agent": "formal-verifier", "notes": "..."}
```

### Pre-flight Safety Gate (Phase 0)

Before any analysis:
1. **Consent** — explicit user confirmation for exploit PoC code
2. **Scope** — program ID, repo URL, declared attack surface
3. **Cluster** — devnet/localnet only for PoC execution
4. **Credentials** — wallet config masked from output

---

## Findings Schema

Every finding has a mandatory field set:

```json
{
  "id": "CRIT-01",
  "severity": "CRITICAL",
  "cvss": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cwe": "CWE-306",
  "location": {"file": "path.rs", "line": 42, "function": "admin_withdraw"},
  "description": "...",
  "impact": "...",
  "recommendation": "...",
  "rule_caught": "Rule 8",
  "status": "Open"
}
```

**Derived fields (auto-computed, never hand-entered):**
- `cvss` — must match CVSS 3.1 formula applied to `cvss_vector`
- `poc_status` — `pending | confirmed | verified | fixed | disproved`

---

## Non-Goals (What This Repo Does NOT Do)

- Real exploit execution against mainnet (consent-gated; no auto-apply)
- Live deployment or on-chain interaction
- Native Solana program compilation without toolchain
- Replacing human auditor judgment
- Business logic verification (SAST scope — rules catch *how*, not *whether*)
