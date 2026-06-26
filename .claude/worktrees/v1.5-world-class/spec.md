# Spec — Solana Auditor Shiba Skill

> **Technical Specification**
> _Version 1.6.0 — World-Class Submission FINAL_
> Last updated: 2026-06-26

---

## 1. System Architecture

### 1.1 Component Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Claude Code CLI                       │
│  ┌──────────────────────────────────────────────────┐   │
│  │          solana-auditor-shiba Skill               │   │
│  │  ┌─────────────┐  ┌──────────┐  ┌────────────┐  │   │
│  │  │ Orchestrator │  │  Auditor  │  │Skill Files │  │   │
│  │  │  Agent       │→ │  Agent    │→ │(6 phases)  │  │   │
│  │  └──────┬───────┘  └────┬─────┘  └────────────┘  │   │
│  │         │               │                         │   │
│  │  ┌──────┴───────┐  ┌────┴──────┐                  │   │
│  │  │ Formal-Verif │  │ Report    │                  │   │
│  │  │ Agent        │  │ Writer    │                  │   │
│  │  └──────────────┘  └───────────┘                  │   │
│  │  ┌────────────────────────────────────────────┐   │   │
│  │  │ Rules Engine (26 path-scoped rules)        │   │   │
│  │  └────────────────────────────────────────────┘   │   │
│  │  ┌────────────────────────────────────────────┐   │   │
│  │  │ Commands (8 slash commands)                │   │   │
│  │  └────────────────────────────────────────────┘   │   │
│  │  ┌────────────────────────────────────────────┐   │   │
│  │  │ Integrity (86 checks) + Fuzz (19 tests)    │   │   │
│  │  └────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### 1.2 Data Flow

```
User Input
  │
  ▼
Orchestrator Agent ──► Intent matching ──► Phase routing
  │                                                │
  ▼                                                ▼
Skill Files (01-06) ──► Agent execution ──► Findings DB
                                                    │
                                                    ▼
                                            Report Writer
                                                    │
                                          ┌────────────┴────────────┐
                                          ▼                         ▼
                                    findings.json          AUDIT_REPORT.md
                              cross_program_findings.json    + findings-pr.json
                              runtime_findings.json        + fix_suggestions.json
```

### 1.3 Automation Tools

| Tool | Purpose | Trigger |
|------|---------|---------|
| `scripts/pre-commit-audit.sh` | SAST on staged .rs files, block HIGH+ | Git pre-commit |
| `scripts/audit-history.sh` | Track findings across versions | After audit |
| `scripts/audit-fix-suggestions.py` | Generate fix templates from findings | After triage |
| `commands/audit-pr.md` | Diff-based PR audit | `/audit-pr` command |

## 2. Agent Contracts

### 2.1 Orchestrator → Specialist Handoff

```json
{
  "agent": "<specialist-name>",
  "phase": 1-6,
  "input_artifacts": ["<path>"],
  "expected_outputs": ["<path>"],
  "context": "<user-request-summary>"
}
```

### 2.2 Specialist → Orchestrator Response

```json
{
  "status": "ok | needs_input | failed",
  "outputs": ["<path>"],
  "next_agent": "<name | null>",
  "notes": "<free-form>"
}
```

## 3. Findings Database Schema

### 3.1 JSON Schema (findings.json)

```json
{
  "findings": [
    {
      "id": "VULN-01",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
      "cvss": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cwe": "CWE-306",
      "title": "<finding-title>",
      "location": {
        "file": "programs/vault/src/lib.rs",
        "line": 142,
        "function": "admin_withdraw"
      },
      "description": "<technical-description>",
      "impact": "<concrete-impact>",
      "recommendation": "<fix-guidance>",
      "poc_status": "pending | confirmed | verified | fixed | disproved",
      "rule_caught": "<rule-number | null>",
      "status": "Open"
    }
  ],
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "total": 0
  }
}
```

## 4. Integrity Check Specification

### 4.1 Current Checks (62 PASS points, 28+ named categories)

| Check | Description | PASS Points | Verification |
|-------|-------------|-------------|-------------|
| 1 | Phase file numbering | 7 | Filename matches `# Phase N:` heading |
| 2 | Command cross-refs | 1 | All referenced paths exist |
| 3 | Vault VULN ↔ findings | 4 | Every VULN-XX has a finding + audit files exist |
| 4 | CWE format | 1 | 24 CWE refs valid + point to mitre.org |
| 5 | Rules/Refs 1:1 | 1 | 17 rules = 17 References blocks |
| 6 | Summary ↔ counts | 2 | findings.json summary matches actual (both fixtures) |
| 7 | Report ↔ findings | 2 | AUDIT_REPORT.md counts match findings.json (both fixtures) |
| 8 | CVSS consistency | 2 | Score + vector match across files (both fixtures) |
| 9 | Agent consistency | 3 | Docs match agents/ directory (CLAUDE.md, SKILL.md, README.md) |
| 10 | CVSS math | 2 | Scores derivable from vectors (both fixtures) |
| 11 | Phase chaining | 5 | Each phase references next |
| 12 | Quick-scan alignment | 1 | Pattern numbers match commands |
| 13 | Agent YAML | 4 | All 4 agents have frontmatter |
| 14 | Fuzz tests pass | 1 | 19 property-based tests pass |
| 15 | PT-BR glossary | 1 | ≥5 PT-BR references in terminology file |
| 16 | SDD files present | 5 | PRD, Spec, Kanban, Learnings present |
| 17 | Demo script exists | 1 | demo.sh present and executable |
| 18 | Token-2022 VULN coverage | 4 | Every VULN-XX has a finding + audit files exist |
| 19 | Methodology-trace CVSS | 2 | Trace CVSS scores match findings.json (both fixtures) |

### 4.2 Verification Methods

| Method | Tool | When |
|--------|------|------|
| Markdown structure | ripgrep + shell assertions | Every CI run |
| JSON validity | Python json.load | Every CI run |
| CVSS math | `tests/severity_counts.py check-cvss-math` | Every CI run |
| Count consistency | `tests/severity_counts.py check-summary` / `check-report` | Every CI run |
| Cross-file consistency | `tests/severity_counts.py check-cvss` | Every CI run |
| Property-based invariants | Hypothesis (19 tests, 1000s of examples) | Every CI run |
| Trace CVSS consistency | `check_trace_cvss_for_fixture()` in bash | Every CI run |

## 5. Rules Engine Design

### 5.1 Rule Lifecycle

```
File opened → Path-matched against rules/audit.rules
  → Matching rules injected into system prompt
  → Rules apply to all responses for that file
  → On file close: rules are removed from prompt
```

### 5.2 Severity Defaulting Matrix

```python
DEFAULTS = {
    "unsigned_privileged_action": "CRITICAL",
    "unsigned_invoke_transfer": "CRITICAL",
    "wrong_close_target": "CRITICAL",
    "wrong_token_program": "HIGH",
    "missing_init_payer_space": "HIGH",
    "unverified_cpi_program": "HIGH",
    "missing_checked_arith": "MEDIUM",
    "hardcoded_pda_bump": "MEDIUM",
    "missing_token_fee_math": "MEDIUM",
    "panic_in_instruction": "LOW",
    "missing_error_mapping": "LOW",
    "unwrap_on_cpi": "MEDIUM",
}
```

## 6. Property-Based Testing Design

### 6.1 Fuzz Targets (19 tests)

| Test | Property Verified | Examples Generated |
|------|------------------|-------------------|
| P1 | CVSS score in [0.0, 10.0] | 200 random vectors |
| P2 | Score is multiple of 0.1 (roundUp) | 200 random vectors |
| P3 | Parse roundtrip is idempotent | 200 random vectors |
| P4 | Scope:C >= Scope:U (all else equal) | 100 metric combinations |
| P5 | Severity binning is monotonic | 100 boundary scores |
| P6 | Count total matches len(findings) | 50 random finding lists |
| P7 | All finding CVSS in range | 50 random finding lists |
| P8 | Vault fixture CVSS math correct | 10 fixture findings |
| P9 | All severity levels reachable | 500 random vectors |
| P10 | Worst-case vectors produce 9.8/10.0 | 2 known vectors |
| P11 | CIA metrics contribute independently | 100 metric combinations |
| P12 | Token-2022 fixture CVSS math correct | 6 fixture findings |
| P13 | Token-2022 severity distribution correct | 6 fixture findings |
| P14 | Token-2022 finding count = 6 | 6 fixture findings |
| P15 | All Token-2022 findings reference Rule 5 | 6 fixture findings |
| P16 | Token-2022 VULN IDs sequential (11-16) | 6 fixture findings |
| P17 | Severity defaulting consistent with matrix | 300 random vectors |
| P18 | Token-2022 VULN IDs match source tags | 6 fixture findings + source |
| P19 | Vault VULN IDs match source tags | 10 fixture findings + source |

### 6.2 CVSS Strategy

```python
@st.composite
def cvss_vectors(draw):
    """Generate random valid CVSS 3.1 base metric vectors.
    
    All 8 required metrics (AV, AC, PR, UI, S, C, I, A)
    drawn from CVSS 3.1 enumeration sets.
    """
    av = draw(st.sampled_from(["N", "A", "L", "P"]))
    ac = draw(st.sampled_from(["L", "H"]))
    pr = draw(st.sampled_from(["N", "L", "H"]))
    ui = draw(st.sampled_from(["N", "R"]))
    s = draw(st.sampled_from(["U", "C"]))
    c = draw(st.sampled_from(["H", "L", "N"]))
    i = draw(st.sampled_from(["H", "L", "N"]))
    a = draw(st.sampled_from(["H", "L", "N"]))
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
```

## 7. Contest Requirements

### 7.1 Judge Experience

```bash
git clone <repo>
cd solana-auditor-shiba-skill
bash demo.sh          # < 30s evaluation
bash tests/test-skill-integrity.sh  # 49 checks, all green
python3 -m pytest tests/fuzz/ -q   # 19 fuzz tests, all pass
```

### 7.2 Brazilian Portuguese Support

- `skill/00-terminology.md` expanded with PT-BR translations
- 7 PT-BR table sections, 12 security phrases translated
- Commands accept Portuguese query patterns

### 7.3 Token-2022 Coverage

- 2 fixtures: vault (10 vulns) + token-extensions (6 vulns) = 16 total
- Vault: core Anchor bug classes (signer checks, CPI safety, arithmetic, PDA bumps, reinit)
- Token-2022: extension-level bugs (wrong program, transfer_fee, close authority, delegate, metadata, non-transferable)
- All findings CVSS-math-verified + methodology-trace-cross-referenced

## 8. File Organization

```
/
├── PRD.md                          # Product requirements
├── spec.md                         # Technical spec
├── kanban.md                       # Project kanban
├── learnings.md                    # Decision log
├── MEMORY.md                       # Durable operational memory
├── CHANGELOG.md                    # Release history
├── SKILL.md                        # Skill hub router
├── CLAUDE.md                       # Claude instructions
├── pyproject.toml                  # Black + mypy + pytest config
├── install.sh                      # Skill installer
├── demo.sh                         # Contest demo script
├── skill/
│   ├── 00-terminology.md           # Glossary (EN + PT-BR)
│   ├── 01-recon.md .. 06-remediation.md
├── agents/
│   ├── orchestrator.md
│   ├── auditor.md
│   ├── formal-verifier.md
│   └── report-writer.md
│   └── AUDIT.md                    # Agent coverage matrix
├── commands/                       # 5 slash commands
├── rules/audit.rules               # 12 path-scoped rules (24 CWE refs)
├── templates/                      # 3 PoC templates
├── tests/
│   ├── test-skill-integrity.sh     # 49 integrity checks
│   ├── severity_counts.py          # CVSS + count helpers (4 modes)
│   └── fuzz/
│       └── test_properties.py      # 19 property-based tests
├── examples/
│   └── sample-vulnerable-program/
│       ├── README.md               # Fixture documentation
│       ├── Anchor.toml             # Minimal Anchor config
│       ├── programs/vault/         # Core Anchor fixture (10 vulns)
│       │   ├── Cargo.toml
│       │   └── src/lib.rs
│       ├── programs/token-extensions/  # Token-2022 fixture (6 vulns)
│       │   ├── Cargo.toml
│       │   └── src/lib.rs
│       └── audit-output/
│           ├── findings.json       # Vault expected findings
│           ├── AUDIT_REPORT.md     
│           ├── quick-scan-results.md
│           ├── methodology-trace.md
│           └── token-extensions/   # Token-2022 expected findings
│               ├── findings.json
│               ├── AUDIT_REPORT.md
│               ├── quick-scan-results.md
│               └── methodology-trace.md
└── .github/workflows/test.yml     # 3-job CI pipeline
```
