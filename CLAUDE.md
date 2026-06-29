# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Solana Auditor Skill (Shiba)

World-class Solana security auditor — 7-phase lifecycle, 50 path-scoped rules (auto-activate), 10 specialist agents, 9 commands, compile-verified fixture, 161 integrity checks, 22 fuzz tests.

**Version**: v1.14.2 | **Contest**: Superteam Brasil Solana Skills (July 8, 2026)

---

## Commands

```bash
# Install skill (copies to ~/.claude/)
./install.sh -y

# Demo — zero setup, no Solana toolchain needed
bash demo.sh

# Integrity checks (161 verification points — all must pass before push)
bash tests/test-skill-integrity.sh

# Single category
bash tests/test-skill-integrity.sh 2>&1 | grep "Check 50"

# Fuzz tests (22 Hypothesis strategies)
python3 -c "import pytest; pytest.main(['-v', 'tests/fuzz/test_properties.py'])"

# Single fuzz test
python3 -c "import pytest; pytest.main(['-v', 'tests/fuzz/test_properties.py', '-k', 'test_cvss_vector_roundtrip'])"

# Verify CVSS math (recomputes every score from vector)
python3 tests/severity_counts.py check-cvss-math examples/sample-vulnerable-program/audit-output/findings.json

# HTML dashboard
python3 scripts/dashboard.py examples/sample-vulnerable-program/audit-output/findings.json /tmp/dashboard.html
```

---

## Architecture

```
skill/
  SKILL.md                          # Hub — routes to phases
  00-terminology.md                 # EN + PT-BR glossary
  00-safety-guard.md               # Phase 0: consent, scope, cluster
  01-recon.md                      # Phase 1: attack surface
  01B-architecture-review.md        # Phase 1B: authority/tokenomics topology
  01C-economic-security.md          # Phase 1C: tokenomics, MEV, invariants
  02-static-analysis.md             # Phase 2: SAST (50 rules)
  02A-threat-modeling.md            # Phase 2A: STRIDE enumeration
  02B-runtime-testing.md            # Phase 2B: anchor test (requires toolchain)
  03-formal-verification.md         # Phase 3: QED 2A invariant proofs
  04-findings-triage.md            # Phase 4: CVSS 3.1 scoring
  05-report-generation.md           # Phase 5: markdown + JSON output
  06-remediation.md                # Phase 6: fix guidance + regression

agents/
  orchestrator.md      # Entry — routes to specialists
  auditor.md          # Primary audit execution
  safety-guard.md     # Phase 0 consent/scope guard
  architecture-reviewer.md   # Phase 1B: structural topology
  economic-security-analyst.md # Phase 1C: tokenomics/MEV
  threat-modeler.md    # Phase 2A: STRIDE + exploit intel
  formal-verifier.md  # Phase 3: QED 2A
  report-writer.md     # Phase 5: structured output
  cross-program-agent.md    # CPI chain + flash loan detection
  AUDIT.md             # Auto-generated during audits

commands/             # 9 slash commands — /audit, /audit-quick, etc.
rules/audit.rules     # 50 rules (auto-activate on path match)
scripts/
  dashboard.py        # HTML dashboard from findings.json
  audit-fix-suggestions.py   # Inline fix generator
  audit-history.sh    # Audit history DB
  pre-commit-audit.sh # Pre-commit SAST hook
  export-sarif.py     # SARIF export for CI

examples/
  sample-vulnerable-program/       # 10-bug Anchor vault (CRIT/HIGH/MED)
  solend-governance-audit/       # Live exploit: $1.26M flash loan (2022)
  klive-live-audit/               # Kamino Finance live audit (June 2026)
  token-2022-real/               # Token Extensions fixture
```

### How Phases Flow

```
User: /audit <repo>
  → orchestrator.md (phase routing)
    → 00-safety-guard.md (Phase 0 — consent gate)
    → 01-recon.md (Phase 1 — attack surface)
    → 01B-architecture-review.md (Phase 1B — structural)
    → 01C-economic-security.md (Phase 1C — economic design)
    → 02A-threat-modeling.md (Phase 2A — STRIDE)
    → 02-static-analysis.md (Phase 2 — 50 rules)
    → 02B-runtime-testing.md (Phase 2B — anchor test, toolchain)
    → 03-formal-verification.md (Phase 3 — QED 2A)
    → 04-findings-triage.md (Phase 4 — CVSS scoring)
    → 05-report-generation.md (Phase 5 — report)
    → 06-remediation.md (Phase 6 — fix guidance)
```

### Two-Tier Execution

| Tier | Trigger | Capabilities |
|------|---------|-------------|
| TIER1 | No Anchor/Solana CLI | SAST-only, 50 path-scoped rules |
| TIER2 | `anchor-cli` available | Full anchor test + runtime verification |
| TIER2-FULL | Full toolchain + QED | TIER2 + QED 2A invariant proofs |

### 50 Security Rules (4 Groups)

Rules auto-activate when Claude enters matching file paths — **no command needed**.

| Group | Rules | Auto-activate on |
|-------|-------|-----------------|
| Anchor Core | 1–26 | `programs/**/*.rs`, `Anchor.toml` |
| Token-2022 Transfer Hook | 27–35 | `programs/**/*.rs` |
| Pinocchio / Native Solana | 36–45 | `programs/**/*.rs`, `sysvars/` |
| AI Agent Safety | 46–50 | All skill operations |

Full rule table in README.md. Every rule cites CWE + real exploit reference (Wormhole, Cashio, Crema, Mango, Raydium, Solend, etc.).

---

## Agent Handoff Protocol

Orchestrator → Specialist handoff uses structured JSON in the message:

```json
{"agent": "auditor", "phase": 2, "input_artifacts": [...], "context": "..."}
```

Specialist → Orchestrator response:
```json
{"status": "ok", "outputs": [...], "next_agent": "formal-verifier", "notes": "..."}
```

---

## Fixture Contracts

Every fixture `findings.json` must have:

```json
{
  "id": "VULN-01",
  "severity": "CRITICAL",
  "cvss": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cwe": "CWE-306",
  "rule": 8,
  "rule_caught": "Rule 8 — Signer Verification",
  "title": "...",
  "location": {"file": "path.rs", "line": 42, "function": "fn_name"},
  "description": "...",
  "impact": "...",
  "recommendation": "...",
  "poc_status": "pending",
  "status": "Open"
}
```

**Critical**: `rule` (integer) is canonical — `rule_caught` (text) is descriptive. Both must be present. Every `// VULN-XX:` in source must have a matching finding in `findings.json`.

Fixture output structure:
```
examples/<name>/
  programs/<prog>/src/lib.rs   # VULN tags (// VULN-01:, etc.)
  audit-output/
    findings.json             # Structured findings
    AUDIT_REPORT.md           # Human-readable report
    quick-scan-results.md      # /audit-quick output
    methodology-trace.md       # Phase-to-finding mapping
```

---

## CVSS Math Verification

**Every score is mathematically verified from its vector** — not hand-entered:

```bash
python3 tests/cvss.py check examples/sample-vulnerable-program/audit-output/findings.json
```

`tests/cvss.py` recomputes CVSS 3.1 base score from the vector string. Any mismatch → Check 10 fails in integrity checks. Score-vec pairs are verified by CI on every push.

---

## Critical Constraints

| Rule | Rationale |
|------|-----------|
| **PoC consent required** | Explicit typed consent before exploit execution |
| **No auto-apply fixes** | Operator reviews; skill suggests, never flips |
| **No live execution** | Consent gate enforced; mainnet requires owner auth |
| **No secrets in scope files** | Audit scope is plaintext — no private keys |
| **Mainnet = double-confirm** | Verify program owner identity before auditing |

**Absolute prohibitions:**
1. Never auto-apply security fixes without operator review
2. Never execute PoCs without explicit typed consent (`YES` or equivalent)
3. Never commit secrets/private keys to audit scope files
4. Never audit mainnet program without verifying program owner identity
5. Never write live exploit code in reports — reference PoC path only

---

## Tool Requirements

- `anchor-cli` **0.31.1** (example fixture built against this — older versions fail)
- `solana-cli` 2.x
- `rustc` 1.75+
- QED 2A (optional — Phase 3 formal verification)

Setup:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-tooltoolchain stable
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
cargo install --git https://github.com/coral-xyz/anchor --tag v0.31.1 anchor-cli --locked
```

---

## Key Gotchas

- **pytest**: Use `python3 -c "import pytest; pytest.main([...])"` — `python3 -m pytest` fails on system Python without pytest installed.
- **argparse in dashboard.py**: `--compare` is a flag appended at END of positional args. Never insert it mid-command.
- **VULN tag ↔ finding 1:1**: Every `// VULN-XX:` in source must have a matching finding in `findings.json`. Missing pairs → Check 11 fails.
- **Severity**: CRITICAL = fund loss / authority bypass. HIGH = significant logic flaw. MEDIUM = indirect path. LOW = best practice.
- **Rules auto-activate**: You don't invoke `/audit` for every file — rules in `rules/audit.rules` activate when you open matching paths. Commands kick off full audits.
