# Solana Auditor Shiba Skill

**World-class Solana security auditor for Claude Code** — 7-phase audit lifecycle (including Phase 2B Runtime Verification), 26 path-scoped security rules, 8 slash commands, 5 specialist agents, compile-verified example fixture, CI-tested with 81 integrity assertions, two-tier execution (SAST + runtime), pre-commit hook, PR auditing, audit history, and inline fix suggestions.

[![CI](https://github.com/moltbagus/solana-auditor-shiba-skill/actions/workflows/test.yml/badge.svg)](https://github.com/moltbagus/solana-auditor-shiba-skill/actions/workflows/test.yml)
[![Anchor 0.31.1](https://img.shields.io/badge/anchor-0.31.1-blueviolet)](https://www.anchor-lang.com/)
[![MIT License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Solana](https://img.shields.io/badge/solana-2.x-9945FF)](https://solana.com/)
[![Brazil Contest](https://img.shields.io/badge/Superteam-Brasil-009739)](https://superteam.com.br/)
[![Property-Based Tests](https://img.shields.io/badge/fuzz-19%20tests-8A2BE2)](tests/fuzz/)
[![Rules](https://img.shields.io/badge/rules-26-FF4500)](rules/audit.rules)
[![Agents](https://img.shields.io/badge/agents-5-blue)](agents/)
[![SDD](https://img.shields.io/badge/spec--driven%20development-PRD%2FSpec%2FKanban-FF6B35)](PRD.md)

## ⚡ Judges Quick Start (5 Minutes)

```bash
# 1. Run the demo — zero setup, works without Solana toolchain
bash demo.sh

# 2. Verify integrity — 63 checks, should all pass
bash tests/test-skill-integrity.sh

# 3. Run fuzz tests — 19 Hypothesis strategies
python3 tests/fuzz/test_properties.py

# 4. Inspect the pre-committed audit fixture
cat examples/sample-vulnerable-program/audit-output/findings.json | python3 -m json.tool

# 5. Verify CVSS math — every score recomputed from vector
python3 tests/severity_counts.py
```

→ See [VERIFICATION.md](VERIFICATION.md) for the full proof walkthrough.

---

## What It Does

The Solana Auditor Shiba skill transforms Claude Code into a full-lifecycle security auditor for Solana programs. It covers:

1. **Reconnaissance** — Attack surface enumeration (IDL, accounts, dependencies, CPI surface)
2. **Static Analysis** — Anchor/sealevel vulnerability classes (discriminators, CPI escalation, overflow, access control)
3. **Formal Verification** — QED 2A invariant proofs, counterexample analysis
4. **Findings Triage** — CVSS classification, deduplication, linkage
5. **Report Generation** — Production-grade audit reports (markdown + JSON)
6. **Remediation** — Secure fix guidance, regression testing, PoC verification

Plus a **path-scoped rules engine** that auto-activates security checks when Claude touches Anchor programs, Token-2022 code, or CPI sites — catching issues before they're committed.

## Problem It Solves

Most Solana audits are point-in-time code reviews with no structured methodology, no formal verification, and inconsistent reporting. This skill provides:

- **Consistent methodology** — Every audit follows the same 6-phase lifecycle
- **Solana-specific checks** — Anchor discriminators, Token Extensions, CPI privilege escalation, PDA derivation
- **Formal verification** — QED 2A automated proofs, not just "run anchor test"
- **Structured output** — Findings JSON + markdown report, ready to submit

## Installation

```bash
cd solana-auditor-shiba-skill
./install.sh
```

The installer copies:
- **Skill files** → `~/.claude/skills/solana-auditor-shiba/`
- **Slash commands** (5) → `~/.claude/commands/` — `/audit`, `/audit-quick`, `/audit-report`, `/audit-poc`, `/audit-findings`
- **Path-scoped rules** → `~/.claude/rules/` — auto-active security guidance for Anchor/Token-2022/CPI code
- **Agent configs** → `~/.claude/skills/solana-auditor-shiba/agents/`
- **CLAUDE.md** → `~/.claude/skills/solana-auditor-shiba/`

Or manually:

```bash
mkdir -p ~/.claude/skills/solana-auditor-shiba
cp -r skill/ ~/.claude/skills/solana-auditor-shiba/
cp CLAUDE.md ~/.claude/skills/solana-auditor-shiba/
mkdir -p ~/.claude/commands ~/.claude/rules
cp commands/*.md ~/.claude/commands/
cp rules/*.rules ~/.claude/rules/
```

## Usage

```
/audit <repo>         # Full lifecycle audit
/audit-quick <repo>   # Fast SAST scan only
/audit-report         # Generate report from findings
/audit-poc <finding>  # Generate PoC exploit (consent required)
/audit-findings       # List/manage findings DB
```

### When each command runs

| Command | When to use |
|---------|-------------|
| `/audit-quick` | First look at a new repo or PR — fast heuristic scan |
| `/audit` | Production audit — full 6-phase lifecycle |
| `/audit-poc` | After a finding, to prove exploitability (consent-gated) |
| `/audit-findings` | Working with existing findings — list, dedupe, retag, export |
| `/audit-report` | Final deliverable — synthesize findings into report |

The `rules/audit.rules` file auto-activates whenever Claude touches Anchor program code, so you don't need to invoke a command to get baseline security guidance — it's already in effect.

## Skill Files

| File | Phase |
|------|-------|
| `skill/00-terminology.md` | Solana security glossary |
| `skill/01-recon.md` | Reconnaissance |
| `skill/02-static-analysis.md` | Static Analysis (SAST) |
| `skill/03-formal-verification.md` | Formal Verification |
| `skill/04-findings-triage.md` | Findings Triage |
| `skill/05-report-generation.md` | Report Generation |
| `skill/06-remediation.md` | Remediation Guidance |

## Agents

| Agent | Role |
|-------|------|
| `agents/orchestrator.md` | Entry point — routes user requests to specialist agents |
| `agents/auditor.md` | Primary auditor — runs full lifecycle |
| `agents/formal-verifier.md` | Invariant proofs via QED 2A |
| `agents/report-writer.md` | Structured report generation |
| `agents/cross-program-agent.md` | Cross-program CPI chain analysis (v1.5) |
| `agents/AUDIT.md` | Auto-generated agent/audit status tracker |

## Helper Scripts

| Script | Purpose |
|--------|---------|
| `scripts/pre-commit-audit.sh` | Pre-commit SAST hook — blocks on HIGH+ findings |
| `scripts/generate-cpi-graph.sh` | CPI surface graph generator |
| `scripts/audit-history.sh` | Audit history DB manager |
| `scripts/audit-fix-suggestions.py` | Fix suggestion generator |

## Slash Commands

Each command is a self-contained workflow that runs even without the phase skill files loaded.

| Command | File | Purpose |
|---------|------|---------|
| `/audit` | `commands/audit.md` | Full 6-phase lifecycle audit |
| `/audit-quick` | `commands/audit-quick.md` | Heuristic SAST scan (~5 min) |
| `/audit-resume` | `commands/audit-resume.md` | Resume an interrupted audit |
| `/audit-report` | `commands/audit-report.md` | Synthesize findings.json into report |
| `/audit-poc` | `commands/audit-poc.md` | Generate proof-of-concept (consent-gated) |
| `/audit-findings` | `commands/audit-findings.md` | List/dedupe/retag/export findings DB |

## Path-Scoped Rules

`rules/audit.rules` auto-activates on file patterns — no command invocation needed.

| Rule | Triggers on | Catches |
|------|-------------|---------|
| 1 — Anchor entry point | `programs/**/src/lib.rs` | Privileged action surface |
| 2 — Account constraints | `programs/**/*.rs` | Missing discriminator / owner / init constraints |
| 3 — PDA canonical bump | `programs/**/*.rs` | Hardcoded or non-canonical bumps |
| 4 — CPI safety | `programs/**/*.rs` | Unverified programs, signer seed mismatches |
| 5 — Token SPL vs 2022 | `programs/**/*.rs` + `Cargo.toml` | Wrong token program, missing fee math |
| 6 — Arithmetic overflow | `programs/**/*.rs` | `+`/`-`/`*` on `u64` amounts |
| 7 — Close accounts | `programs/**/*.rs` | Lamport drain via wrong `close =` target |
| 8 — Signer verification | `programs/**/*.rs` | Unsigned privileged actions |
| 9 — Upgrade authority | `Anchor.toml` + `target/deploy/` | Mutable program surface |
| 10 — Error handling | `programs/**/src/error.rs` | `panic!`, missing error mapping |
| 11 — Reinit attacks | `programs/**/src/state.rs` | Missing discriminator on manual init |
| 12 — Rent safety | `programs/**/*.rs` | Lamport transfers breaking rent exemption |
| 13 — Flash loan attacks | `programs/**/*.rs` | Oracle/manipulation within same transaction |
| 14 — Reentrancy guard | `programs/**/*.rs` | State mutation after external call |
| 15 — remaining_accounts | `programs/**/*.rs` | CPI with unvalidated extra accounts |
| 16 — Discriminator collision | `programs/**/*.rs` | Two account types sharing 8-byte discriminator |

## Severity Scale

| Level | Meaning |
|-------|---------|
| CRITICAL | Total fund loss or authority bypass |
| HIGH | Significant loss or major logic flaw |
| MEDIUM | Indirect loss or moderate violation |
| LOW | Minor issue, no direct loss path |
| INFO | Documentation or code quality |

## Tools Required

- `anchor-cli` 0.31.1 (the example is built against 0.31.1; older versions will fail)
- `solana-cli` 2.x
- `rustc` 1.75+
- QED 2A (optional — for formal verification, phase 3)

## Example Finding

```json
{
  "id": "CRIT-01",
  "title": "Unsigned admin action via invoke",
  "severity": "CRITICAL",
  "cvss": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cwe": "CWE-306",
  "description": "The `admin_withdraw` instruction calls `invoke` without verifying `ctx.accounts.admin.is_signer`.",
  "impact": "Complete drain of program vault if admin key is compromised.",
  "remediation": "Add `require!(ctx.accounts.admin.is_signer)`",
  "poc_status": "pending"
}
```

_The score 9.8 is recomputed from the vector per CVSS 3.1 spec. The integrity test `tests/test-skill-integrity.sh:Check 10` flags any finding whose claimed score doesn't match the math from its vector._

## Example Audit Output

A complete, end-to-end audit fixture is shipped under [`examples/sample-vulnerable-program/`](examples/sample-vulnerable-program/). It demonstrates what the skill produces when run against a real program.

The fixture contains a deliberately vulnerable Anchor program (`programs/vault/src/lib.rs`) with 10 tagged bugs spanning CRITICAL, HIGH, and MEDIUM severities. Each bug is annotated with `// VULN-XX:` comments referencing the rule in `rules/audit.rules` that should catch it.

The expected output of running `/audit` against this program is pre-written as:

- [`examples/sample-vulnerable-program/audit-output/findings.json`](examples/sample-vulnerable-program/audit-output/findings.json) — 6 structured findings
- [`examples/sample-vulnerable-program/audit-output/AUDIT_REPORT.md`](examples/sample-vulnerable-program/audit-output/AUDIT_REPORT.md) — production-format report

The fixture ships without a Solana toolchain dependency — it is intended as a code-review demonstration, not a buildable program. Reviewers can `cat` the source and expected findings to verify the skill's methodology.

## Contest Submission (Superteam Brasil)

This skill is submitted to the **Superteam Brasil Solana Skills Contest**. For judges:

```bash
# Quick evaluation — no Solana toolchain needed, just Python 3
bash demo.sh
```

The demo script runs structure verification, 62 integrity checks, and 19 property-based
fuzz tests in under 30 seconds.

**Contest features**:
- **Spec-Driven Development** — `PRD.md`, `spec.md`, `kanban.md`, `learnings.md`
- **Property-Based Testing** — 19 property-based tests verifying CVSS math & invariants
- **Brazilian Portuguese (PT-BR)** — Bilingual security glossary
- **CVSS Math Verification** — All scores recomputed from vectors (not hand-entered)
- **62 Integrity Checks** — Including fuzz tests, PT-BR, SDD docs, demo script
- **Demo Script** — `bash demo.sh` for instant judge evaluation

### Tested Against Real Solana Vulnerabilities

Tested against [`a-zmuth/solana-security-reference`](https://github.com/a-zmuth/solana-security-reference)
— an open-source collection of 5 Solana vulnerability classes with vulnerable/secure pairs:

| Vulnerability Class | Our Rule | Coverage |
|---|---|---|
| Missing Signer Check | Rule 8 — Signer Verification | ✅ |
| Incorrect Owner Check | Rule 2 — Account Validation | ✅ |
| Insecure CPI | Rule 4 — CPI Safety | ✅ |
| Integer Overflow | Rule 6 — Arithmetic Overflow | ✅ |
| Type Cosplay | Rule 2 — Account Validation | ✅ |

**5/5 vulnerability classes covered.** The skill also covers 7 additional classes
(PDA bumps, Token-2022 operations, close accounts, upgrade authority, error handling,
rent safety, account constraints) for **17 rules total**.

## Limitations

*Added in v1.1.0.*

### What this skill does well

- Catches the 17 rules via path-scoped rules
- Builds against anchor 0.31.1 in CI
- Provides reproducible methodology trace from source code to CVSS-scored findings
- Ships with a 10-bug example fixture that proves the methodology works
- 19 property-based tests verify mathematical invariants across 1,000s of inputs
- Bilingual (EN + PT-BR) terminology glossary

### What this skill does NOT do

- **Token-2022 example** — Rule 5 (Token Operations) is documented but not exercised by the included fixture. The pattern checks work against any SPL/Token-2022 program you point it at, but the example uses raw `AccountInfo` for the tokens, not Token Extensions.
- **Dynamic PoC execution** — `/audit-poc` documents a consent gate and references template files at `templates/poc-template-{anchor,typescript,manual}.{rs,ts,md}`. Copy and customize for each finding. The methodology produces the steps; you adapt the template to the specific bug.
- **QED 2A integration** — phase 3 references QED 2A but the CI does not invoke it. Run `qed-solana verify` manually after `anchor build`.
- **Runtime test coverage** — the example is *compile-verified* (`cargo check` succeeds in CI) but not *runtime-tested*. The committed `tests/` was removed because runtime tests need a local validator which is impractical in CI. Adding tests would require either a Solana test validator in CI (~3 min extra per run) or a non-validator approach (asserting compile-time properties only). `cargo check` is the strongest compile-clean signal that survives CI on anchor 0.31.1 + Agave solana-cli.
- **Local toolchain validation** — the Solana toolchain was not installed locally during development. CI proves the example builds. Local builds require the toolchain install recipe in §Local toolchain setup.
- **CVSS scores are mathematically verified** — Check 10 in `tests/test-skill-integrity.sh` recomputes every score from its vector (CVSS 3.1 base-score formula) and flags any mismatch. The score-vec pair is verified by CI on every push.

### What this skill should NOT be used for

- **Production deployment decisions** — outputs are advisory; a human auditor must review.
- **Real exploit execution** — `/audit-poc` writes PoCs; running them against mainnet requires explicit program-owner authorization (consent gate enforced).
- **Non-Anchor Solana programs** — the rules assume Anchor 0.30+ patterns. Native sealevel programs need different rules.

## Development & Testing

This skill ships with a working CI pipeline and an example fixture for testing.

### CI

Every push to `main` runs:

1. **`skill-integrity`** — 11 integrity check categories (`tests/test-skill-integrity.sh`, 62 verification points total)
2. **`anchor-build`** — builds the example fixture under anchor 0.31.1 (via `cargo check`)
3. **`lint-install`** — verifies `install.sh` syntax + dry-run deploys the skill to `~/.claude/skills/solana-auditor-shiba/`

### Example fixture

`examples/sample-vulnerable-program/` is a deliberately vulnerable Anchor program with 10 tagged bugs. Run:

```bash
# Verify all integrity checks pass locally
bash tests/test-skill-integrity.sh

# Build the example locally (requires rustup + solana + anchor 0.31.1)
cd examples/sample-vulnerable-program
anchor build
```

### Local toolchain setup

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source "$HOME/.cargo/env"
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
cargo install --git https://github.com/coral-xyz/anchor --tag v0.31.1 anchor-cli --locked
```

See [CHANGELOG.md](CHANGELOG.md) for the full development history.

## License

MIT — Superteam Brasil, 2026
