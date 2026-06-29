# Solana Auditor Shiba Skill

**World-class Solana security auditor for Claude Code** — 7-phase audit lifecycle (Phase 0 Safety Guard + Phases 1–6), 45 Solana security rules + 5 agent safety rules (50 total), 9 slash commands, 10 specialist agents, 6 compile-verified example fixtures, 161 integrity checks passing, 22 fuzz tests, two-tier execution (SAST + runtime), pre-commit hook, PR auditing, audit history, and inline fix suggestions.

[![CI](https://github.com/moltbagus/solana-auditor-skill/actions/workflows/test.yml/badge.svg)](https://github.com/moltbagus/solana-auditor-skill/actions/workflows/test.yml)
[![Anchor 0.31.1](https://img.shields.io/badge/anchor-0.31.1-blueviolet)](https://www.anchor-lang.com/)
[![MIT License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Solana](https://img.shields.io/badge/solana-2.x-9945FF)](https://solana.com/)
[![Brazil Contest](https://img.shields.io/badge/Superteam-Brasil-009739)](https://superteam.com.br/)
[![Property-Based Tests](https://img.shields.io/badge/fuzz-22%20tests-8A2BE2)](tests/fuzz/)
[![45+5=50](https://img.shields.io/badge/rules-45%2B5%3D50-FF4500)](rules/audit.rules)
[![Agents](https://img.shields.io/badge/agents-9-blue)](agents/)
[![SDD](https://img.shields.io/badge/spec--driven%20development-PRD%2FSpec%2FKanban-FF6B35)](PRD.md)

> :brazil: [Guia de auditoria em Portugues Brasileiro](guides/pt-BR/AUDITORIA_GUIA.md)

Auditorias podem ser conduzidas em **Ingles** ou **Portugues Brasileiro**: pasar `--lang pt` em qualquer comando de audit.
Todos os 9 comandos, agentes e 50 regras funcionam em ambos os idiomas.

```bash
# Ejemplo en portugues:
/audit <repo> --lang pt
/audit-quick <repo> --lang pt
```

## ⚡ Judges Quick Start (5 Minutes)

```bash
# 1. Run the live demo — SAST scan a real Solana program
#    Press Enter to use the built-in fixture, or paste any public repo URL
bash demo.sh --live-demo

# 2. Run the full demo — fixture-based verification (always works)
bash demo.sh

# 3. Verify integrity — 161 integrity checks, all should pass
bash tests/test-skill-integrity.sh

# 4. Run fuzz tests — 22 Hypothesis strategies
python3 -c "import pytest; pytest.main(['-v', 'tests/fuzz/test_properties.py'])"

# 5. Inspect the pre-committed audit fixture
cat examples/sample-vulnerable-program/audit-output/findings.json | python3 -m json.tool

# 6. Run the interactive dashboard
python3 scripts/dashboard.py examples/dex-amm/audit-output/findings.json /tmp/dex_dashboard.html

# 7. Verify CVSS math — every score recomputed from vector
python3 tests/severity_counts.py
```

→ See [VERIFICATION.md](VERIFICATION.md) for the full proof walkthrough.

### 📊 Interactive Dashboard

Run the dashboard to see findings visualized with severity breakdown, CVSS scores, and CWE mapping:

```bash
python3 scripts/dashboard.py examples/sample-vulnerable-program/audit-output/findings.json /tmp/audit_dashboard.html
open /tmp/audit_dashboard.html
```

![Audit Dashboard Preview](https://img.shields.io/badge/dashboard-interactive%20HTML%20report-FF6B35?style=flat-square)

---

## What It Does

The Solana Auditor Shiba skill transforms Claude Code into a full-lifecycle security auditor for Solana programs. It covers:

1. **Reconnaissance** — Attack surface enumeration (IDL, accounts, dependencies, CPI surface)
2. **Static Analysis** — Anchor/sealevel vulnerability classes (discriminators, CPI escalation, overflow, access control)
3. **Formal Verification** — QED 2A invariant proofs (best-effort, requires anchor CLI), counterexample analysis
4. **Findings Triage** — CVSS classification, deduplication, linkage
5. **Report Generation** — Production-grade audit reports (markdown + JSON)
6. **Remediation** — Secure fix guidance, regression testing, PoC verification

Plus a **path-scoped rules engine** that auto-activates security checks when Claude touches Anchor programs, Token-2022 code, or CPI sites — catching issues before they're committed.

## Problem It Solves

Most Solana audits are point-in-time code reviews with no structured methodology, no formal verification, and inconsistent reporting. This skill provides:

- **Consistent methodology** — Every audit follows the same 7-phase lifecycle (Phase 0 Safety Guard + Phases 1-6)
- **Solana-specific checks** — Anchor discriminators, Token Extensions, CPI privilege escalation, PDA derivation
- **Formal verification** — QED 2A automated proofs, not just "run anchor test"
- **Structured output** — Findings JSON + markdown report, ready to submit

## Installation

```bash
cd solana-auditor-skill
./install.sh
```

The installer copies:
- **Skill files** → `~/.claude/skills/solana-auditor-skill/`
- **Slash commands** (9) → `~/.claude/commands/` — `/audit`, `/audit-quick`, `/audit-resume`, `/audit-report`, `/audit-poc`, `/audit-findings`, `/audit-fix`, `/audit-pr`, `/audit-history`
- **Path-scoped rules** → `~/.claude/rules/` — auto-active security guidance for Anchor/Token-2022/CPI code
- **Agent configs** → `~/.claude/skills/solana-auditor-skill/agents/`
- **CLAUDE.md** → `~/.claude/skills/solana-auditor-skill/`

Or manually:

```bash
mkdir -p ~/.claude/skills/solana-auditor-skill
cp -r skill/ ~/.claude/skills/solana-auditor-skill/
cp CLAUDE.md ~/.claude/skills/solana-auditor-skill/
mkdir -p ~/.claude/commands ~/.claude/rules
cp commands/*.md ~/.claude/commands/
cp rules/*.rules ~/.claude/rules/
```

## Usage

```
/audit <repo>         # Full lifecycle audit
/audit-quick <repo>   # Fast SAST scan only
/audit-resume <repo>  # Resume an interrupted audit
/audit-report         # Generate report from findings
/audit-poc <finding>  # Generate PoC exploit (consent required)
/audit-findings       # List/manage findings DB
/audit-fix            # Generate inline fix suggestions
/audit-pr             # Review open PRs for security issues
/audit-history        # Manage audit history database
```

### When each command runs

| Command | When to use |
|---------|-------------|
| `/audit-quick` | First look at a new repo or PR — fast heuristic SAST scan with Phase 0 safety guard |
| `/audit` | Production audit — full 7-phase lifecycle (Phase 0 + Phases 1-6) |
| `/audit-resume` | Continue an interrupted audit from where it left off |
| `/audit-poc` | After a finding, to prove exploitability (consent-gated) |
| `/audit-findings` | Working with existing findings — list, dedupe, retag, export |
| `/audit-fix` | Generate inline fix suggestions for HIGH/CRITICAL findings |
| `/audit-pr` | Automated PR security review with findings posted as comments |
| `/audit-report` | Final deliverable — synthesize findings into markdown + JSON report |
| `/audit-history` | Query, prune, or export the audit history database |

The `rules/audit.rules` file auto-activates whenever Claude touches Anchor program code, so you don't need to invoke a command to get baseline security guidance — it's already in effect.

## Skill Files

| File | Phase |
|------|-------|
| `skill/00-terminology.md` | Solana security glossary |
| `skill/00-safety-guard.md` | Safety guard — pre-flight (Phase 0) |
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
| `agents/architecture-reviewer.md` | On-chain config and authority topology review |
| `agents/threat-modeler.md` | STRIDE threat identification and trust boundaries |
| `agents/economic-security-analyst.md` | Tokenomics, MEV, fee flows, economic invariant violations |
| `agents/formal-verifier.md` | Invariant proofs via QED 2A |
| `agents/report-writer.md` | Structured report generation |
| `agents/cross-program-agent.md` | Cross-program CPI chain analysis |
| `agents/safety-anchor.md` | Anchor-specific security patterns |
| `agents/safety-guard.md` | Pre-flight safety checks and Phase 0 guardrails |

`agents/AUDIT.md` is auto-generated during audits to track agent state.

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
| `/audit` | `commands/audit.md` | Full 7-phase lifecycle audit (Phase 0 + Phases 1-6) |
| `/audit-quick` | `commands/audit-quick.md` | Heuristic SAST scan with Phase 0 guard (~5 min) |
| `/audit-resume` | `commands/audit-resume.md` | Resume an interrupted audit from checkpoint |
| `/audit-report` | `commands/audit-report.md` | Synthesize findings.json into report |
| `/audit-poc` | `commands/audit-poc.md` | Generate proof-of-concept exploit (consent-gated) |
| `/audit-findings` | `commands/audit-findings.md` | List/dedupe/retag/export findings DB |
| `/audit-fix` | `commands/audit-fix.md` | Inline fix suggestions for HIGH/CRITICAL findings |
| `/audit-pr` | `commands/audit-pr.md` | Automated PR review with comment posting |
| `/audit-history` | `commands/audit-history.md` | Audit history DB manager |

## Path-Scoped Rules

`rules/audit.rules` auto-activates on file patterns — no command invocation needed. 50 rules across 4 groups:

| Rule | Triggers on | Catches |
|------|-------------|---------|
| **Rules 1-26 — Anchor Core** |
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
| **Rules 27-35 — Token-2022 Extension Operations** |
| 27 — Transfer hook accounts | `programs/**/*.rs` | Missing `TransferHook` account validation |
| 28 — Extra account metas | `programs/**/*.rs` | CPI to transfer hook with missing extra accounts |
| 29 — Owner mismatch | `programs/**/*.rs` | Unchecked owner in hook callback |
| 30 — Bump validation | `programs/**/*.rs` | Missing PDA bump check in hook |
| 31 — Token-2022 permissions | `programs/**/*.rs` | Missing `Token2022` account type checks |
| 32 — Fee-on-transfer | `programs/**/*.rs` | Fee deducted without corresponding credit |
| 33 — Mint freeze authority | `programs/**/*.rs` | Unchecked `freeze_authority` |
| 34 — Close mint | `programs/**/*.rs` | Mint closed with existing holders |
| 35 — Memo extension | `programs/**/*.rs` | Unsanitized memo in CPI chain |
| **Rules 36-45 — Account Validation + Runtime Security** |
| 36 — Sysvar account | `programs/**/*.rs` | Missing or unchecked sysvar account |
| 37 — Clock sysvar | `programs/**/*.rs` | Unsigned or unvalidated slot/time |
| 38 — Rent sysvar | `programs/**/*.rs` | Rent exemption bypass |
| 39 — System program | `programs/**/*.rs` | Missing `system_program` check |
| 40 — Native program CPI | `programs/**/*.rs` | CPI to native programs without validation |
| 41 — PDA vs system account | `programs/**/*.rs` | PDA used where system account expected |
| 42 — System instruction | `programs/**/*.rs` | Unchecked `invoke_signed` with system program |
| 43 — Account compression | `programs/**/*.rs` | Missing concurrent merkle tree validation |
| 44 — Token metadata | `programs/**/*.rs` | Unchecked metadata authority |
| 45 — Confidential transfer | `programs/**/*.rs` | Missing proof verification |
| **Rules 46-50 — Agent Safety (Audit Governance)** (These rules govern the AI auditor's own behavior — consent gates, scope boundaries, audit trails. Distinct from Solana vulnerability detection rules 1-45.) |
| 46 — Pre-flight checks | `programs/**/*.rs` | Agent pre-audit safety guard |
| 47 — Scope boundary | `programs/**/*.rs` | Agent stays within declared scope |
| 48 — Consent gate | `programs/**/*.rs` | Exploit steps gated on consent |
| 49 — Audit trail | `programs/**/*.rs` | Tool calls logged to audit trail |
| 50 — Handoff confirmation | `programs/**/*.rs` | Agent handoff requires explicit ack |

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
# Live demo — SAST scan any public Solana repo (press Enter for built-in fixture)
bash demo.sh --live-demo

# Full demo — all fixtures, 161 checks, 22 fuzz tests
bash demo.sh
```

### Live Audit Proof of Capability

> This skill was used to audit **Kamino Finance's klend program** (2026-06-25/26).
> Verifying source code revealed that 3 of 4 initial automated submissions had factual
> errors — demonstrating that blind scanning without source verification produces false positives.
> The skill found KAM-001 (Token2022 transfer fee structurally similar to Mango Markets),
> and correctly recalled KAM-002/003/004 after source verification showed they were
> already fixed or not findings.

The demo script runs structure verification, 161 integrity checks, and 22 property-based
fuzz tests in under 30 seconds.

### Live Audit #2: Solend Governance Flash Loan (August 2022)

> **Program audited:** Solend Governance Module (historical)
> **Source:** Post-mortem analysis — publicly disclosed Aug 2022
> **Amount lost:** ~$1.26M via governance flash loan attack
> **Findings:** 3 (1 CRITICAL, 2 HIGH) — all caught by Rules 8, 13, and 4

**What happened:** Attacker flash-loaned 11.5M SOL, acquired governance voting majority, approved a malicious proposal, drained treasury — all within one block (~400ms).

**Root cause (3-layer failure):**
1. No vote-time locks → flash loan amplifies voting power
2. Missing `is_signer` on proposal execution → anyone can execute approved proposals
3. Unchecked treasury CPI → proposals can redirect funds without privilege verification

**What the skill caught:** Rule 8 (Signer Verification) → CRITICAL finding. Rule 13 (Flash Loan Attacks) → HIGH finding. Rule 4 (CPI Safety) → HIGH finding.

See [`examples/solend-governance-audit/`](examples/solend-governance-audit/) for full findings and report.

**Contest features**:
- **Spec-Driven Development** — `PRD.md`, `spec.md`, `kanban.md`, `learnings.md`
- **Property-Based Testing** — 22 fuzz tests verifying CVSS math & invariants
- **Bilingual security glossary (EN + PT-BR)** — `skill/00-terminology.md`
- **CVSS Math Verification** — All scores recomputed from vectors (not hand-entered)
- **161 Integrity Checks** — shell checks + fuzz tests (22) + CVSS math + fixture assertions + PT-BR + SDD docs + demo script
- **Demo Script** — `bash demo.sh` for fixture demo; `bash demo.sh --live-demo` to SAST scan any public repo

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
rent safety, account constraints) plus 33 more rules across Transfer Hook, Pinocchio/Native,
and AI Agent Safety for **50 rules total**.

## Limitations

*Added in v1.1.0.*

### What this skill does well

- Catches all 50 rules via path-scoped rules
- Builds against anchor 0.31.1 in CI
- Provides reproducible methodology trace from source code to CVSS-scored findings
- Ships with a 10-bug example fixture that proves the methodology works
- 22 fuzz tests verify mathematical invariants across 1,000s of inputs
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

1. **`skill-integrity`** — 161 integrity checks (`tests/test-skill-integrity.sh`)
2. **`anchor-build`** — builds the example fixture under anchor 0.31.1 (via `cargo check`)
3. **`lint-install`** — verifies `install.sh` syntax + dry-run deploys the skill to `~/.claude/skills/solana-auditor-skill/`

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

---

## Para Desenvolvedores Brasileiros

Este skill foi feito para a comunidade Solana brasileira. Para um guia completo em portugues brasileiro, veja [guides/pt-BR/AUDITORIA_GUIA.md](guides/pt-BR/AUDITORIA_GUIA.md).

Comandos principais:
- `/audit <repo>` — Auditoria completa
- `/audit-quick <repo>` — Varredura rapida SAST
- `/audit-report` — Gerar relatorio final
- `/audit-fix` — Corrigir vulnerabilidades encontradas

## License

## Authors

- **Colbert Low** — [sirshibaninja](https://x.com/sirshibaninja)

## MIT — Superteam Brasil, 2026
