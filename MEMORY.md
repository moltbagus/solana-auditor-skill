# Memory — Solana Auditor Skill

Durable lessons from the multi-loop build of this skill. Read this before
touching the repo again. These are the things future-me will wish past-me
had written down.

## Current state (v1.14.2 — Contest Submission)

**Contest**: Superteam Brasil Solana Skills (July 8, 2026)
**Submission**: https://github.com/solanabr/solana-auditor-skill (target PR)

- **161 integrity checks**: all green
- **22 fuzz tests**: all green
- **10 agents**: orchestrator, auditor, safety-guard, architecture-reviewer, economic-security-analyst, threat-modeler, formal-verifier, report-writer, cross-program-agent + AUDIT.md (auto-generated)
- **9 commands**: /audit, /audit-quick, /audit-resume, /audit-report, /audit-poc, /audit-findings, /audit-fix, /audit-history, /audit-pr
- **50 rules**: Rules 1-26 Anchor Core, 27-35 Token-2022 Transfer Hook, 36-45 Pinocchio/Native Solana, 46-50 AI Agent Safety
- **12 phases**: 00-safety-guard, 00-terminology, 01-recon, 01B-architecture-review, 01C-economic-security, 02-static-analysis, 02-threat-modeling, 02B-runtime-testing, 03-formal-verification, 04-findings-triage, 05-report-generation, 06-remediation
- **6 fixtures**: vault (10 VULN), token-2022-real (14 VULN), dex-amm (14 VULN), staking-pool (14 VULN), nft-candy-machine (14 VULN), live audits (Kamino, Raydium, Solend)
- **demo.sh**: zero toolchain, < 60s, shows commands box, 161 checks + 22 fuzz
- **install.sh**: idempotent, explicit error on cp failure, per-file counts
- **git tag**: v1.14.2

## Contest submission checklist

Before pushing, verify ALL of these:
- [ ] `bash demo.sh` runs clean (161/161 + 22/22)
- [ ] `git describe --tags` returns v1.14.2 (if not, `git tag -a v1.14.2`)
- [ ] SKILL.md version = v1.14.2
- [ ] CLAUDE.md version = v1.14.2
- [ ] PRD.md header = v1.14.2
- [ ] No `02A-static-analysis.md` references (should be `02-threat-modeling.md`)
- [ ] No `safety-anchor.md` references (should be `safety-guard.md`)
- [ ] No "8-phase" claims (should be "7-phase": Phase 0 + Phases 1-6)
- [ ] install.sh has no `|| true` on cp commands
- [ ] demo.sh shows the commands box during execution

## Bug classes that bit us (and how to catch them)

| Bug class | Detection | Prevention |
|---|---|---|
| **Stale version numbers** | 4 files had different versions in v1.14.2 | Git tag is canonical; every header should say "v{tag}" or derive from `git describe --tags` |
| **Broken SKILL.md routing** | `02A-static-analysis.md` doesn't exist; dead link kills Phase 2A | Check that every file path in SKILL.md actually exists: `rg -l "skill/0[0-9][A-Za-z-]*\.md" skill/SKILL.md \| xargs -I{} sh -c 'test -f {}'` |
| **Silent install failures** | `cp ... || true` masks errors; operator sees green but files missing | Replace `|| true` with `|| { echo RED "[!] Failed"; exit 1; }` |
| **File count drift** | `wc -l` on glob returns wrong count if `.DS_Store` present | Use `find DIR -maxdepth 1 -name "*.md" \| wc -l` |
| **Agent list drift** | README said "9 agents", CLAUDE.md said "10 agents", SKILL.md said "9 specialists" | Count with `ls agents/*.md \| wc -l` and propagate to all docs |
| **Duplicate changelog sections** | PRD.md had v1.14.0 listed twice | Search for `### v1\.1[0-9]\.` with `rg -c` before shipping |
| **Wrong architecture-review path** | PRD referenced `07-architecture-review.md` (doesn't exist) | Always cross-check file names in documentation against `ls skill/` |
| **Subagent findings not verified** | P107 review flagged `safety-anchor.md` — file didn't exist but wasn't verified before claiming | Run `ls agents/` to count and verify before accepting claims |
| **Commands not visible during demo** | `cat << EOF` block was buried in `#` comments; invisible during script execution | Run `bash demo.sh \| head -30` to verify visible output |

## CVSS 3.1 quick reference

```
ISS = 1 - (1 - C) * (1 - I) * (1 - A)
Impact = 6.42 * ISS
Exploitability = 8.22 * AV * AC * PR * UI
Base = roundUp(min(Impact + Exploitability, 10))
roundUp(x) = ceil(x * 10) / 10

Severity: CRITICAL ≥ 9.0 | HIGH ≥ 7.0 | MEDIUM ≥ 4.0 | LOW ≥ 0.1
```

Verify: `python3 tests/severity_counts.py check-cvss-math examples/.../findings.json`

## Toolchain / environment

- **Host**: macOS (26.5.1), user `colbert1`. Working dir: `/Users/colbert1/solana-auditor-skill`
- **pytest**: always use `python3 -c "import pytest; pytest.main([...])"` — `python3 -m pytest` fails on system Python without pytest installed
- **ripgrep**: always preinstall in CI (`apt-get install -y ripgrep`)
- **GitHub Actions**: `ubuntu-latest` does NOT have ripgrep pre-installed

## Files & purposes

| Path | Purpose |
|---|---|
| `skill/SKILL.md` | Progressive routing entry point; routes user intent → phase/agent |
| `skill/00-safety-guard.md` | Phase 0: consent, scope, cluster boundary |
| `skill/00-terminology.md` | EN + PT-BR glossary |
| `skill/01B-architecture-review.md` | Phase 1B: structural topology (NOT `07-*`) |
| `skill/01C-economic-security.md` | Phase 1C: tokenomics, MEV, economic invariants |
| `skill/02-threat-modeling.md` | Phase 2A: STRIDE enumeration (NOT `02A-*`) |
| `skill/02B-runtime-testing.md` | Phase 2B: CPI surface graph, BanksClient |
| `agents/orchestrator.md` | Entry-point router; handoff protocol (status/outputs/next_agent) |
| `agents/safety-guard.md` | Phase 0 pre-flight; NOT `safety-anchor.md` |
| `commands/*.md` | 9 slash commands with `name:` YAML frontmatter |
| `rules/audit.rules` | 50 path-scoped rules; auto-activate on file match |
| `install.sh` | Idempotent installer; explicit error on failure; no `|| true` |
| `demo.sh` | Zero-toolchain demo; shows commands box + runs integrity/fuzz |
| `tests/test-skill-integrity.sh` | 161-point verification; PASS/FAIL tally at end |
| `tests/fuzz/test_properties.py` | 22 Hypothesis property-based tests |
| `scripts/dashboard.py` | HTML dashboard from findings.json |

## Key gotchas

- **VULN tag ↔ finding 1:1**: Every `// VULN-XX:` in source must have a matching finding in findings.json
- **argparse in dashboard.py**: `--compare` is a flag appended at END of positional args
- **Rules auto-activate**: Path-scoped rules fire when Claude opens matching files; commands kick off full audits
- **Phase 0 is mandatory**: Safety guard always runs first before any analysis

## CI pipeline

3 jobs in `.github/workflows/test.yml`:
1. `skill-integrity` — `bash tests/test-skill-integrity.sh`
2. `fuzz-tests` — `python3 -c "import pytest; pytest.main(['-v', 'tests/fuzz/test_properties.py'])"`
3. `lint-install` — `bash install.sh --dry-run` + syntax check

CI pinned solana-cli v4.0.2 via `release.anza.xyz/v4.0.2/install`.
