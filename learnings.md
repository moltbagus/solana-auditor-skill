# Learnings — Solana Auditor Skill

> **Decision Log & Lessons Learned**
> _Superteam Brasil Solana Skills Contest — v1.14.2_
> Last updated: 2026-06-30

---

## 2026-06-30 — Secrets Scan + Co-Creator Sprint

### What we did
Full multi-pattern secrets scan across all code, configs, and scripts. Ran 8 grep patterns simultaneously: seed phrases, Solana keypairs, JWT/Bearer tokens, API keys, AWS credentials, passwords, GitHub tokens, mnemonic phrases.

### Results: 21 matches, 0 real secrets
| Match type | Files | Status |
|---|---|---|
| Rust seed constant paths (`seeds::WITHDRAW_TICKET`) | `klend/handlers/*.rs` | ✅ Safe — module references, not key material |
| Public program deploy addresses | `data/protocols/known-vulns.json` | ✅ Safe — intentionally public |
| Public Solana program addresses | `generate-cpi-graph.sh` | ✅ Safe — well-known SPL programs |
| Placeholder program names | `agents/cross-program-agent.md` | ✅ Safe — documentation examples |
| Public lending market addresses | `klend-interface/README.md` | ✅ Safe — well-known deployed programs |

### Changes made
- README: co-creator credit added — "Co-created by sirshibaninja and Claude Code"
- .gitignore: added `.claude/worktrees/` (was missing)
- PRD.md, kanban.md, learnings.md: synced to 2026-06-30
- Spec.md: agent roster count corrected (8→10 specialists)

### Key lessons
1. **Secrets scan is fast and definitive** — 8 grep patterns in <2s, zero false positives on real code
2. **Public program addresses trigger seed-phrase patterns** — `HUBBLE*` and `SLND*` look like seeds but are Solana public keys in known-vulns.json
3. **Rust seed constants are module paths** — `seeds::WITHDRAW_TICKET` is a Rust module path constant, not a cryptographic seed
4. **Worktrees directory was un-ignored** — `.claude/worktrees/` not in .gitignore allowed the stale v1.5 worktree to exist untracked

---

## 2026-06-30 — v1.14.2 Command Audit Sprint

### What we did
2 senior engineers audited all 9 commands in parallel. Corporate-grade review + principal-systems review.

### Key lesson: verify before accepting subagent claims
Subagent A claimed "02A-threat-modeling.md doesn't exist → SKILL.md is broken." Subagent B claimed "SKILL.md claims Phase 7 which doesn't exist."
**Both were hallucinations.** Ran `test -f skill/02-threat-modeling.md` — file EXISTS. Checked SKILL.md — no "Phase 7" reference found.
**Rule: always `test -f` or `ls` before acting on a subagent's claim about filesystem state.**

### Issues found and fixed (3 real, 15 hallucinated)
- SKILL.md: loop_state.json → phase-state.json (HIGH — matches audit-resume.md)
- audit-report.md: dashboard.py invocation wrong (HIGH — docs said <output-dir>/ but it expects <file-path>)
- audit-findings.md: search path audit-report/findings.json → audit-output/findings.json (HIGH)
- Subagent hallucinations 1: "02A-threat-modeling.md doesn't exist" → verified EXISTS, ignored
- Subagent hallucinations 2: "SKILL.md claims Phase 7" → verified NOT referenced, ignored
- Subagent hallucinations 3-15: various references to non-existent features verified not present

### Self-fixing loop applied
Persisted correction rules to ~/.claude/corrections/solana-auditor-skill/:
- failures.jsonl: 7 raw failure logs
- rules.md: synthesized rules for pre-session triggers
- verify.json: 8-item verification checklist
- ~/.claude/corrections/global/rules.md: secrets scanning, repo state check

---

## 2026-06-29 — Contest Sprint v1.14.2 (Final Polish)

### What we did
Multi-agent parallel audit (P107 code review + corporate-grade polish review) to optimize for Superteam Brasil top-10 submission. Ran 2 parallel subagents with p107-senior-code-review and principal-systems-engineer skills.

### Issues found and fixed
1. SKILL.md routing: `02A-static-analysis.md` → `02-static-analysis.md` (broken dead link)
2. SKILL.md missing Phase 0 Safety Guard entry in routing table
3. SKILL.md version: `v1.8.0` → `v1.14.2`
4. SKILL.md agents: "9 specialists" → "10 configs" (AUDIT.md auto-generated counted)
5. SKILL.md "New in v1.7.0" section stale for v1.14.2 — kept as-is (content still accurate, just old version)
6. CLAUDE.md version: `v1.13.0` → `v1.14.2`
7. README.md: `safety-anchor.md` (non-existent) → `safety-guard.md` (duplicate entry removed)
8. PRD.md: duplicate v1.14.0 section removed; wrong `07-architecture-review.md` → `01B-architecture-review.md`
9. demo.sh: "8-phase" → "7-phase" (2 occurrences) — Phase 0 + Phases 1-6 = 7 phases
10. demo.sh: added visible `cat << EOF` block so commands display during script execution (not buried in comments)
11. install.sh: all `cp` commands had `|| true` silently masking failures → explicit error + exit 1 on failure
12. install.sh: fragile `wc -l | tr -d ' '` → `find -maxdepth 1 -name "*.md" | wc -l | tr -d ' '`
13. install.sh: added per-file counts to success messages for transparency
14. orchestrator.md: added explicit "Malformed response handling" and "Partial failure" sections to agent handoff contract
15. Git tag v1.14.2 created for `git describe --tags` to show correct version in demo.sh summary

### Contest lessons
- **Run the tests**. The demo.sh script has an "8-phase" claim that contradicts all docs. This would have been caught by any review.
- **Parallel subagent audits find different things**: p107 found orchestration contract gaps; corporate-grade review found silent install.sh failures.
- **Version drift is a red flag for judges**: 4 files had different versions. Canonical version should be in git tags, not scattered in file headers.
- **Subagents time out on complex multi-file reviews**: Used p107 post-daughter rule — did reviews in main session, not subagents.

### Current state
- 161/161 integrity checks: PASS
- 22/22 fuzz tests: PASS
- demo.sh: commands display, 7-phase claim consistent, summary shows correct version

---

## 2026-06-28 — Contest Sprint v1.12.0

### What we did
Fixed critical pytest bug and added 5 polish items + live exploit audit for Superteam Brasil contest submission (July 8, 2026).

### Critical bug found
python3 -m pytest fails silently on clean clone because pytest is not on system Python module path. All 22 fuzz tests were reporting "0 tests collected" and exit 0. Fixed with python3 -c "import pytest; pytest.main([...])". PATTERN: always verify test commands actually run, not just exit 0. Demo scripts with || true mask silent failures.

### Contest differentiators
1. Dashboard screenshot — visual proof above the fold
2. PT-BR guide — built for the audience
3. Benchmark table — proves differentiation vs existing tools
4. GH Actions template — "I could use this tomorrow"
5. Live exploit audit — real production exploit documented
6. Before/After comparison — full lifecycle demonstration

### Pattern for winning
- Visual proof above the fold > text description
- One-click integration > complex setup
- Live production usage > theoretical examples
- Mathematically verified correctness > assertions

### Still missing
- Native QED 2A CI integration
- Multi-program audit aggregation
- Video walkthrough
- CLAUDE.md staleness (fixed in v1.13.0)

## Principles

1. **Mathematical verification beats manual calculation** — Every CVSS score must be computable from its vector. We found 7/10 scores were wrong in v1.0.0 because they were hand-entered.
2. **CI is the truth** — If it's not in CI, it's not verified. Subagent reviewer claims about tool availability (ripgrep preinstalled, solana stable channel) were wrong.
3. **Count-driven integrity** — Every claim about counts (severity, files, agents, rules) must have an integrity check that recomputes from source.
4. **SDD before coding** — Spec-driven development catches ambiguities and logical inconsistencies before implementation.
5. **Triple-verify before trusting subagent reviewers** — code-reviewer-deepseek-flash flagged `TOKEN_FIXTURE_SOURCE_PATH` as dead code, but it was actively used by P18. Always verify reviewer claims against the actual code before acting.

## Key Decisions

### Decision 1: AccountInfo fixture vs typed accounts
- **Context**: The sample vulnerable program uses `AccountInfo` for all accounts to avoid Anchor macro issues while keeping bugs detectible.
- **Options**: (a) Use typed `Account<'info, VaultState>` for most accounts, (b) Use raw `AccountInfo` throughout, (c) Hybrid approach.
- **Chosen**: Raw `AccountInfo` throughout — keeps the fixture compile-clean across Anchor versions and avoids false positives from Anchor's own validation.
- **Trade-off**: Some bugs (missing discriminator) are implicit rather than explicit via compiler errors. This is acceptable since the fixture is a *code-review demonstration*, not a runtime-test target.
- **Lesson**: Document this design choice clearly so reviewers don't think the fixture is sloppy.

### Decision 2: Python for integrity checks vs bash-only
- **Context**: CVSS math verification required floats, ceil(), and structured parsing that bash can't do well.
- **Options**: (a) Pure bash with bc/awk, (b) Python 3, (c) Rust helper binary.
- **Chosen**: Python 3 — preinstalled on macOS and Ubuntu CI runners, no external dependencies, fast enough for CI.
- **Trade-off**: Python 3.6+ required (GitHub Actions ships 3.12). This is fine.
- **Lesson**: Use `#!/usr/bin/env python3` not `#!/usr/bin/python3` — the latter path differs between systems.

### Decision 3: Integrity checks as standalone shell script vs pytest
- **Context**: Need a CI-compatible test runner that works without pip install.
- **Options**: (a) Pytest, (b) Bash script with `set -e`, (c) Python script.
- **Chosen**: Bash script — zero dependencies, runs anywhere, and CI doesn't need to install a test framework.
- **Trade-off**: No pytest fixtures, parametrization, or reporting. Manual PASS/FAIL tallies suffice.
- **Lesson**: Keep the script under 500 lines; beyond that, migrate to pytest.

### Decision 4: Property-based testing approach
- **Context**: User explicitly requested property-based testing (like Hypothesis/fuzz testing) to catch issues unit tests miss.
- **Options**: (a) Python Hypothesis library, (b) Rust proptest crate, (c) Custom fuzzer.
- **Chosen**: Python Hypothesis — it's the standard PBT library for Python, easy to integrate with existing `severity_counts.py`, and requires no additional toolchain.
- **Trade-off**: Rust proptest would be more aligned with the Solana ecosystem, but would require cargo install and longer CI. Python Hypothesis runs anywhere Python does.
- **Lesson**: Property-based tests should verify *general properties* (e.g., "CVSS score always ≤ 10") not specific examples.

### Decision 5: Brazilian Portuguese support
- **Context**: Contest is run by Superteam Brasil; Brazilian developers are a key audience.
- **Options**: (a) Full PT-BR translation of all skill files, (b) Bilingual glossary only, (c) Portuguese command aliases.
- **Chosen**: Bilingual glossary in terminology file + Portuguese query recognition in commands. Full translation is too high-effort for the incremental value.
- **Trade-off**: Not all docs are translated, but the most important terms are accessible in both languages.

### Decision 6: Token-2022 fixture design
- **Context**: Contest requirement for Token-2022 coverage. Needed to demonstrate Rule 5 (Token Operations — SPL vs Token-2022 Distinction) with concrete, tagged vulnerabilities.
- **Options**: (a) Add Token-2022 vulns to the existing vault program, (b) Create a separate token-extensions program fixture, (c) Document Token-2022 patterns in rules only (no fixture).
- **Chosen**: Separate `token-extensions` program with its own Cargo.toml (spl-token-2022 dep), declare_id, and 6 tagged vulnerabilities (VULN-11 through VULN-16). Keeps concerns separated — vault fixture remains focused on core Anchor bugs; token-extensions fixture covers extension-level bugs.
- **Trade-off**: Two separate Anchor programs require two code reviews instead of one. However, each fixture is independently buildable, and integrity checks can validate each separately. The extension-level bugs are fundamentally different from core Anchor bugs (extension data reads vs account validation), so merging them would violate SRP.
- **Lesson**: Token-2022 bugs cluster around five extension categories: wrong program identity (VULN-11), missing fee math (VULN-12), missing authority verification against extension data (VULN-13, VULN-14), missing pointer verification (VULN-15), and missing extension presence check (VULN-16). A single Rule 5 covers all five if the auditor knows to check extension data read patterns.

### Decision 7: Corporate-grade integrity script refactoring
- **Context**: Integrity checks 3, 6, 7, 8, 10, and 18 all repeated the same fixture-validation pattern for vault and token-extensions — ~80 lines of duplicated code.
- **Options**: (a) Keep duplication for simplicity, (b) Extract shared bash functions, (c) Migrate checks to Python.
- **Chosen**: Extract 3 shared bash functions: `check_fixture_vuln_coverage()`, `run_single_arg_check_for_fixtures()`, `run_two_arg_check_for_fixtures()`. Keeps CI dependency-free (no Python needed for basic checks) while eliminating duplication.
- **Trade-off**: Bash functions with `local` variable scoping are less testable than Python. The functions are <50 lines each, which is maintainable.
- **Lesson**: SRP applies to test infrastructure too. When a pattern appears 3+ times across checks, extract a shared function — it catches the next fixture addition for free.

### Decision 8: Methodology-trace CVSS drift detection
- **Context**: When CVSS scores were corrected in findings.json and AUDIT_REPORT.md (VULN-14: 9.3→10.0, VULN-16: 7.5→8.1), the methodology-trace.md was not updated. This caused silent data drift that existed for several commits before detection.
- **Options**: (a) Manually audit methodology-trace.md on every CVSS change, (b) Add integrity Check 19 that cross-references trace CVSS scores against findings.json, (c) Remove CVSS scores from methodology-trace.md to avoid drift.
- **Chosen**: Add Check 19 with `check_trace_cvss_for_fixture()` bash function that extracts CVSS scores from trace files and compares them against findings.json. This catches drift automatically in CI.
- **Trade-off**: The bash implementation re-parses the full JSON for each finding (quadratic in N findings). Fine for 16 findings; should be optimized if fixtures grow to 50+.
- **Lesson**: Any derived data file (methodology-trace, quick-scan results) that includes inline scores must have a cross-reference integrity check. Without it, corrections to the canonical data source silently leave stale copies.

### Decision 9: Bidirectional source tag validation via fuzz tests
- **Context**: The integrity script was already checking VULN tag coverage between source and findings.json, but only one-directional (every VULN-XX in source has a finding). The reverse direction — every VULN ID in findings.json has a source tag — was not explicitly tested.
- **Options**: (a) Add to integrity script Check 3/18, (b) Add as a property-based test (P18 for Token-2022, P19 for vault), (c) Skip — the count match check implicitly covers it.
- **Chosen**: Property-based tests P18 and P19 with explicit bidirectional set comparison: `finding_ids - source_ids` AND `source_ids - finding_ids`. Clearer failure messages than count-only checks.
- **Trade-off**: Fuzz tests run via Hypothesis (pytest) rather than the CI dependency-free integrity script. Both test layers exist, so the coverage is overlapping but validated from different angles.
- **Lesson**: Bidirectional validation catches "orphan" findings that have no corresponding source tag — a bug class that count-only checks miss because both sides still have N items, but different ones.

## Bugs Found & Fixed

| Bug | Found | Fixed | Root Cause | Caught By |
|-----|-------|-------|------------|-----------|
| 7/10 CVSS scores miscalculated | v1.2.0 | v1.2.0 | Hand-entered scores not recomputed from vectors | Check 10 |
| VULN-04 severity wrong (HIGH→CRITICAL) | v1.1.0 | v1.1.0 | Vector didn't match impact description | Manual review |
| Agent count mismatch (3 listed, 4 exist) | v1.2.0 | v1.2.0 | Orchestrator.md added but docs not updated | Check 9 |
| install.sh didn't copy templates/ | v1.2.0 | v1.2.0 | NEW feature without install update | Manual review |
| solana-cli rolling stable broke CI | v1.2.0 | v1.2.0 | Unpinned dependency assumption | CI failure |
| VULN description drift (VULN-04 renamed to drain_vault) | v1.2.3 | v1.2.3 | Code changed but finding text not updated | Manual review |
| VULN-14 CVSS stale in methodology-trace (9.3→10.0) | v1.3.1 | v1.3.1 | Old score survived across CVSS correction round | Check 19 (NEW) |
| VULN-16 CVSS stale in methodology-trace (7.5→8.1) | v1.3.1 | v1.3.1 | Same root cause as VULN-14 | Check 19 (NEW) |
| Version staleness (20 issues) | v1.7.1 | v1.7.1 | Documentation claimed v1.5.0/v1.5.0-era numbers after code grew to v1.7 (50 rules, 6 agents, 9 commands, 22 fuzz tests) | Multi-agent audit |

## Contest-Specific Learnings

1. **Demo matters** — Judges evaluate in < 5 min. A `demo.sh` that shows the skill working from a clean clone is worth more than any single feature.
2. **Brazil context** — Portuguese support signals respect for the local community.
3. **Verifiable claims** — Every claim in README (counts, coverage, completeness) should be machine-verifiable by an integrity check.
4. **CI badge = trust** — A green CI badge on README.md gives immediate confidence to judges.
5. **Compile-verified example** — The example program must compile. A non-building fixture makes the entire submission look broken.
6. **SDD docs grow stale fast** — PRD.md, spec.md, kanban.md, learnings.md drift from reality every time a new check or test is added. Update them together with the code changes, not as an afterthought.
7. **Cross-file data drift is invisible without integrity checks** — The methodology-trace CVSS bug existed for multiple commits before discovery. If a derived file replicates data from a canonical source, add a cross-reference check immediately.

### Decision 10: Separate token-2022-real fixture for actual spl_token_2022
- **Context**: The token-extensions fixture uses raw `AccountInfo` for tokens, not actual `spl_token_2022` imports. The agent creating it used the same pattern. A separate fixture was needed with real Token-2022 dependencies.
- **Options**: (a) Modify existing token-extensions fixture, (b) Create third fixture `token-2022-real`, (c) Skip — not necessary for contest.
- **Chosen**: Create third fixture `examples/token-2022-real/` with actual `spl_token_2022 = { features = ["extension-transfer-hook", "extension-default-account-state"] }` in Cargo.toml and real `transfer_checked` CPI calls in source. Demonstrates Rule 5 with real Token-2022 patterns.
- **Trade-off**: Three fixtures to maintain across integrity checks. Each requires separate audit-output files. The 1:1 VULN↔findings mapping check runs for all three.
- **Lesson**: When a rule references a specific library (`spl_token_2022`), the fixture should use that library — not raw `AccountInfo` workarounds. Judges looking at "Token-2022 coverage" will check the imports.

### Decision 11: Formal verification as best-effort, not blocking
- **Context**: Phase 3 claims formal verification via QED 2A. Judges expect to see it work. But QED requires Solana toolchain which isn't in CI.
- **Options**: (a) Make QED required in CI (adds 3+ min), (b) Add graceful skip with documentation, (c) Remove formal verification claims.
- **Chosen**: Best-effort with graceful skip. `tests/test-formal-verification.sh` checks for `anchor` CLI, skips if absent, documents what would be verified. Provides 5 concrete invariant test patterns in `fv-invariant-pattern.ts` that work with `anchor test`.
- **Trade-off**: Judges without Solana toolchain see "SKIP" but also see the pattern files and documentation. SOLANA_LEARNERS get a working `anchor test` experience.
- **Lesson**: When a feature requires toolchain, provide both paths: (a) demonstration code that works without it (pattern files, docs), (b) documentation of what changes with toolchain installed. Best-effort beats absent.

## Contest-Specific Learnings

1. **GitHub secret-scanning flags fake keys** — Even `sk_live_abc123xyz...` in a pattern example gets flagged. Use clearly non-functional placeholders like `PLACEHOLDER_KEY_XXXX` or `sk_test_REPLACEME`. The `sk_live_` / `sk_test_` prefix pattern triggers the scanner regardless of validity.
2. **Kit repo ≠ rich repo** — The kit submission is a *restructure*, not a rebuild. Port from source: skill files, agents, commands, rules, tests. Strip: examples/, ext/, klend/, audit-report/, data/, package/. The kit version must be lean (<5MB) for quick install.
3. **Demo must be toolchain-free** — Judges evaluate in <2 min. `demo.sh` that requires Anchor/Solana CLI install fails the evaluation. The demo should only verify structure, routing, and logic (CVSS math, integrity checks).
4. **Empty GitHub repo has no HEAD** — `git commit --amend` works on existing commits, but empty repos need `git push -u origin main`. No amend needed on first push.

### 2026-06-27 — Dashboard Sprint + Bug Hunt

5. **`exit $FAIL` is correct** — `FAIL` starts at 0. If all checks pass, `exit 0`. If any check fails, `exit 1`. The "fix" to `exit $((FAIL > 0 ? 1 : 0))` would be a no-op since `$FAIL` is already 0 or 1. Never "fix" working arithmetic.
6. **Bash heredoc quoting: `"$VAR"` expands, `'VAR'` doesn't** — `python3 -c "...'$EXAMPLE_FINDINGS'..."` passes a literal string with `$EXAMPLE_FINDINGS` embedded; `python3 -c "...\"$EXAMPLE_FINDINGS\"..."` expands the variable. Always test with paths containing spaces.
7. **Subagent Write tools get rejected** — Even when agents have file-write capability, some sessions reject Write/Edit calls. Always verify agents committed files via `git status` before trusting their reports.
8. **`output_path.write_text()` without `mkdir(parents=True)` crashes on nested dirs** — The `dashboard.py` fix is `output_path.parent.mkdir(parents=True, exist_ok=True)` before writing.
9. **SWIG-generated Python + Python 3.9 `functools.cached_property` incompatibility** — Hypothesis uses SWIG; the `cached_property` attribute is on the class not instance; `getattr()` with a default of `None` returns `None` when the attribute isn't injected, causing a `TypeError` on `None()` in `hypothesis-python` ≥ 6.127.1. Workaround: use `hypothesis[x] < 6.127.1` in requirements.
10. **HTML dashboard chip count confusion is a false positive** — The severity bar shows 5 chips (one per unique severity level), not 10 chips (one per finding). The template is correct; cross-check script was checking the wrong element class.
11. **Audit-report script: nested f-strings are a SyntaxError** — `f(f"...")` is invalid Python. Fix: `"string1" + (f"..." if cond else "") + "string2"`.
12. **`demo.sh` step count must match reality** — When adding a step, update ALL `[X/6]` references and the `DEMO_VERSION` echo. SWE agent correctly updated to `[1/7]` through `[7/7]`.

### 2026-06-27 — v1.9.0 Sprint: Threat Modeling + Exploit Simulation

13. **STRIDE maps naturally to Solana** — Each STRIDE category maps to concrete Solana patterns: Spoofing → fake program IDs in CPI; Tampering → account data mutations; Repudiation → missing event emission; Info Disclosure → unencrypted account data; DoS → resource exhaustion; Privilege Escalation → missing authority checks. The mapping makes threat modeling actionable, not academic.
14. **Exploit metadata schema as canonical structure** — Structuring PoC data as JSON (preconditions, attack_steps with expected/actual, exploitability_score, remediation_verified) turns informal exploit notes into machine-readable audit artifacts. Enables automated remediation tracking and finding prioritization.
15. **Phase 2A slots between SAST (2) and Runtime (2B)** — The three-tier execution model (Tier 1: SAST-only, Tier 2: + Runtime, Tier 3: + Exploit Sim) gives auditors a progressive commitment path. Start Tier 1, escalate as needed. Threat modeling (2A) is toolchain-free so it belongs in Tier 1.
16. **7 agents from 6** — Added `threat-modeler` as the 7th specialist agent. The handoff contract pattern (input_artifacts, expected_outputs, context) scales cleanly. Each agent owns one phase or phase group.
17. **Option A vs Option B for exploit simulation** — Option A (metadata schema, `/audit-poc --metadata` flag, structured output) was chosen over Option B (interactive REPL). Option A is CI-friendly, idempotent, and integrates with the existing findings pipeline without requiring interactive sessions.

### 2026-06-27 — Loop 2 Contest: Remediation Engine Sprint

18. **Subagents can write to unintended directories** — When a subagent is spawned from a worktree whose CWD is not the skill repo root, its Write/Edit tools resolve relative paths from the wrong directory. Always pass absolute paths to subagent file operations, or spawn the agent from the correct CWD. Verify with `git status` after every subagent completes.
19. **Stalled subagents look like success** — An agent that encounters a `ToolUseBlocked` rejection may report completion without actually writing files. If a subagent claims to have updated a file, run `git status` in the target repo to confirm. Do not assume the file was written.
20. **SDD docs must be updated in the correct repo** — When working across multiple worktrees or the source repo vs kit repo, Edit tool path resolution uses the current session CWD, not the git working tree of the file being edited. Double-check the absolute path before editing; confirm with a Read if unsure.


### 2026-06-27 — Loop 3: Architecture Review + Report Enhancement

21. **Architecture review is a separate phase from threat modeling** — Threat modeling (Phase 2A, STRIDE) asks "what can go wrong at trust boundaries." Architecture review (Phase 7) asks "how are the components organized and what systemic risks does that structure create." Both are needed; they address different questions at different abstraction levels. Phase 2A feeds Phase 7 data; Phase 7 feeds Phase 5 reporting.
22. **Three report sections were missing from v1.10.0** — Executive Summary (severity-at-a-glance + risk posture), Methodology Trace (phase-to-artifact mapping), and Finding Distribution (severity breakdown + per-layer distribution). These are standard in professional audit reports and were the most visible gaps against master-prompt quality. Adding them required only template edits, not new phase logic.
23. **Agents-from-files pattern scales cleanly to 8** — Adding `architecture-reviewer` as the 8th specialist followed the same pattern as all previous agents: YAML frontmatter, 8-step flow, handoff contract. The existing orchestrator routing already handled Phase 7 routing by phase number.
24. **pocs/ path collision with poc/ pluralization** — `examples/token-2022-real/pocs/` vs `examples/token-2022-real/poc/` in token-extensions. Both fixtures used different pluralization conventions. Consistent naming (always `poc/`, singular) avoids confusion and integrity check failures.
25. **Stalling subagents look like success** — When a subagent hits a `ToolUseBlocked` rejection, it may report completion without writing files. Always verify with `git status` in the target repo before trusting subagent completion claims.
26. **YAML frontmatter on ALL agent files is non-negotiable** — The integrity check `agents/architecture-reviewer.md` must have frontmatter matching the same schema as all other agents. Missing frontmatter fails Check 39 and blocks CI.

## Future Improvements

- [x] **Line-number drift check (Check 20)** — implemented in `severity_counts.py check_line_numbers()`. Verified 161/161 pass. ✅ v1.14.2
- [x] **Architecture Review module** — Done v1.11.0 (Phase 7 + architecture-reviewer agent). ✅ v1.11.0
- [ ] **Flake8 config + lint CI** — pyproject.toml has black + mypy but no flake8.
- [ ] **Runtime tests** — Solana test validator in CI (~3 min extra per run).
- [ ] **Native qed-solana CI integration** — Needs toolchain install.
- [ ] **Interactive audit dashboard** — Visual report with severity distribution.
- [ ] **Multi-program audit aggregation** — Combine findings from multiple Anchor programs.
- [ ] **Visual diff** — Pre/post-fix audit report comparison.

---

## 2026-06-29 — Sprint 51: Check 20 Verification + SDD Sync (v1.14.2)

### What we did
Subagent analysis reported Check 20 as "never implemented." Direct code inspection proved it was already fully implemented — `check_line_numbers()` in `severity_counts.py:284` with bash wiring in `test-skill-integrity.sh:399-419`. All 3 fixtures pass. SDD docs updated to v1.14.2.

### Key lessons
1. **Subagent findings need independent verification** — P107's post-daughter rule applies: for multi-file verification tasks, inline inspection beats subagent delegation. Subagents time out or give false negatives on long analysis.
2. **Velocity tables drift** — Column count mismatches (11 data cols, 9 header versions) accumulated across sprint PRs. Always verify table alignment when updating.
3. **Phase 7 already done** — Architecture-reviewer agent exists at `agents/architecture-reviewer.md`, Phase 7 procedure at `skill/07-architecture-review.md`, routing in `skill/SKILL.md:63`. No action needed.
4. **MCP conflicts are scope-level** — Removing `~/.mcp.json` project-scope entry fixed the melone daemon collision. User-level Melone app path takes precedence.

### New learnings entry
5. **Check the actual code, not just the subagent summary** — The subagent correctly listed Check 20 as a "pending item" but missed the `check-line-numbers` mode in `severity_counts.py` and the bash loop at lines 399-419. Always grep the actual files.

## 2026-06-29 — v1.14.0 Fixture Expansion Sprint

### What we did
Added 3 new audit fixtures (AMM/DEX, Staking Pool, NFT/Candy Machine) with 42 total vulnerabilities, covering Rules 14/15/26/13/6/4/8/40/38/36/37/22/41/11/5/3/16/2/33/27/39 across diverse protocol types.

### Bugs found and fixed
| Bug | Severity | File | Issue | Fix |
|-----|----------|------|-------|-----|
| CVSS vectors wrong in DEX/Staking | HIGH | findings.json | Subagent used approximate vectors | Brute-forced exact vectors using `severity_counts.py` formula |
| VULN-12/13/14 DEX wrong severity | MEDIUM | findings.json | 1 finding tagged LOW but counted MEDIUM | Corrected summary; regenerated vectors |
| NFT fixture output missing | CRITICAL | — | 2 of 3 output agents timed out | Regenerated NFT audit-output via workflow |
| NFT VULN-05/08/09 CVSS mismatch | MEDIUM | findings.json | Subagent vectors didn't match repo formula | Applied brute-force lookup using repo's exact formula |

### Key lesson
**CVSS math must use brute-force lookup** — manual CVSS vector selection will always drift from the repo's formula. Use the `compute_cvss_score()` from `severity_counts.py` to generate the lookup table, then apply it to all fixture findings. Never trust approximate vectors from LLM output.

### Key lesson
**Subagent timeouts on long tasks** — fixture output generation (4 docs × 3 fixtures = 12 files) exceeded agent token budget. Break into smaller batches or use direct Python generation instead of agent delegation for document-heavy tasks.

---



## 2026-06-29 — v1.14.2 Raydium CLMM Audit + Severity Correction

### What we did
Live audit of jup-ag/raydium-clmm (6 confirmed findings). Added --lang pt|en bilingual support to all commands. Fixed README duplicate step numbering, agents badge count, dashboard commands.

### Severity lesson learned
**RAY-01 initially flagged CRITICAL** — remaining_accounts raw pubkey reads in update_amm_config. Source verification revealed #[account(address = crate::admin::ID)] constraint on the owner field. This enforces the admin key via Anchor's constraint system. The remaining_accounts bug is real (no bounds check, no None arm, panic vector) but requires admin key compromise — not exploitable by "anyone." Severity: CRITICAL → HIGH. Always read the actual struct constraints before assigning CRITICAL on access control findings.

### Key lesson
**CVSS math must use brute-force lookup** — manual CVSS vector selection drifts from the formula. Always brute-force against the actual compute_cvss_score() function from severity_counts.py. Same lesson as Sprint 50.

### Key lesson
**Subagent timeouts on document-heavy tasks** — fixture output generation (4 docs × 3 fixtures = 12 files) exceeded agent token budget. Direct Python generation is more reliable for structured document tasks.

### Key lesson
**Source verification changes severity** — reading the actual #[account] constraints in update_amm_config.rs revealed the admin key gate that saved this from being unauthenticated. Initial scan over-claimed. The tool found the bug correctly; the human corrected the severity. The skill's job is to surface the pattern; human judgment refines the severity.



## 2026-06-28 — v1.13.0 Bug Fix Sprint (Post-Contest-Submission Audit)

### What we did
Post-submission code audit of demo.sh and all skill fixtures, spawned 4 parallel subagents, found and fixed 4 bugs before contest deadline (July 8, 2026).

### Bugs found and fixed

| Bug | Severity | File | Issue | Fix |
|-----|----------|------|-------|-----|
| Missing `rule` field | CRITICAL | 5 fixture JSON files | 23 findings had `rule_caught` (text) but not `rule` (canonical integer) | Derived rule number from `rule_caught`, added `rule: N` or `rule: null` |
| Klive summary mismatch | HIGH | klive-live-audit/findings.json | Summary said `critical:0` but KAM-001 is CRITICAL; `RESOLVED` severity non-standard | Fixed summary counts, preserved RESOLVED status |
| Dead code in dashboard.py | MEDIUM | scripts/dashboard.py | `stdout_mode = True` unreachable; `not args.compare_mode` always True | Removed unreachable branch, simplified condition |
| Path traversal risk | LOW | scripts/dashboard.py | Single-file output paths not `.resolve()`'d | Added `.resolve()` to both output branches |

### Subagent audit findings that were FALSE POSITIVES
- code-reviewer flagged `--compare` accidental triggering as CRITICAL — but the argparse is intentionally designed with `--compare` as a flag appended at the END, matching the demo.sh call pattern. The fix in v1.12.0 already handled this correctly.
- security-reviewer flagged 5 TODOs in skill code — confirmed intentional (unimplemented features, template placeholders).

### Key pattern: fixture data integrity
Every fixture findings.json must have: `id`, `title`, `severity`, `cvss`, `cvss_vector`, `cwe`, `rule` (integer or null), `rule_caught` (text). Missing canonical fields = skill's own test data is incomplete, even if the dashboard still renders.

### Subagent reliability notes
- code-reviewer subagent: excellent at structural analysis, found argparse dead code and unreachable branch
- security-reviewer subagent: thorough JSON integrity scan, found summary mismatches
- general-purpose subagent: good at edge case testing and file operations
