# Verification Guide for Judges

This file walks a judge through every verification step — what it proves, how to run it, and what "pass" looks like. Five minutes to fully verify the skill.

---

## Step 1: Demo Script (30 seconds, no toolchain needed)

```bash
bash demo.sh
```

**What it proves:** All files are present, syntax is valid, demo runs end-to-end without crashing.

**Pass:** Script exits 0. No `FAIL` lines in output.

---

## Step 2: Integrity Checks — 47 categories (45 seconds)

```bash
bash tests/test-skill-integrity.sh
```

**What it proves:** Skill is internally consistent — no broken cross-references, no drifted VULN-ID counts, no malformed CWE URLs, CVSS math is verified, fixtures are complete, agent YAML frontmatter is valid.

**Pass:** `PASS: 47` / `FAIL: 0` at the bottom.

---

## Step 3: Fuzz Tests — 22 strategies (30 seconds)

```bash
python3 -m pytest tests/fuzz/ -v
```

**What it proves:** CVSS scoring is mathematically correct across thousands of random inputs. Severity binning is monotonic. All committed fixture CVSS scores are valid.

**Pass:** `22 passed` in the pytest output.

---

## Step 4: Example Fixture — Findings (2 minutes)

```bash
cat examples/sample-vulnerable-program/audit-output/findings.json | python3 -m json.tool | head -80
```

**What it proves:** The skill produced structured findings from a real (deliberately vulnerable) Anchor program. Every finding has: `id`, `title`, `severity`, `cvss`, `cvss_vector`, `cwe`, `description`, `impact`, `remediation`, `poc_status`, and a `location.file`.

**Pass:** JSON parses cleanly. Findings have all required fields. CVSS scores are in range [0.0, 10.0].

---

## Step 5: CVSS Math Proof (30 seconds)

```bash
python3 tests/severity_counts.py check-cvss-math \
  examples/sample-vulnerable-program/audit-output/findings.json
```

**What it proves:** Every finding's claimed CVSS score is mathematically derivable from its `cvss_vector`. No hand-entered scores.

**Pass:** Exit 0. No `FAIL` lines.

---

## Step 6: Anchor Build — Example Program (3 minutes, requires Anchor 0.31.1)

```bash
cd examples/sample-vulnerable-program
anchor build
```

**What it proves:** The example fixture compiles cleanly under Anchor 0.31.1 + Solana Agave. (Required: `anchor-cli` 0.31.1 and `solana-cli` 2.x installed.)

**Pass:** `Build successful.` output from anchor.

---

## Quick Verification Checklist

| Step | Command | Pass Criteria |
|------|---------|---------------|
| Demo | `bash demo.sh` | Exit 0, no FAIL |
| Integrity | `bash tests/test-skill-integrity.sh` | PASS: 47, FAIL: 0 |
| Fuzz | `python3 -m pytest tests/fuzz/ -v` | 22 passed |
| Fixture | `cat examples/.../findings.json` | Valid JSON, all required fields |
| CVSS math | `python3 tests/severity_counts.py check-cvss-math ...` | Exit 0 |
| Build | `cd examples/... && anchor build` | Build successful |

---

## Source Files

| What to verify | File |
|----------------|------|
| 47 integrity checks | `tests/test-skill-integrity.sh` |
| 22 fuzz tests | `tests/fuzz/test_properties.py` |
| CVSS formula | `tests/cvss.py` |
| Example findings | `examples/sample-vulnerable-program/audit-output/findings.json` |
| Example report | `examples/sample-vulnerable-program/audit-output/AUDIT_REPORT.md` |
| 50 audit rules | `rules/audit.rules` |
| 9 slash commands | `commands/` |
| 6 specialist agents | `agents/` |
