#!/usr/bin/env python3
"""Shared severity-counting helper for integrity Checks 6, 7, 8, and 10.

Reads findings.json, computes the count per severity level, and
compares against either (a) findings.json's summary field, (b) a
parsed severity table in AUDIT_REPORT.md, (c) CVSS score+vector
consistency between findings.json and AUDIT_REPORT.md, or (d) CVSS
score mathematically derivable from its vector.

Usage:
    python3 severity_counts.py check-summary    <findings.json>
    python3 severity_counts.py check-report     <findings.json> <report.md>
    python3 severity_counts.py check-cvss       <findings.json> <report.md>
    python3 severity_counts.py check-cvss-math  <findings.json>

Exit code: 0 on match, 1 on mismatch (with diff printed to stderr).
"""
import json
import math
import re
import sys
from typing import Optional, Any, Dict, List, Tuple

SEVERITIES = ("critical", "high", "medium", "low", "info")

# Maximum allowable gap (lines) between a VULN comment in source and the
# claimed line number in findings.json. If the gap exceeds this threshold,
# the finding's line number has likely drifted due to source edits.
MAX_ALLOWABLE_VULN_LINE_GAP: int = 12

# CVSS 3.1 base score metric values
_CVSS_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

# CVSS 3.1 formula constants
# Impact Sub-Score (ISS) multiplier for Scope:Unchanged
CVSS_IMPACT_MULTIPLIER: float = 6.42
# Exploitability coefficient
CVSS_EXPLOITABILITY_COEFFICIENT: float = 8.22
# Scope:Changed impact formula constants
CVSS_SCOPE_C_IMPACT_MULTIPLIER: float = 7.52
CVSS_SCOPE_C_IMPACT_CONSTANT_1: float = 0.029
CVSS_SCOPE_C_IMPACT_CONSTANT_2: float = 0.02
CVSS_SCOPE_C_IMPACT_POWER: float = 15.0
# Scope:Changed scope bonus multiplier
CVSS_SCOPE_C_BONUS_MULTIPLIER: float = 1.08
# Maximum CVSS score
CVSS_MAX_SCORE: float = 10.0
# Tolerance for floating point comparison
CVSS_SCORE_TOLERANCE: float = 0.05


def count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Return {sev: count, total: N} from a list of finding dicts."""
    if not findings:
        return {sev: 0 for sev in SEVERITIES}  # type: ignore[dict-item]
    counts: Dict[str, int] = {sev: 0 for sev in SEVERITIES}  # type: ignore[dict-item]
    for finding in findings:
        sev = finding.get("severity", "").lower()
        if sev in counts:
            counts[sev] += 1
    counts["total"] = len(findings)
    return counts


def load_findings(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fp:
        return json.load(fp)


def _mismatches(
    expected: Dict[str, int], actual: Dict[str, int], label_a: str, label_b: str
) -> List[Tuple[str, int, int]]:
    """Return list of (key, expected, actual) for severity keys that differ."""
    return [
        (sev, expected.get(sev, 0), actual.get(sev, 0))
        for sev in SEVERITIES
        if expected.get(sev, 0) != actual.get(sev, 0)
    ]


def check_summary(findings_path: str) -> int:
    """Verify findings.json summary field matches computed counts.

    Compares per-severity keys only. The 'total' key is skipped because
    it's derivable from len(findings) and a missing/extra 'total' is a
    schema issue, not a counting issue.
    """
    d = load_findings(findings_path)
    expected = count_by_severity(d.get("findings", []))
    actual = d.get("summary", {})
    diffs = _mismatches(expected, actual, "expected", "actual")
    if diffs:
        print(f"MISMATCH: {diffs}", file=sys.stderr)
        print(f"EXPECTED: {expected}", file=sys.stderr)
        print(f"ACTUAL:   {actual}", file=sys.stderr)
        return 1
    return 0


def parse_report_counts(report_path: str) -> Dict[str, int]:
    """Parse the | CRITICAL | N | row from AUDIT_REPORT.md's severity table."""
    with open(report_path, encoding="utf-8") as fp:
        report = fp.read()
    counts: Dict[str, int] = {}
    for sev in SEVERITIES:
        m = re.search(rf"\|\s*{sev.upper()}\s*\|\s*(\d+)\s*\|", report, re.IGNORECASE)
        if m:
            counts[sev] = int(m.group(1))
    return counts


def check_report(findings_path: str, report_path: str) -> int:
    """Verify AUDIT_REPORT.md severity table matches findings.json counts.

    Compares per-severity keys only. The report table does not include a
    'total' column, so 'total' is skipped.
    """
    d = load_findings(findings_path)
    fn_counts = count_by_severity(d.get("findings", []))
    report_counts = parse_report_counts(report_path)
    diffs = _mismatches(fn_counts, report_counts, "findings", "report")
    if diffs:
        print(f"MISMATCH: {diffs}", file=sys.stderr)
        print(f"FINDINGS: {fn_counts}", file=sys.stderr)
        print(f"REPORT:   {report_counts}", file=sys.stderr)
        return 1
    return 0


def check_cvss_math(findings_path: str) -> int:
    """Verify each finding's CVSS score is mathematically derivable from its vector.

    CVSS 3.1 base score formula:
      ISS = 1 - (1 - C) * (1 - I) * (1 - A)
      Impact = 6.42 * ISS
      Exploitability = 8.22 * AV * AC * PR * UI
      Base = roundUp(min(Impact + Exploitability, 10))

    PR depends on Scope: U → {N:0.85, L:0.62, H:0.5}; C → {N:0.85, L:0.68, H:0.5}

    A score that doesn't match its vector indicates a manual miscalculation —
    this is the bug class documented in superpowers/references/cvss-score-verification.md
    (the prior fix caught only VULN-04; this check catches the rest).
    """
    d = load_findings(findings_path)
    diffs: List[Tuple[str, str, str, str]] = []
    for finding in d.get("findings", []):
        fid = finding.get("id")
        claimed = finding.get("cvss")
        vec = finding.get("cvss_vector", "")
        if not vec or claimed is None:
            continue
        computed = compute_cvss_score(vec)
        if computed is None:
            diffs.append((fid, "vector unparseable", str(claimed), vec))
        elif abs(claimed - computed) > CVSS_SCORE_TOLERANCE:
            diffs.append((fid, "score", str(claimed), str(computed)))
    if diffs:
        print(f"CVSS math mismatches ({len(diffs)}):", file=sys.stderr)
        for fid, field, claimed, computed in diffs:
            print(
                f"  {fid} {field}: claimed={claimed!r} computed-from-vector={computed!r}",
                file=sys.stderr,
            )
        return 1
    return 0


def parse_cvss_vector(vec: str) -> Optional[Dict[str, str]]:
    """Parse CVSS:3.1/AV:N/... → dict. Returns None if unparseable."""
    if not vec.startswith("CVSS:3.1/"):
        return None
    out: Dict[str, str] = {}
    try:
        for part in vec[len("CVSS:3.1/") :].split("/"):
            k, v = part.split(":")
            out[k] = v
    except ValueError:
        return None
    return out


def compute_cvss_score(vec: str) -> Optional[float]:
    """Compute CVSS 3.1 base score from vector string. Returns None if invalid.

    Implements the CVSS 3.1 formula per the FIRST specification document:
    https://www.first.org/cvss/v3.1/specification-document

    Notes:
    - PR:L value depends on Scope: 0.62 for Scope U, 0.68 for Scope C.
    - Scope:C scoring uses a different impact formula (7.52*(ISS-0.029)
      - 3.25*(ISS-0.02)^15) and a scope bonus (1.08 multiplier).
    - roundUp is "smallest value with 1 decimal precision >= x".
    """
    m = parse_cvss_vector(vec)
    if m is None:
        return None
    try:
        av = _CVSS_VALUES["AV"][m["AV"]]
        ac = _CVSS_VALUES["AC"][m["AC"]]
        ui = _CVSS_VALUES["UI"][m["UI"]]
        scope = m.get("S", "U")
        if scope == "U":
            pr_table = {"N": 0.85, "L": 0.62, "H": 0.5}
        else:  # Scope:C
            pr_table = {"N": 0.85, "L": 0.68, "H": 0.5}
        pr = pr_table[m["PR"]]
        c = _CVSS_VALUES["C"][m["C"]]
        i = _CVSS_VALUES["I"][m["I"]]
        a = _CVSS_VALUES["A"][m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)

    # Impact differs by scope
    if scope == "U":
        impact = CVSS_IMPACT_MULTIPLIER * iss
    else:  # Scope:C — only valid when ISS > 0
        impact = (
            CVSS_SCOPE_C_IMPACT_MULTIPLIER * (iss - CVSS_SCOPE_C_IMPACT_CONSTANT_1)
            - CVSS_SCOPE_C_IMPACT_CONSTANT_2 * (iss - CVSS_SCOPE_C_IMPACT_CONSTANT_2) ** CVSS_SCOPE_C_IMPACT_POWER
        )

    exploitability = CVSS_EXPLOITABILITY_COEFFICIENT * av * ac * pr * ui

    # Base score depends on scope
    if impact <= 0:
        return 0.0
    if scope == "U":
        base = min(impact + exploitability, CVSS_MAX_SCORE)
    else:  # Scope:C — scope bonus
        base = min(CVSS_SCOPE_C_BONUS_MULTIPLIER * (impact + exploitability), CVSS_MAX_SCORE)

    # CVSS 3.1 roundUp: smallest value with 1 decimal precision >= x
    return math.ceil(base * 10) / 10


def check_cvss_consistency(findings_path: str, report_path: str) -> int:
    """Verify CVSS score + vector in findings.json match AUDIT_REPORT.md.

    For each finding, extract the score from the report's `**CVSS**: N` line
    and the vector from `CVSS:3.1/...`. Compare to findings.json's cvss
    and cvss_vector fields. Mismatches indicate a documentation drift bug.
    """
    d = load_findings(findings_path)
    with open(report_path, encoding="utf-8") as fp:
        report = fp.read()
    diffs: List[Tuple[str, str, str, str]] = []
    for finding in d.get("findings", []):
        fid = finding.get("id")
        score = finding.get("cvss")
        vec = finding.get("cvss_vector", "")
        # Extract this finding's section
        m = re.search(
            rf"### {re.escape(fid)}:.*?(?=### VULN-|^## |\Z)", report, re.MULTILINE | re.DOTALL
        )
        if not m:
            diffs.append((fid, "section not found in report", "", ""))
            continue
        section = m.group(0)
        m2 = re.search(r"\*\*CVSS\*\*:\s*(\S+)", section)
        report_score = m2.group(1) if m2 else None
        m3 = re.search(r"CVSS:3\.1/[^\s)`]+", section)
        report_vec = m3.group(0) if m3 else None
        if str(score) != str(report_score):
            diffs.append((fid, "score", str(score), str(report_score)))
        if vec and report_vec and vec != report_vec:
            diffs.append((fid, "vector", vec, report_vec))
    if diffs:
        print(f"CVSS mismatches ({len(diffs)}):", file=sys.stderr)
        for fid, field, json_v, report_v in diffs:
            print(f"  {fid} {field}: json={json_v!r} report={report_v!r}", file=sys.stderr)
        return 1
    return 0


def check_line_numbers(findings_path: str, source_path: str) -> int:
    """Verify each finding's claimed line number matches its VULN comment in source.

    For each finding with a location.line, find the corresponding `// VULN-XX:`
    comment in the source file. The comment must be within a reasonable distance
    (5 lines) of the claimed line. If the gap exceeds 5 lines, the finding's
    line number has likely drifted due to source edits.

    Returns 0 if all line numbers are correct, 1 if any mismatches found.
    """
    import pathlib

    d = load_findings(findings_path)
    source_text: str = pathlib.Path(source_path).read_text()
    source_lines: list[str] = source_text.splitlines()

    mismatches: list[tuple[str, int, int, int]] = []  # (fid, claimed_line, comment_line, gap)

    for finding in d.get("findings", []):
        finding_id: str = finding.get("id", "")
        if not finding_id.startswith("VULN-"):
            continue

        location = finding.get("location", {})
        claimed_line: int = location.get("line", 0)
        if not claimed_line:
            continue

        # Search for the VULN-XX comment in the source
        # Match both // and /// doc comments with optional leading whitespace
        comment_patterns = [
            f"///\\s+{re.escape(finding_id)}:",
            f"//\\s+{re.escape(finding_id)}:",
        ]
        comment_line: int = 0
        for i, line_text in enumerate(source_lines, start=1):
            for pat in comment_patterns:
                if re.search(pat, line_text):
                    comment_line = i
                    break
            else:
                continue
            break

        if comment_line == 0:
            mismatches.append((finding_id, claimed_line, 0, 999))
            continue

        gap: int = abs(claimed_line - comment_line)
        if gap > MAX_ALLOWABLE_VULN_LINE_GAP:
            mismatches.append((finding_id, claimed_line, comment_line, gap))

    if mismatches:
        print(f"Line number mismatches ({len(mismatches)}):", file=sys.stderr)
        for fid, claimed, comment_line, gap in mismatches:
            if comment_line == 0:
                print(
                    f"  {fid}: VULN comment NOT FOUND in source (claimed line {claimed})",
                    file=sys.stderr,
                )
            else:
                print(
                    f"  {fid}: claimed {claimed}, VULN comment at {comment_line} (gap={gap})",
                    file=sys.stderr,
                )
        return 1
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2

    mode = sys.argv[1]
    try:
        if mode == "check-summary":
            return check_summary(sys.argv[2])
        elif mode == "check-report":
            return check_report(sys.argv[2], sys.argv[3])
        elif mode == "check-cvss":
            return check_cvss_consistency(sys.argv[2], sys.argv[3])
        elif mode == "check-cvss-math":
            return check_cvss_math(sys.argv[2])
        elif mode == "check-line-numbers":
            return check_line_numbers(sys.argv[2], sys.argv[3])
        else:
            print(f"Unknown mode: {mode}", file=sys.stderr)
            return 2
    except Exception as e:
        print(f"Validation error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
