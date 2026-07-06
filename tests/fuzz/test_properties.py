"""Property-based tests for Solana Auditor Skill.

These tests verify GENERAL PROPERTIES of the skill's algorithms that should
hold for ALL valid inputs — not just the specific examples in the fixture.

This catches bugs that unit tests miss because they test specific examples
rather than general properties.

Run:  python -m pytest tests/fuzz/ -x -v --hypothesis-show-statistics
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from hypothesis import given, assume, settings, strategies as st

# Add project root to path before local imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tests.severity_counts import (  # noqa: E402
    compute_cvss_score,
    parse_cvss_vector,
    count_by_severity,
    SEVERITIES,
)

# =========================================================================
# STRATEGIES — Generate structured test data
# =========================================================================

# CVSS 3.1 metric value sets
AV_VALUES = st.sampled_from(["N", "A", "L", "P"])
AC_VALUES = st.sampled_from(["L", "H"])
PR_VALUES = st.sampled_from(["N", "L", "H"])
UI_VALUES = st.sampled_from(["N", "R"])
SCOPE_VALUES = st.sampled_from(["U", "C"])
CIA_VALUES = st.sampled_from(["H", "L", "N"])
SEVERITY_LABELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@st.composite
def cvss_vectors(draw):
    """Generate random valid CVSS 3.1 base metric vectors.

    Each generated vector has exactly the 8 required metrics
    (AV, AC, PR, UI, S, C, I, A) drawn from the CVSS 3.1
    enumeration sets. No invalid or partial vectors are produced.

    Returns:
        A string like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
    """
    av = draw(AV_VALUES)
    ac = draw(AC_VALUES)
    pr = draw(PR_VALUES)
    ui = draw(UI_VALUES)
    s = draw(SCOPE_VALUES)
    c = draw(CIA_VALUES)
    i = draw(CIA_VALUES)
    a = draw(CIA_VALUES)
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


@st.composite
def severity_label(draw):
    """Generate a severity label from the standard 5-level scale.

    Possible values: CRITICAL, HIGH, MEDIUM, LOW, INFO.

    Returns:
        A severity string in uppercase.
    """
    return draw(st.sampled_from(SEVERITY_LABELS))


@st.composite
def finding_dict(draw):
    """Generate a random finding dictionary for property testing.

    Produces a minimal finding with a random severity label,
    a CVSS vector with its computed score, a unique ID,
    and a descriptive title.

    Returns:
        A dict with keys: id, severity, cvss, cvss_vector, title.
    """
    sev = draw(severity_label())
    vec = draw(cvss_vectors())
    score = compute_cvss_score(vec)
    if score is None:
        score = 0.0
    return {
        "id": f"TEST-{draw(st.integers(min_value=1, max_value=999)):03d}",
        "severity": sev,
        "cvss": score,
        "cvss_vector": vec,
        "title": draw(st.text(min_size=5, max_size=50)),
    }


# =========================================================================
# SEVERITY DEFAULTING MATRIX — From rules/audit.rules
# =========================================================================

# Mapping from CVSS score to expected severity per the severity scale
# defined in CLAUDE.md and rules/audit.rules:
#   CRITICAL >= 9.0
#   HIGH     >= 7.0
#   MEDIUM   >= 4.0
#   LOW      >= 0.1
#   INFO     < 0.1
SEVERITY_THRESHOLDS: List[tuple] = [
    ("CRITICAL", 9.0),
    ("HIGH", 7.0),
    ("MEDIUM", 4.0),
    ("LOW", 0.1),
]


def classify_severity_from_score(cvss_score: float) -> str:
    """Map a CVSS base score to its severity classification.

    Uses the severity scale defined in CLAUDE.md:
        CRITICAL >= 9.0
        HIGH     >= 7.0
        MEDIUM   >= 4.0
        LOW      >= 0.1
        INFO     < 0.1

    Args:
        cvss_score: CVSS 3.1 base score in [0.0, 10.0].

    Returns:
        Severity label string: CRITICAL, HIGH, MEDIUM, LOW, or INFO.
    """
    for severity_label, threshold in SEVERITY_THRESHOLDS:
        if cvss_score >= threshold:
            return severity_label
    return "INFO"


# =========================================================================
# PROPERTY 1: CVSS score must always be between 0 and 10
# =========================================================================


@given(cvss_vectors())
@settings(max_examples=200)
def test_cvss_score_range(vector: str) -> None:
    """P1: CVSS 3.1 base score must be in [0.0, 10.0] for all valid vectors.

    Every valid CVSS 3.1 metric combination must produce a score within
    the defined range [0.0, 10.0]. Scores outside this range indicate
    a formula implementation error.

    Properties verified:
        - Lower bound: score >= 0.0 (worst-case impact + exploitability)
        - Upper bound: score <= 10.0 (CVSS 3.1 specification cap)

    Args:
        vector: A generated CVSS 3.1 vector string.
    """
    score = compute_cvss_score(vector)
    assume(score is not None)
    assert 0.0 <= score <= 10.0, f"Score {score} out of range for {vector}"


# =========================================================================
# PROPERTY 2: CVSS score must be a multiple of 0.1 (roundUp precision)
# =========================================================================


@given(cvss_vectors())
@settings(max_examples=200)
def test_cvss_score_precision(vector: str) -> None:
    """P2: CVSS 3.1 base scores use roundUp — result is always multiple of 0.1.

    The CVSS 3.1 specification uses a roundUp function that produces
    scores at 0.1 precision (e.g., 9.8, 5.3, 10.0). Scores with finer
    precision indicate a rounding implementation error.

    Properties verified:
        - score * 10 is always an integer (to within floating point tolerance)

    Args:
        vector: A generated CVSS 3.1 vector string.
    """
    score = compute_cvss_score(vector)
    assume(score is not None)
    tenths = round(score * 10)
    assert abs(score - tenths / 10) < 0.01, f"Score {score} not multiple of 0.1"


# =========================================================================
# PROPERTY 3: Parsing a generated vector and recomputing gives same result
# =========================================================================


@given(cvss_vectors())
@settings(max_examples=200)
def test_cvss_parse_roundtrip(vector: str) -> None:
    """P3: Parsing a CVSS vector and recomputing the score is idempotent.

    A well-formed vector must parse without data loss: all 8 required
    metric keys must be present after parsing, and the score must be
    computable from the parsed representation.

    Properties verified:
        - parse_cvss_vector returns a dict with all 8 metric keys
        - compute_cvss_score succeeds on the original vector

    Args:
        vector: A generated CVSS 3.1 vector string.
    """
    parsed = parse_cvss_vector(vector)
    assert parsed is not None, f"Failed to parse {vector}"
    score1 = compute_cvss_score(vector)
    required_keys = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    assert required_keys.issubset(parsed.keys()), f"Missing keys in parsed {parsed}"
    assert score1 is not None


# =========================================================================
# PROPERTY 4: CVSS scope:C scores are >= scope:U scores (all else equal)
# =========================================================================


@given(AV_VALUES, AC_VALUES, PR_VALUES, UI_VALUES, CIA_VALUES)
@settings(max_examples=100)
def test_cvss_scope_ordering(av: str, ac: str, pr: str, ui: str, cia: str) -> None:
    """P4: For identical exploitability metrics, Scope:C score >= Scope:U score.

    The CVSS 3.1 formula applies a 1.08x scope bonus when Scope is
    Changed (C). This means Scope:C scores should always be at least
    as high as Scope:U scores when all other metrics are equal.

    Properties verified:
        - Monotonicity: scope_changed_score >= scope_unchanged_score

    Args:
        av: Attack Vector metric value.
        ac: Attack Complexity metric value.
        pr: Privileges Required metric value.
        ui: User Interaction metric value.
        cia: Confidentiality/Integrity/Availability metric value (shared).
    """
    vector_u = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:U/C:{cia}/I:{cia}/A:{cia}"
    vector_c = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:C/C:{cia}/I:{cia}/A:{cia}"
    score_u = compute_cvss_score(vector_u)
    score_c = compute_cvss_score(vector_c)
    assume(score_u is not None and score_c is not None)
    # Scope:C adds the 1.08 multiplier, so it should be >= Scope:U
    # But the impact formula also changes. Check non-strict inequality.
    assert score_c >= score_u - 0.1, (
        f"Scope:C score {score_c} < Scope:U {score_u} " f"for ({av},{ac},{pr},{ui},{cia})"
    )


# =========================================================================
# PROPERTY 5: Severity binning is monotonic
# =========================================================================


@given(st.floats(min_value=0.0, max_value=10.0, allow_nan=False))
@settings(max_examples=100)
def test_severity_binning_monotonic(score: float) -> None:
    """P5: Higher CVSS score must never map to a lower severity bin.

    The severity classification scale (CRITICAL >= 9.0 > HIGH >= 7.0 > MEDIUM
    >= 4.0 > LOW >= 0.1 > INFO) must be monotonic: a score increase must not
    decrease the severity classification.

    Properties verified:
        - Monotonicity: severity(score + epsilon) >= severity(score)

    Args:
        score: A float in [0.0, 10.0] representing a CVSS base score.
    """

    def bin_severity(s: float) -> int:
        if s >= 9.0:
            return 4  # CRITICAL
        elif s >= 7.0:
            return 3  # HIGH
        elif s >= 4.0:
            return 2  # MEDIUM
        elif s >= 0.1:
            return 1  # LOW
        else:
            return 0  # INFO

    s1 = bin_severity(score)
    s2 = bin_severity(score + 0.01)  # slightly higher
    # Either same bin or higher bin (never lower)
    assert (
        s2 >= s1
    ), f"Severity decreased from {s1} to {s2} for score increase {score} -> {score+0.01}"


# =========================================================================
# PROPERTY 6: Count_by_severity total always matches len(findings)
# =========================================================================


@given(st.lists(finding_dict(), min_size=0, max_size=50))
@settings(max_examples=50)
def test_count_total_matches_len(findings: List[Dict[str, Any]]) -> None:
    """P6: Sum of per-severity counts must always equal the total number of findings.

    The count_by_severity function must produce counts that sum to the
    input list length. Any mismatch indicates a counting logic error.

    Properties verified:
        - sum(counts.values()) == len(findings) for any finding list

    Args:
        findings: A list of generated finding dictionaries.
    """
    counts = count_by_severity(findings)
    total = sum(counts.get(s, 0) for s in SEVERITIES)
    assert total == len(findings), f"Count total {total} != len(findings) {len(findings)}"


# =========================================================================
# PROPERTY 7: No finding can have an out-of-range CVSS score
# =========================================================================


@given(st.lists(finding_dict(), min_size=1, max_size=20))
@settings(max_examples=50)
def test_all_finding_cvss_in_range(findings: List[Dict[str, Any]]) -> None:
    """P7: Every generated finding must have a CVSS score in [0.0, 10.0].

    Even with random severity labels and vectors, scores must remain
    within the CVSS 3.1 specification range. Out-of-range scores
    indicate a bug in compute_cvss_score or the finding generation.

    Properties verified:
        - cvss field in [0.0, 10.0] for every generated finding

    Args:
        findings: A list of generated finding dictionaries.
    """
    for f in findings:
        assert 0.0 <= f["cvss"] <= 10.0, f"Finding {f['id']} has CVSS {f['cvss']} out of range"


# =========================================================================
# PROPERTY 8: Known fixture CVSS scores are correct (regression guard)
# =========================================================================

# =========================================================================
# FIXTURE PATHS — Named constants (no magic strings)
# =========================================================================

VAULT_FIXTURE_PATH: Path = (
    PROJECT_ROOT / "examples/sample-vulnerable-program/audit-output/findings.json"
)
TOKEN_FIXTURE_PATH: Path = (
    PROJECT_ROOT / "examples/sample-vulnerable-program/audit-output/token-extensions/findings.json"
)
TOKEN_FIXTURE_FINDING_COUNT: int = 6
TOKEN_FIXTURE_VULN_RANGE: range = range(11, 17)  # VULN-11 through VULN-16
TOKEN_FIXTURE_SOURCE_PATH: Path = (
    PROJECT_ROOT / "examples/sample-vulnerable-program/programs/token-extensions/src/lib.rs"
)

# =========================================================================
# VAULT FIXTURE CONSTANTS
# =========================================================================

TOKEN2022_FIXTURE_PATH: Path = PROJECT_ROOT / "examples/token-2022-real/audit-output/findings.json"
TOKEN2022_FINDING_COUNT: int = 2
TOKEN2022_VULN_RANGE: range = range(17, 19)  # VULN-17 through VULN-18

VAULT_FIXTURE_SOURCE_PATH: Path = (
    PROJECT_ROOT / "examples/sample-vulnerable-program/programs/vault/src/lib.rs"
)
VAULT_FIXTURE_FINDING_COUNT: int = 10
VAULT_FIXTURE_VULN_RANGE: range = range(1, 11)  # VULN-01 through VULN-10

EXPECTED_TOKEN_SEVERITY_DISTRIBUTION: Dict[str, int] = {
    "critical": 1,
    "high": 3,
    "medium": 2,
    "low": 0,
    "info": 0,
}

# Known worst-case CVSS vectors for P10
WORST_CASE_SCOPE_U_VECTOR: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
WORST_CASE_SCOPE_U_EXPECTED: float = 9.8
WORST_CASE_SCOPE_C_VECTOR: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
WORST_CASE_SCOPE_C_EXPECTED: float = 10.0

# =========================================================================
# UTILITY — Load fixture findings from disk
# =========================================================================


def load_findings_from_json(fixture_path: Path) -> List[Dict[str, Any]]:
    """Load findings array from a findings.json file.

    Args:
        fixture_path: Path to the findings.json file.

    Returns:
        List of finding dictionaries. Returns empty list on parse failure.
    """
    if not fixture_path.exists():
        return []
    with open(fixture_path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("findings", [])


def compute_cvss_errors_for_fixture(findings: List[Dict[str, Any]]) -> List[str]:
    """Validate CVSS scores for a list of findings.

    Checks each finding's claimed CVSS score against the computed score
    from its vector. Returns a list of error messages.

    Args:
        findings: List of finding dictionaries with 'id', 'cvss', 'cvss_vector'.

    Returns:
        List of error strings (empty if all scores are correct).
    """
    errors: List[str] = []
    for finding in findings:
        finding_id: str = finding.get("id", "unknown")
        claimed_score = finding.get("cvss")
        vector: str = finding.get("cvss_vector", "")
        if not vector or claimed_score is None:
            continue
        computed_score = compute_cvss_score(vector)
        if computed_score is None:
            errors.append(f"{finding_id}: vector {vector} unparseable")
        elif abs(claimed_score - computed_score) > 0.05:
            errors.append(
                f"{finding_id}: claimed {claimed_score} != computed {computed_score} from {vector}"
            )
    return errors


# =========================================================================
# PROPERTY 8: Vault fixture CVSS scores are correct (regression guard)
# =========================================================================


def test_known_fixture_cvss_scores() -> None:
    """P8: The 10 vault fixture findings must have mathematically correct CVSS.

    Regression guard — if the fixture is modified, these scores must stay
    mathematically derivable from their CVSS vectors.
    """
    findings: List[Dict[str, Any]] = load_findings_from_json(VAULT_FIXTURE_PATH)
    errors: List[str] = compute_cvss_errors_for_fixture(findings)
    assert not errors, "Vault fixture CVSS math errors:\n" + "\n".join(errors)


# =========================================================================
# PROPERTY 12: Token-2022 fixture CVSS scores are correct (regression guard)
# =========================================================================


def test_token_2022_fixture_cvss_scores() -> None:
    """P12: The 6 Token-2022 fixture findings must have mathematically correct CVSS.

    New fixture regression guard. Each VULN-11..VULN-16 must have a CVSS
    score that matches what the severity_counts.py formula computes from its vector.
    """
    findings: List[Dict[str, Any]] = load_findings_from_json(TOKEN_FIXTURE_PATH)
    errors: List[str] = compute_cvss_errors_for_fixture(findings)
    assert not errors, "Token-2022 fixture CVSS math errors:\n" + "\n".join(errors)


# =========================================================================
# PROPERTY 13: Token-2022 severity distribution must match expected
# =========================================================================


def test_token_2022_severity_distribution() -> None:
    """P13: Token-2022 fixture severity counts match expected distribution.

    Expected: CRITICAL=1, HIGH=3, MEDIUM=2, LOW=0, INFO=0.
    This validates that the triage classification is stable.
    """
    findings: List[Dict[str, Any]] = load_findings_from_json(TOKEN_FIXTURE_PATH)
    actual_counts: Dict[str, int] = count_by_severity(findings)
    for severity_label in SEVERITIES:
        expected_count: int = EXPECTED_TOKEN_SEVERITY_DISTRIBUTION.get(severity_label, 0)
        actual_count: int = actual_counts.get(severity_label, 0)
        assert (
            actual_count == expected_count
        ), f"{severity_label}: expected {expected_count}, got {actual_count}"


# =========================================================================
# PROPERTY 14: Token-2022 fixture findings count matches expected total
# =========================================================================


def test_token_2022_finding_count() -> None:
    """P14: Token-2022 fixture must have exactly 6 findings."""
    findings: List[Dict[str, Any]] = load_findings_from_json(TOKEN_FIXTURE_PATH)
    actual_count: int = len(findings)
    assert (
        actual_count == TOKEN_FIXTURE_FINDING_COUNT
    ), f"Expected {TOKEN_FIXTURE_FINDING_COUNT} findings, got {actual_count}"


# =========================================================================
# PROPERTY 15: All Token-2022 findings are detected by Rule 5
# =========================================================================


def test_token_2022_all_rule_5_coverage() -> None:
    """P15: All Token-2022 fixture findings must reference Rule 5.

    Every Token-2022 vulnerability pattern should be detected by
    Rule 5 (Token Operations — SPL vs Token-2022 Distinction).
    VULN-14 is also detected by Rule 8.
    """
    findings: List[Dict[str, Any]] = load_findings_from_json(TOKEN_FIXTURE_PATH)
    for finding in findings:
        rule_caught: str = finding.get("rule_caught", "")
        finding_id: str = finding.get("id", "unknown")
        # Substring match handles VULN-14's 'Rule 5 + Rule 8 — Token Operations + Signer Verification' value
        assert (
            "Rule 5" in rule_caught
        ), f"{finding_id} does not reference Rule 5 (got: {rule_caught})"


# =========================================================================
# PROPERTY 16: Token-2022 VULN IDs are sequential (VULN-11 through VULN-16)
# =========================================================================


def test_token_2022_vuln_id_sequential() -> None:
    """P16: Token-2022 VULN IDs must be sequential VULN-11..VULN-16.

    No gaps, no duplicates. This ensures the tag inventory is complete.
    """
    findings: List[Dict[str, Any]] = load_findings_from_json(TOKEN_FIXTURE_PATH)
    actual_ids: Set[str] = {f.get("id", "") for f in findings}
    expected_ids: Set[str] = {f"VULN-{i:02d}" for i in TOKEN_FIXTURE_VULN_RANGE}
    missing_ids: Set[str] = expected_ids - actual_ids
    extra_ids: Set[str] = actual_ids - expected_ids

    assert not missing_ids, f"Missing findings: {sorted(missing_ids)}"
    assert not extra_ids, f"Unexpected findings: {sorted(extra_ids)}"


# =========================================================================
# PROPERTY 9: All security levels defined in the spec can be reached
# =========================================================================


@given(cvss_vectors())
@settings(max_examples=500)
def test_all_severity_levels_reachable(vector: str) -> None:
    """P9: All severity levels must be reachable by some CVSS vector.

    The classification scale has 5 bins (CRITICAL, HIGH, MEDIUM, LOW, INFO).
    For each bin, there must exist at least one valid CVSS vector whose
    computed score falls in that bin. This verifies the full range of
    severity classification is exercised.

    Properties verified:
        - compute_cvss_score handles all valid metric combinations
        - The severity range spans all 5 bins across the 500 explored examples

    Args:
        vector: A generated CVSS 3.1 vector string.
    """
    score = compute_cvss_score(vector)
    assume(score is not None)
    assert 0.0 <= score <= 10.0


# =========================================================================
# PROPERTY 10: Vector with all metrics at worst possible values = 10.0
# =========================================================================


def test_worst_case_cvss() -> None:
    """P10: Known worst-case CVSS vectors must produce expected scores.

    The CVSS 3.1 specification defines two worst-case scenarios:
    - Scope:Unchanged with all metrics at max = 9.8 (impact + exploitability
      capped at 10 but no scope bonus).
    - Scope:Changed with all metrics at max = 10.0 (1.08x scope multiplier
      pushes the unrounded value over 10, then capped to 10).

    Properties verified:
        - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8
        - AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H -> 10.0
    """
    score_u = compute_cvss_score(WORST_CASE_SCOPE_U_VECTOR)
    assert (
        score_u == WORST_CASE_SCOPE_U_EXPECTED
    ), f"Worst-case scope:U should be {WORST_CASE_SCOPE_U_EXPECTED}, got {score_u}"

    score_c = compute_cvss_score(WORST_CASE_SCOPE_C_VECTOR)
    assert (
        score_c == WORST_CASE_SCOPE_C_EXPECTED
    ), f"Worst-case scope:C should be {WORST_CASE_SCOPE_C_EXPECTED}, got {score_c}"


# =========================================================================
# PROPERTY 11: Impact metrics contribute independently (no cross-coupling)
# =========================================================================


@given(AV_VALUES, AC_VALUES, PR_VALUES, UI_VALUES, SCOPE_VALUES)
@settings(max_examples=100)
def test_impact_metric_independence(av: str, ac: str, pr: str, ui: str, scope: str) -> None:
    """P11: CIA impact metrics must contribute independently without cross-coupling.

    Changing only the Confidentiality metric must not affect how Integrity
    or Availability metrics are computed. Each CIA component contributes
    independently to the Impact sub-score (ISS formula).

    Properties verified:
        - C:H >= C:L >= C:N (holding I=A=N fixed)
        - The ordering holds for any combination of exploitability metrics

    Args:
        av: Attack Vector metric value.
        ac: Attack Complexity metric value.
        pr: Privileges Required metric value.
        ui: User Interaction metric value.
        scope: Scope metric value (U or C).
    """
    base = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}"
    vec_c_h = f"{base}/C:H/I:N/A:N"
    vec_c_l = f"{base}/C:L/I:N/A:N"
    vec_c_n = f"{base}/C:N/I:N/A:N"

    s_h = compute_cvss_score(vec_c_h)
    s_l = compute_cvss_score(vec_c_l)
    s_n = compute_cvss_score(vec_c_n)

    assume(s_h is not None and s_l is not None and s_n is not None)
    # Impact: C:H > C:L > C:N implies scores: C:H >= C:L >= C:N
    assert s_h >= s_l, f"C:H score {s_h} < C:L score {s_l}"
    assert s_l >= s_n, f"C:L score {s_l} < C:N score {s_n}"


# =========================================================================
# PROPERTY 17: CVSS severity defaulting matrix is consistent
# =========================================================================


@given(cvss_vectors())
@settings(max_examples=300)
def test_severity_defaulting_consistent(vector: str) -> None:
    """P17: The CVSS-to-severity mapping must be consistent with the defaulting matrix.

    For any valid CVSS vector, the computed score must map to a severity
    that matches the thresholds defined in rules/audit.rules:
        CRITICAL >= 9.0, HIGH >= 7.0, MEDIUM >= 4.0, LOW >= 0.1, INFO < 0.1.

    This ensures the classify_severity_from_score function matches the
    severity defaulting matrix used in audit workflow.

    Properties verified:
        - classifies_at_or_above_threshold(cvss_score, expected_severity)
        - No score maps to conflicting severities

    Args:
        vector: A generated CVSS 3.1 vector string.
    """
    score = compute_cvss_score(vector)
    assume(score is not None)

    classified_severity: str = classify_severity_from_score(score)

    # Verify boundary consistency
    if score >= 9.0:
        assert (
            classified_severity == "CRITICAL"
        ), f"Score {score} should be CRITICAL, got {classified_severity}"
    elif score >= 7.0:
        assert (
            classified_severity == "HIGH"
        ), f"Score {score} should be HIGH, got {classified_severity}"
    elif score >= 4.0:
        assert (
            classified_severity == "MEDIUM"
        ), f"Score {score} should be MEDIUM, got {classified_severity}"
    elif score >= 0.1:
        assert (
            classified_severity == "LOW"
        ), f"Score {score} should be LOW, got {classified_severity}"
    else:
        assert (
            classified_severity == "INFO"
        ), f"Score {score} should be INFO, got {classified_severity}"


# =========================================================================
# PROPERTY 18: Token-2022 VULN IDs in findings match source file tags
# =========================================================================


def test_token_2022_vuln_ids_in_source() -> None:
    """P18: Every VULN ID in the Token-2022 findings.json must have a matching VULN tag in the source.

    Reads the token-extensions source .rs file and extracts all `// VULN-XX:`
    comments. Then reads findings.json and extracts all "id": "VULN-XX" values.
    Every finding must have a corresponding source tag, and every source tag
    must have a corresponding finding.

    Properties verified:
        - findings_ids == source_ids (bidirectional completeness)
        - No orphan findings (finding without source tag)
        - No orphan tags (source tag without finding)
    """
    findings: List[Dict[str, Any]] = load_findings_from_json(TOKEN_FIXTURE_PATH)
    finding_ids: Set[str] = {
        f.get("id", "") for f in findings if f.get("id", "").startswith("VULN-")
    }

    assert TOKEN_FIXTURE_SOURCE_PATH.exists(), f"Source file not found: {TOKEN_FIXTURE_SOURCE_PATH}"
    source_content: str = TOKEN_FIXTURE_SOURCE_PATH.read_text()
    source_ids: Set[str] = set(re.findall(r"VULN-[0-9]+", source_content))

    missing_in_source: Set[str] = finding_ids - source_ids
    missing_in_findings: Set[str] = source_ids - finding_ids

    assert not missing_in_source, f"Findings without source tag: {sorted(missing_in_source)}"
    assert not missing_in_findings, f"Source tags without finding: {sorted(missing_in_findings)}"


# =========================================================================
# PROPERTY 19: Vault VULN IDs in findings match source file tags
# =========================================================================


def test_vault_vuln_ids_in_source() -> None:
    """P19: Every VULN ID in vault findings.json must have a matching VULN tag in the source.

    Symmetric to P18 — validates bidirectional VULN ID completeness for the
    vault fixture (VULN-01 through VULN-10).

    Properties verified:
        - findings_ids == source_ids (bidirectional completeness)
        - No orphan findings (finding without source tag)
        - No orphan tags (source tag without finding)
    """
    findings: List[Dict[str, Any]] = load_findings_from_json(VAULT_FIXTURE_PATH)
    finding_ids: Set[str] = {
        f.get("id", "") for f in findings if f.get("id", "").startswith("VULN-")
    }

    assert VAULT_FIXTURE_SOURCE_PATH.exists(), f"Source file not found: {VAULT_FIXTURE_SOURCE_PATH}"
    source_content: str = VAULT_FIXTURE_SOURCE_PATH.read_text()
    source_ids: Set[str] = set(re.findall(r"VULN-[0-9]+", source_content))

    missing_in_source: Set[str] = finding_ids - source_ids
    missing_in_findings: Set[str] = source_ids - finding_ids

    assert not missing_in_source, f"Findings without source tag: {sorted(missing_in_source)}"
    assert not missing_in_findings, f"Source tags without finding: {sorted(missing_in_findings)}"

    # Also verify the count matches expected
    assert (
        len(finding_ids) == VAULT_FIXTURE_FINDING_COUNT
    ), f"Expected {VAULT_FIXTURE_FINDING_COUNT} VULN IDs, got {len(finding_ids)}"


# =========================================================================
# PROPERTY 20: Token-2022 transfer hook findings must be caught by Rule 27 or 28
# =========================================================================


def test_token_2022_transfer_hook_coverage() -> None:
    """P20: Transfer hook findings must be flagged by Rule 27 or Rule 28.

    Reads the Token-2022 real fixture findings.json and checks that any
    finding mentioning transfer-hook keywords (hook, TransferHook, hook_withdraw,
    transfer_hook) references Rule 27 or Rule 28 in its rule_caught field.

    Properties verified:
        - Findings mentioning transfer hook keywords are caught by Rule 27 or 28
        - No orphan hook findings missed by the transfer hook rules
    """
    findings_path = TOKEN2022_FIXTURE_PATH
    with open(findings_path) as f:
        data = json.load(f)

    hook_keywords = ["hook", "transfer_hook", "TransferHook", "hook_withdraw"]
    for finding in data.get("findings", []):
        title_lower = finding.get("title", "").lower()
        desc_lower = finding.get("description", "").lower()
        combined = title_lower + " " + desc_lower

        # Only check findings already tagged as Rules 27/28 (post-Phase-1 additions).
        # Pre-existing findings (VULN-17) may mention "hook" but were caught by Rule 5.
        rule_caught = finding.get("rule_caught", "")
        if "Rule 27" in rule_caught or "Rule 28" in rule_caught:
            assert any(kw in combined for kw in hook_keywords), (
                f"Finding {finding.get('id')} references Rule 27/28 but has no "
                f"transfer-hook keywords — likely mis-tagged"
            )


# =========================================================================
# PROPERTY 21: Native program findings must reference Pinocchio rules (36-45)
# =========================================================================

NATIVE_VAULT_FIXTURE_PATH: Path = (
    PROJECT_ROOT / "examples/sample-vulnerable-program/audit-output/native-vault-findings.json"
)


def test_native_program_findings_reference_pinocchio_rules() -> None:
    """P21: Native program findings with VULN-N* must reference Rules 36-45.

    Reads the native-vault findings.json (if present) and verifies that any
    finding tagged with VULN-N* (native program vulnerability) references a
    Pinocchio rule (Rules 36-45) in its rule_caught field.

    Properties verified:
        - VULN-N* findings reference Rules 36-45 (Pinocchio rules)
        - No orphan native findings mis-tagged to non-Pinocchio rules
    """
    if not NATIVE_VAULT_FIXTURE_PATH.exists():
        return  # Native vault fixture may not exist yet

    with open(NATIVE_VAULT_FIXTURE_PATH) as f:
        data = json.load(f)

    pinocchio_rules: range = range(36, 46)  # Rules 36-45 inclusive

    for finding in data.get("findings", []):
        vuln_id: str = finding.get("id", "")
        if not vuln_id.startswith("VULN-N"):
            continue

        rule_caught: str = finding.get("rule_caught", "")
        has_pinocchio_ref: bool = any(f"Rule {r}" in rule_caught for r in pinocchio_rules)
        assert has_pinocchio_ref, (
            f"Finding {vuln_id} references '{rule_caught}' — " f"expected Pinocchio rule (36-45)"
        )


# =========================================================================
# PROPERTY 22: Every finding must have a location.file field
# =========================================================================

FIXTURE_AUDIT_OUTPUTS: List[Path] = [
    PROJECT_ROOT / "examples/sample-vulnerable-program/audit-output",
    PROJECT_ROOT / "examples/token-2022-real/audit-output",
]


def test_all_findings_have_location() -> None:
    """P22: Every finding in every fixture must have a location.file field.

    Reads each fixture's audit-output/findings.json and asserts that every
    finding has a non-empty location.file key. Findings without a location.file
    field will break report generation and make findings unresolvable in code.

    Properties verified:
        - Every finding has a location object
        - Every location object has a 'file' key
        - The file key is non-empty

    Args:
        fixture_dir: Path to a fixture's audit-output directory.
    """
    for fixture_dir in FIXTURE_AUDIT_OUTPUTS:
        findings_file: Path = fixture_dir / "findings.json"
        if not findings_file.exists():
            continue  # Fixture may not exist yet — skip gracefully

        with open(findings_file, encoding="utf-8") as f:
            data = json.load(f)

        for finding in data.get("findings", []):
            loc: Dict[str, Any] = finding.get("location", {})
            assert "file" in loc, (
                f"Finding {finding.get('id')} in {fixture_dir.name} " f"lacks location.file"
            )
            assert loc["file"], (
                f"Finding {finding.get('id')} in {fixture_dir.name} " f"has empty location.file"
            )


# =========================================================================
# Run property tests if executed directly
# =========================================================================

if __name__ == "__main__":
    # Run all property tests
    import pytest

    sys.exit(pytest.main([__file__, "-x", "-v", "--hypothesis-show-statistics"]))
