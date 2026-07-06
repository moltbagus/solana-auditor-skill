#!/usr/bin/env python3
"""
triage-findings.py — Phase 4: Findings triage & CVSS scoring.

Reads an audit-output findings JSON, applies CVSS triage logic, and writes a
prioritized, severity-ordered list of findings. Supports an optional inline
recompute of the CVSS score from `cvss_vector` using tests/severity_counts.py
when available; falls back to the stored `cvss` field otherwise.

Used by `.github/workflows/audit-scheduled.yml` Phase 4 step.

Usage:
    python scripts/triage-findings.py
    python scripts/triage-findings.py --input findings.json --output prioritized.json
    python scripts/triage-findings.py --recompute-cvss
    python scripts/triage-findings.py --min-severity HIGH          # CRITICAL + HIGH only
    python scripts/triage-findings.py --status Open
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

SCRIPT_VERSION = "1.0.0"
DEFAULT_INPUT = "findings.json"
DEFAULT_OUTPUT = "prioritized_findings.json"

SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Statuses considered actionable (not yet resolved)
OPEN_STATUSES = {"Open", "PENDING", "POC-PENDING"}
# Default scoring constants (used when cvss value is missing/invalid)
DEFAULT_CVSS = 5.0
CVSS_RECOMPUTE_TOLERANCE = 0.1

EXIT_SUCCESS = 0
EXIT_BAD_INPUT = 1


@dataclass
class TriageEntry:
    """Single finding row in the prioritized list."""

    id: str
    severity: str
    cvss: float
    cvss_vector: str
    rule: Optional[int]
    rule_caught: str
    cwe: str
    file: str
    line: Optional[int]
    status: str
    priority_score: float
    title: str
    location_function: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TriageReport:
    """Top-level triage output document."""

    generated_at: str
    input_file: str
    total_findings: int
    by_severity: dict[str, int] = field(default_factory=dict)
    mean_cvss: float = 0.0
    max_cvss: float = 0.0
    open_count: int = 0
    cvss_recomputed: int = 0
    cvss_mismatches: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# CVSS recompute (best-effort: prefers tests/severity_counts.py)
# ---------------------------------------------------------------------------


def _import_severity_counts() -> Optional[Any]:
    """Best-effort import of the test helper. Returns None if unavailable."""
    here = Path(__file__).resolve().parent.parent
    candidate = here / "tests" / "severity_counts.py"
    if not candidate.exists():
        return None
    import importlib.util

    try:
        spec = importlib.util.spec_from_file_location(
            "severity_counts", str(candidate)
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:  # pragma: no cover — defensive
        return None


@dataclass
class CvssMetric:
    """Subset of CVSS 3.1 base metrics used for score lookup."""

    AV: str = "N"
    AC: str = "L"
    UI: str = "N"
    S: str = "U"
    C: str = "N"
    I: str = "N"
    A: str = "N"
    PR: str = "N"


_CVSS_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "PR": {
        "N": 0.85,
        "L": 0.62,
        "H": 0.27,
    },
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def parse_cvss_vector(vector: str) -> Optional[CvssMetric]:
    """Parse a CVSS 3.1 base vector into metric values, or None on failure."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:3.1/"):
        return None
    metrics = CvssMetric()
    for part in vector[len("CVSS:3.1/") :].split("/"):
        if not part:
            continue
        if part.startswith("S:"):
            metrics.S = part[2:]
            continue
        if part.startswith("PR:"):
            metrics.PR = part[3:]
            continue
        if len(part) >= 3 and part[2] in ("N", "L", "H", "A", "R", "P", "C"):
            key = part[:2]
            val = part[2]
            if key in _CVSS_VALUES and val in _CVSS_VALUES[key]:
                setattr(metrics, key, val)
    return metrics


def compute_cvss_score(metrics: CvssMetric) -> Optional[float]:
    """Compute CVSS 3.1 base score from parsed metrics. Returns None on bad input."""
    try:
        av = _CVSS_VALUES["AV"][metrics.AV]
        ac = _CVSS_VALUES["AC"][metrics.AC]
        ui = _CVSS_VALUES["UI"][metrics.UI]
        pr = _CVSS_VALUES["PR"][metrics.PR]
        c = _CVSS_VALUES["C"][metrics.C]
        i_val = _CVSS_VALUES["I"][metrics.I]
        a = _CVSS_VALUES["A"][metrics.A]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i_val) * (1 - a)
    if iss <= 0:
        base = 0.0
    else:
        if metrics.S == "U":
            impact = 6.42 * iss
            scope_text = "U"
        else:  # "C"
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
            scope_text = "C"
        exploit = 8.22 * av * ac * pr * ui
        if scope_text == "U":
            base = min(impact + exploit, 10.0)
            if impact + exploit <= 0:
                base = 0.0
        else:
            base = min(1.08 * (impact + exploit), 10.0)
            if impact + exploit <= 0:
                base = 0.0

    return round(base, 1)


def _recompute_one(vector: str, helper: Optional[Any]) -> Optional[float]:
    """Recompute a CVSS score from `vector`. Uses helper if signatures match.

    helper.compute_cvss_score takes a vector string in tests/severity_counts.py.
    Falling back to local parser/computer when helper is absent or mismatched.
    """
    if helper is not None and hasattr(helper, "compute_cvss_score"):
        try:
            score = helper.compute_cvss_score(vector)
            if isinstance(score, (int, float)):
                return float(score)
        except Exception:
            pass
    metrics = parse_cvss_vector(vector)
    if metrics is None:
        return None
    return compute_cvss_score(metrics)


def recompute_cvss(findings: list[dict[str, Any]]) -> tuple[int, int]:
    """For each finding with cvss_vector, recompute and apply (best-effort).

    Returns (mismatch_count, recomputed_count). Helper module used if available.
    """
    helper = _import_severity_counts()
    mismatches = 0
    recomputed = 0
    for finding in findings:
        vector = finding.get("cvss_vector")
        if not isinstance(vector, str):
            continue
        score = _recompute_one(vector, helper)
        if score is None:
            continue
        stored = finding.get("cvss")
        if not isinstance(stored, (int, float)):
            finding["cvss"] = score
            recomputed += 1
            continue
        if abs(float(stored) - score) > CVSS_RECOMPUTE_TOLERANCE:
            finding["cvss"] = score
            mismatches += 1
        recomputed += 1
    return mismatches, recomputed


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------


def _read_findings(path: Path) -> list[dict[str, Any]]:
    """Load findings from a JSON file. Accepts `{findings:[]}` or raw list."""
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "findings" in data:
        items = data["findings"]
    elif isinstance(data, list):
        items = data
    else:
        raise ValueError(
            "Invalid findings schema: expected list or object with 'findings' key"
        )
    if not isinstance(items, list):
        raise ValueError("Invalid findings schema: 'findings' must be a list")
    return items


def _findings_to_input_list(data: Any) -> list[dict[str, Any]]:
    """Normalize JSON to a list of finding dicts (same as _read_findings)."""
    if isinstance(data, dict) and "findings" in data and isinstance(
        data["findings"], list
    ):
        return data["findings"]
    if isinstance(data, list):
        return data
    return []


def severity_rank(value: str) -> int:
    """Map a severity string to its rank (CRITICAL=4 ... INFO=0)."""
    return SEVERITY_RANK.get(value.upper(), -1)


def priority_score(finding: dict[str, Any]) -> float:
    """Compute a simple priority score (higher = handle first).

    Score = cvss * 10 + severity_weight + open_bonus.
    Open findings get +5; resolved findings get +0.
    """
    cvss = float(finding.get("cvss") or DEFAULT_CVSS)
    sev_bonus = severity_rank(str(finding.get("severity", "MEDIUM"))) * 2
    status = str(finding.get("status", "Open")).upper()
    open_bonus = 5.0 if status in OPEN_STATUSES else 0.0
    return round(cvss * 10 + sev_bonus + open_bonus, 2)


def enrich_finding(finding: dict[str, Any]) -> TriageEntry:
    """Convert a raw finding dict into a triage row."""
    location = finding.get("location") or {}
    return TriageEntry(
        id=str(finding.get("id", "")),
        severity=str(finding.get("severity", "MEDIUM")).upper(),
        cvss=float(finding.get("cvss") or DEFAULT_CVSS),
        cvss_vector=str(finding.get("cvss_vector") or ""),
        rule=finding.get("rule") if isinstance(finding.get("rule"), int) else None,
        rule_caught=str(finding.get("rule_caught") or ""),
        cwe=str(finding.get("cwe") or ""),
        file=str(location.get("file") or ""),
        line=location.get("line") if isinstance(location.get("line"), int) else None,
        status=str(finding.get("status", "Open")),
        priority_score=priority_score(finding),
        title=str(finding.get("title") or ""),
        location_function=str(location.get("function") or ""),
    )


def triage(
    findings: list[dict[str, Any]],
    min_severity: Optional[str],
    status_filter: Optional[str],
    recompute: bool,
) -> tuple[TriageReport, int, int]:
    """Triage findings into a sorted report.

    Returns (report, total_input, total_filtered).
    """
    cvss_mismatches = 0
    cvss_recomputed = 0
    if recompute:
        cvss_mismatches, cvss_recomputed = recompute_cvss(findings)

    filtered = list(findings)
    if min_severity and severity_rank(min_severity) >= 0:
        min_rank = severity_rank(min_severity)
        filtered = [f for f in filtered if severity_rank(str(f.get("severity", ""))) >= min_rank]
    if status_filter:
        sf = status_filter.upper()
        filtered = [f for f in filtered if str(f.get("status", "")).upper() == sf]

    rows = [enrich_finding(f) for f in filtered]
    rows.sort(
        key=lambda r: (
            -severity_rank(r.severity),
            -r.priority_score,
            -r.cvss,
            r.id,
        )
    )

    report = TriageReport(
        generated_at=_now_iso(),
        input_file="",
        total_findings=len(rows),
        mean_cvss=_mean_cvss(rows),
        max_cvss=_max_cvss(rows),
        open_count=sum(1 for r in rows if r.status.upper() in OPEN_STATUSES),
        cvss_recomputed=cvss_recomputed,
        cvss_mismatches=cvss_mismatches,
        findings=[r.to_dict() for r in rows],
    )
    for r in rows:
        report.by_severity[r.severity] = report.by_severity.get(r.severity, 0) + 1

    return report, len(findings), len(filtered)


def _mean_cvss(rows: list[TriageEntry]) -> float:
    if not rows:
        return 0.0
    return round(sum(r.cvss for r in rows) / len(rows), 2)


def _max_cvss(rows: list[TriageEntry]) -> float:
    if not rows:
        return 0.0
    return round(max(r.cvss for r in rows), 1)


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def render_text(report: TriageReport, total_input: int) -> str:
    """Render a human-readable triage report."""
    lines = [
        "=== Phase 4: Findings Triage ===",
        f"Generated:        {report.generated_at}",
        f"Total findings:   {report.total_findings} (of {total_input} input)",
        f"Mean CVSS:        {report.mean_cvss}",
        f"Max CVSS:         {report.max_cvss}",
        f"Open:             {report.open_count}",
        f"CVSS recomputed:  {report.cvss_recomputed}",
        f"CVSS mismatches:  {report.cvss_mismatches}",
        "",
        "By severity:",
    ]
    for sev in SEVERITY_ORDER:
        if sev in report.by_severity:
            lines.append(f"  {sev:<10} {report.by_severity[sev]}")
    lines.append("")
    lines.append("Top prioritized findings:")
    if not report.findings:
        lines.append("  (none)")
        return "\n".join(lines) + "\n"
    for idx, finding in enumerate(report.findings[:20], start=1):
        lines.append(
            f"  {idx:>2}. [{finding['severity']:<8}] "
            f"CVSS={finding['cvss']:<4} "
            f"score={finding['priority_score']:<5} "
            f"{finding['id']:<12} {finding['title']}"
        )
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input",
        "-i",
        default=DEFAULT_INPUT,
        help=f"Path to findings JSON (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=DEFAULT_OUTPUT,
        help=f"Prioritized output JSON (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=("json", "text"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--recompute-cvss",
        action="store_true",
        help="Recompute CVSS scores from cvss_vector and apply fixes",
    )
    parser.add_argument(
        "--min-severity",
        choices=SEVERITY_ORDER,
        help="Keep findings at or above this severity (e.g., HIGH = CRITICAL+HIGH)",
    )
    parser.add_argument(
        "--status",
        help="Filter to findings with this status (e.g., Open, Fixed, Pending)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite output file even if it exists",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"%(prog)s {SCRIPT_VERSION}",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    args = parse_args(argv)
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        return EXIT_BAD_INPUT

    if output_path.exists() and not args.force:
        print(
            f"Error: output already exists: {output_path} (use --force to overwrite)",
            file=sys.stderr,
        )
        return EXIT_BAD_INPUT

    try:
        raw = _read_findings(input_path)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT

    findings = [f for f in raw if isinstance(f, dict)]
    report, total_input, _ = triage(
        findings,
        min_severity=args.min_severity,
        status_filter=args.status,
        recompute=args.recompute_cvss,
    )
    report.input_file = str(input_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    if args.format == "json":
        sys.stdout.write(json.dumps(report.to_dict(), indent=2) + "\n")
    else:
        sys.stdout.write(render_text(report, total_input))

    print(
        f"Wrote {report.total_findings} prioritized findings to {output_path}",
        file=sys.stderr,
    )
    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
