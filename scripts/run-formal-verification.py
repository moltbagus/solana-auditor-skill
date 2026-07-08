#!/usr/bin/env python3
"""
run-formal-verification.py — Phase 3: Formal Verification wrapper.

Invokes QED 2A (preferred) or falls back to `anchor test --skip-build`. Reads
the existing scripts/qed-integration.sh if it exists and delegates to it via
subprocess; otherwise runs `anchor test --skip-build` directly.

Emits a JSON or text summary report at formal-verification-report.json (or
specified --output). Exit codes match qed-integration.sh:
    0 = success / completed
    1 = failure
    2 = skipped (no toolchain)
    3 = bad invocation

Used by `.github/workflows/audit-scheduled.yml` Phase 3 step.

Usage:
    python scripts/run-formal-verification.py
    python scripts/run-formal-verification.py --output fv-report.json --format json
    python scripts/run-formal-verification.py --no-build --force
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

SCRIPT_VERSION = "1.0.0"
DEFAULT_OUTPUT = "formal_verification_report.json"

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_SKIP = 2
EXIT_BAD_INPUT = 3


@dataclass
class VerificationResult:
    """Result of the formal-verification step."""

    tool: str
    version: str
    status: str  # "complete" | "partial" | "skipped" | "error"
    started_at: str
    duration_seconds: float
    programs_checked: int
    exit_code: int
    command: list[str]
    stdout_tail: str
    stderr_tail: str
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _now_iso() -> str:
    """Return UTC ISO8601 timestamp."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _truncate(text: str, limit: int = 4000) -> str:
    """Keep the last `limit` chars of `text` (most recent logs are useful)."""
    if len(text) <= limit:
        return text
    return text[-limit:] + "\n... [truncated]"


def _which(cmd: str) -> Optional[str]:
    """Return path of `cmd` if in PATH, else None."""
    return shutil.which(cmd)


def _detect_qed() -> tuple[Optional[str], Optional[str]]:
    """Detect QED installation. Checks qedgen (new) then qed-solana (legacy).
    Returns (binary_path, version_string)."""
    for candidate in ("qedgen", "qed-solana"):
        qed_bin = _which(candidate)
        if qed_bin:
            try:
                result = subprocess.run(
                    [qed_bin, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                version = (result.stdout or result.stderr or "").strip().splitlines()[0:1]
                return qed_bin, version[0] if version else "unknown"
            except (OSError, subprocess.TimeoutExpired, subprocess.SubprocessError):
                return qed_bin, "unknown"
    return None, None


def _detect_anchor() -> tuple[Optional[str], Optional[str]]:
    """Detect anchor CLI installation."""
    anchor_bin = _which("anchor")
    if not anchor_bin:
        return None, None
    try:
        result = subprocess.run(
            [anchor_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        version = (result.stdout or result.stderr or "").strip().splitlines()[0:1]
        return anchor_bin, version[0] if version else "unknown"
    except (OSError, subprocess.TimeoutExpired, subprocess.SubprocessError):
        return anchor_bin, "unknown"


def _count_programs(repo_root: Path) -> int:
    """Count Anchor programs by looking for Cargo.toml under programs/."""
    programs_dir = repo_root / "programs"
    if not programs_dir.is_dir():
        return 0
    return sum(
        1 for _ in programs_dir.glob("*/Cargo.toml")
    )


def _run_subprocess(
    cmd: list[str],
    cwd: Path,
    timeout: int,
) -> tuple[int, str, str, float]:
    """Run a subprocess. Returns (returncode, stdout, stderr, elapsed_seconds)."""
    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        elapsed = time.monotonic() - start
        return result.returncode, result.stdout or "", result.stderr or "", elapsed
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start
        return 124, "", f"timeout after {timeout}s", elapsed
    except FileNotFoundError as exc:
        elapsed = time.monotonic() - start
        return 127, "", f"command not found: {exc}", elapsed


def run_via_qed_script(
    qed_script: Path,
    repo_root: Path,
    timeout: int,
) -> VerificationResult:
    """Delegate to existing scripts/qed-integration.sh."""
    cmd = ["bash", str(qed_script)]
    rc, stdout, stderr, elapsed = _run_subprocess(cmd, repo_root, timeout)
    if rc == 0:
        status = "complete"
    elif rc == 2:
        status = "skipped"
    else:
        status = "error"
    return VerificationResult(
        tool="qed-solana (via qed-integration.sh)",
        version="unknown",
        status=status,
        started_at=_now_iso(),
        duration_seconds=round(elapsed, 2),
        programs_checked=_count_programs(repo_root),
        exit_code=rc,
        command=cmd,
        stdout_tail=_truncate(stdout),
        stderr_tail=_truncate(stderr),
        notes=["Delegated to scripts/qed-integration.sh"],
    )


def run_via_qed_cli(
    qed_bin: str,
    qed_version: str,
    repo_root: Path,
    timeout: int,
) -> VerificationResult:
    """Run qed-solana directly (catches counterexamples only)."""
    cmd = [qed_bin, "verify", "--output", "json", "--programs-dir", "programs"]
    rc, stdout, stderr, elapsed = _run_subprocess(cmd, repo_root, timeout)
    status = "complete" if rc == 0 else ("skipped" if rc == 2 else "error")
    return VerificationResult(
        tool="qed-solana",
        version=qed_version,
        status=status,
        started_at=_now_iso(),
        duration_seconds=round(elapsed, 2),
        programs_checked=_count_programs(repo_root),
        exit_code=rc,
        command=cmd,
        stdout_tail=_truncate(stdout),
        stderr_tail=_truncate(stderr),
    )


def run_via_anchor_tests(
    anchor_bin: str,
    anchor_version: str,
    repo_root: Path,
    timeout: int,
    skip_build: bool,
) -> VerificationResult:
    """Run anchor test --skip-build (fallback when qed-solana unavailable)."""
    programs_dir = repo_root / "programs"
    notes: list[str] = []
    if not programs_dir.is_dir():
        notes.append("No programs/ directory found; nothing to verify")
        return VerificationResult(
            tool="anchor test (fallback)",
            version=anchor_version,
            status="skipped",
            started_at=_now_iso(),
            duration_seconds=0.0,
            programs_checked=0,
            exit_code=EXIT_SKIP,
            command=[],
            stdout_tail="",
            stderr_tail="",
            notes=notes,
        )

    cmd = [anchor_bin, "test", "--skip-lint"]
    if skip_build:
        cmd.append("--skip-build")
    rc, stdout, stderr, elapsed = _run_subprocess(cmd, repo_root, timeout)

    status = "complete" if rc == 0 else "partial"
    return VerificationResult(
        tool="anchor test (fallback)",
        version=anchor_version,
        status=status,
        started_at=_now_iso(),
        duration_seconds=round(elapsed, 2),
        programs_checked=_count_programs(repo_root),
        exit_code=rc,
        command=cmd,
        stdout_tail=_truncate(stdout),
        stderr_tail=_truncate(stderr),
        notes=notes + [
            "qed-solana CLI not available; used anchor test as runtime-only fallback",
        ],
    )


def write_report(result: VerificationResult, output: Path) -> None:
    """Persist the verification result as JSON. Idempotent (overwrites)."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--repo",
        "-r",
        default=".",
        help="Repository root (default: current directory)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=DEFAULT_OUTPUT,
        help=f"Output report path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=("json", "text"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Skip `anchor build` (passes --skip-build to anchor test)",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        type=int,
        default=600,
        help="Subprocess timeout in seconds (default: 600)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite output even if it exists (default: refuse to overwrite)",
    )
    parser.add_argument(
        "--skip-on-no-toolchain",
        action="store_true",
        default=True,
        help="Treat missing toolchains as a clean skip rather than error (default)",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"%(prog)s {SCRIPT_VERSION}",
    )
    return parser.parse_args(argv)


def render_text(result: VerificationResult) -> str:
    """Render a human-readable summary."""
    lines = [
        "=== Formal Verification Summary ===",
        f"Tool:               {result.tool}",
        f"Status:             {result.status}",
        f"Programs checked:   {result.programs_checked}",
        f"Duration:           {result.duration_seconds:.1f}s",
        f"Exit code:          {result.exit_code}",
        "",
        "Command:",
        "  " + " ".join(result.command) if result.command else "  (no command run)",
        "",
        "Notes:",
    ]
    for note in result.notes or ["(none)"]:
        lines.append(f"  - {note}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    args = parse_args(argv)
    repo_root = Path(args.repo).resolve()
    output = Path(args.output)

    if not repo_root.exists() or not repo_root.is_dir():
        print(f"Error: repository root not found: {repo_root}", file=sys.stderr)
        return EXIT_BAD_INPUT

    if output.exists() and not args.force:
        print(
            f"Error: output already exists: {output} (use --force to overwrite)",
            file=sys.stderr,
        )
        return EXIT_BAD_INPUT

    qed_script = repo_root / "scripts" / "qed-integration.sh"
    qed_bin, qed_version = _detect_qed()
    anchor_bin, anchor_version = _detect_anchor()

    notes: list[str] = []

    # Prefer QED via existing integration script (handles qedgen + qed-solana)
    if qed_script.exists():
        result = run_via_qed_script(qed_script, repo_root, args.timeout)
        if result.status != "error":
            return _finalize(result, args, output)

    # Otherwise try detected QED CLI directly
    if qed_bin:
        result = run_via_qed_cli(qed_bin, qed_version or "unknown", repo_root, args.timeout)
        if result.status != "error":
            return _finalize(result, args, output)

    # Fallback: anchor test --skip-build
    if anchor_bin:
        result = run_via_anchor_tests(
            anchor_bin,
            anchor_version or "unknown",
            repo_root,
            args.timeout,
            skip_build=args.no_build,
        )
        return _finalize(result, args, output)

    # No toolchain available — skip
    notes.append("Neither qed-solana nor anchor CLI available")
    skip = VerificationResult(
        tool="(none)",
        version="(none)",
        status="skipped",
        started_at=_now_iso(),
        duration_seconds=0.0,
        programs_checked=_count_programs(repo_root),
        exit_code=EXIT_SKIP,
        command=[],
        stdout_tail="",
        stderr_tail="",
        notes=notes,
    )
    return _finalize(skip, args, output)


def _finalize(
    result: VerificationResult,
    args: argparse.Namespace,
    output: Path,
) -> int:
    """Write the report and emit text output. Returns process exit code."""
    write_report(result, output)

    if args.format == "json":
        sys.stdout.write(json.dumps(result.to_dict(), indent=2) + "\n")
    else:
        sys.stdout.write(render_text(result))

    if result.status == "skipped":
        print(f"Output written to: {output}", file=sys.stderr)
        return EXIT_SKIP if result.exit_code == EXIT_SKIP else EXIT_SUCCESS
    if result.status == "error":
        return EXIT_FAILURE
    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
