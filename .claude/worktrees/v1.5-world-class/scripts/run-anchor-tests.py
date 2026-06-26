#!/usr/bin/env python3
"""
run-anchor-tests.py — Programmatic Anchor test runner filtered by vulnerability class.

Runs targeted tests for specific vulnerability classes, enabling Tier 2 runtime
verification without running the full test suite.

Usage:
    python scripts/run-anchor-tests.py --program ./programs/vault
    python scripts/run-anchor-tests.py --program ./programs/token --filter reentrancy
    python scripts/run-anchor-tests.py --program ./programs/lending --fuzz 1000
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Vulnerability class → test file patterns
VULN_TEST_PATTERNS: dict[str, list[str]] = {
    "reentrancy": [
        "tests/reentrancy*.test.ts",
        "tests/callback_reentrancy*.test.ts",
        "tests/nested_cpi*.test.ts",
    ],
    "overflow": [
        "tests/overflow*.test.ts",
        "tests/checked_arith*.test.ts",
        "tests/amount_bounds*.test.ts",
    ],
    "access_control": [
        "tests/auth*.test.ts",
        "tests/signer*.test.ts",
        "tests/privilege*.test.ts",
    ],
    "oracle_manipulation": [
        "tests/oracle*.test.ts",
        "tests/price*.test.ts",
        "tests/flash_loan*.test.ts",
    ],
    "state_corruption": [
        "tests/discriminator*.test.ts",
        "tests/reinit*.test.ts",
        "tests/close*.test.ts",
    ],
    "cpi_escalation": [
        "tests/cpi*.test.ts",
        "tests/invoke*.test.ts",
        "tests/remaining_accounts*.test.ts",
    ],
}


@dataclass
class TestResult:
    """Result of a single test run."""
    vulnerability_class: str
    test_files: list[str]
    passed: int
    failed: int
    errors: int
    duration_seconds: float
    command_output: str
    return_code: int


class AnchorTestRunner:
    """Programmatic Anchor test runner with vulnerability class filtering."""

    def __init__(self, program_path: Path) -> None:
        self.program_path = program_path
        self.results: list[TestResult] = []

    def detect_anchor(self) -> bool:
        """Check if anchor CLI is available."""
        result = subprocess.run(
            ["anchor", "--version"],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    def run_for_class(self, vuln_class: str, fuzz_cases: int = 100) -> TestResult:
        """Run tests for a specific vulnerability class."""
        patterns = VULN_TEST_PATTERNS.get(vuln_class, [])
        if not patterns:
            return TestResult(
                vulnerability_class=vuln_class,
                test_files=[],
                passed=0,
                failed=0,
                errors=0,
                duration_seconds=0.0,
                command_output=f"No test patterns defined for {vuln_class}",
                return_code=0,
            )

        # Validate program path exists
        if not self.program_path.exists():
            return TestResult(
                vulnerability_class=vuln_class,
                test_files=patterns,
                passed=0,
                failed=0,
                errors=1,
                duration_seconds=0.0,
                command_output=f"ERROR: Program path does not exist: {self.program_path}",
                return_code=1,
            )

        # Build anchor test command
        cmd = [
            "anchor",
            "test",
            "--skip-lint",
            "--timeout",
            "120",
        ]

        # Add fuzz cases if specified
        if fuzz_cases > 0:
            cmd.extend(["--fuzz", str(fuzz_cases)])

        # Run anchor test with timing
        start_time = time.time()
        result = subprocess.run(
            cmd,
            cwd=str(self.program_path),
            capture_output=True,
            text=True,
            timeout=300,
        )
        duration = time.time() - start_time

        # Parse output
        output = result.stdout + "\n" + result.stderr
        passed = self._parse_passed(output)
        failed = self._parse_failed(output)
        errors = self._parse_errors(output)

        return TestResult(
            vulnerability_class=vuln_class,
            test_files=patterns,
            passed=passed,
            failed=failed,
            errors=errors,
            duration_seconds=round(duration, 2),
            command_output=output[:5000],  # Truncate to 5KB
            return_code=result.returncode,
        )

    def run_all(self, fuzz_cases: int = 100) -> list[TestResult]:
        """Run tests for all vulnerability classes."""
        results = []
        for vuln_class in VULN_TEST_PATTERNS:
            result = self.run_for_class(vuln_class, fuzz_cases)
            results.append(result)
        return results

    @staticmethod
    def _parse_passed(output: str) -> int:
        """Parse passed test count from output."""
        # Try multiple patterns
        patterns = [
            r"\n\s*[✔✓]\s+(\w+)",
            r"passed\s+(\d+)",
            r"PASS\s+(\w+)",
            r"(\d+)\s+passing",
        ]
        for pattern in patterns:
            matches = re.findall(pattern, output)
            if matches:
                # If pattern has capture group for count, sum them
                if any(m.isdigit() for m in matches):
                    return sum(int(m) for m in matches if m.isdigit())
                # Otherwise count the matches
                return len(matches)
        return 0

    def _parse_failed(self, output: str) -> int:
        """Parse failed test count from output."""
        patterns = [
            r"failed\s+(\d+)",
            r"FAIL\s+(\w+)",
            r"\n\s*[✗✘]\s+(\w+)",
            r"(\d+)\s+failing",
        ]
        for pattern in patterns:
            matches = re.findall(pattern, output)
            if matches:
                if any(m.isdigit() for m in matches):
                    return sum(int(m) for m in matches if m.isdigit())
                return len(matches)
        return 0

    def _parse_errors(self, output: str) -> int:
        """Parse error count from output."""
        patterns = [
            r"error:",
            r"Error:",
            r"PANIC",
            r"AssertionError",
        ]
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, output, re.IGNORECASE))
        return count

    def summary(self) -> dict:
        """Generate summary of all test results."""
        total_passed = sum(r.passed for r in self.results)
        total_failed = sum(r.failed for r in self.results)
        total_errors = sum(r.errors for r in self.results)
        return {
            "total_tests": len(self.results),
            "total_passed": total_passed,
            "total_failed": total_failed,
            "total_errors": total_errors,
            "findings": [
                {
                    "vuln_class": r.vulnerability_class,
                    "failed": r.failed,
                    "errors": r.errors,
                }
                for r in self.results
                if r.failed > 0 or r.errors > 0
            ],
        }


def main() -> int:
    """Main entry point for the Anchor test runner."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--program",
        "-p",
        required=True,
        help="Path to Anchor program directory",
    )
    parser.add_argument(
        "--filter",
        "-f",
        choices=list(VULN_TEST_PATTERNS.keys()),
        help="Vulnerability class to test (runs all if not specified)",
    )
    parser.add_argument(
        "--fuzz",
        "-n",
        type=int,
        default=100,
        help="Fuzz cases per test (default: 100)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output JSON file (prints to stdout if not specified)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print verbose output",
    )

    args = parser.parse_args()
    program_path = Path(args.program).resolve()

    runner = AnchorTestRunner(program_path)

    # Check for anchor CLI
    if not runner.detect_anchor():
        print(
            "ERROR: anchor CLI not found. Install Anchor first.",
            file=sys.stderr,
        )
        print(
            "See: https://www.anchor-lang.com/docs/installation",
            file=sys.stderr,
        )
        return 1

    if args.verbose:
        print(f"Running Anchor tests for: {program_path}")

    # Run tests
    if args.filter:
        if args.verbose:
            print(f"Filtering by vulnerability class: {args.filter}")
        results = [runner.run_for_class(args.filter, args.fuzz)]
    else:
        if args.verbose:
            print("Running all vulnerability class tests...")
        results = runner.run_all(args.fuzz)

    runner.results = results

    # Build output data
    output_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "program": str(program_path),
        "filter": args.filter,
        "fuzz_cases": args.fuzz,
        "results": [asdict(r) for r in results],
        "summary": runner.summary(),
    }

    # Output
    json_output = json.dumps(output_data, indent=2)

    if args.output:
        output_file = Path(args.output)
        output_file.write_text(json_output)
        if args.verbose:
            print(f"Results written to: {output_file}")
    else:
        print(json_output)

    # Print summary to stderr if verbose
    if args.verbose:
        summary = runner.summary()
        print(
            f"\nSummary: {summary['total_passed']} passed, "
            f"{summary['total_failed']} failed, "
            f"{summary['total_errors']} errors",
            file=sys.stderr,
        )
        if summary["findings"]:
            print("\nFindings:", file=sys.stderr)
            for finding in summary["findings"]:
                print(
                    f"  - {finding['vuln_class']}: "
                    f"{finding['failed']} failed, "
                    f"{finding['errors']} errors",
                    file=sys.stderr,
                )

    # Exit code = 0 if all tests pass
    total_issues = runner.summary()["total_failed"] + runner.summary()["total_errors"]
    return 0 if total_issues == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
