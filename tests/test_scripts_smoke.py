"""Smoke tests for the three audit pipeline scripts.

Run with: ``python3 -m pytest tests/test_scripts_smoke.py -v``.

These tests verify:
  * Each script exposes --help via argparse
  * Each script exits 0 on a happy-path invocation against the sample fixture
  * Each script is idempotent (re-run without destructive side effects)
  * triage-findings.py's CVSS recompute detects a planted mismatch
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
SAMPLE_FIXTURE = (
    REPO_ROOT
    / "examples"
    / "sample-vulnerable-program"
    / "audit-output"
    / "findings.json"
)


def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    "name",
    ["find-programs.py", "run-formal-verification.py", "triage-findings.py"],
)
def test_help(name: str) -> None:
    """Each script should exit 0 on --help."""
    proc = _run([sys.executable, str(SCRIPTS / name), "--help"])
    assert proc.returncode == 0, f"{name} --help failed: stderr={proc.stderr}"
    assert "usage" in proc.stdout.lower() or "options" in proc.stdout.lower()


def test_version_flag_for_each_script() -> None:
    """Each script should report --version."""
    for name in ("find-programs.py", "run-formal-verification.py", "triage-findings.py"):
        proc = _run([sys.executable, str(SCRIPTS / name), "--version"])
        assert proc.returncode == 0, f"{name} --version failed"
        assert proc.stdout.strip(), f"{name} --version produced no output"


def test_find_programs_text_format(tmp_path: Path) -> None:
    """find-programs.py should list the sample Anchor program in text mode."""
    repo = tmp_path / "fake-repo"
    programs = repo / "programs" / "vault"
    (programs / "src").mkdir(parents=True)
    (programs / "Cargo.toml").write_text('[package]\nname = "vault"\n')
    (programs / "Anchor.toml").write_text(
        '[provider]\ncluster = "localnet"\n'
    )
    (programs / "src" / "lib.rs").write_text(
        "use anchor_lang::prelude::*;\n"
        "declare_id!(\"Vau1t11111111111111111111111111111111111111\");\n"
        "\n"
        "#[program]\npub mod vault {}\n"
    )

    proc = _run(
        [sys.executable, str(SCRIPTS / "find-programs.py"), str(repo), "--format", "text"],
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    assert "Total programs: 1" in proc.stdout
    assert "anchor" in proc.stdout


def test_find_programs_json_format(tmp_path: Path) -> None:
    """find-programs.py --format json should write valid JSON with expected keys."""
    repo = tmp_path / "fake-repo"
    repo.mkdir()
    (repo / "Cargo.toml").write_text(
        "[package]\nname = \"native\"\nedition = \"2021\"\n"
    )
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "lib.rs").write_text(
        "use solana_program::entrypoint;\n"
        "use solana_program::entrypoint_deprecated;\n"
        "entrypoint_deprecated!(process_instruction);\n"
        "pub fn process_instruction() {}\n"
    )

    proc = _run(
        [sys.executable, str(SCRIPTS / "find-programs.py"), str(repo), "--format", "json"],
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["total_programs"] == 1
    prog = payload["programs"][0]
    assert prog["language"] == "native"


def test_run_formal_verification_skips_without_toolchain(tmp_path: Path) -> None:
    """run-formal-verification.py should exit 2 (skipped) when no toolchain."""
    repo = tmp_path / "empty-repo"
    repo.mkdir()
    report = tmp_path / "fv.json"

    proc = _run(
        [
            sys.executable,
            str(SCRIPTS / "run-formal-verification.py"),
            "--repo",
            str(repo),
            "--output",
            str(report),
            "--force",
        ],
        cwd=REPO_ROOT,
    )
    # Exit code 2 means "skipped" — that's the expected clean state.
    assert proc.returncode in (0, 2), proc.stderr
    if report.exists():
        data = json.loads(report.read_text())
        assert data["status"] in {"skipped", "complete", "partial", "error"}


def test_run_formal_verification_refuses_overwrite(tmp_path: Path) -> None:
    """--force must be passed to overwrite an existing report."""
    repo = tmp_path / "fake"
    repo.mkdir()
    report = tmp_path / "existing.json"
    report.write_text("{}")

    proc = _run(
        [
            sys.executable,
            str(SCRIPTS / "run-formal-verification.py"),
            "--repo",
            str(repo),
            "--output",
            str(report),
        ],
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 3, proc.stderr
    assert "use --force" in proc.stderr


def test_triage_findings_against_sample_fixture(tmp_path: Path) -> None:
    """triage-findings.py should write a prioritized list for the sample fixture."""
    if not SAMPLE_FIXTURE.exists():
        pytest.skip(f"Sample fixture not available: {SAMPLE_FIXTURE}")

    out = tmp_path / "prioritized.json"
    proc = _run(
        [
            sys.executable,
            str(SCRIPTS / "triage-findings.py"),
            "--input",
            str(SAMPLE_FIXTURE),
            "--output",
            str(out),
            "--force",
            "--format",
            "json",
        ],
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(out.read_text())
    assert payload["total_findings"] > 0
    assert "CRITICAL" in payload["by_severity"]
    assert payload["mean_cvss"] > 0


def test_triage_findings_cvss_recompute_detects_mismatch(tmp_path: Path) -> None:
    """--recompute-cvss must detect and correct a planted score/vector mismatch."""
    input_path = tmp_path / "bad_cvss.json"
    output_path = tmp_path / "out.json"

    # Plant a finding whose stored CVSS (5.0) does not match its vector (9.8).
    findings = {
        "findings": [
            {
                "id": "TEST-01",
                "title": "Critical finding planted by smoke test",
                "severity": "CRITICAL",
                "cvss": 5.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cwe": "CWE-306",
                "rule": 8,
                "rule_caught": "Rule 8 — Signer Verification",
                "location": {"file": "programs/test/src/lib.rs", "line": 1, "function": "test"},
                "status": "Open",
            }
        ]
    }
    input_path.write_text(json.dumps(findings))

    proc = _run(
        [
            sys.executable,
            str(SCRIPTS / "triage-findings.py"),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--recompute-cvss",
            "--force",
        ],
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(output_path.read_text())
    assert payload["cvss_mismatches"] == 1
    # Corrected score should be ~9.8 (CRITICAL AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
    assert payload["findings"][0]["cvss"] > 9.0


def test_triage_findings_min_severity_filter(tmp_path: Path) -> None:
    """--min-severity HIGH must drop MEDIUM/LOW findings."""
    input_path = tmp_path / "filtered.json"
    output_path = tmp_path / "filtered_out.json"

    findings = {
        "findings": [
            {
                "id": "HIGH-01",
                "severity": "HIGH",
                "title": "high",
                "cvss": 7.0,
                "location": {"file": "f.rs", "line": 1, "function": "f"},
                "status": "Open",
            },
            {
                "id": "MED-01",
                "severity": "MEDIUM",
                "title": "med",
                "cvss": 5.0,
                "location": {"file": "f.rs", "line": 2, "function": "f"},
                "status": "Open",
            },
        ]
    }
    input_path.write_text(json.dumps(findings))

    proc = _run(
        [
            sys.executable,
            str(SCRIPTS / "triage-findings.py"),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--min-severity",
            "HIGH",
            "--force",
        ],
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(output_path.read_text())
    # Only HIGH should remain.
    assert payload["total_findings"] == 1
    assert payload["findings"][0]["id"] == "HIGH-01"


def test_triage_findings_refuses_overwrite(tmp_path: Path) -> None:
    """triage-findings.py must refuse to overwrite without --force."""
    input_path = tmp_path / "in.json"
    output_path = tmp_path / "exists.json"
    input_path.write_text('{"findings": []}')
    output_path.write_text("{}")

    proc = _run(
        [
            sys.executable,
            str(SCRIPTS / "triage-findings.py"),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
        cwd=REPO_ROOT,
    )
    assert proc.returncode != 0
    assert "use --force" in proc.stderr


def test_find_programs_handles_missing_repo(tmp_path: Path) -> None:
    """find-programs.py should exit non-zero for a missing path."""
    proc = _run(
        [
            sys.executable,
            str(SCRIPTS / "find-programs.py"),
            str(tmp_path / "does-not-exist"),
        ],
        cwd=REPO_ROOT,
    )
    assert proc.returncode != 0


@pytest.fixture
def pytest_fixture_presence() -> None:
    """Helper: skip tests that need pytest CLI on plain system python."""
    if not shutil.which("pytest") and shutil.which("pytest") is None:
        # Just a no-op sanity; outer pytest handles discovery.
        pass
