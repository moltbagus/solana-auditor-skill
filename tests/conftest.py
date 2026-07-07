"""Shared fixtures and path setup for fix_* module tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Ensure scripts/ is on sys.path for fix_* module imports
_SCRIPTS_DIR = str(Path(__file__).resolve().parent.parent / "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)


# ---------------------------------------------------------------------------
# Reusable sample finding dicts
# ---------------------------------------------------------------------------

@pytest.fixture
def finding_critical() -> dict:
    """A CRITICAL finding with Rule 8 (Signer Verification)."""
    return {
        "id": "VULN-01",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-306",
        "rule": 8,
        "rule_caught": "Rule 8 — Signer Verification",
        "title": "Missing signer verification on admin_withdraw",
        "description": "The admin_withdraw instruction does not verify the admin is a signer.",
        "impact": "Any user can drain all vault lamports.",
        "location": {"file": "programs/vault/src/lib.rs", "line": 42, "function": "admin_withdraw"},
        "status": "Open",
        "poc_status": "pending",
    }


@pytest.fixture
def finding_high() -> dict:
    """A HIGH finding with Rule 6 (Arithmetic Overflow)."""
    return {
        "id": "VULN-05",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "cwe": "CWE-190",
        "rule": 6,
        "rule_caught": "Rule 6 — Arithmetic Overflow",
        "title": "Unchecked integer overflow in deposit",
        "description": "User-supplied deposit amount wraps on overflow.",
        "impact": "Attacker can inflate balance to any value.",
        "location": {"file": "programs/vault/src/lib.rs", "line": 88, "function": "deposit"},
        "status": "Open",
        "poc_status": "pending",
    }


@pytest.fixture
def finding_medium() -> dict:
    """A MEDIUM finding with Rule 3 (PDA Bump)."""
    return {
        "id": "VULN-02",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe": "CWE-340",
        "rule": 3,
        "rule_caught": "Rule 3 — PDA Canonical Bump",
        "title": "Hardcoded PDA bump value",
        "description": "PDA bump is hardcoded to 254 instead of using canonical bump.",
        "impact": "Multiple valid PDAs derived from same seeds.",
        "location": {"file": "programs/vault/src/lib.rs", "line": 15, "function": "initialize"},
        "status": "Open",
        "poc_status": "pending",
    }


@pytest.fixture
def minimal_finding() -> dict:
    """A minimal finding with only required fields."""
    return {
        "id": "MIN-01",
        "severity": "LOW",
        "title": "Minor finding",
        "description": "A low-severity best-practice finding.",
        "location": {"file": "programs/test/src/lib.rs", "line": 1, "function": "test_fn"},
        "status": "Open",
    }


@pytest.fixture
def sample_findings_list(
    finding_critical: dict,
    finding_high: dict,
    finding_medium: dict,
    minimal_finding: dict,
) -> list[dict]:
    """A list of 4 findings of varying severity for batch tests."""
    return [finding_critical, finding_high, finding_medium, minimal_finding]


# ---------------------------------------------------------------------------
# Paths to real fixture files
# ---------------------------------------------------------------------------

@pytest.fixture
def vault_fixture_path() -> Path:
    """Path to the vault findings.json fixture."""
    return (
        Path(__file__).resolve().parent.parent
        / "examples"
        / "sample-vulnerable-program"
        / "audit-output"
        / "findings.json"
    )


@pytest.fixture
def vault_fixture_data(vault_fixture_path: Path) -> dict | None:
    """Load the vault fixture JSON if it exists."""
    if vault_fixture_path.exists():
        return json.loads(vault_fixture_path.read_text(encoding="utf-8"))
    return None
