#!/bin/bash
# scripts/create-contest-zip.sh
#
# Create a contest submission ZIP package for Superteam Brasil judges.
# Packages all key files: README, CHANGELOG, SDD docs, skill files,
# agents, commands, rules, templates, tests, fixtures, and CI config.
#
# Usage:
#   bash scripts/create-contest-zip.sh
#
# Output:
#   solana-auditor-shiba-contest.zip (in project root)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

OUTPUT_ZIP="solana-auditor-shiba-contest.zip"
VERSION="v1.5.0"

echo "Creating contest submission ZIP: $OUTPUT_ZIP"
echo "Version: $VERSION"
echo ""

# Remove previous zip if it exists
rm -f "$OUTPUT_ZIP"

# Collect all key files
FILES=(
    # Root documentation
    README.md
    CHANGELOG.md
    CLAUDE.md
    LICENSE
    MEMORY.md
    pyproject.toml
    .flake8
    install.sh
    demo.sh

    # SDD documentation
    PRD.md
    spec.md
    kanban.md
    learnings.md

    # Skill files (hub + 7 phases + terminology + specs)
    skill/SKILL.md
    skill/00-terminology.md
    skill/01-recon.md
    skill/02-static-analysis.md
    skill/02B-runtime-testing.md
    skill/03-formal-verification.md
    skill/04-findings-triage.md
    skill/05-report-generation.md
    skill/06-remediation.md
    skill/SPEC-REMEDIATION.md

    # Agent definitions
    agents/orchestrator.md
    agents/auditor.md
    agents/formal-verifier.md
    agents/report-writer.md
    agents/cross-program-agent.md
    agents/AUDIT.md

    # Slash commands
    commands/audit.md
    commands/audit-quick.md
    commands/audit-resume.md
    commands/audit-report.md
    commands/audit-poc.md
    commands/audit-findings.md
    commands/audit-history.md
    commands/audit-pr.md

    # Path-scoped rules
    rules/audit.rules

    # PoC templates
    templates/poc-template-anchor.rs
    templates/poc-template-typescript.ts
    templates/poc-template-manual.md

    # Scripts
    scripts/export-sarif.py
    scripts/protocol-fingerprint.sh
    scripts/audit-history.sh
    scripts/create-contest-zip.sh

    # Tests
    tests/test-skill-integrity.sh
    tests/severity_counts.py
    tests/fuzz/test_properties.py

    # CI configuration
    .github/workflows/test.yml

    # Protocol fingerprinting data
    data/protocols/known-vulns.json
    data/protocols/protocol-signatures.json

    # Verification doc (judge walkthrough)
    VERIFICATION.md

    # Vault fixture
    examples/sample-vulnerable-program/README.md
    examples/sample-vulnerable-program/Anchor.toml
    examples/sample-vulnerable-program/programs/vault/Cargo.toml
    examples/sample-vulnerable-program/programs/vault/src/lib.rs
    examples/sample-vulnerable-program/audit-output/findings.json
    examples/sample-vulnerable-program/audit-output/AUDIT_REPORT.md
    examples/sample-vulnerable-program/audit-output/quick-scan-results.md
    examples/sample-vulnerable-program/audit-output/methodology-trace.md

    # Token-2022 fixture
    examples/sample-vulnerable-program/programs/token-extensions/Cargo.toml
    examples/sample-vulnerable-program/programs/token-extensions/src/lib.rs
    examples/sample-vulnerable-program/audit-output/token-extensions/findings.json
    examples/sample-vulnerable-program/audit-output/token-extensions/AUDIT_REPORT.md
    examples/sample-vulnerable-program/audit-output/token-extensions/quick-scan-results.md
    examples/sample-vulnerable-program/audit-output/token-extensions/methodology-trace.md
)

# Verify all files exist before zipping
MISSING_FILES=0
for f in "${FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "  MISSING: $f"
        MISSING_FILES=$((MISSING_FILES + 1))
    fi
done

if [ "$MISSING_FILES" -gt 0 ]; then
    echo ""
    echo "ERROR: $MISSING_FILES files are missing. Aborting."
    exit 1
fi

echo "All ${#FILES[@]} files exist. Creating ZIP..."
echo ""

# Create the ZIP
zip "$OUTPUT_ZIP" "${FILES[@]}" > /dev/null

# Verify
ZIP_SIZE=$(wc -c < "$OUTPUT_ZIP" | tr -d ' ')
ZIP_COUNT=$(unzip -l "$OUTPUT_ZIP" | tail -1 | awk '{print $2}')

echo "=============================================="
echo " Contest ZIP created successfully!"
echo "=============================================="
echo ""
echo "  File:     $OUTPUT_ZIP"
echo "  Size:     $ZIP_SIZE bytes"
echo "  Files:    $ZIP_COUNT"
echo "  Version:  $VERSION"
echo ""
echo "To inspect contents:"
echo "  unzip -l $OUTPUT_ZIP"
echo ""
echo "To extract:"
echo "  unzip $OUTPUT_ZIP -d /tmp/contest-review/"
echo ""
