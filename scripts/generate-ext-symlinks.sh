#!/bin/bash
#
# generate-ext-symlinks.sh
# Creates the symlink structure in ext/solana-auditor-skill/
# so the ext/ directory is thin — content lives in the root,
# and only unique ext/ files are copied.
#
# Usage: bash scripts/generate-ext-symlinks.sh
#

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(cd "$SCRIPT_DIR/../ext/solana-auditor-skill" && pwd)"

echo -e "${BLUE}[*] Generating ext/ symlinks in $WORK_DIR${NC}"
echo ""

# ── Root-level files (copy, not symlink — these are ext/ metadata) ──────────

# SKILL.md — symlink to root skill/SKILL.md so the AI Kit hub resolves correctly
link_once() {
    local target="$1"
    local link="$2"
    local rel
    # Use Python for cross-platform relative path (macOS realpath lacks --relative-to)
    rel="$(python3 -c "import os; print(os.path.relpath('$target', '$(dirname "$link")'))" 2>/dev/null)" || rel="$target"
    if [[ ! -e "$link" ]]; then
        ln -s "$rel" "$link"
        echo -e "  ${GREEN}symlink${NC}  $(basename "$link") → $(basename "$target")"
    else
        echo -e "  ${BLUE}exists${NC}  $(basename "$link") (skip)"
    fi
}

# SKILL.md — core routing hub (must be at ext root per AI Kit conventions)
link_once "$SCRIPT_DIR/../skill/SKILL.md" "$WORK_DIR/SKILL.md"

# install.sh — ext-mode aware installer
link_once "$SCRIPT_DIR/../install.sh" "$WORK_DIR/install.sh"

# ── skill/ phase files ───────────────────────────────────────────────────────
SKILL_FILES=(
    00-terminology.md
    01-recon.md
    02-static-analysis.md
    02B-runtime-testing.md
    03-formal-verification.md
    04-findings-triage.md
    05-report-generation.md
    06-remediation.md
)

mkdir -p "$WORK_DIR/skill"
for f in "${SKILL_FILES[@]}"; do
    link_once "$SCRIPT_DIR/../skill/$f" "$WORK_DIR/skill/$f"
done

# ── agents/ ────────────────────────────────────────────────────────────────
AGENT_FILES=(
    AUDIT.md
    auditor.md
    cross-program-agent.md
    formal-verifier.md
    orchestrator.md
    report-writer.md
)

mkdir -p "$WORK_DIR/agents"
for f in "${AGENT_FILES[@]}"; do
    link_once "$SCRIPT_DIR/../agents/$f" "$WORK_DIR/agents/$f"
done

# ── commands/ ───────────────────────────────────────────────────────────────
COMMAND_FILES=(
    audit.md
    audit-findings.md
    audit-history.md
    audit-poc.md
    audit-pr.md
    audit-quick.md
    audit-report.md
    audit-resume.md
)

mkdir -p "$WORK_DIR/commands"
for f in "${COMMAND_FILES[@]}"; do
    link_once "$SCRIPT_DIR/../commands/$f" "$WORK_DIR/commands/$f"
done

# ── rules/ ────────────────────────────────────────────────────────────────
RULES_FILES=(
    audit.rules
    semgrep-solana.yaml
)

mkdir -p "$WORK_DIR/rules"
for f in "${RULES_FILES[@]}"; do
    link_once "$SCRIPT_DIR/../rules/$f" "$WORK_DIR/rules/$f"
done

# ── scripts/ ───────────────────────────────────────────────────────────────
SCRIPT_FILES=(
    audit-fix-suggestions.py
    audit-history.sh
    create-contest-zip.sh
    export-sarif.py
    findings-to-sarif.py
    generate-cpi-graph.sh
    generate-ext-symlinks.sh
    pre-commit-audit.sh
    protocol-fingerprint.sh
    run-anchor-tests.py
    run-sast.py
    toolchain-detector.py
)

mkdir -p "$WORK_DIR/scripts"
for f in "${SCRIPT_FILES[@]}"; do
    link_once "$SCRIPT_DIR/$f" "$WORK_DIR/scripts/$f"
done

# ── templates/ (copy, not symlink — these go to ~/.claude/templates) ────────
TEMPLATE_FILES=(
    poc-template-anchor.rs
    poc-template-manual.md
    poc-template-typescript.ts
)

mkdir -p "$WORK_DIR/templates"
for f in "${TEMPLATE_FILES[@]}"; do
    link_once "$SCRIPT_DIR/../templates/$f" "$WORK_DIR/templates/$f"
done

# ── CLAUDE.md ───────────────────────────────────────────────────────────────
link_once "$SCRIPT_DIR/../CLAUDE.md" "$WORK_DIR/CLAUDE.md"

echo ""
echo -e "${GREEN}[+] Symlink generation complete${NC}"
echo ""
echo "Next steps:"
echo "  1. Review ext/solana-auditor-skill/skill-registry.json"
echo "  2. Copy to AI Kit ext/:  cp -r ext/solana-auditor-skill ~/.claude/skills/ext/"
echo "  3. Or reference from AI Kit skill-registry.json"
