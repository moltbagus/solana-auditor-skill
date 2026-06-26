#!/bin/bash
#
# solana-auditor-skill — Installer
# Installs the auditor-lifecycle skill for Solana AI Kit
#
# Usage: ./install.sh [-y|--yes]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR"
DEST_DIR="$HOME/.claude/skills/solana-auditor-skill"
COMMANDS_DIR="$HOME/.claude/commands"
RULES_DIR="$HOME/.claude/rules"
SKIP_CONFIRM=false

version() {
    git describe --tags 2>/dev/null || echo "v1.0.0"
}

banner() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  Solana Auditor Skill  —  Solana AI Kit                  ║"
    echo "║  $(version)  —  50 rules, 6 agents, 9 commands             ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
}

help() {
    echo "Usage: ./install.sh [-y|--yes]"
    echo "  -y, --yes   Skip confirmation"
    echo "  -h, --help  Show this message"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -y|--yes) SKIP_CONFIRM=true; shift ;;
        -h|--help) help; exit 0 ;;
        *) echo "Unknown: $1"; help; exit 1 ;;
    esac
done

banner

if [[ "$SKIP_CONFIRM" != "true" ]]; then
    echo "Install to: $DEST_DIR"
    read -p "Proceed? [y/N] " -n 1 -r
    echo ""
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
fi

# Install skill files
mkdir -p "$DEST_DIR"
cp -r "$SOURCE_DIR"/{SKILL.md,skill,agents,commands,rules,references,tests} "$DEST_DIR/" 2>/dev/null || true
echo "✓ Skill files → $DEST_DIR"

# Slash commands
mkdir -p "$COMMANDS_DIR"
cp "$DEST_DIR/commands"/*.md "$COMMANDS_DIR/" 2>/dev/null || true
echo "✓ Commands → $COMMANDS_DIR"

# Path-scoped rules
mkdir -p "$RULES_DIR"
cp "$DEST_DIR/rules"/*.rules "$RULES_DIR/" 2>/dev/null || true
echo "✓ Rules → $RULES_DIR"

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Install complete!  Run:  /audit <repo>                  ║"
echo "╚════════════════════════════════════════════════════════════╝"
