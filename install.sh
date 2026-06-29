#!/bin/bash
#
# solana-auditor-skill Skill - Installer
# Installs the auditor-lifecycle skill for Solana AI Kit
#
# Usage: ./install.sh [-y|--yes]
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/skill"
AGENTS_DIR="$SCRIPT_DIR/agents"
COMMANDS_DIR="$SCRIPT_DIR/commands"
RULES_DIR="$SCRIPT_DIR/rules"
TEMPLATES_DIR="$SCRIPT_DIR/templates"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"

SKILLS_DIR="$HOME/.claude/skills"
AUDIT_SKILL_PATH="$SKILLS_DIR/solana-auditor-skill"
COMMANDS_PATH="$HOME/.claude/commands"
RULES_PATH="$HOME/.claude/rules"
TEMPLATES_PATH="$HOME/.claude/templates"
CLAUDE_MD_PATH="$HOME/.claude/CLAUDE.md"

SKIP_CONFIRM=false

print_banner() {
    local version="${1:-v1.14.2}"
    local mode_tag="${2:-Standard}"
    echo ""
    echo -e "${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC}  ${WHITE}Solana Auditor Shiba Skill for Claude Code${NC}              ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}║${NC}  ${CYAN}World-Class Security Auditor — ${version}${NC}"
    echo -e "${MAGENTA}║${NC}  ${CYAN}50 rules (45 SAST + 5 AI), 10 agents, 9 commands${NC}         ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}║${NC}  ${CYAN}Mode: ${mode_tag}${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_help() {
    echo "Solana Auditor Shiba Skill - Installer"
    echo ""
    echo "Usage: ./install.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -y, --yes       Skip confirmation prompt"
    echo "  -h, --help      Show this help message"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -y|--yes)
            SKIP_CONFIRM=true
            shift
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_help
            exit 1
            ;;
    esac
done

install_skill() {
    echo -e "${BLUE}[*] Creating skills directory...${NC}"
    mkdir -p "$SKILLS_DIR"

    echo -e "${BLUE}[*] Installing auditor skill to $AUDIT_SKILL_PATH${NC}"
    mkdir -p "$AUDIT_SKILL_PATH"

    # Copy skill files
    # CRITICAL: copy INTO $AUDIT_SKILL_PATH (not $SKILLS_DIR). The skill
    # is registered as "solana-auditor-skill" by Claude Code based on the
    # directory name; copying into $SKILLS_DIR/skill/ would not be picked up.
    if [[ -d "$SOURCE_DIR" ]]; then
        cp -r "$SOURCE_DIR"/. "$AUDIT_SKILL_PATH/" 2>/dev/null || {
            echo -e "${RED}[!] Failed to copy skill files into $AUDIT_SKILL_PATH${NC}"
            exit 1
        }
        if [[ ! -f "$AUDIT_SKILL_PATH/SKILL.md" ]]; then
            echo -e "${RED}[!] Skill copy did not produce SKILL.md — aborting${NC}"
            exit 1
        fi
        echo -e "${GREEN}[+] Skill files copied to $AUDIT_SKILL_PATH${NC}"
    fi

    # Copy agents
    if [[ -d "$AGENTS_DIR" ]]; then
        mkdir -p "$AUDIT_SKILL_PATH/agents"
        if ! cp -r "$AGENTS_DIR"/* "$AUDIT_SKILL_PATH/agents/"; then
            echo -e "${RED}[!] Failed to copy agents${NC}"
            exit 1
        fi
        echo -e "${GREEN}[+] Agent configs copied ($(ls "$AGENTS_DIR"/*.md 2>/dev/null | wc -l | tr -d ' ') files)${NC}"
    fi

    # Copy slash commands to ~/.claude/commands/
    if [[ -d "$COMMANDS_DIR" ]]; then
        mkdir -p "$COMMANDS_PATH"
        if ! cp "$COMMANDS_DIR"/*.md "$COMMANDS_PATH/"; then
            echo -e "${RED}[!] Failed to copy commands${NC}"
            exit 1
        fi
        local cmd_count
        cmd_count=$(find "$COMMANDS_DIR" -maxdepth 1 -name "*.md" | wc -l | tr -d ' ')
        echo -e "${GREEN}[+] Slash commands installed ($cmd_count commands)${NC}"
    fi

    # Copy path-scoped rules to ~/.claude/rules/
    if [[ -d "$RULES_DIR" ]]; then
        mkdir -p "$RULES_PATH"
        if ! cp "$RULES_DIR"/*.rules "$RULES_PATH/"; then
            echo -e "${RED}[!] Failed to copy rules${NC}"
            exit 1
        fi
        echo -e "${GREEN}[+] Path-scoped rules installed ($(ls "$RULES_DIR"/*.rules 2>/dev/null | wc -l | tr -d ' ') files)${NC}"
    fi

    # Copy PoC templates to ~/.claude/templates/solana-auditor-skill/
    if [[ -d "$TEMPLATES_DIR" ]]; then
        mkdir -p "$TEMPLATES_PATH/solana-auditor-skill"
        if ! cp "$TEMPLATES_DIR"/* "$TEMPLATES_PATH/solana-auditor-skill/"; then
            echo -e "${RED}[!] Failed to copy templates${NC}"
            exit 1
        fi
        echo -e "${GREEN}[+] PoC templates installed ($(ls "$TEMPLATES_DIR"/* 2>/dev/null | wc -l | tr -d ' ') files)${NC}"
    fi

    # Copy helper scripts to $AUDIT_SKILL_PATH/scripts/
    if [[ -d "$SCRIPTS_DIR" ]]; then
        mkdir -p "$AUDIT_SKILL_PATH/scripts"
        if ! cp "$SCRIPTS_DIR"/*.sh "$AUDIT_SKILL_PATH/scripts/"; then
            echo -e "${RED}[!] Failed to copy bash scripts${NC}"
            exit 1
        fi
        if ! cp "$SCRIPTS_DIR"/*.py "$AUDIT_SKILL_PATH/scripts/"; then
            echo -e "${RED}[!] Failed to copy python scripts${NC}"
            exit 1
        fi
        local sh_count py_count
        sh_count=$(find "$SCRIPTS_DIR" -maxdepth 1 -name "*.sh" | wc -l | tr -d ' ')
        py_count=$(find "$SCRIPTS_DIR" -maxdepth 1 -name "*.py" | wc -l | tr -d ' ')
        echo -e "${GREEN}[+] Helper scripts installed ($sh_count bash + $py_count python)${NC}"
        # Offer pre-commit hook installation
        if [[ -f "$SCRIPTS_DIR/pre-commit-audit.sh" ]]; then
            echo -e "${YELLOW}[!] Run '$AUDIT_SKILL_PATH/scripts/pre-commit-audit.sh --install' to enable the pre-commit hook${NC}"
        fi
    fi

    # Copy CLAUDE.md
    if [[ -f "$SCRIPT_DIR/CLAUDE.md" ]]; then
        cp "$SCRIPT_DIR/CLAUDE.md" "$AUDIT_SKILL_PATH/CLAUDE.md"
        echo -e "${GREEN}[+] CLAUDE.md installed${NC}"
    fi

    # Copy demo script
    if [[ -f "$SCRIPT_DIR/demo.sh" ]]; then
        cp "$SCRIPT_DIR/demo.sh" "$AUDIT_SKILL_PATH/demo.sh"
        echo -e "${GREEN}[+] Demo script copied${NC}"
    fi

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  ${WHITE}Install complete!${NC}                                                ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}Skill: $AUDIT_SKILL_PATH${NC}                          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}v1.14.2: 50 rules (45 SAST + 5 AI), 10 agents, 9 commands${NC} ${GREEN}║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Main
print_banner
if [[ "$SKIP_CONFIRM" != "true" ]]; then
        echo -e "${YELLOW}[!] This will install solana-auditor-skill skill to:${NC}"
        echo "    $AUDIT_SKILL_PATH"
        echo ""
        read -p "Proceed? [y/N] " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${RED}[-] Install cancelled.${NC}"
            exit 0
        fi
    fi
    install_skill