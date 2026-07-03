#!/usr/bin/env python3
"""toolchain-detector.py — Detect available Solana audit toolchain.

Detects installed tools and classifies the environment into one of three tiers:
  TIER1      - Minimal Rust-only environment
  TIER2_FULL - Full Solana audit suite (Anchor, Solana CLI, QED)
  TIER3      - Production-grade with RPC API access (TIER2 + Helius key)

Usage:
    python3 scripts/toolchain-detector.py
    python3 scripts/toolchain-detector.py --json
    python3 scripts/toolchain-detector.py --check <tool>
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
from typing import Optional


class ToolchainTier(str, Enum):
    """Classification tiers for detected toolchain readiness."""

    TIER1 = "TIER1"
    TIER2_PARTIAL = "TIER2_PARTIAL"
    TIER2_FULL = "TIER2_FULL"
    TIER3 = "TIER3"


@dataclass
class ToolInfo:
    """Metadata for a single detected tool."""

    name: str
    path: Optional[str]
    version: Optional[str] = None
    available: bool = False


@dataclass
class Toolchain:
    """Complete toolchain detection result."""

    tier: ToolchainTier
    anchor: ToolInfo
    solana: ToolInfo
    cargo_audit: ToolInfo
    rustc: ToolInfo
    helius_key: ToolInfo
    qed: ToolInfo
    cargo: ToolInfo
    programs: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to dict for JSON output."""
        result = asdict(self)
        result["tier"] = self.tier.value
        return result

    def summary(self) -> str:
        """Human-readable summary."""
        lines = [
            f"Toolchain Tier: {self.tier.value}",
            "",
            "Detected Tools:",
            f"  anchor       {self._available_icon(self.anchor)}",
            f"  solana       {self._available_icon(self.solana)}",
            f"  cargo-audit  {self._available_icon(self.cargo_audit)}",
            f"  rustc        {self._available_icon(self.rustc)}",
            f"  qed-solana   {self._available_icon(self.qed)}",
            f"  HELIUS_RPC   {self._available_icon(self.helius_key)}",
            "",
            "Recommendations:",
        ]

        if self.tier == ToolchainTier.TIER1:
            lines.append("  - Install: anchor, solana-cli, cargo-audit")
            lines.append("  - Run: curl -sSfL https://release.anza.xyz/stable/install | sh")
        elif self.tier == ToolchainTier.TIER2_PARTIAL:
            lines.append("  - Install: cargo install cargo-audit")
            lines.append("  - Consider: cargo install --git https://github.com/qed-dev/qed qed-solana")
        elif self.tier == ToolchainTier.TIER2_FULL:
            lines.append("  - Add HELIUS_RPC_KEY for production API access")
        elif self.tier == ToolchainTier.TIER3:
            lines.append("  - Full production audit suite ready")

        return "\n".join(lines)

    @staticmethod
    def _available_icon(tool: ToolInfo) -> str:
        if tool.available:
            if tool.version:
                return f"[OK] {tool.version}"
            return "[OK]"
        return "[MISSING]"


def run_command(cmd: list[str], timeout: int = 10) -> tuple[Optional[str], int]:
    """Execute a command and return stdout and exit code."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else None, result.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return None, -1


def detect_tool(name: str, args: list[str]) -> ToolInfo:
    """Detect a single tool's presence and version."""
    path = shutil.which(name)
    version = None

    if path:
        output, _ = run_command([name] + args)
        if output:
            version = output.split("\n")[0]
            if len(version) > 50:
                version = version[:47] + "..."

    return ToolInfo(
        name=name,
        path=path,
        version=version,
        available=path is not None,
    )


def detect_helius_key() -> ToolInfo:
    """Detect Helius RPC API key from environment."""
    key = os.environ.get("HELIUS_RPC_KEY") or os.environ.get("HELIUS_API_KEY")
    available = bool(key)
    masked = None

    if key:
        if len(key) > 8:
            masked = f"{key[:4]}...{key[-4:]}"
        else:
            masked = "***"

    return ToolInfo(
        name="HELIUS_RPC_KEY",
        path=None,
        version=masked,
        available=available,
    )


def detect_programs() -> dict:
    """Detect Anchor programs in common locations."""
    programs = {}
    search_paths = [
        Path.cwd(),
        Path.cwd() / "programs",
        Path.home() / "src",
    ]

    for search_root in search_paths:
        if not search_root.exists():
            continue

        for Cargo_toml in search_root.rglob("Cargo.toml"):
            anchor_proj = Cargo_toml.parent / "Anchor.toml"
            if anchor_proj.exists():
                rel = Cargo_toml.relative_to(Path.cwd())
                programs[str(rel.parent)] = "anchor"

    return programs


def detect_qed() -> ToolInfo:
    """Detect QED formal verification tool with multiple naming conventions."""
    for name in ["qed-solana", "qed", "qeds"]:
        info = detect_tool(name, ["--version"])
        if info.available:
            return info

    return ToolInfo(
        name="qed-solana",
        path=None,
        available=False,
    )


def classify_tier(
    anchor: ToolInfo,
    solana: ToolInfo,
    qed: ToolInfo,
    helius: ToolInfo,
) -> ToolchainTier:
    """Classify environment based on available tools."""
    if anchor.available and solana.available and qed.available and helius.available:
        return ToolchainTier.TIER3
    if anchor.available and solana.available and qed.available:
        return ToolchainTier.TIER2_FULL
    if anchor.available and solana.available:
        return ToolchainTier.TIER2_PARTIAL
    return ToolchainTier.TIER1


def detect() -> Toolchain:
    """Run full toolchain detection."""
    anchor = detect_tool("anchor", ["--version"])
    solana = detect_tool("solana", ["--version"])
    cargo_audit = detect_tool("cargo-audit", ["--version"])
    rustc = detect_tool("rustc", ["--version"])
    cargo = detect_tool("cargo", ["--version"])
    helius = detect_helius_key()
    qed = detect_qed()
    programs = detect_programs()

    tier = classify_tier(anchor, solana, qed, helius)

    return Toolchain(
        tier=tier,
        anchor=anchor,
        solana=solana,
        cargo_audit=cargo_audit,
        rustc=rustc,
        helius_key=helius,
        qed=qed,
        cargo=cargo,
        programs=programs,
    )


def check_single_tool(tool_name: str) -> int:
    """Check if a specific tool is available, exit code 0 if found."""
    info = detect_tool(tool_name, ["--version"])
    if info.available:
        print(f"{tool_name}: {info.version or info.path}")
        return 0
    print(f"{tool_name}: not found")
    return 1


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Detect available Solana audit toolchain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s              Detect all tools and print summary
  %(prog)s --json       Output machine-readable JSON
  %(prog)s --check anchor   Check if anchor is installed
        """,
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of human-readable summary",
    )
    parser.add_argument(
        "--check",
        metavar="TOOL",
        help="Check if a specific tool is installed",
    )
    parser.add_argument(
        "--tier-only",
        action="store_true",
        help="Output only the tier string (useful for scripts)",
    )
    args = parser.parse_args()

    if args.check:
        return check_single_tool(args.check)

    toolchain = detect()

    if args.tier_only:
        print(toolchain.tier.value)
        return 0

    if args.json:
        print(json.dumps(toolchain.to_dict(), indent=2))
    else:
        print(toolchain.summary())

    return 0


if __name__ == "__main__":
    sys.exit(main())
