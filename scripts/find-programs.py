#!/usr/bin/env python3
"""
find-programs.py — Phase 1: Attack-surface recon for Solana projects.

Enumerates Solana/Anchor programs in a repository and emits a JSON or text
summary listing each program with its relative path, detected language
(anchor/native/pinocchio), and approximate lines of code.

Used by `.github/workflows/audit-scheduled.yml` Phase 1 step.

Usage:
    python scripts/find-programs.py                       # scan current dir
    python scripts/find-programs.py /path/to/repo        # scan a directory
    python scripts/find-programs.py --format json --output programs.json
    python scripts/find-programs.py --format text         # human-readable
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

SCRIPT_VERSION = "1.0.0"

# Anchor / native / pinocchio markers
ANCHOR_TOML = "Anchor.toml"
NATIVE_RS_MARKERS = (
    "solana_program::entrypoint",
    "solana_program::entrypoint_deprecated",
    "entrypoint!",
    "process_instruction",
)
PINOCCHIO_MARKERS = (
    "pinocchio",
    "PinocchioAccount",
    "pinocchio_lang",
)
NATIVE_LIB_MARKERS = (
    "declare_id!",
    "pub fn process_instruction",
)

# File extensions counted toward LOC
RUST_EXT = ".rs"
SOLANA_EXT = (".rs", ".so")  # native extensions we treat as relevant


@dataclass
class Program:
    """A single Solana program detected in the repository."""

    name: str
    path: str
    language: str  # "anchor" | "native" | "pinocchio"
    entry_point: str
    lib_rs: str
    loc: int
    has_tests: bool
    has_cargo_lock: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Top-level scan output."""

    repo_root: str
    scanned_at: str
    total_programs: int
    by_language: dict[str, int] = field(default_factory=dict)
    programs: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _import_datetime():
    from datetime import datetime, timezone

    return datetime, timezone


def _is_within(child: Path, parent: Path) -> bool:
    """True if `child` is inside `parent` (symlink-free)."""
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _count_loc(rs_path: Path) -> int:
    """Approximate lines of code in a .rs file (newline count, blank lines included)."""
    try:
        with rs_path.open("r", encoding="utf-8", errors="replace") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def _read_first_n(path: Path, n: int = 8192) -> str:
    """Read at most `n` bytes from a file as text."""
    try:
        with path.open("rb") as f:
            return f.read(n).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _detect_language(programs_dir: Path) -> str:
    """Detect program language from Anchor.toml and lib.rs markers."""
    if (programs_dir / ANCHOR_TOML).exists():
        return "anchor"

    lib_rs_candidates = list(programs_dir.glob(f"src/lib{RUST_EXT}")) + [
        programs_dir / "src" / "lib.rs"
    ]
    for candidate in lib_rs_candidates:
        if not candidate.exists():
            continue
        head = _read_first_n(candidate, n=16_384)
        head_lower = head.lower()
        if any(marker.lower() in head_lower for marker in PINOCCHIO_MARKERS):
            return "pinocchio"
        if any(marker in head for marker in NATIVE_RS_MARKERS) or any(
            marker in head for marker in NATIVE_LIB_MARKERS
        ):
            return "native"

    # Fallback: if lib.rs exists and Cargo.toml present, treat as native
    if (programs_dir / "src" / "lib.rs").exists() and (programs_dir / "Cargo.toml").exists():
        return "native"
    return "unknown"


def _find_lib_rs(program_dir: Path) -> Path | None:
    """Return the lib.rs path for a program, or None."""
    candidate = program_dir / "src" / "lib.rs"
    if candidate.exists():
        return candidate
    return None


def find_programs(repo_root: Path) -> list[Program]:
    """Walk repo_root and return all detected Solana programs."""
    if not repo_root.exists():
        return []

    programs: list[Program] = []
    seen: set[str] = set()

    # Strategy 1: Anchor monorepo layout — programs/<name>/Cargo.toml
    programs_dir = repo_root / "programs"
    if programs_dir.is_dir():
        for sub in sorted(programs_dir.iterdir()):
            if sub.is_dir() and (sub / "Cargo.toml").exists():
                _maybe_add_program(programs, seen, sub, repo_root)

    # Strategy 2: top-level Cargo.toml
    top_cargo = repo_root / "Cargo.toml"
    if top_cargo.exists() and top_cargo.parent != programs_dir:
        _maybe_add_program(programs, seen, top_cargo.parent, repo_root)

    # Strategy 3: native-rs standalone files with declare_id!
    src_dir = repo_root / "src"
    if src_dir.is_dir():
        for rs_path in src_dir.rglob(f"*{RUST_EXT}"):
            head = _read_first_n(rs_path, n=4096)
            if "declare_id!" in head and "process_instruction" in head:
                # Treat as native program at repo_root
                _maybe_add_program(
                    programs,
                    seen,
                    repo_root,
                    repo_root,
                    language_override="native",
                )
                break

    return programs


def _maybe_add_program(
    programs: list[Program],
    seen: set[str],
    program_dir: Path,
    repo_root: Path,
    language_override: str | None = None,
) -> None:
    """If a new Solana program is detected, append a Program to `programs`."""
    try:
        rel = program_dir.relative_to(repo_root).as_posix()
    except ValueError:
        rel = program_dir.as_posix()

    if rel in seen:
        return
    seen.add(rel)

    name = program_dir.name
    lib_rs = _find_lib_rs(program_dir)
    loc = _count_loc(lib_rs) if lib_rs else 0

    language = (
        language_override
        if language_override is not None
        else _detect_language(program_dir)
    )

    has_tests = (program_dir / "tests").exists()
    has_cargo_lock = (repo_root / "Cargo.lock").exists() or (
        program_dir / "Cargo.lock"
    ).exists()

    programs.append(
        Program(
            name=name,
            path=rel,
            language=language,
            entry_point=str(
                lib_rs.relative_to(repo_root) if lib_rs and _is_within(lib_rs, repo_root) else ""
            ),
            lib_rs=str(lib_rs) if lib_rs else "",
            loc=loc,
            has_tests=has_tests,
            has_cargo_lock=has_cargo_lock,
        )
    )


def render_text(result: ScanResult) -> str:
    """Render a human-readable summary."""
    lines = [
        f"Repository: {result.repo_root}",
        f"Total programs: {result.total_programs}",
        "Language breakdown:",
    ]
    for language, count in sorted(result.by_language.items()):
        lines.append(f"  {language:<12} {count}")
    if not result.by_language:
        lines.append("  (none detected)")
    lines.append("")
    lines.append("Programs:")
    for prog in result.programs:
        lines.append(
            f"  - {prog['name']:<24} {prog['language']:<10} "
            f"LOC={prog['loc']:>5}  {prog['path']}"
        )
    return "\n".join(lines) + "\n"


def render_json(result: ScanResult) -> str:
    """Render the scan result as pretty JSON."""
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


def build_result(repo_root: Path, programs: Iterable[Program]) -> ScanResult:
    """Aggregate a list of Programs into a ScanResult."""
    datetime, timezone = _import_datetime()
    prog_dicts = [p.to_dict() for p in programs]
    by_language: dict[str, int] = {}
    for d in prog_dicts:
        by_language[d["language"]] = by_language.get(d["language"], 0) + 1
    return ScanResult(
        repo_root=str(repo_root.resolve()),
        scanned_at=datetime.now(timezone.utc).isoformat(),
        total_programs=len(prog_dicts),
        by_language=by_language,
        programs=prog_dicts,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "repo",
        nargs="?",
        default=".",
        help="Path to repository root (default: current directory)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=("json", "text"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path (default: stdout)",
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
    repo_root = Path(args.repo).resolve()

    if not repo_root.exists():
        print(f"Error: repository root not found: {repo_root}", file=sys.stderr)
        return 1
    if not repo_root.is_dir():
        print(f"Error: not a directory: {repo_root}", file=sys.stderr)
        return 1

    programs = find_programs(repo_root)
    result = build_result(repo_root, programs)

    if args.format == "json":
        rendered = render_json(result) + "\n"
    else:
        rendered = render_text(result)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
        print(
            f"Wrote {result.total_programs} program(s) to {out_path}",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(rendered)

    # Exit code: 0 if found programs OR if explicitly empty (e.g. repo with no
    # programs is a valid scan target); non-zero only on bad input.
    return 0


if __name__ == "__main__":
    sys.exit(main())
