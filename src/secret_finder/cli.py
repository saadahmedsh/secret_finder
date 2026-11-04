"""Command-line interface for Secret Finder."""

import argparse
from typing import Sequence


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="secret-finder",
        description="Detect exposed secrets within Git changes (diffs, commits, or working tree).",
    )
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument(
        "--diff",
        metavar="PATH",
        help="Path to a unified diff file, or '-' to read from stdin.",
    )
    source_group.add_argument(
        "--commit",
        metavar="HASH",
        help="Scan changes introduced by a specific Git commit hash.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as formatted JSON.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entrypoint for the secret-finder CLI."""
    parser = build_parser()
    parser.parse_args(argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

