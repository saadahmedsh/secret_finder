"""Command-line interface and output formatting for Secret Finder."""

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence, TextIO

from secret_finder.detectors import scan_diff_lines
from secret_finder.diff_parser import (
    DiffSourceError,
    get_commit_diff,
    get_working_tree_diff,
    parse_unified_diff,
    read_diff_from_file,
)
from secret_finder.models import Finding


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
        "--repo",
        metavar="DIR",
        default=None,
        help="Path to the Git repository directory (defaults to current working directory).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as formatted JSON.",
    )
    return parser


def format_findings_text(findings: Sequence[Finding]) -> str:
    """Format findings into a human-readable report showing file, line, reason, and snippet."""
    if not findings:
        return "No secrets detected."

    plural = "s" if len(findings) != 1 else ""
    lines = [f"Detected {len(findings)} potential secret{plural}:", ""]
    for idx, finding in enumerate(findings, start=1):
        lines.append(
            f"  {idx}. {finding.file_path}:{finding.line_number} [{finding.rule_id}]"
        )
        lines.append(f"     Reason:  {finding.reason}")
        lines.append(f"     Snippet: {finding.snippet}")
        lines.append("")
    return "\n".join(lines).rstrip()


def format_findings_json(findings: Sequence[Finding]) -> str:
    """Format findings as a JSON string."""
    payload = {
        "count": len(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2)


def _resolve_diff_text(
    args: argparse.Namespace,
    stdin_stream: TextIO | None = None,
    cwd: str | Path | None = None,
) -> str:
    """Retrieve raw unified diff text based on parsed CLI arguments."""
    target_cwd = args.repo if args.repo is not None else cwd
    if args.diff is not None:
        return read_diff_from_file(args.diff, stdin_stream=stdin_stream)
    if args.commit is not None:
        return get_commit_diff(args.commit, cwd=target_cwd)
    return get_working_tree_diff(cwd=target_cwd)


def main(
    argv: Sequence[str] | None = None,
    stdin_stream: TextIO | None = None,
    stdout_stream: TextIO | None = None,
    stderr_stream: TextIO | None = None,
    cwd: str | Path | None = None,
) -> int:
    """Run the secret-finder CLI and return the process exit code.

    Exit codes:
        0: No secrets detected.
        1: One or more secrets detected.
        2: CLI usage or diff source error.
    """
    out = stdout_stream if stdout_stream is not None else sys.stdout
    err = stderr_stream if stderr_stream is not None else sys.stderr

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        diff_text = _resolve_diff_text(args, stdin_stream=stdin_stream, cwd=cwd)
    except DiffSourceError as exc:
        print(f"Error: {exc}", file=err)
        return 2

    diff_lines = parse_unified_diff(diff_text)
    findings = scan_diff_lines(diff_lines)

    if args.json:
        print(format_findings_json(findings), file=out)
    else:
        print(format_findings_text(findings), file=out)

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
