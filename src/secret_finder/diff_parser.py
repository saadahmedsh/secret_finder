"""Unified diff ingestion and parsing for Secret Finder."""

from pathlib import Path
import re
import subprocess
import sys
from typing import TextIO

from secret_finder.models import DiffLine

HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

IGNORED_LOCKFILES = frozenset(
    {
        "uv.lock",
        "package-lock.json",
        "poetry.lock",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Cargo.lock",
        "Gemfile.lock",
        "composer.lock",
    }
)

IGNORED_SUFFIXES = (".min.js", ".min.css", ".bundle.js", ".map")


class DiffSourceError(Exception):
    """Raised when a diff input source cannot be read or retrieved from Git."""


def should_skip_file(file_path: str) -> bool:
    """Return True if the file path is /dev/null, a lockfile, or minified asset."""
    if not file_path or file_path == "/dev/null":
        return True
    normalized = file_path.replace("\\", "/")
    basename = normalized.rsplit("/", maxsplit=1)[-1]
    if basename in IGNORED_LOCKFILES:
        return True
    if basename.endswith(IGNORED_SUFFIXES):
        return True
    return False


def _normalize_diff_path(raw_path: str) -> str:
    """Normalize the target file path from a '+++ ' unified diff header.

    Strips optional tab-separated timestamps and leading 'b/' prefixes.
    """
    cleaned = raw_path.strip()
    if "\t" in cleaned:
        cleaned = cleaned.split("\t", maxsplit=1)[0]
    if cleaned.startswith("b/"):
        return cleaned[2:]
    return cleaned


def parse_unified_diff(diff_text: str) -> list[DiffLine]:
    """Parse unified diff text and return only added lines with file and line numbers."""
    added_lines: list[DiffLine] = []
    current_file: str | None = None
    current_line: int | None = None

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("diff --git "):
            current_file = None
            current_line = None
            continue

        if raw_line.startswith("Binary files ") or raw_line.startswith("GIT binary patch"):
            current_file = None
            current_line = None
            continue

        if raw_line.startswith("--- "):
            continue

        if raw_line.startswith("+++ "):
            target_path = _normalize_diff_path(raw_line[4:])
            if should_skip_file(target_path):
                current_file = None
            else:
                current_file = target_path
            current_line = None
            continue

        hunk_match = HUNK_HEADER_RE.match(raw_line)
        if hunk_match:
            if current_file is not None:
                current_line = int(hunk_match.group(1))
            continue

        if current_file is None or current_line is None:
            continue

        if raw_line.startswith("+"):
            added_lines.append(
                DiffLine(
                    file_path=current_file,
                    line_number=current_line,
                    content=raw_line[1:],
                )
            )
            current_line += 1
        elif raw_line.startswith(" "):
            current_line += 1
        elif raw_line.startswith("-") or raw_line.startswith("\\"):
            continue

    return added_lines


def read_diff_from_file(path: str, stdin_stream: TextIO | None = None) -> str:
    """Read unified diff content from a file path or '-' for stdin."""
    if path == "-":
        stream = stdin_stream if stdin_stream is not None else sys.stdin
        return stream.read()

    file_path = Path(path)
    if not file_path.exists():
        raise DiffSourceError(f"Diff file not found: {path}")
    if not file_path.is_file():
        raise DiffSourceError(f"Diff path is not a file: {path}")

    try:
        return file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise DiffSourceError(f"Failed to read diff file '{path}': {exc}") from exc


def _run_git(args: list[str], cwd: str | Path | None = None) -> subprocess.CompletedProcess[str]:
    """Execute a git command and return the completed process."""
    try:
        return subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        raise DiffSourceError("Git executable not found in PATH.") from exc


def get_commit_diff(commit_hash: str, cwd: str | Path | None = None) -> str:
    """Retrieve unified diff for a specific Git commit hash."""
    cleaned_hash = commit_hash.strip()
    if not cleaned_hash or cleaned_hash.startswith("-"):
        raise DiffSourceError(f"Invalid Git commit reference: '{commit_hash}'")

    result = _run_git(["show", "--format=", "--unified=0", "--no-color", cleaned_hash], cwd=cwd)
    if result.returncode != 0:
        err_msg = result.stderr.strip() or f"Failed to inspect commit '{cleaned_hash}'"
        raise DiffSourceError(f"Git error for commit '{cleaned_hash}': {err_msg}")
    return result.stdout


def _build_untracked_files_diff(cwd: str | Path | None = None) -> str:
    """Build synthetic unified diff sections for untracked, non-ignored working tree files."""
    untracked_proc = _run_git(["ls-files", "--others", "--exclude-standard"], cwd=cwd)
    if untracked_proc.returncode != 0 or not untracked_proc.stdout.strip():
        return ""

    base_dir = Path(cwd) if cwd is not None else Path.cwd()
    sections: list[str] = []

    for rel_path in untracked_proc.stdout.splitlines():
        rel_clean = rel_path.strip()
        if not rel_clean or should_skip_file(rel_clean):
            continue
        full_path = base_dir / rel_clean
        if not full_path.is_file():
            continue
        try:
            raw_bytes = full_path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw_bytes[:8192]:
            continue
        text = raw_bytes.decode("utf-8", errors="replace")
        file_lines = text.splitlines()
        if not file_lines:
            continue
        added_body = "\n".join(f"+{line}" for line in file_lines)
        sections.append(
            f"diff --git a/{rel_clean} b/{rel_clean}\n"
            f"--- /dev/null\n"
            f"+++ b/{rel_clean}\n"
            f"@@ -0,0 +1,{len(file_lines)} @@\n"
            f"{added_body}"
        )

    return "\n".join(sections)


def get_working_tree_diff(cwd: str | Path | None = None) -> str:
    """Retrieve unified diff for uncommitted changes (staged, unstaged, and untracked) in the working directory.

    Diffs tracked files against HEAD when available, falling back to combining staged and
    unstaged diffs for newly initialized repositories with an unborn HEAD, and appends
    untracked non-ignored files.
    """
    check_repo = _run_git(["rev-parse", "--is-inside-work-tree"], cwd=cwd)
    if check_repo.returncode != 0:
        err_msg = check_repo.stderr.strip() or "Not inside a Git repository."
        raise DiffSourceError(f"Git repository error: {err_msg}")

    untracked_diff = _build_untracked_files_diff(cwd=cwd)

    head_diff = _run_git(["diff", "--unified=0", "--no-color", "HEAD"], cwd=cwd)
    if head_diff.returncode == 0:
        return f"{head_diff.stdout}\n{untracked_diff}".strip()

    unstaged = _run_git(["diff", "--unified=0", "--no-color"], cwd=cwd)
    staged = _run_git(["diff", "--cached", "--unified=0", "--no-color"], cwd=cwd)
    if unstaged.returncode != 0 or staged.returncode != 0:
        err_msg = unstaged.stderr.strip() or staged.stderr.strip() or "Unable to read working tree diff."
        raise DiffSourceError(f"Git diff error: {err_msg}")

    return f"{staged.stdout}\n{unstaged.stdout}\n{untracked_diff}".strip()
