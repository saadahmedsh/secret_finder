"""Automated tests for Secret Finder."""

import io
from pathlib import Path
import subprocess
import pytest

from secret_finder.cli import main
from secret_finder.diff_parser import (
    DiffSourceError,
    get_commit_diff,
    get_working_tree_diff,
    parse_unified_diff,
    read_diff_from_file,
)
from secret_finder.models import DiffLine


def test_cli_help_exits_cleanly() -> None:
    """Verify CLI parser initializes and handles arguments cleanly."""
    assert main([]) == 0


def test_diff_parser_tracks_files_hunks_and_line_numbers() -> None:
    """Verify multi-file, multi-hunk unified diff parsing and accurate line numbering."""
    sample_diff = "\n".join(
        [
            "diff --git a/src/config.py b/src/config.py",
            "index 1111111..2222222 100644",
            "--- a/src/config.py",
            "+++ b/src/config.py",
            "@@ -10,4 +15,5 @@ def load_config():",
            "     debug = False",
            "-    old_key = 'removed_line_should_be_ignored'",
            "+    api_key = 'added_on_line_16'",
            "     timeout = 30",
            "+    retries = 3",
            "@@ -40,0 +42,2 @@ def second_hunk():",
            "+    first_in_hunk = 'line_42'",
            "+    second_in_hunk = 'line_43'",
            "diff --git a/src/auth.py b/src/auth.py",
            "new file mode 100644",
            "--- /dev/null",
            "+++ b/src/auth.py",
            "@@ -0,0 +1,2 @@",
            "+TOKEN = 'new_file_line_1'",
            "+",
        ]
    )

    parsed = parse_unified_diff(sample_diff)

    assert parsed == [
        DiffLine(file_path="src/config.py", line_number=16, content="    api_key = 'added_on_line_16'"),
        DiffLine(file_path="src/config.py", line_number=18, content="    retries = 3"),
        DiffLine(file_path="src/config.py", line_number=42, content="    first_in_hunk = 'line_42'"),
        DiffLine(file_path="src/config.py", line_number=43, content="    second_in_hunk = 'line_43'"),
        DiffLine(file_path="src/auth.py", line_number=1, content="TOKEN = 'new_file_line_1'"),
        DiffLine(file_path="src/auth.py", line_number=2, content=""),
    ]


def test_diff_parser_skips_deleted_files_lockfiles_and_binaries() -> None:
    """Verify deleted files, lockfiles, and minified assets are skipped."""
    sample_diff = "\n".join(
        [
            "diff --git a/old_secrets.py b/old_secrets.py",
            "deleted file mode 100644",
            "--- a/old_secrets.py",
            "+++ /dev/null",
            "@@ -1,2 +0,0 @@",
            "-SECRET = 'deleted'",
            "diff --git a/uv.lock b/uv.lock",
            "--- a/uv.lock",
            "+++ b/uv.lock",
            "@@ -1,0 +1,2 @@",
            '+checksum = "sha256:abcdef1234567890"',
            "diff --git a/static/app.min.js b/static/app.min.js",
            "--- a/static/app.min.js",
            "+++ b/static/app.min.js",
            "@@ -1 +1 @@",
            "+var a='minified';",
            "diff --git a/real.py b/real.py",
            "--- a/real.py",
            "+++ b/real.py",
            "@@ -1,0 +1,1 @@",
            "+x = 1",
        ]
    )

    parsed = parse_unified_diff(sample_diff)
    assert parsed == [DiffLine(file_path="real.py", line_number=1, content="x = 1")]


def test_read_diff_from_file_and_stdin(tmp_path: Path) -> None:
    """Verify reading diff content from both a file path and stdin stream."""
    diff_content = "--- a/app.py\n+++ b/app.py\n@@ -1,0 +1,1 @@\n+hello = 1\n"
    diff_file = tmp_path / "sample.diff"
    diff_file.write_text(diff_content, encoding="utf-8")

    assert read_diff_from_file(str(diff_file)) == diff_content
    assert read_diff_from_file("-", stdin_stream=io.StringIO(diff_content)) == diff_content

    with pytest.raises(DiffSourceError, match="Diff file not found"):
        read_diff_from_file(str(tmp_path / "missing.diff"))


def test_git_commit_and_working_tree_diff_modes(tmp_path: Path) -> None:
    """Verify git commit diff and working tree diff ingestion plus error handling."""
    with pytest.raises(DiffSourceError, match="Git repository error"):
        get_working_tree_diff(cwd=tmp_path)

    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, check=True)

    tracked_file = tmp_path / "service.py"
    tracked_file.write_text("line1 = 'initial'\n", encoding="utf-8")
    subprocess.run(["git", "add", "service.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=tmp_path, check=True, capture_output=True)

    commit_hash = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    commit_diff = get_commit_diff(commit_hash, cwd=tmp_path)
    assert parse_unified_diff(commit_diff) == [
        DiffLine(file_path="service.py", line_number=1, content="line1 = 'initial'")
    ]

    tracked_file.write_text("line1 = 'initial'\nline2 = 'uncommitted'\n", encoding="utf-8")
    working_diff = get_working_tree_diff(cwd=tmp_path)
    assert parse_unified_diff(working_diff) == [
        DiffLine(file_path="service.py", line_number=2, content="line2 = 'uncommitted'")
    ]

    with pytest.raises(DiffSourceError, match="Git error for commit"):
        get_commit_diff("deadbeef999999999999", cwd=tmp_path)
