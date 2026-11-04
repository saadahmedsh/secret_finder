"""Automated tests for Secret Finder."""

import io
import json
from pathlib import Path
import subprocess
import pytest

from secret_finder.cli import main
from secret_finder.detectors import scan_diff_line, scan_diff_lines
from secret_finder.diff_parser import (
    DiffSourceError,
    get_commit_diff,
    get_working_tree_diff,
    parse_unified_diff,
    read_diff_from_file,
)
from secret_finder.models import DiffLine


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


def test_detectors_flag_provider_generic_and_high_entropy_secrets() -> None:
    """Verify Layer 1 signatures, Layer 2 generic assignments, Layer 3 entropy, deduplication, and redaction."""
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    gh_token = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    slack_token = "xoxb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
    stripe_key = "sk_live_" + "51H8b9c2e3f4g5h6i7j8k9l0m1n2o3p4q"
    google_key = "AIza" + "SyDa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    private_key_header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    generic_pass = "Sup3r$ecretProdPass99!"
    entropy_blob = "k9#mP2$vL8@nQ5!xR7&wZ4^yT1*uB3"

    lines = [
        DiffLine("aws.py", 10, f'aws_secret = "{aws_key}"'),
        DiffLine("gh.py", 20, f'token = "{gh_token}"'),
        DiffLine("slack.py", 30, f'SLACK = "{slack_token}"'),
        DiffLine("billing.py", 40, f'STRIPE = "{stripe_key}"'),
        DiffLine("gcp.py", 50, f'GCP_KEY = "{google_key}"'),
        DiffLine("id_rsa", 1, private_key_header),
        DiffLine("db.yaml", 12, f'db_password: "{generic_pass}"'),
        DiffLine("crypto.py", 88, f'SIGNING_BLOB = "{entropy_blob}"'),
    ]

    findings = scan_diff_lines(lines)
    assert len(findings) == 8

    rule_ids = [f.rule_id for f in findings]
    assert rule_ids == [
        "AWS_ACCESS_KEY",
        "GITHUB_TOKEN",
        "SLACK_TOKEN",
        "STRIPE_KEY",
        "GOOGLE_API_KEY",
        "PRIVATE_KEY",
        "GENERIC_PASSWORD",
        "HIGH_ENTROPY",
    ]

    for finding in findings:
        assert aws_key not in finding.snippet
        assert gh_token not in finding.snippet
        assert generic_pass not in finding.snippet
        assert entropy_blob not in finding.snippet


def test_detectors_suppress_false_positives() -> None:
    """Verify environment lookups, placeholders, URLs, file paths, and UUIDs are not flagged."""
    benign_lines = [
        DiffLine("config.py", 1, 'api_key = os.environ["SECRET_API_KEY"]'),
        DiffLine("config.py", 2, "password = os.getenv('DB_PASSWORD')"),
        DiffLine("config.js", 3, "const secret = process.env.JWT_SECRET;"),
        DiffLine("config.yaml", 4, "password: ${DB_PASSWORD}"),
        DiffLine("settings.py", 5, 'password = "changeme"'),
        DiffLine("settings.py", 6, 'api_key = "your_api_key_here"'),
        DiffLine("settings.py", 7, 'secret = "example_secret_value"'),
        DiffLine("settings.py", 8, 'token = "TODO_replace_before_prod"'),
        DiffLine("settings.py", 9, 'password = "xxxxxxxxxxxx"'),
        DiffLine("settings.py", 10, 'secret = "<secret>"'),
        DiffLine("client.py", 11, 'endpoint = "https://api.example.com/v1/users/authenticate"'),
        DiffLine("paths.py", 12, 'cert_path = "/usr/local/share/ca-certificates/root.crt"'),
        DiffLine("models.py", 13, 'request_id = "550e8400-e29b-41d4-a716-446655440000"'),
    ]

    for line in benign_lines:
        assert scan_diff_line(line) == [], f"Unexpected finding on benign line: {line}"


def test_cli_end_to_end_reporting_json_and_exit_codes(tmp_path: Path) -> None:
    """Verify CLI text/JSON reporting, required fields, and exit codes 0, 1, and 2."""
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    diff_with_secret = "\n".join(
        [
            "diff --git a/src/settings.py b/src/settings.py",
            "--- a/src/settings.py",
            "+++ b/src/settings.py",
            "@@ -4,0 +5,2 @@",
            f'+AWS_KEY = "{aws_key}"',
            '+SAFE_VAR = "hello"',
        ]
    )

    out_text = io.StringIO()
    exit_code = main(
        ["--diff", "-"],
        stdin_stream=io.StringIO(diff_with_secret),
        stdout_stream=out_text,
    )
    report = out_text.getvalue()

    assert exit_code == 1
    assert "src/settings.py:5" in report
    assert "AWS Access Key ID pattern" in report
    assert aws_key not in report
    assert "AKIA************MPLE" in report

    out_json = io.StringIO()
    json_exit_code = main(
        ["--diff", "-", "--json"],
        stdin_stream=io.StringIO(diff_with_secret),
        stdout_stream=out_json,
    )
    payload = json.loads(out_json.getvalue())

    assert json_exit_code == 1
    assert payload["count"] == 1
    assert payload["findings"][0]["file_path"] == "src/settings.py"
    assert payload["findings"][0]["line_number"] == 5
    assert payload["findings"][0]["rule_id"] == "AWS_ACCESS_KEY"

    clean_diff = "--- a/app.py\n+++ b/app.py\n@@ -1,0 +1,1 @@\n+x = 42\n"
    out_clean = io.StringIO()
    clean_exit_code = main(
        ["--diff", "-"],
        stdin_stream=io.StringIO(clean_diff),
        stdout_stream=out_clean,
    )
    assert clean_exit_code == 0
    assert "No secrets detected." in out_clean.getvalue()

    err_stream = io.StringIO()
    err_exit_code = main(
        ["--diff", str(tmp_path / "nonexistent.diff")],
        stderr_stream=err_stream,
    )
    assert err_exit_code == 2
    assert "Error:" in err_stream.getvalue()
