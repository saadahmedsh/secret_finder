"""Automated tests for Secret Finder."""

from secret_finder.cli import main


def test_cli_help_exits_cleanly() -> None:
    """Verify CLI parser initializes and handles arguments cleanly."""
    assert main([]) == 0

