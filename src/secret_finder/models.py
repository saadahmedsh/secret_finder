"""Data models for Secret Finder."""

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class DiffLine:
    """Represents a single added line extracted from a unified Git diff."""

    file_path: str
    line_number: int
    content: str


@dataclass(frozen=True)
class Finding:
    """Represents a detected secret finding in a specific file and line."""

    file_path: str
    line_number: int
    rule_id: str
    reason: str
    snippet: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to a dictionary for JSON output."""
        return asdict(self)

