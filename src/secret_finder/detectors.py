"""Multi-layer secret detection engine for Secret Finder."""

from collections import Counter
from dataclasses import dataclass
import math
import re
from typing import Iterable

from secret_finder.models import DiffLine, Finding


@dataclass(frozen=True)
class SignatureRule:
    """Defines a Layer 1 regex signature rule for a known secret provider."""

    rule_id: str
    reason: str
    pattern: re.Pattern[str]


SIGNATURE_RULES: tuple[SignatureRule, ...] = (
    SignatureRule(
        rule_id="PRIVATE_KEY",
        reason="Cryptographic Private Key header",
        pattern=re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----"),
    ),
    SignatureRule(
        rule_id="AWS_ACCESS_KEY",
        reason="AWS Access Key ID pattern",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    SignatureRule(
        rule_id="GITHUB_TOKEN",
        reason="GitHub Personal Access Token pattern",
        pattern=re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"
        ),
    ),
    SignatureRule(
        rule_id="SLACK_TOKEN",
        reason="Slack API Token pattern",
        pattern=re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,250}\b"),
    ),
    SignatureRule(
        rule_id="STRIPE_KEY",
        reason="Stripe API Key pattern",
        pattern=re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b"),
    ),
    SignatureRule(
        rule_id="GOOGLE_API_KEY",
        reason="Google API Key pattern",
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ),
)

GENERIC_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b(
        [a-z0-9_.-]*
        (?:
            password | passwd | pwd |
            secret | client_?secret | jwt_?secret |
            api_?key | access_?key | private_?key |
            access_?token | auth_?token | bearer_?token | token |
            db_?pass
        )
        [a-z0-9_.-]*
    )
    \s*["']?\s*[:=]\s*
    (?:
        ["']([^"'\r\n]{8,})["']
        |
        ([^\s"'#;,)}\]]{8,})
    )
    """
)

QUOTED_CANDIDATE_RE = re.compile(r"""["']([^"'\s\r\n]{20,})["']""")

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

ENV_LOOKUP_PATTERNS: tuple[str, ...] = (
    "os.environ",
    "os.getenv",
    "process.env",
    "system.getenv",
    "env.get(",
    "env[",
    "viper.get",
    "dotenv",
)

PLACEHOLDER_SUBSTRINGS: tuple[str, ...] = (
    "changeme",
    "your_api_key",
    "your-api-key",
    "your_secret",
    "your-secret",
    "your_token",
    "your_password",
    "replace_me",
    "insert_key",
    "example",
    "placeholder",
    "todo",
    "fixme",
    "dummy",
    "sample",
    "xxxxxx",
    "******",
)

PLACEHOLDER_EXACT: frozenset[str] = frozenset(
    {
        "none",
        "null",
        "true",
        "false",
        "undefined",
        "default",
        "password",
        "secret",
        "api_key",
    }
)


def calculate_shannon_entropy(token: str) -> float:
    """Compute the Shannon entropy in bits per character for a given string."""
    if not token:
        return 0.0
    length = len(token)
    counts = Counter(token)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def redact_secret(secret: str) -> str:
    """Mask the interior characters of a secret string for safe display."""
    if secret.startswith("-----BEGIN ") and secret.endswith("-----"):
        return "-----BEGIN [REDACTED PRIVATE KEY]-----"
    if len(secret) <= 8:
        return "*" * len(secret)
    prefix = secret[:4]
    suffix = secret[-4:]
    mask_len = min(12, len(secret) - 8)
    return f"{prefix}{'*' * mask_len}{suffix}"


def redact_line_snippet(line_content: str, secret: str) -> str:
    """Return a trimmed code snippet with the detected secret value redacted."""
    stripped = line_content.strip()
    if not secret:
        return stripped
    return stripped.replace(secret, redact_secret(secret))


def _is_env_or_reference(line_content: str, value: str) -> bool:
    """Return True if the line or value represents an environment lookup or variable reference."""
    lower_line = line_content.lower()
    if any(marker in lower_line for marker in ENV_LOOKUP_PATTERNS):
        return True
    if value.startswith(("$", "${", "{{", "%(", "<", "[")):
        return True
    if value.endswith((">", "}}")) or "(" in value or ")" in value:
        return True
    return False


def _is_placeholder_or_non_secret(value: str) -> bool:
    """Return True if the candidate value is a known placeholder, URL, path, or UUID."""
    lower_val = value.strip().lower()
    if len(lower_val) < 8:
        return True
    if lower_val in PLACEHOLDER_EXACT:
        return True
    if any(sub in lower_val for sub in PLACEHOLDER_SUBSTRINGS):
        return True
    if len(set(lower_val)) <= 2:
        return True
    if UUID_RE.match(value):
        return True
    if lower_val.startswith(("http://", "https://", "ftp://", "ws://", "wss://", "git@", "mailto:")):
        return True
    if lower_val.startswith(("/", "./", "../", "~/", "c:\\", "file://")):
        return True
    if "/" in value and not value.endswith("="):
        return True
    return False


def _has_secret_character_diversity(token: str) -> bool:
    """Return True if the token has character class diversity typical of generated secrets."""
    has_lower = any(ch.islower() for ch in token)
    has_upper = any(ch.isupper() for ch in token)
    has_digit = any(ch.isdigit() for ch in token)
    has_symbol = any(not ch.isalnum() for ch in token)

    if any(ch in token for ch in (" ", "\t", "::")):
        return False

    classes = sum((has_lower, has_upper, has_digit, has_symbol))
    if classes >= 3 and has_digit:
        return True
    if has_lower and has_digit and all(ch in "0123456789abcdefABCDEF" for ch in token) and len(token) >= 32:
        return True
    return False


def _spans_overlap(span_a: tuple[int, int], span_b: tuple[int, int]) -> bool:
    """Return True if two half-open character intervals [start, end) overlap."""
    return max(span_a[0], span_b[0]) < min(span_a[1], span_b[1])


def scan_diff_line(diff_line: DiffLine, entropy_threshold: float = 4.0) -> list[Finding]:
    """Scan a single added diff line across all three detection layers."""
    line = diff_line.content
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", "//", "/*", "*")):
        if "-----BEGIN " not in stripped:
            return []

    findings: list[Finding] = []
    claimed_spans: list[tuple[int, int]] = []

    for rule in SIGNATURE_RULES:
        for match in rule.pattern.finditer(line):
            span = match.span()
            if any(_spans_overlap(span, existing) for existing in claimed_spans):
                continue
            secret_val = match.group(0)
            claimed_spans.append(span)
            findings.append(
                Finding(
                    file_path=diff_line.file_path,
                    line_number=diff_line.line_number,
                    rule_id=rule.rule_id,
                    reason=rule.reason,
                    snippet=redact_line_snippet(line, secret_val),
                )
            )

    for match in GENERIC_ASSIGNMENT_RE.finditer(line):
        value_group = 2 if match.group(2) is not None else 3
        secret_val = match.group(value_group)
        span = match.span(value_group)

        if any(_spans_overlap(span, existing) for existing in claimed_spans):
            continue
        if _is_env_or_reference(line, secret_val) or _is_placeholder_or_non_secret(secret_val):
            continue

        key_name = match.group(1).lower()
        if any(p in key_name for p in ("password", "passwd", "pwd", "db_pass")):
            reason = "Generic password assignment"
            rule_id = "GENERIC_PASSWORD"
        else:
            reason = "Generic secret or API key assignment"
            rule_id = "GENERIC_SECRET"

        claimed_spans.append(span)
        findings.append(
            Finding(
                file_path=diff_line.file_path,
                line_number=diff_line.line_number,
                rule_id=rule_id,
                reason=reason,
                snippet=redact_line_snippet(line, secret_val),
            )
        )

    for match in QUOTED_CANDIDATE_RE.finditer(line):
        candidate = match.group(1)
        span = match.span(1)

        if any(_spans_overlap(span, existing) for existing in claimed_spans):
            continue
        if _is_env_or_reference(line, candidate) or _is_placeholder_or_non_secret(candidate):
            continue
        if not _has_secret_character_diversity(candidate):
            continue

        entropy = calculate_shannon_entropy(candidate)
        if entropy >= entropy_threshold:
            claimed_spans.append(span)
            findings.append(
                Finding(
                    file_path=diff_line.file_path,
                    line_number=diff_line.line_number,
                    rule_id="HIGH_ENTROPY",
                    reason=f"High-entropy secret string (entropy: {entropy:.2f})",
                    snippet=redact_line_snippet(line, candidate),
                )
            )

    return findings


def scan_diff_lines(diff_lines: Iterable[DiffLine], entropy_threshold: float = 4.0) -> list[Finding]:
    """Scan an iterable of added diff lines and return all detected secret findings."""
    all_findings: list[Finding] = []
    for diff_line in diff_lines:
        all_findings.extend(scan_diff_line(diff_line, entropy_threshold=entropy_threshold))
    return all_findings
