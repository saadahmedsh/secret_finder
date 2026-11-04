# Secret Finder

A lightweight, zero-dependency Python CLI tool that detects exposed secrets within Git changes (uncommitted working tree modifications, specific commits, or raw unified diffs).

---

## Quick Start (with `uv`)

### 1. Setup & Install
```bash
uv sync
```

### 2. Run the CLI

Secret Finder supports all three Git change input modes:

- **Scan uncommitted changes in the working directory (default):**
  ```bash
  uv run secret-finder
  ```
  *(Optional: pass `--repo <path>` to scan another Git repository directory)*

- **Scan a specific Git commit hash:**
  ```bash
  uv run secret-finder --commit <COMMIT_HASH>
  ```

- **Scan a `git diff` file or piped `stdin`:**
  ```bash
  uv run secret-finder --diff changes.diff
  git diff | uv run secret-finder --diff -
  ```

- **Output as JSON (for CI/CD pipelines):**
  ```bash
  uv run secret-finder --diff changes.diff --json
  ```

### Exit Codes
| Code | Meaning |
| :--- | :--- |
| `0` | Clean — no secrets detected |
| `1` | One or more potential secrets detected |
| `2` | Usage error or invalid Git/file input |

### Example Output
```text
Detected 2 potential secrets:

  1. src/config.py:16 [AWS_ACCESS_KEY]
     Reason:  AWS Access Key ID pattern
     Snippet: AWS_ACCESS_KEY_ID = "AKIA************MPLE"

  2. deploy/db.yaml:12 [GENERIC_PASSWORD]
     Reason:  Generic password assignment
     Snippet: db_password: "Sup3************s99!"
```

---

## Running Automated Tests

```bash
uv run pytest -v
```

---

## Architecture & Trade-Offs

The tool is structured as a 3-stage pipeline with zero third-party runtime dependencies:

1. **Diff Ingestion & Unified Diff Parser (`src/secret_finder/diff_parser.py`)**
   - Normalizes all inputs (`git diff HEAD`, `git show <commit>`, or file/`stdin`) into unified diff text with `--unified=0`.
   - Tracks `+++ b/<file>` headers and `@@ -old +new @@` hunk offsets to compute exact 1-based line numbers in the target file.
   - Emits **only added lines (`+`)** so removed lines (`-`) and surrounding context do not trigger false alarms when developers delete or rotate a secret.
   - Automatically skips deleted files (`/dev/null`), binary patches, lockfiles (`uv.lock`, `package-lock.json`, etc.), and minified bundles (`.min.js`).

2. **Multi-Layer Detection Engine (`src/secret_finder/detectors.py`)**
   - **Layer 1 — Known Provider Signatures (High Precision):** Matches structured credentials with fixed prefixes (AWS `AKIA`/`ASIA` keys, GitHub `ghp_`/`github_pat_` tokens, Slack `xox*` tokens, Stripe `sk_live_` keys, Google `AIza` keys, and `-----BEGIN ... PRIVATE KEY-----` headers).
   - **Layer 2 — Contextual Generic Assignments (Medium/High Precision):** Detects secret-related identifier names (`password`, `secret`, `api_key`, `access_token`, `db_pass`, etc.) assigned to string literals across Python, JS/TS, YAML, JSON, and `.env` syntax, while filtering out environment variable lookups (`os.environ`, `process.env`, `${VAR}`) and common placeholders (`changeme`, `your_api_key_here`, `example`, `todo`, `<secret>`).
   - **Layer 3 — Shannon Entropy Heuristics (Catch-All):** Computes Shannon entropy ($H = -\sum p_i \log_2 p_i$) on remaining quoted literals ($\ge 20$ chars). Flags strings with entropy $\ge 4.0$ bits/char and character-class diversity while excluding URLs, file paths, and UUIDs.
   - **Span Deduplication & Redaction:** Character spans claimed by higher-precision layers are skipped by lower layers to prevent duplicate alerts on the same token. All secrets are masked before printing.

3. **CLI & Formatter (`src/secret_finder/cli.py`)**
   - Provides human-readable and `--json` output modes with deterministic exit codes for pre-commit hooks or CI checks.

---

## Where It Fails (Known Limitations & Edge Cases)

Because this tool uses static line-by-line heuristics rather than full program data-flow analysis or live credential verification, it fails in the following scenarios:

1. **Multi-Line Secrets Without Standard Headers:**
   - The parser evaluates added lines individually. While `-----BEGIN ... PRIVATE KEY-----` is caught via its header on line 1, a raw multi-line secret or base64 payload split across multiple lines without a header or secret-named variable assignment can evade single-line regex and length thresholds.
2. **Secrets Split or Constructed Dynamically:**
   - String concatenation (`key = "AKIA" + "IOSFODNN7EXAMPLE"`), character arrays, or secrets decoded at runtime (`base64.b64decode(...)`) are not reconstructed statically.
3. **Low-Entropy Passwords in Non-Descriptive Variable Names:**
   - If a developer assigns a weak, low-entropy dictionary password to an innocuous variable name (e.g., `val = "Summer2026!"`), Layer 1 misses it (no provider prefix), Layer 2 misses it (variable name does not suggest a secret), and Layer 3 misses it (too short / low entropy).
4. **High-Entropy Non-Secret Literals (False Positives):**
   - Random-looking test fixtures, inline cryptographic public keys/hashes, JWT test payloads, or obfuscated regex/CSS strings that exceed 20 characters with mixed character classes and entropy $\ge 4.0$ will be flagged by Layer 3.
5. **Ignored Lockfiles or Custom Binary/Encoded Formats:**
   - Lockfiles (`uv.lock`, `package-lock.json`) and binary files are skipped to avoid high false-positive noise from integrity hashes; a secret accidentally embedded inside a skipped file or a binary archive will not be scanned.
6. **Historical Git Commits Outside the Target Diff:**
   - By design, the tool inspects a single diff, commit, or working tree state rather than walking the entire Git reflog/history graph.

