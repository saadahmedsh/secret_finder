# AI Usage Log

This document records the prompts, iterative workflow, and architectural decisions made with AI assistance (Google Antigravity) during the development of `secret-finder`.

---

## 1. Prompts & Interaction Log

1. **Prompt 1:**
   > *"Have a look at the task at hand and propose solutions"*
   - **Outcome:** Reviewed `TASK.md`, inspected installed runtimes on the machine (Python 3.13 / 3.12 and Node.js v24), and proposed a 3-stage pipeline architecture (Diff Ingestion & Parser, 3-Layer Detection Engine, and CLI Reporter) with three implementation options (Zero-Dependency Python CLI, Zero-Dependency Node/TS CLI, and Config-Driven Hybrid Scanner).

2. **Prompt 2:**
   > *"Recommended options looks good to me, divide into phases few changes I want use uv for quick setup. Do not write any code yet"*
   - **Outcome:** Designed a 5-phase implementation plan using `uv` (`uv init --package`, `uv add --dev pytest`, `uv run secret-finder`) without writing code:
     - Phase 1: Project Initialization with `uv`
     - Phase 2: Diff Ingestion & Unified Diff Parser
     - Phase 3: Multi-Layer Detection Engine
     - Phase 4: CLI Interface & Reporting
     - Phase 5: Automated Tests & Documentation

3. **Prompt 3:**
   > *"I would also like an acceptance criteria for each phase"*
   - **Outcome:** Defined explicit, testable Acceptance Criteria checklists for each of the 5 phases before writing any code.

4. **Prompt 4:**
   > *"start with phase 1"*
   - **Outcome:** Initialized the `uv` package in `secret_finder/`, configured `[project.scripts]` (`secret-finder = "secret_finder.cli:main"`), added `pytest` as a dev dependency, and created the core dataclasses (`DiffLine`, `Finding`) and initial CLI entrypoint.

5. **Prompt 5:**
   > *"add a gitnore first"*
   - **Outcome:** Added `.gitignore` excluding `.venv/`, `__pycache__/`, `.pytest_cache/`, build artifacts, and IDE files.

6. **Prompt 6:**
   > *"phase 2"*
   - **Outcome:** Implemented `src/secret_finder/diff_parser.py` supporting `--diff <file|->`, `--commit <hash>`, and uncommitted working tree diffs, along with hunk line-number tracking and lockfile/deleted-file filtering, plus unit tests.

7. **Prompt 7:**
   > *"I don't want inline comments, only block and docstrings"*
   - **Outcome:** Refactored existing code and tests to remove all inline `#` comments and rely exclusively on module, class, and function docstrings. Applied this rule to all subsequent phases.

8. **Prompt 8:**
   > *"Move to phase 3"*
   - **Outcome:** Implemented `src/secret_finder/detectors.py` with Layer 1 provider regex signatures, Layer 2 generic secret/password assignments, Layer 3 Shannon entropy heuristics, false-positive allowlisting (env vars, placeholders, URLs, paths, UUIDs), span-based deduplication, and secret redaction.

9. **Prompt 9:**
   > *"yeah"* (Proceed to Phase 4)
   - **Outcome:** Implemented `src/secret_finder/cli.py` with human-readable and `--json` formatting, plus exit codes `0`, `1`, and `2`, and added end-to-end CLI tests.

10. **Prompt 10:**
    > *"Yeah"* (Proceed to Phase 5)
    - **Outcome:** Completed `README.md` (usage, architecture, trade-offs, and known limitations) and `AI_USAGE.md`, and verified the full `pytest` suite.

---

## 2. Key Architectural Decisions & Trade-Offs

- **Added Lines Only (`+`):** Scanning context or removed (`-`) lines causes noisy false positives when a commit is specifically removing a leaked secret. Restricting detection to added lines keeps the tool focused on newly introduced risk.
- **Layered Detection with Span Deduplication:** Pure regex misses custom secrets; pure entropy flags too many false positives and gives vague reasons. Combining Layer 1 (provider signatures), Layer 2 (contextual variable names), and Layer 3 (entropy fallback) with span-based deduplication ensures every secret gets the most specific reason possible without duplicate alerts.
- **Zero Runtime Dependencies:** Using only Python's standard library (`re`, `math`, `subprocess`, `argparse`, `dataclasses`, `json`) ensures instant portability while `uv` + `pytest` provides fast, reproducible developer workflows.

