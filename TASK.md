# Secret Finder — Coding Challenge

Developers sometimes commit passwords or keys by mistake. Your task is to build a CLI tool from scratch that detects exposed secrets within a Git change.

## Requirements

### Input
The CLI tool must accept at least one of the following inputs:
- A `git diff` (via file path or `stdin`)
- A specific Git commit hash
- Current uncommitted changes in the working directory

### Output
- A formatted list of findings containing:
  - **File path** and **line number**
  - **Short reason** for each flag (e.g., high entropy, AWS Access Key pattern, generic password assignment)

## Rules & Constraints
- **Format:** CLI only. Start from scratch.
- **Tech Stack:** Use any programming language, libraries, tools, or AI assistants you prefer.
- **Time Limit:** Approximately 30 minutes.
- **Deliverables:**
  1. Source code for the CLI tool.
  2. A concise `README.md` explaining **how to run the tool** and **where it fails** (known limitations/edge cases).
  3. **2–3 automated tests** verifying core functionality.
  4. **AI Usage Logs:** If you use AI, include your prompts or chat logs in the repository.
- **Follow-up:** Be prepared to walk through and explain your architecture and trade-offs later.