# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ZavanVulnFinder is a Claude Code agent skill for discovering code vulnerabilities by bug class in snippets or codebases. The skill supports 18 bug classes (SQL injection, deserialization, XSS, SSRF, etc.) across 8 languages (Java, Python, Go, C#, PHP, Ruby, JavaScript, TypeScript).

## Commands

- Run the Python entry point: `uv run main.py`
- Run the grep-based first-pass scanner: `bash skills/vuln-discovery/scripts/grep-patterns.sh [directory] [language]`
  - Language filter options: `py`, `php`, `rb`, `js`, `ts`, `java`, `go`, `cs`

## Architecture

The skill lives entirely under `skills/vuln-discovery/` and follows a layered reference design:

- **`SKILL.md`** -- Main skill definition: workflow steps, inputs, rules, and resource pointers. This is the entry point the agent reads when the skill is invoked.
- **`references/`** -- Lookup tables loaded on demand:
  - `bug-classes.md` -- Canonical bug-class IDs, user-term-to-ID mapping, and the ordered "ALL" list.
  - `patterns-by-language.md` -- Sinks and dangerous APIs organized by language then bug class. This is the core pattern reference for analysis.
  - `exploit-chains.md` -- Common chain patterns (e.g. SSRF -> metadata -> RCE) and how to outline/document them in reports.
  - `poc-guide.md` -- When/how to suggest PoC payloads and iteratively build Python PoC scripts with the user.
- **`assets/`** -- Templates:
  - `report-template.md` -- Report structure with finding blocks, optional exploit chain section, and PoC section.
  - `poc-script-template.py` -- Starter Python script for PoC (uses `requests`, argparse, config placeholders).
- **`scripts/grep-patterns.sh`** -- Optional first-pass grep over a codebase for candidate dangerous API calls.

## Skill Workflow

1. Resolve user's bug-class terms to canonical IDs via `bug-classes.md`
2. Identify target languages from file extensions or user hint
3. Load relevant sink/pattern sections from `patterns-by-language.md`
4. Search and analyze (grep first-pass for codebases, then contextual analysis)
5. Evaluate exploit chains if multiple findings exist (via `exploit-chains.md`)
6. Generate report using `report-template.md`
7. For Critical/High findings: suggest PoC payload, gather user details, build Python PoC from template

## Key Rules

- No false positives by default -- only report when there is a plausible exploitation path
- PoC scripts are only built for Critical/High severity findings or chains
- The `chips/` directory is a test target (vulnerable Node.js app) and is git-ignored
