# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ZavanVulnFinder is a Claude Code agent skill for discovering code vulnerabilities by bug class in snippets or codebases. The skill supports 37 bug classes (including injection, access control, memory safety, CI/CD, and supply chain categories) across 12 languages (Java, Python, Go, C#, PHP, Ruby, JavaScript, TypeScript, C/C++, Kotlin, GitHub Actions, Shell).

## Commands

- Run the Python entry point: `uv run main.py`
- Run the first-pass candidate scanner: `bash skills/vuln-discovery/scripts/grep-patterns.sh [directory] [language] [class]`
  - Language filter: `py`, `php`, `rb`, `js`, `ts`, `java`, `go`, `cs`, `kt`, `c`, `cpp`, `sh`, `yml`
  - Class filter: `injection`, `access`, `memory`, `cicd`, `secrets`, `crypto`, `ssrf`, `upload`
  - Uses `rg` (ripgrep) when available, falls back to `grep`

## Architecture

The skill lives entirely under `skills/vuln-discovery/` and follows a layered reference design:

- **`SKILL.md`** -- Main skill definition: workflow steps, inputs, rules, and resource pointers. This is the entry point the agent reads when the skill is invoked.
- **`references/`** -- Lookup tables loaded on demand by domain:
  - `bug-classes.md` -- Canonical bug-class IDs with CWE mappings, user-term-to-ID aliases, and the ordered "ALL" list.
  - `patterns-web.md` -- Sinks and dangerous APIs for injection, XSS, SSRF, deserialization, secrets, crypto, file upload per language.
  - `patterns-access-control.md` -- Authentication, authorization, CSRF, CORS, JWT/session patterns per language and framework.
  - `patterns-memory-safety.md` -- Buffer overflow, OOB read/write, use-after-free, integer overflow, format string for C/C++.
  - `patterns-ci-cd.md` -- GitHub Actions injection, permission abuse, artifact poisoning, unsafe triggers, shell script issues.
  - `patterns-resource-exhaustion.md` -- ReDoS, unbounded queries, upload size, GraphQL depth, rate limiting.
  - `exploit-chains.md` -- Common chain patterns and how to outline/document them in reports.
  - `poc-web.md` -- PoC guidance for HTTP/API endpoint vulnerabilities.
  - `poc-local-file.md` -- PoC guidance for file parsing, archive extraction, local exploitation.
  - `poc-ci-cd.md` -- PoC guidance for CI/CD and workflow vulnerabilities.
  - `poc-memory.md` -- PoC guidance for memory corruption vulnerabilities.
- **`assets/`** -- Templates:
  - `report-template.md` -- Report structure with CWE, confidence, source/sink, exploitability context.
  - `poc-script-template.py` -- Starter Python script for PoC (uses `requests`, argparse, config placeholders).
- **`scripts/grep-patterns.sh`** -- First-pass candidate search with rg/grep, filterable by language and bug-class family.

## Skill Workflow

1. Resolve user's bug-class terms to canonical IDs via `bug-classes.md`
2. Identify target languages from file extensions or user hint
3. Load relevant domain-specific pattern references
4. Search and analyze (grep first-pass for codebases, then source-to-sink contextual analysis)
5. Evaluate exploit chains if multiple findings exist (via `exploit-chains.md`)
6. Generate report using `report-template.md` (includes CWE, confidence, source, sink, exploitability)
7. For Critical/High findings: suggest PoC payload, gather user details, build PoC using domain-specific guide

## Key Rules

- No false positives by default -- only report when there is a plausible exploitation path
- Every finding includes CWE, confidence level, and source-to-sink trace
- PoC scripts are only built for Critical/High severity findings or chains
- The `chips/` directory is a test target (vulnerable Node.js app) and is git-ignored
