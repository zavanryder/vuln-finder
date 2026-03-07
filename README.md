# ZavanVulnFinder

Agent skill for discovering code vulnerabilities by bug class in snippets or codebases.

## Location

The skill lives at **`skills/vuln-discovery/`**.

## Usage

Ask the agent to find vulnerabilities and specify:

1. **Bug class(es)** — One or more types, or **ALL** for every supported type.  
   Examples: *deserialization*, *sql injection*, *prototype pollution*, *xss*, *ssrf*, *path traversal*, *hardcoded secrets*, etc.

2. **Target** — Either:
   - A **code snippet** (paste or point to a file), or  
   - A **codebase path** (e.g. `./src`, `backend/`) to scan.

**Supported languages:** Java, Python, Go, C#, PHP, Ruby, JavaScript, TypeScript.

### Example prompts

- “Find SQL injection and deserialization issues in `./api` (Python).”
- “Check this snippet for prototype pollution and XSS.” [paste code]
- “Run a full vulnerability check for ALL bug types on the `server/` directory.”

## Skill layout

| Path | Purpose |
|------|--------|
| `SKILL.md` | Workflow, inputs, and pointers to references/assets/scripts |
| `references/bug-classes.md` | Canonical bug-class IDs and “ALL” list |
| `references/patterns-by-language.md` | Sinks and dangerous APIs per language and bug class |
| `assets/report-template.md` | Output report structure |
| `scripts/grep-patterns.sh` | Optional first-pass grep for candidate lines |

The skill keeps `SKILL.md` short and pushes detail into references, assets, and scripts so the agent can load only what it needs.
