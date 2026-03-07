---
name: vuln-discovery
description: Discovers code vulnerabilities by bug class (e.g. deserialization, SQL injection, prototype pollution) in snippets or codebases. Use when the user asks to find vulnerabilities, security issues, or to audit code for specific bug types in Java, Python, Go, C#, PHP, Ruby, JavaScript, or TypeScript.
---

# Vulnerability Discovery

Finds security issues in code based on user-specified bug classes and supported languages (Java, Python, Go, C#, PHP, Ruby, JavaScript, TypeScript).

## Inputs

1. **Bug class(es)**  
   One or more types (e.g. `deserialization`, `sql injection`, `prototype pollution`) or **ALL** for every supported type.

2. **Target**  
   A code snippet (inline or pasted) or a codebase path/directory to examine.

## Workflow

1. **Resolve bug classes**  
   If the user said "ALL", use the full list from [references/bug-classes.md](references/bug-classes.md). Otherwise map the user’s terms to the canonical IDs in that file (e.g. "sql injection" → `sql-injection`).

2. **Identify languages**  
   Infer from file extensions or user hint. Supported: Java, Python, Go, C#, PHP, Ruby, JavaScript, TypeScript.

3. **Load patterns**  
   For each relevant language and chosen bug class, read [references/patterns-by-language.md](references/patterns-by-language.md) and use the sections for that language and the bug classes you’re checking.

4. **Search and analyze**  
   - For a **snippet**: analyze the provided code against the patterns for the chosen bug classes and languages.  
   - For a **codebase**: search for dangerous APIs, sinks, and patterns (e.g. `eval`, `unserialize`, `execute` with string concatenation, `child_process.exec`, `__proto__`/`constructor.prototype`). Use [scripts/grep-patterns.sh](scripts/grep-patterns.sh) for a first pass if helpful; then confirm each finding in context (data flow, sanitization, configuration).

5. **Evaluate exploit chains**  
   If two or more distinct vulnerabilities were found, consider whether they can be chained for greater impact (e.g. RCE, critical data exfiltration, privilege escalation). Use [references/exploit-chains.md](references/exploit-chains.md) for common chain patterns and how to outline a potential exploit. If a viable chain exists, add an **Exploit chain** section to the report with an outline and flow.

6. **Report**  
   Use [assets/report-template.md](assets/report-template.md) and fill one finding per issue: location, bug class, severity, snippet, and remediation. When an exploit chain was identified, include the optional Exploit chain section from the template.

7. **Proof of concept (Critical / High only)**  
   For any finding rated **Critical** or **High**, or for any **exploit chain** whose result is Critical or High (e.g. RCE, high-value data exfiltration), **suggest a proof-of-concept payload** and **offer to build a fully functional PoC script in Python** with the user. Follow [references/poc-guide.md](references/poc-guide.md): ask the user for relevant URLs, parameters, and other details (e.g. where user-controlled data is injected), then iteratively build the script. Use [assets/poc-script-template.py](assets/poc-script-template.py) as the starting structure.

## Rules

- **No false positives by default.** Only report when there is a plausible path to exploitation (e.g. user/source data reaches a sink without proper validation or encoding). Note “possible” or “needs review” when uncertain.
- **One language per finding.** If the same bug appears in multiple files, you may group by bug class but list each location.
- **Prefer references over long text.** Keep SKILL.md short; use `references/bug-classes.md` and `references/patterns-by-language.md` for definitions and patterns. Use `scripts/grep-patterns.sh` instead of hand-listing every pattern in the skill.
- **PoC for Critical/High.** For Critical or High findings, or chains with Critical/High impact, always suggest a PoC payload and work with the user to build a functional Python PoC (gather URLs and injection points first).

## Resources

| Resource | When to use |
|----------|-------------|
| [references/bug-classes.md](references/bug-classes.md) | Resolve "ALL" or user bug-class names; get canonical list and short descriptions. |
| [references/patterns-by-language.md](references/patterns-by-language.md) | Get sinks, dangerous APIs, and pattern hints per language and bug class. |
| [references/exploit-chains.md](references/exploit-chains.md) | Evaluate and document exploit chains when multiple findings exist. |
| [references/poc-guide.md](references/poc-guide.md) | When and how to suggest PoC, what to ask the user, and how to build a Python PoC script. |
| [assets/report-template.md](assets/report-template.md) | Structure the final vulnerability report (including optional Exploit chain section). |
| [assets/poc-script-template.py](assets/poc-script-template.py) | Starting structure for a Python PoC script. |
| [scripts/grep-patterns.sh](scripts/grep-patterns.sh) | Optional first pass over a codebase to find candidate files/lines. |

## Quick reference: supported bug classes

- Deserialization, SQL injection, NoSQL injection, Prototype pollution (JS/TS), Command/OS injection, XSS, Path traversal, SSRF, IDOR, Hardcoded secrets, XXE, LDAP injection, Template injection (SSTI), Open redirect, Weak crypto/randomness, Mass assignment, Insecure file upload, Auth/authz bypass.

Full list and IDs: [references/bug-classes.md](references/bug-classes.md).
