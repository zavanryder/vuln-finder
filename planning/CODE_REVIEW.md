# Code Review and Update Plan

Date: 2026-04-02

## Scope

Reviewed the current skill implementation and reference files:

- [skills/vuln-discovery/SKILL.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/SKILL.md)
- [skills/vuln-discovery/references/bug-classes.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/references/bug-classes.md)
- [skills/vuln-discovery/references/patterns-by-language.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/references/patterns-by-language.md)
- [skills/vuln-discovery/references/exploit-chains.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/references/exploit-chains.md)
- [skills/vuln-discovery/references/poc-guide.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/references/poc-guide.md)
- [skills/vuln-discovery/assets/report-template.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/assets/report-template.md)
- [skills/vuln-discovery/scripts/grep-patterns.sh](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/scripts/grep-patterns.sh)

Compared them against current primary-source guidance from MITRE CWE, OWASP, GitHub Octoverse, and GitHub CodeQL.

## Executive Summary

The current skill is a good v1 for common web-app issues, especially SQLi, deserialization, SSRF, prototype pollution, exploit chaining, and PoC follow-up. The main problem is not quality of the existing guidance; it is scope. The skill is now materially behind current vulnerability trends and current language/tooling coverage.

The highest-value changes are:

1. Expand bug-class coverage for access control, CSRF, code injection, resource exhaustion, and memory-safety classes.
2. Expand language coverage beyond the current 8 languages, with C/C++ first and Kotlin/Rust/Swift next.
3. Make access-control analysis much more explicit and granular.
4. Replace the current grep-first heuristics with broader, framework-aware, high-signal search patterns.
5. Upgrade the report and PoC workflow so findings include enough exploitability context to be used directly by security engineers.

## Review Findings

### 1. High: the skill misses several now-priority weakness classes

Current `ALL` coverage is limited to 18 classes and omits several weaknesses that are now either highly ranked or rapidly rising in current ecosystem data.

Relevant current gaps in [references/bug-classes.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/references/bug-classes.md#L5):

- `csrf`
- `missing-authentication`
- `missing-authorization`
- `incorrect-authorization`
- `code-injection`
- `resource-exhaustion`
- `sensitive-data-exposure`
- `security-misconfiguration`
- `vulnerable-components`
- `software-data-integrity`

Why this matters:

- MITRE's 2025 Top 25 ranks CSRF at #3, Missing Authorization at #4, Code Injection at #10, Missing Authentication at #21, and Allocation of Resources Without Limits or Throttling at #25.
- OWASP API Security 2023 splits access-control issues into object-level authorization, object-property-level authorization, and function-level authorization. The current skill mostly compresses these into `idor`, `mass-assignment`, and `auth-bypass`, which is too coarse for modern APIs.

Impact on the current skill:

- `ALL` is no longer close to "all of the high-value classes."
- Access-control issues are under-modeled.
- The skill is weak on modern API and service abuse patterns.

### 2. High: access control is treated too generically

[references/bug-classes.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/references/bug-classes.md#L15) and [references/patterns-by-language.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/references/patterns-by-language.md#L35) currently flatten several distinct classes into `idor`, `mass-assignment`, and `auth-bypass`.

That causes three practical problems:

- Object-level authorization and function-level authorization need different search patterns.
- Property-level authorization is broader than classic mass assignment.
- Missing authentication and incorrect authorization often deserve different severity and remediation guidance.

Recommendation:

- Split access control into at least:
  - `object-level-authorization`
  - `object-property-authorization`
  - `function-level-authorization`
  - `missing-authentication`
  - `missing-authorization`
  - `incorrect-authorization`
- Keep `idor` as a common alias that maps to `object-level-authorization`.

### 3. High: there is no memory-safety coverage at all

[SKILL.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/SKILL.md#L23) supports only Java, Python, Go, C#, PHP, Ruby, JavaScript, and TypeScript. That excludes C and C++, which means the skill currently cannot address multiple Top 25 high/critical classes:

- out-of-bounds write
- out-of-bounds read
- use-after-free
- classic buffer overflow
- stack-based buffer overflow
- heap-based buffer overflow

Given the skill's stated emphasis on high and critical bugs, this is the largest structural coverage gap.

Recommendation:

- Add `C/C++` support in the next update cycle.
- Add memory-safety bug classes and patterns as a first-class track, not as a footnote.

### 4. Medium: language coverage lags current ecosystem and current CodeQL support

The current supported-language list in [SKILL.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/SKILL.md#L23) is now behind both GitHub ecosystem trends and current GitHub CodeQL language coverage.

Recommended additions:

- `C/C++`
- `Kotlin`
- `Rust`
- `Swift`
- `GitHub Actions` workflows
- `Shell`

Reasoning:

- GitHub's Octoverse 2025 reports TypeScript as the most used language on GitHub and shows Shell and C++ still materially important.
- GitHub CodeQL currently supports C/C++, Kotlin, Rust, Swift, and GitHub Actions as first-class analyzable targets.
- GitHub's 2025 security write-up shows Broken Access Control rising sharply, and current CodeQL coverage includes first-class GitHub Actions workflow analysis.

Priority order:

1. C/C++
2. Kotlin
3. GitHub Actions
4. Rust
5. Swift
6. Shell

### 5. Medium: `patterns-by-language.md` is too shallow for 2026 expectations

The current reference in [references/patterns-by-language.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/references/patterns-by-language.md#L1) is concise, but it is missing several patterns that have become standard in modern secure code review and CodeQL-style analysis.

Examples of missing or underdeveloped pattern families:

- Zip Slip and archive extraction traversal
- symlink extraction issues
- partial SSRF and unsafe URL composition
- GitHub Actions injection and permission abuse
- JWT verification mistakes
- CORS misconfiguration
- regex DoS / resource exhaustion
- GraphQL authorization and overexposure issues
- unsafe third-party API consumption
- exposed admin/debug/test endpoints
- dangerous framework defaults and disabled protections

Examples where the current file is notably thin:

- Go has no file-upload, XXE, LDAP, SSTI, or resource exhaustion guidance.
- JavaScript/TypeScript access-control guidance is only a single generic line.
- Python path traversal and SSRF guidance is too endpoint-centric and not enough about validation failures.
- No section exists for CI/CD or workflow security despite that being a major current attack surface.

Recommendation:

- Split `patterns-by-language.md` into smaller focused references, for example:
  - `patterns-web-by-language.md`
  - `patterns-access-control.md`
  - `patterns-memory-safety.md`
  - `patterns-ci-cd.md`
  - `patterns-resource-exhaustion.md`

### 6. Medium: the grep helper will miss many high-signal cases

[scripts/grep-patterns.sh](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/scripts/grep-patterns.sh#L1) is useful as a starter, but it is currently too narrow for reliable first-pass bug hunting.

Specific weaknesses:

- Only 8 language filters.
- No support for C/C++, Kotlin, Swift, Rust, shell, or workflow YAML.
- No archive extraction / Zip Slip patterns.
- No GitHub Actions patterns.
- No JWT/authz/middleware patterns.
- No GraphQL-specific access-control indicators.
- No resource exhaustion / regex / pagination / upload-size indicators.
- It uses `grep`, not `rg`, and does not take advantage of better file filtering or multiline ergonomics.
- Several regexes are so broad that they will create noise without enough companion patterns to improve precision.

Recommendation:

- Keep the helper, but expand it into a "candidate search" tool organized by bug-class family.
- Prefer `rg` when available, with a `grep` fallback.
- Group patterns by class and framework so the user can request narrower scans.

### 7. Medium: the reporting template is missing security-engineering context

[assets/report-template.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/assets/report-template.md#L21) is readable, but it does not capture enough context for downstream triage.

Add fields for:

- CWE
- confidence
- source
- sink
- sanitizer / guard present or absent
- exploit prerequisites
- impact
- why severity is high or critical
- PoC idea / verification path
- fix sketch

Why this matters:

- The current template is fine for a short chat answer.
- It is weaker as a durable artifact for a security backlog or handoff to engineers.

### 8. Medium: PoC guidance is too HTTP-centric

[references/poc-guide.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/references/poc-guide.md#L12) assumes a web endpoint for most PoCs. That works for SSRF, SQLi, and API authz bugs, but it underserves:

- deserialization in local or queue-driven contexts
- archive extraction issues
- file parsing issues
- GitHub Actions / CI workflows
- memory-safety findings

Recommendation:

- Split PoC guidance into:
  - `poc-web.md`
  - `poc-local-file.md`
  - `poc-ci-cd.md`
  - `poc-memory-corruption.md`
- Keep Python as the default scripting language, but explicitly allow shell snippets or workflow reproductions where that is the better fit.

### 9. Medium: the skill lacks an evaluation corpus

There is no visible regression suite for the skill itself. For a security-analysis skill, that is a significant maintainability gap.

Recommendation:

- Add a small fixture corpus with vulnerable and safe examples per language and bug class.
- Track expected findings, expected severities, and known acceptable misses.
- Add a few exploit-chain fixtures, not just isolated bugs.

### 10. Low: repo metadata is still placeholder-level

[pyproject.toml](/home/jake/projects/skills/ZavanVulnFinder/pyproject.toml#L1) still has a placeholder description and [main.py](/home/jake/projects/skills/ZavanVulnFinder/main.py#L1) is only a hello-world stub.

This is not blocking the skill itself, but it makes the repo feel unfinished.

## Suggested Bug Classes to Add

### Priority 0

- `csrf`
  - Rationale: MITRE 2025 Top 25 rank #3.
- `missing-authentication`
  - Rationale: MITRE 2025 Top 25 rank #21; common high-severity API issue.
- `missing-authorization`
  - Rationale: MITRE 2025 Top 25 rank #4.
- `incorrect-authorization`
  - Rationale: MITRE 2025 Top 25 rank #17.
- `object-level-authorization`
  - Rationale: maps cleanly to BOLA / IDOR.
- `object-property-authorization`
  - Rationale: aligns to OWASP API3:2023; broader and better than only `mass-assignment`.
- `function-level-authorization`
  - Rationale: aligns to OWASP API5:2023.
- `code-injection`
  - Rationale: MITRE 2025 Top 25 rank #10; should be separate from OS command injection.
- `resource-exhaustion`
  - Rationale: MITRE 2025 Top 25 rank #25 and OWASP API4:2023.

### Priority 1

- `security-misconfiguration`
  - Include dangerous debug mode, permissive CORS, unsafe parser flags, disabled CSRF protections, unsafe default credentials, missing least-privilege workflow permissions.
- `software-data-integrity`
  - Include unsafe update/download behavior, untrusted code inclusion, unsafe workflow triggers, artifact poisoning patterns.
- `vulnerable-components`
  - Include stale dependencies, known vulnerable actions, unpinned actions, missing lockfile/version visibility.
- `jwt-session-issues`
  - Include signature bypass, `alg=none`, weak secret, missing audience/issuer verification, insecure cookie/session handling.
- `sensitive-data-exposure`
  - Include overbroad serialization, debug dumps, artifact leakage, stack traces, unsafe logs.

### Priority 2

- `regex-dos`
- `graphql-overexposure`
- `cors-misconfiguration`
- `unsafe-api-consumption`
- `unsafe-redirect-forward`

## Suggested Language Support Additions

### Add next

- `C/C++`
  - Needed for memory-safety classes that dominate multiple Top 25 positions.
- `Kotlin`
  - Natural extension of existing Java support and already covered by CodeQL.
- `GitHub Actions`
  - Increasingly important for code-injection, secrets exposure, permission misuse, and artifact poisoning.

### Add soon after

- `Rust`
  - Important modern systems language with growing usage and first-class CodeQL support.
- `Swift`
  - Valuable for mobile and Apple-platform services.
- `Shell`
  - Useful for command injection, secret leakage, and CI/CD glue code.

## Concrete Update Plan

### Phase 1: taxonomy and workflow

- Expand the canonical bug-class list.
- Split access control into object, property, function, authentication, and authorization classes.
- Reorder `ALL` so the first pass emphasizes the highest current-value classes.
- Update the skill description so the new classes and languages are visible in trigger metadata.

### Phase 2: references

- Split the existing monolithic language-pattern file into smaller references.
- Add a dedicated access-control reference with REST, GraphQL, and framework patterns.
- Add a dedicated CI/CD and workflow reference.
- Add memory-safety references for C/C++.
- Add resource-exhaustion patterns.
- Add framework-specific examples, not just raw API names.

### Phase 3: search helper

- Replace `grep` with `rg` when available.
- Add language filters for new targets.
- Add framework-specific searches:
  - Express, Fastify, NestJS
  - Spring / Spring Security
  - Rails / Sinatra
  - Django / Flask / FastAPI
  - ASP.NET
  - GitHub Actions YAML
- Add candidate searches for:
  - archive extraction
  - JWT decoding / verification
  - role and permission checks
  - GraphQL resolvers
  - CORS
  - workflow `permissions:`
  - `pull_request_target`
  - artifact download / upload

### Phase 4: output quality

- Add CWE and confidence to each finding.
- Require a short source-to-sink explanation for all High and Critical findings.
- Add a "why exploitable" line.
- Add a "verification / PoC path" line.
- Add a "chainability" note for findings that combine naturally.

### Phase 5: evaluation

- Add fixtures by language and bug class.
- Add a regression document or script that checks expected findings.
- Add negative fixtures to keep false positives under control.

## Proposed File-Level Changes Later

These are suggestions only. No implementation yet.

- Update [skills/vuln-discovery/SKILL.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/SKILL.md)
  - expand supported languages
  - expand bug classes
  - refine the workflow around access control and confidence
- Replace [skills/vuln-discovery/references/bug-classes.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/references/bug-classes.md)
  - with a richer taxonomy and aliases
- Split [skills/vuln-discovery/references/patterns-by-language.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/references/patterns-by-language.md)
  - into multiple references by domain
- Expand [skills/vuln-discovery/scripts/grep-patterns.sh](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/scripts/grep-patterns.sh)
  - into a broader candidate-search helper
- Update [skills/vuln-discovery/assets/report-template.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/assets/report-template.md)
  - add CWE, confidence, prerequisites, exploitability
- Split [skills/vuln-discovery/references/poc-guide.md](/home/jake/projects/skills/ZavanVulnFinder/skills/vuln-discovery/references/poc-guide.md)
  - into multiple PoC modes

## External Sources

- MITRE CWE Top 25 2025:
  - https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
- OWASP Top 10 2021 A01 Broken Access Control:
  - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- OWASP API Security Top 10 2023:
  - BOLA: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
  - BOPLA: https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
  - Unrestricted Resource Consumption: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
  - BFLA: https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- OWASP Top 10 2021:
  - Vulnerable and Outdated Components: https://owasp.org/Top10/en/A06_2021-Vulnerable_and_Outdated_Components/
  - Software and Data Integrity Failures: https://owasp.org/Top10/2021/A08_2021-Software_and_Data_Integrity_Failures/
- GitHub Octoverse 2025:
  - https://github.blog/news-insights/octoverse/octoverse-a-new-developer-joins-github-every-second-as-ai-leads-typescript-to-1/
- GitHub CodeQL supported languages and frameworks:
  - https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/
- GitHub CodeQL query/help references used for pattern expansion ideas:
  - Python path injection: https://codeql.github.com/codeql-query-help/python/py-path-injection/
  - Go Zip Slip: https://codeql.github.com/codeql-query-help/go/go-zipslip/
  - GitHub Actions query index: https://codeql.github.com/codeql-query-help/actions/
  - GitHub Actions vulnerable action: https://codeql.github.com/codeql-query-help/actions/actions-vulnerable-action/
  - GitHub Actions untrusted checkout: https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-high/
  - GitHub Actions missing workflow permissions: https://codeql.github.com/codeql-query-help/actions/actions-missing-workflow-permissions/
  - GitHub Actions code injection: https://codeql.github.com/codeql-query-help/actions/actions-code-injection-critical/
  - GitHub Actions improper access control: https://codeql.github.com/codeql-query-help/actions/actions-improper-access-control/
  - GitHub Actions PATH injection: https://codeql.github.com/codeql-query-help/actions/actions-envpath-injection-critical/
  - GitHub Actions secrets in artifacts: https://codeql.github.com/codeql-query-help/actions/actions-secrets-in-artifacts/
  - GitHub Actions artifact poisoning: https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/
