---
name: vuln-discovery
description: Discovers code vulnerabilities by bug class (e.g. SQL injection, CSRF, prototype pollution, buffer overflow, broken access control, resource exhaustion, Kubernetes RBAC, container security, Terraform misconfig, prompt injection, ML model integrity) in snippets or codebases. Use when the user asks to find vulnerabilities, security issues, audit code, check for specific bug types, review access control, or scan for secrets/misconfigurations. Supports Java, Python, Go, C#, PHP, Ruby, JavaScript, TypeScript, C/C++, Kotlin, Rust, GitHub Actions workflows, Shell scripts, Dockerfiles, Helm charts, and Terraform/HCL. Also use when the user mentions OWASP, CWE, CVE scanning, secure code review, Kubernetes security, cloud-native security, container security, IaC security, or AI/ML pipeline security.
---

# Vulnerability Discovery

Finds security issues in code based on user-specified bug classes across supported languages.

## Supported languages

Java, Python, Go, C#, PHP, Ruby, JavaScript, TypeScript, C/C++, Kotlin, Rust, GitHub Actions (YAML workflows), Shell, Dockerfile, Helm charts, Terraform/HCL, Azure Bicep, ARM JSON, AWS CloudFormation (YAML/JSON).

## Inputs

1. **Bug class(es)**
   One or more types (e.g. `sql-injection`, `csrf`, `missing-authorization`) or **ALL** for every supported type.

2. **Target**
   A code snippet (inline or pasted) or a codebase path/directory to examine.

## Workflow

1. **Resolve bug classes**
   If the user said "ALL", use the full list from [references/bug-classes.md](references/bug-classes.md). Otherwise map the user's terms to canonical IDs using the alias table in that file. Memory-safety classes only apply when C/C++ files are present.

2. **Identify languages**
   Infer from file extensions or user hint. Match to the appropriate pattern references. If `package.json` lists `electron` as a dependency, also load the Electron-specific patterns from `patterns-web.md` -- Electron is a runtime, not a file extension, so it won't be detected from file types alone.

3. **Load patterns**
   For each relevant language and chosen bug class, read the appropriate pattern reference:
   - Web and injection patterns: [references/patterns-web.md](references/patterns-web.md)
   - Access control patterns: [references/patterns-access-control.md](references/patterns-access-control.md)
   - Memory safety (C/C++/Rust): [references/patterns-memory-safety.md](references/patterns-memory-safety.md)
   - CI/CD and workflows: [references/patterns-ci-cd.md](references/patterns-ci-cd.md)
   - Resource exhaustion: [references/patterns-resource-exhaustion.md](references/patterns-resource-exhaustion.md)
   - Kubernetes and cloud-native: [references/patterns-kubernetes.md](references/patterns-kubernetes.md)
   - Container and IaC (Dockerfile, Helm, Terraform): [references/patterns-container.md](references/patterns-container.md)
   - Cloud IaC (Azure ARM/Bicep, AWS CloudFormation, GCP, OCI): [references/patterns-cloud-iac.md](references/patterns-cloud-iac.md)
   - AI/ML pipeline security: [references/patterns-ai-ml.md](references/patterns-ai-ml.md)

4. **Search and analyze**
   - For a **snippet**: analyze the provided code against the patterns for the chosen bug classes and languages.
   - For a **codebase**: search for dangerous APIs, sinks, and patterns. Use [scripts/grep-patterns.sh](scripts/grep-patterns.sh) for a first pass if helpful; then confirm each finding in context (data flow, sanitization, configuration, framework guards).
   - **Trace source to sink**: for each candidate, identify the source (user input, external data), the sink (dangerous API/operation), and whether any sanitizer or guard intervenes. Only report when there is a plausible path from source to sink.
   - **Check pinned dependencies**: if a lockfile is present (`package-lock.json`, `yarn.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, pinned `requirements.txt`, `composer.lock`), scan it for known-vulnerable versions. Transitive deps are reachable code -- a vulnerable `merge` library three levels deep is the same sink as one called directly.

5. **Evaluate exploit chains**
   If two or more distinct vulnerabilities were found, consider whether they can be chained for greater impact (e.g. RCE, critical data exfiltration, privilege escalation). Use [references/exploit-chains.md](references/exploit-chains.md) for common chain patterns. If a viable chain exists, add an **Exploit chain** section to the report.

6. **Report**
   Use [assets/report-template.md](assets/report-template.md) and fill one finding per issue. Each finding must include: CWE, confidence level, location, source, sink, severity with justification, and remediation. When an exploit chain was identified, include the Exploit chain section.

7. **Proof of concept (Critical / High only)**
   For any finding rated **Critical** or **High**, or for any **exploit chain** whose result is Critical or High:
   - Suggest a proof-of-concept payload.
   - Offer to build a PoC script with the user.
   - Follow the appropriate PoC guide:
     - HTTP/API targets: [references/poc-web.md](references/poc-web.md)
     - Local file / archive / parsing: [references/poc-local-file.md](references/poc-local-file.md)
     - CI/CD workflows: [references/poc-ci-cd.md](references/poc-ci-cd.md)
     - Memory corruption (C/C++): [references/poc-memory.md](references/poc-memory.md)
   - Use [assets/poc-script-template.py](assets/poc-script-template.py) as starting structure for Python PoCs.

## Rules

- **No false positives by default.** Only report when there is a plausible path to exploitation. Note "possible" or "needs review" when uncertain, and set confidence accordingly.
- **Verify dismissals by value, not by shape.** When ruling out a grep hit as benign (test fixture, attribute-name constant, sample data), base the dismissal on the literal right-hand-side value -- not the variable name or surrounding context. `passwordAttr = 'Password'` is a key; `Password = 'welcome1'` is a credential. The same scrutiny applied to findings should apply to non-findings.
- **Include CWE and confidence.** Every finding gets a CWE ID and a confidence level (Confirmed, High, Medium, Low).
- **Source-to-sink required for High/Critical.** For High and Critical findings, explicitly trace the data flow from source to sink and note whether a sanitizer/guard is present or absent.
- **Calibrate severity by trust boundary crossed.** Before rating High or Critical, ask: what privilege does the attacker need to reach the source, and what do they gain at the sink? If the required access is equivalent to the gained access (admin to admin, local user to that user's own files), the finding is informational regardless of how dangerous the sink looks in isolation.
- **One language per finding.** If the same bug appears in multiple files, group by bug class but list each location.
- **PoC for Critical/High.** For Critical or High findings, or chains with Critical/High impact, always suggest a PoC payload and offer to build a functional PoC.
- **Prefer references over long text.** Keep this file short; use the pattern reference files for definitions and patterns.

## Resources

| Resource | When to use |
|----------|-------------|
| [references/bug-classes.md](references/bug-classes.md) | Resolve "ALL" or user bug-class names; get canonical list, CWE mappings, and aliases. |
| [references/patterns-web.md](references/patterns-web.md) | Sinks and dangerous APIs for injection, XSS, SSRF, deserialization, secrets, crypto, file upload, and general web bugs per language. |
| [references/patterns-access-control.md](references/patterns-access-control.md) | Patterns for authentication, authorization, CSRF, CORS, JWT, and session issues per language and framework. |
| [references/patterns-memory-safety.md](references/patterns-memory-safety.md) | Buffer overflow, OOB read/write, use-after-free, integer overflow, format string patterns for C/C++, and Rust unsafe patterns. |
| [references/patterns-ci-cd.md](references/patterns-ci-cd.md) | GitHub Actions injection, permission abuse, artifact poisoning, unsafe triggers, shell script issues. |
| [references/patterns-resource-exhaustion.md](references/patterns-resource-exhaustion.md) | ReDoS, unbounded pagination, upload size, GraphQL depth, and other resource exhaustion patterns. |
| [references/patterns-kubernetes.md](references/patterns-kubernetes.md) | Kubernetes RBAC misconfiguration, pod security, network exposure, unsafe volume mounts, cross-namespace access, cloud metadata SSRF. |
| [references/patterns-container.md](references/patterns-container.md) | Dockerfile security, Helm chart misconfiguration, image pinning, Terraform/HCL insecure defaults. |
| [references/patterns-cloud-iac.md](references/patterns-cloud-iac.md) | Cloud-provider-specific IaC patterns: Azure ARM/Bicep, AWS CloudFormation, GCP Terraform, OCI Terraform, shell provisioning security. |
| [references/patterns-ai-ml.md](references/patterns-ai-ml.md) | ML model integrity (torch.load, pickle, joblib), prompt injection, RAG pipeline security. |
| [references/exploit-chains.md](references/exploit-chains.md) | Common chain patterns and how to outline a potential exploit. |
| [references/poc-web.md](references/poc-web.md) | PoC guidance for HTTP/API endpoint vulnerabilities. |
| [references/poc-local-file.md](references/poc-local-file.md) | PoC guidance for file parsing, archive extraction, and local exploitation. |
| [references/poc-ci-cd.md](references/poc-ci-cd.md) | PoC guidance for CI/CD and workflow vulnerabilities. |
| [references/poc-memory.md](references/poc-memory.md) | PoC guidance for memory corruption vulnerabilities. |
| [assets/report-template.md](assets/report-template.md) | Structure the final vulnerability report. |
| [assets/poc-script-template.py](assets/poc-script-template.py) | Starting structure for a Python PoC script. |
| [scripts/grep-patterns.sh](scripts/grep-patterns.sh) | First-pass candidate search over a codebase. |

## Quick reference: supported bug classes

**Injection:** SQL injection, NoSQL injection, command injection, code injection, deserialization, SSTI, LDAP injection, XXE.

**Access control:** Missing authentication, missing authorization, incorrect authorization, object-level authorization (BOLA/IDOR), object-property authorization (BOPLA/mass assignment), function-level authorization (BFLA), CSRF.

**Client-side and request:** XSS, open redirect, SSRF, path traversal (incl. Zip Slip), CORS misconfiguration.

**Data and secrets:** Hardcoded secrets, sensitive data exposure, JWT/session issues, weak crypto.

**Infrastructure:** Security misconfiguration, insecure file upload, resource exhaustion (incl. ReDoS), vulnerable components, software/data integrity, GraphQL overexposure.

**JS/TS specific:** Prototype pollution.

**Kubernetes and cloud-native:** RBAC misconfiguration, pod security, network exposure, unsafe volume mounts, container misconfiguration.

**IaC:** Terraform/HCL, Azure ARM/Bicep, AWS CloudFormation, GCP, and OCI misconfiguration (public storage/registries, overpermissive IAM, unencrypted storage, open network rules, disabled logging).

**AI/ML:** ML model integrity, prompt injection.

**Memory safety (C/C++/Rust):** Buffer overflow, out-of-bounds write, out-of-bounds read, use-after-free, integer overflow, format string, Rust unsafe code.

Full list with CWE mappings and aliases: [references/bug-classes.md](references/bug-classes.md).
