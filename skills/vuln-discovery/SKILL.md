---
name: vuln-discovery
description: Discovers code vulnerabilities by bug class (e.g. SQL injection, CSRF, prototype pollution, buffer overflow, broken access control, resource exhaustion, Kubernetes RBAC, container security, Terraform misconfig, prompt injection, ML model integrity, Oracle Database security, K8s operator security, default credentials, race conditions) in snippets or codebases. Use when the user asks to find vulnerabilities, security issues, audit code, check for specific bug types, review access control, or scan for secrets/misconfigurations. Supports Java, Python, Go, C#, PHP, Ruby, JavaScript, TypeScript, C/C++, Kotlin, Rust, GitHub Actions workflows, Shell scripts, Dockerfiles, Helm charts, Terraform/HCL, and PL/SQL. Also use when the user mentions OWASP, CWE, CVE scanning, secure code review, Kubernetes security, cloud-native security, container security, IaC security, AI/ML pipeline security, or Oracle Database security.
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
   Infer from file extensions or user hint. Match to the appropriate pattern references. If `package.json` lists `electron` as a dependency, also load the Electron-specific patterns from `patterns-web.md` -- Electron is a runtime, not a file extension, so it won't be detected from file types alone. If Oracle DB connection code is present (JDBC Oracle thin URLs, `oracledb` imports, `sqlplus` invocations, `.sql` files with PL/SQL), also load `patterns-oracle-db.md`. If the codebase contains Kubernetes operator code (controller-runtime imports, CRD definitions, webhook configurations), also load `patterns-k8s-operators.md`.

3. **Load patterns**
   For each relevant language and chosen bug class, read the appropriate pattern reference:
   - Web and injection patterns: [references/patterns-web.md](references/patterns-web.md)
   - Expression Language injection (OGNL / SpEL / JSP EL / ADF EL / JEXL / MVEL / Camel Simple): [references/patterns-el-injection.md](references/patterns-el-injection.md)
   - Access control patterns: [references/patterns-access-control.md](references/patterns-access-control.md)
   - Memory safety (C/C++/Rust): [references/patterns-memory-safety.md](references/patterns-memory-safety.md)
   - CI/CD and workflows: [references/patterns-ci-cd.md](references/patterns-ci-cd.md)
   - Resource exhaustion: [references/patterns-resource-exhaustion.md](references/patterns-resource-exhaustion.md)
   - Kubernetes and cloud-native: [references/patterns-kubernetes.md](references/patterns-kubernetes.md)
   - Container and IaC (Dockerfile, Helm, Terraform): [references/patterns-container.md](references/patterns-container.md)
   - Cloud IaC (Azure ARM/Bicep, AWS CloudFormation, GCP, OCI): [references/patterns-cloud-iac.md](references/patterns-cloud-iac.md)
   - AI/ML pipeline security: [references/patterns-ai-ml.md](references/patterns-ai-ml.md)
   - Oracle Database security: [references/patterns-oracle-db.md](references/patterns-oracle-db.md)
   - Kubernetes operator security: [references/patterns-k8s-operators.md](references/patterns-k8s-operators.md)

4. **Search and analyze**
   - For a **snippet**: analyze the provided code against the patterns for the chosen bug classes and languages.
   - For a **codebase**: search for dangerous APIs, sinks, and patterns. Use [scripts/grep-patterns.sh](scripts/grep-patterns.sh) for a first pass if helpful; then confirm each finding in context (data flow, sanitization, configuration, framework guards).
   - **Trace source to sink**: for each candidate, identify the source (user input, external data), the sink (dangerous API/operation), and whether any sanitizer or guard intervenes. Only report when there is a plausible path from source to sink.
   - **Check pinned dependencies**: if a lockfile is present (`package-lock.json`, `yarn.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, pinned `requirements.txt`, `composer.lock`), scan it for known-vulnerable versions. Transitive deps are reachable code -- a vulnerable `merge` library three levels deep is the same sink as one called directly.

5. **Evaluate exploit chains**
   If two or more distinct vulnerabilities were found, consider whether they can be chained for greater impact (e.g. RCE, critical data exfiltration, privilege escalation). Use [references/exploit-chains.md](references/exploit-chains.md) for common chain patterns. If a viable chain exists, add an **Exploit chain** section to the report.

6. **Report**
   Use [assets/report-template.md](assets/report-template.md) and fill one finding per issue. Each finding must include: CWE, confidence level, **CVSS v3.1 base vector + score** (required for every finding, score the bug as-shipped not the worst-case chain), location, source, sink, severity with justification, and a summary remediation. If the caller requests remediation depth (e.g. harness flag `--remediation-poc`, or explicit user instruction), also include the **detailed remediation block** (root cause, principle, fix-in-depth layers, what NOT to do, verification) for every finding. When an exploit chain was identified, include the Exploit chain section.

7. **Proof of concept (Critical / High only)**
   For any finding rated **Critical** or **High**, or for any **exploit chain** whose result is Critical or High:
   - Suggest a proof-of-concept payload.
   - Offer to build a PoC script with the user.
   - **Every PoC must begin with a `Run:` line** stating the language/runtime and the exact command to execute it (e.g. `Run: uv run poc_f1.py --base-url http://localhost:8080`, `Run: npx tsx poc_f2.ts`, `Run: gcc poc.c -o poc && ./poc crash.bin`).
   - **Prefer Python executed via `uv run`.** Use another language only when it materially simplifies the exploit (e.g. the target's own runtime is needed to demonstrate the bug, or a memory-corruption PoC needs C).
   - **For exploit chains, attempt a single end-to-end PoC** (Python/uv preferred) that performs every step in sequence. If an end-to-end script is not feasible, say so and explain the gap.
   - Follow the appropriate PoC guide:
     - HTTP/API targets: [references/poc-web.md](references/poc-web.md)
     - Local file / archive / parsing: [references/poc-local-file.md](references/poc-local-file.md)
     - CI/CD workflows: [references/poc-ci-cd.md](references/poc-ci-cd.md)
     - Memory corruption (C/C++): [references/poc-memory.md](references/poc-memory.md)
   - Use [assets/poc-script-template.py](assets/poc-script-template.py) as starting structure for Python PoCs.

8. **Remediation proof of concept (opt-in)**
   Produce a **remediation PoC** for every finding only when the caller asks for it (e.g. harness flag `--remediation-poc`, or explicit user instruction). When requested, include a RemPoC for every finding regardless of severity -- Critical, High, Medium, Low, and Info alike.
   - Show the **fixed code** -- prefer a unified diff against the vulnerable excerpt; fall back to a full replacement block when a diff would be unreadable. Annotate each substantive change with a short inline comment explaining why it closes the bug.
   - Provide a **verification test** against the patched code with a clear pass/fail signal (status code, error, assertion, denied operation):
     - For Critical/High findings: re-run the same payload as the exploit PoC and assert it no longer works.
     - For Medium/Low/Info findings (no exploit PoC to mirror): submit the equivalent unsafe-input case and assert the fix rejects or neutralizes it (e.g. malformed config rejected at load, tainted value escaped in output, weak cipher refused).
   - Lead the remediation PoC with a **`Run (verify fix):`** line naming the exact command (e.g. `Run (verify fix): uv run verify_f1_fix.py --base-url http://localhost:8080`). Prefer Python via `uv run`; use another language only when the target runtime requires it.
   - State the **expected result** of the verification test and, when relevant, **regression notes** describing any behavior the fix intentionally breaks.
   - For exploit chains, provide one remediation PoC per step OR a single combined fix if one mitigation closes the whole chain -- state explicitly which approach applies.

## Rules

- **No false positives by default.** Only report when there is a plausible path to exploitation. Note "possible" or "needs review" when uncertain, and set confidence accordingly.
- **Verify dismissals by value, not by shape.** When ruling out a grep hit as benign (test fixture, attribute-name constant, sample data), base the dismissal on the literal right-hand-side value -- not the variable name or surrounding context. `passwordAttr = 'Password'` is a key; `Password = 'welcome1'` is a credential. The same scrutiny applied to findings should apply to non-findings.
- **Include CWE, confidence, and CVSS.** Every finding gets a CWE ID, a confidence level (Confirmed, High, Medium, Low), and a CVSS v3.1 base vector with computed score. Score the bug as it exists in the code, not the worst-case chain result.
- **Source-to-sink required for High/Critical.** For High and Critical findings, explicitly trace the data flow from source to sink and note whether a sanitizer/guard is present or absent.
- **Calibrate severity by trust boundary crossed.** Before rating High or Critical, ask: what privilege does the attacker need to reach the source, and what do they gain at the sink? If the required access is equivalent to the gained access (admin to admin, local user to that user's own files), the finding is informational regardless of how dangerous the sink looks in isolation.
- **One language per finding.** If the same bug appears in multiple files, group by bug class but list each location.
- **PoC for Critical/High.** For Critical or High findings, or chains with Critical/High impact, always suggest a PoC payload and offer to build a functional PoC. Lead every PoC with a `Run:` line (language + exact command). Prefer Python via `uv run`; use another language only if it simplifies the exploit.
- **Remediation PoC is opt-in.** When the caller requests it (e.g. `--remediation-poc` harness flag, or explicit user instruction), every finding at every severity must ship a remediation PoC -- fixed code plus a verification test (`Run (verify fix):` line) with a clear pass/fail signal. For Critical/High, the test re-runs the exploit payload and asserts it fails. For Medium/Low/Info, the test submits the equivalent unsafe-input case and asserts the fix rejects or neutralizes it. When not requested, the summary-remediation line is sufficient.
- **Prefer references over long text.** Keep this file short; use the pattern reference files for definitions and patterns.

## False-positive exclusion rules

A finding that matches any rule is FALSE POSITIVE (drop it, or downgrade to Info with the rule cited). Cite the rule number in the finding's rationale or validation column. Rules:

1. Volumetric DoS / missing rate-limiting (handled at infrastructure layer). ReDoS, algorithmic complexity, and unbounded recursion ARE still valid.
2. Test-only code, dead code, example/fixture code, or a crash with no security impact.
3. Behavior that is intended by design (compression middleware, a backward-compatible weak algorithm offered alongside a strong one).
4. Memory-safety concerns in memory-safe languages outside `unsafe` / FFI blocks.
5. SSRF where the attacker controls only the URL path, not the host or protocol.
6. User input flowing into an AI/LLM prompt (prompt injection is not a code vulnerability in the target).
7. Path traversal in object storage (S3/GCS) where `../` does not escape a trust boundary.
8. Trusted operator inputs (env vars, CLI flags) used as the attack vector, UNLESS the environment makes them untrusted (multi-tenant, pipeline parameters from external actors, webhook payloads).
9. Client-side code flagged for a server-side vulnerability class.
10. Outdated dependency versions with no explicit reachable vulnerability (managed by a separate dependency-scan process). **When dismissing a bundled-but-unreachable library because the runtime supplies an alternative (container shared library, OS package, sidecar), you MUST name the runtime alternative's version and confirm it falls outside the CVE's affected-version range. Merely naming the alternative source is not sufficient; the runtime version must be identified and verified patched.**
11. Weak randomness used for non-security purposes (jitter, shuffling, dev-only fallbacks).
12. Low-impact nuisance issues (log spoofing, CSRF on logout, self-XSS).
13. Unverified / hallucinated file path. Every `Location:` path MUST be the exact result of an actual Glob/Grep/Read against the target repo. Do not compose paths from product/brand knowledge or sibling-product naming. If the path cannot be confirmed by the harness's post-scan path validator, the finding is downgraded one severity level and the path corrected; if no real path backs the underlying pattern, the finding is removed.
14. Hardcoded column / table names in dynamic SQL. When a SQL injection finding's allegedly tainted identifier is a string literal or `static final` (or equivalent compile-time-constant) in source code -- regardless of how many call hops it travels before reaching the SQL builder -- the value has zero injection surface and is functionally equivalent to a static query. Distinct from rule 8: rule 8 is runtime trust (env / CLI), this rule is compile-time trust. Trigger ONLY when the identifier is provably constant at every program point on its path to the sink. Do NOT trigger when the identifier originates from request data, config files, JDBC metadata, environment variables, or any user-controlled source at any point in its provenance.

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
| [references/patterns-oracle-db.md](references/patterns-oracle-db.md) | Oracle Database: PL/SQL injection, connection security, ORDS, TDE/Wallet, default credentials, dangerous PL/SQL APIs (UTL_HTTP, DBMS_SCHEDULER). |
| [references/patterns-k8s-operators.md](references/patterns-k8s-operators.md) | Kubernetes operator security: CRD field injection, confused deputy, RBAC escalation, webhook security, controller reconciliation. |
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

**Oracle Database:** Oracle DB misconfiguration (SYSDBA abuse, TDE, SQL*Net, ORDS, database links), default/weak credentials.

**Operator and trust-boundary:** Confused deputy / cross-tenant access, TOCTOU race conditions, privilege escalation via system config.

**AI/ML:** ML model integrity, prompt injection.

**Memory safety (C/C++/Rust):** Buffer overflow, out-of-bounds write, out-of-bounds read, use-after-free, integer overflow, format string, Rust unsafe code.

Full list with CWE mappings and aliases: [references/bug-classes.md](references/bug-classes.md).
