# ZavanVulnFinder

A Claude Code agent skill for discovering security vulnerabilities by bug class across codebases and code snippets.

## What it does

ZavanVulnFinder performs structured vulnerability discovery: it resolves bug classes, loads domain-specific pattern references, runs a first-pass grep scan, then does contextual source-to-sink analysis. Findings are reported with CWE IDs, confidence levels, severity justification, and exploit chain analysis. For Critical/High findings, it generates proof-of-concept payloads.

## Coverage

**46 bug classes** organized by domain:

| Domain | Bug classes |
|--------|-------------|
| **Injection** | SQL injection, NoSQL injection, command injection, code injection, deserialization, SSTI, LDAP injection, XXE |
| **Access control** | Missing authentication, missing authorization, incorrect authorization, BOLA/IDOR, BOPLA/mass assignment, BFLA, CSRF |
| **Client-side** | XSS, open redirect, SSRF, path traversal (incl. Zip Slip), CORS misconfiguration |
| **Data & secrets** | Hardcoded secrets, sensitive data exposure, JWT/session issues, weak crypto |
| **Infrastructure** | Security misconfiguration, insecure file upload, resource exhaustion (incl. ReDoS), vulnerable components, software/data integrity, GraphQL overexposure |
| **Kubernetes & cloud** | RBAC misconfiguration, pod security, network exposure, unsafe volume mounts, container misconfiguration |
| **IaC** | Terraform/HCL misconfiguration (public buckets, overpermissive IAM, unencrypted storage, open security groups) |
| **AI/ML** | ML model integrity (pickle/torch.load/joblib), prompt injection (direct + RAG stored injection) |
| **JS/TS** | Prototype pollution |
| **Memory safety** | Buffer overflow, OOB read/write, use-after-free, integer overflow, format string, Rust unsafe code |

**16 languages and file types:**

Java, Python, Go, C#, PHP, Ruby, JavaScript, TypeScript, C/C++, Kotlin, Rust, GitHub Actions (YAML), Shell, Dockerfile, Helm charts, Terraform/HCL.

## Usage

Ask the agent to find vulnerabilities and specify:

1. **Bug class(es)** -- one or more types, or **ALL** for every applicable type.
2. **Target** -- a code snippet (paste or point to a file) or a codebase path to scan.

### Example prompts

```
Scan ./backend for ALL vulnerability classes
```
```
Check our Kubernetes manifests and Helm charts in k8s/ for RBAC and pod security issues
```
```
Find prompt injection and model integrity issues in the RAG pipeline under src/ai/
```
```
Look for SQL injection, deserialization, and hardcoded secrets in the Java API at src/main/java/
```
```
Audit the Dockerfiles and Terraform modules in infra/ for security misconfigurations
```
```
Check this Rust crate's unsafe blocks for memory safety issues
```

## How it works

1. **Resolve** user's bug-class terms to canonical IDs via `references/bug-classes.md`
2. **Identify** target languages from file extensions
3. **Load** domain-specific pattern references (only the relevant ones)
4. **Search** with `scripts/grep-patterns.sh` for a first-pass candidate scan
5. **Analyze** each candidate in context -- trace source to sink, check for sanitizers/guards
6. **Chain** -- evaluate whether multiple findings combine into exploit chains
7. **Report** with CWE, confidence, severity, source/sink trace, and remediation
8. **PoC** -- for Critical/High findings, suggest proof-of-concept payloads

## Skill layout

```
skills/vuln-discovery/
  SKILL.md                              # Workflow, inputs, rules
  references/
    bug-classes.md                      # 46 canonical IDs, CWE mappings, aliases
    patterns-web.md                     # Injection, XSS, SSRF, deserialization per language
    patterns-access-control.md          # Auth, authz, CSRF, CORS, JWT per language/framework
    patterns-memory-safety.md           # C/C++ memory bugs + Rust unsafe patterns
    patterns-ci-cd.md                   # GitHub Actions injection, supply chain
    patterns-resource-exhaustion.md     # ReDoS, unbounded queries, upload size
    patterns-kubernetes.md              # RBAC, pod security, network exposure, volume mounts
    patterns-container.md               # Dockerfile, Helm, Terraform/HCL patterns
    patterns-ai-ml.md                   # Model integrity, prompt injection, RAG security
    exploit-chains.md                   # Common chain patterns
    poc-web.md                          # PoC guidance: HTTP/API targets
    poc-local-file.md                   # PoC guidance: file/archive/local exploitation
    poc-ci-cd.md                        # PoC guidance: CI/CD workflows
    poc-memory.md                       # PoC guidance: memory corruption
  assets/
    report-template.md                  # Report structure template
    poc-script-template.py              # Python PoC starter script
  scripts/
    grep-patterns.sh                    # First-pass candidate search (rg/grep)
```

The skill keeps `SKILL.md` concise and pushes detail into domain-specific references so the agent loads only what it needs per scan.
