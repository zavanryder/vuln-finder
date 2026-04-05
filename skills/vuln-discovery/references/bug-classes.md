# Bug Classes Reference

Canonical IDs and short descriptions for vulnerability discovery. Use these IDs when resolving user terms (e.g. "sql injection" -> `sql-injection`) and when tagging findings.

## Canonical bug classes

| ID | Name | CWE | Brief description |
|----|------|-----|-------------------|
| `deserialization` | Insecure deserialization | CWE-502 | Untrusted data deserialized without validation; can lead to RCE or object-injection (e.g. pickle, Java ObjectInputStream, .NET BinaryFormatter, PHP unserialize). |
| `sql-injection` | SQL injection | CWE-89 | User input concatenated or formatted into SQL; unsanitized input can alter query logic. |
| `nosql-injection` | NoSQL injection | CWE-943 | Same idea for MongoDB, CouchDB, etc.; operator injection or JSON injection in query objects. |
| `prototype-pollution` | Prototype pollution | CWE-1321 | (JS/TS) Assigning to `__proto__`, `constructor.prototype`, or merge into object that reaches prototype; affects all objects. |
| `command-injection` | Command / OS injection | CWE-78 | User input passed into shell/process execution (exec, system, ProcessBuilder, etc.) without sanitization. |
| `code-injection` | Code injection | CWE-94 | User input evaluated as code (eval, Function constructor, dynamic import, reflection-based invocation) distinct from OS command execution. |
| `xss` | Cross-site scripting | CWE-79 | Unescaped user/source data in HTML/JS context (reflected, stored, or DOM). |
| `csrf` | Cross-site request forgery | CWE-352 | State-changing action performed via forged request because the server relies solely on cookies/session for authentication without a CSRF token or SameSite enforcement. |
| `path-traversal` | Path / directory traversal | CWE-22 | User-controlled path segments (e.g. `../`) used in file operations without normalization or allowlisting. Includes Zip Slip and symlink extraction. |
| `ssrf` | Server-Side Request Forgery | CWE-918 | Server issues HTTP/other requests using user-controlled URL or host; can reach internal services or cloud metadata. Includes partial SSRF via unsafe URL composition. |
| `object-level-authz` | Object-level authorization | CWE-639 | Access to objects (e.g. by ID) without authorization checks; user can change ID to access others' data. Replaces and extends classic IDOR (OWASP API1:2023 BOLA). |
| `object-property-authz` | Object-property-level authorization | CWE-915 | Request body/params bound to model without property allowlist; attacker sets privileged fields. Extends classic mass assignment (OWASP API3:2023 BOPLA). |
| `function-level-authz` | Function-level authorization | CWE-285 | Missing or incorrect authorization on privileged endpoints or actions; user accesses admin/internal functions (OWASP API5:2023 BFLA). |
| `missing-authentication` | Missing authentication | CWE-306 | Endpoint or resource accessible without any authentication check. |
| `missing-authorization` | Missing authorization | CWE-862 | Authenticated user can access resources or actions they should not; no authorization check present. |
| `incorrect-authorization` | Incorrect authorization | CWE-863 | Authorization check exists but is flawed (e.g. client-side only, wrong role compared, bypassable logic). |
| `hardcoded-secrets` | Hardcoded secrets | CWE-798 | Passwords, API keys, tokens, or private keys in source or config. |
| `xxe` | XML External Entity | CWE-611 | XML parser processes external entities or DTD that can read files or trigger SSRF. |
| `ldap-injection` | LDAP injection | CWE-90 | User input used in LDAP filter or DN without escaping. |
| `ssti` | Server-side template injection | CWE-1336 | User input in template engine (Jinja2, Twig, Freemarker, etc.) can lead to RCE or data exposure. |
| `open-redirect` | Open redirect | CWE-601 | Redirect URL or target is user-controlled and not validated against an allowlist. |
| `weak-crypto` | Weak crypto / randomness | CWE-327 | Weak or predictable randomness (e.g. `Math.random()` for security), deprecated ciphers, or bad key handling. |
| `insecure-file-upload` | Insecure file upload | CWE-434 | Uploads not validated (type, size, content); stored with executable extension or in web-accessible path. |
| `resource-exhaustion` | Resource exhaustion | CWE-400 | No limits on request size, pagination, file upload size, regex complexity, or iteration count; enables DoS. Includes ReDoS (CWE-1333). |
| `sensitive-data-exposure` | Sensitive data exposure | CWE-200 | Overbroad serialization, debug dumps, stack traces in production, artifact leakage, sensitive data in logs. |
| `security-misconfiguration` | Security misconfiguration | CWE-16 | Dangerous debug mode, permissive CORS, unsafe parser flags, disabled CSRF protections, missing security headers, exposed admin/debug/test endpoints. |
| `jwt-session-issues` | JWT / session issues | CWE-345 | JWT signature bypass (`alg=none`), weak secret, missing audience/issuer verification, insecure cookie/session handling. |
| `vulnerable-components` | Vulnerable components | CWE-1395 | Stale dependencies with known CVEs, unpinned actions, missing lockfile integrity. |
| `software-data-integrity` | Software / data integrity | CWE-494 | Unsafe update/download behavior, untrusted code inclusion, unsafe CI/CD triggers, artifact poisoning. |
| `cors-misconfiguration` | CORS misconfiguration | CWE-942 | Overly permissive `Access-Control-Allow-Origin`, reflecting arbitrary origins, allowing credentials with wildcards. |
| `graphql-overexposure` | GraphQL overexposure | CWE-200 | Missing query depth/complexity limits, introspection enabled in production, authorization missing on resolvers. |

### Kubernetes and cloud-native classes

| ID | Name | CWE | Brief description |
|----|------|-----|-------------------|
| `k8s-rbac-misconfig` | Kubernetes RBAC misconfiguration | CWE-269 | Overpermissive ClusterRoles/Roles: wildcard verbs/resources, secrets access at cluster scope, escalation-capable verbs (bind, escalate, impersonate). |
| `k8s-pod-security` | Kubernetes pod security | CWE-250 | Missing or insufficient pod securityContext: running as root, privileged containers, missing capability drops, host namespace access, writable root filesystem. |
| `k8s-network-exposure` | Kubernetes network exposure | CWE-284 | Unauthenticated service endpoints (management, metrics, health), LoadBalancer/NodePort on internal services, missing NetworkPolicy, servers bound to 0.0.0.0. |
| `unsafe-volume-mount` | Unsafe volume mount | CWE-269 | Host filesystem paths mounted into containers: docker.sock, /etc, /proc, host root. Writable mounts to sensitive host paths. |
| `container-misconfig` | Container misconfiguration | CWE-250 | Dockerfile: running as root, unpinned base images (:latest), ADD from URLs, secrets in build layers, exposed debug ports. Helm: permissive defaults, tpl injection. |

### IaC classes

| ID | Name | CWE | Brief description |
|----|------|-----|-------------------|
| `iac-misconfig` | Infrastructure-as-code misconfiguration | CWE-1188 | Terraform/HCL, Azure ARM/Bicep, AWS CloudFormation, GCP, and OCI: public storage/registries, overpermissive IAM/RBAC, unencrypted storage/transport, open network rules (NSGs/security groups/firewalls with 0.0.0.0/0), disabled logging/auditing, admin interfaces exposed to internet. |

### AI/ML classes

| ID | Name | CWE | Brief description |
|----|------|-----|-------------------|
| `ml-model-integrity` | ML model integrity | CWE-494 | Loading serialized ML models via pickle-based formats (torch.load, joblib.load, pickle.load) from untrusted sources without integrity verification. Includes eval artifacts. |
| `prompt-injection` | Prompt injection | CWE-74 | User input concatenated into LLM prompts or RAG context without sanitization; enables overriding system instructions, data exfiltration, or stored injection via vector stores. |

### Memory-safety classes (C/C++/Rust)

| ID | Name | CWE | Brief description |
|----|------|-----|-------------------|
| `buffer-overflow` | Buffer overflow | CWE-120 | Writing past buffer boundaries (stack or heap). Includes classic (CWE-120), stack-based (CWE-121), and heap-based (CWE-122). |
| `out-of-bounds-write` | Out-of-bounds write | CWE-787 | Writing to memory outside allocated buffer bounds. |
| `out-of-bounds-read` | Out-of-bounds read | CWE-125 | Reading from memory outside allocated buffer bounds; can leak sensitive data. |
| `use-after-free` | Use-after-free | CWE-416 | Accessing memory after it has been freed; can lead to code execution. |
| `integer-overflow` | Integer overflow / wraparound | CWE-190 | Arithmetic overflow leads to unexpected values used in allocation sizes, loop bounds, or security checks. |
| `format-string` | Format string vulnerability | CWE-134 | User input used as format string in printf-family functions; can read/write arbitrary memory. |
| `rust-unsafe` | Rust unsafe code | CWE-787 | Unsafe blocks: raw pointer dereference, transmute, FFI boundary issues, ManuallyDrop misuse, unchecked indexing, incorrect Send/Sync impls. |

## User term -> ID mapping

- "deserialization", "unsafe deserialize", "pickle", "unserialize" -> `deserialization`
- "sql injection", "sqli" -> `sql-injection`
- "nosql", "mongo injection" -> `nosql-injection`
- "prototype pollution", "proto pollution" -> `prototype-pollution`
- "command injection", "os command", "shell injection" -> `command-injection`
- "code injection", "eval injection", "dynamic code" -> `code-injection`
- "xss", "cross-site scripting" -> `xss`
- "csrf", "cross-site request forgery" -> `csrf`
- "path traversal", "directory traversal", "lfi", "zip slip" -> `path-traversal`
- "ssrf", "server-side request forgery" -> `ssrf`
- "idor", "bola", "direct object reference", "object-level" -> `object-level-authz`
- "mass assignment", "parameter binding", "bopla", "object property" -> `object-property-authz`
- "bfla", "function-level", "privilege escalation endpoint" -> `function-level-authz`
- "missing auth", "no authentication", "unauthenticated" -> `missing-authentication`
- "missing authorization", "no authz", "no access control" -> `missing-authorization`
- "incorrect auth", "broken auth", "auth bypass", "authorization bypass" -> `incorrect-authorization`
- "secrets", "credentials", "api key", "hardcoded" -> `hardcoded-secrets`
- "xxe", "xml external entity" -> `xxe`
- "ldap injection" -> `ldap-injection`
- "ssti", "template injection", "jinja", "twig" -> `ssti`
- "open redirect", "redirect" -> `open-redirect`
- "weak crypto", "random", "crypto" -> `weak-crypto`
- "file upload", "upload" -> `insecure-file-upload`
- "dos", "resource exhaustion", "redos", "rate limit" -> `resource-exhaustion`
- "data exposure", "info leak", "sensitive data", "debug dump" -> `sensitive-data-exposure`
- "misconfiguration", "debug mode", "cors", "security headers" -> `security-misconfiguration`
- "jwt", "session", "token bypass", "alg none" -> `jwt-session-issues`
- "outdated", "vulnerable dependency", "cve", "supply chain" -> `vulnerable-components`
- "integrity", "artifact poisoning", "unsafe trigger" -> `software-data-integrity`
- "cors" -> `cors-misconfiguration`
- "graphql" -> `graphql-overexposure`
- "k8s rbac", "rbac misconfiguration", "clusterrole", "overpermissive rbac" -> `k8s-rbac-misconfig`
- "pod security", "securitycontext", "privileged container", "host namespace" -> `k8s-pod-security`
- "network exposure", "unauthenticated endpoint", "missing networkpolicy", "loadbalancer exposure" -> `k8s-network-exposure`
- "volume mount", "hostpath", "docker socket", "docker.sock" -> `unsafe-volume-mount`
- "container security", "dockerfile", "helm misconfig", "image pinning" -> `container-misconfig`
- "iac", "terraform", "hcl", "infrastructure as code", "public bucket", "security group" -> `iac-misconfig`
- "arm", "bicep", "azure iac", "nsg", "azure storage" -> `iac-misconfig`
- "cloudformation", "cfn", "aws iac", "security group" -> `iac-misconfig`
- "gcp iac", "gcp firewall", "gcs public" -> `iac-misconfig`
- "oci iac", "oci security list", "oci public bucket" -> `iac-misconfig`
- "model integrity", "torch.load", "joblib", "ml model", "model poisoning", "safetensors" -> `ml-model-integrity`
- "prompt injection", "rag injection", "llm injection", "context injection" -> `prompt-injection`
- "buffer overflow", "bof", "stack overflow", "heap overflow" -> `buffer-overflow`
- "oob write", "out of bounds write" -> `out-of-bounds-write`
- "oob read", "out of bounds read", "information leak" -> `out-of-bounds-read`
- "use after free", "uaf", "dangling pointer" -> `use-after-free`
- "integer overflow", "integer wraparound", "int overflow" -> `integer-overflow`
- "format string", "printf" -> `format-string`
- "rust unsafe", "unsafe block", "transmute", "raw pointer", "ffi safety" -> `rust-unsafe`

## ALL list (ordered by current priority)

When user specifies "ALL", check for these IDs in order. Domain-specific classes are only checked when relevant files are present (see conditional notes per section).

### Core injection and execution
1. `sql-injection`
2. `nosql-injection`
3. `command-injection`
4. `code-injection`
5. `deserialization`
6. `ssti`
7. `ldap-injection`
8. `xxe`

### Access control
9. `missing-authentication`
10. `missing-authorization`
11. `incorrect-authorization`
12. `object-level-authz`
13. `object-property-authz`
14. `function-level-authz`
15. `csrf`

### Client-side and request handling
16. `xss`
17. `open-redirect`
18. `ssrf`
19. `path-traversal`
20. `cors-misconfiguration`

### Data and secrets
21. `hardcoded-secrets`
22. `sensitive-data-exposure`
23. `jwt-session-issues`
24. `weak-crypto`

### Infrastructure and supply chain
25. `security-misconfiguration`
26. `insecure-file-upload`
27. `resource-exhaustion`
28. `vulnerable-components`
29. `software-data-integrity`
30. `graphql-overexposure`

### Prototype pollution (JS/TS only)
31. `prototype-pollution`

### Kubernetes and cloud-native (checked when K8s manifests, Helm charts, or operator code is present)
32. `k8s-rbac-misconfig`
33. `k8s-pod-security`
34. `k8s-network-exposure`
35. `unsafe-volume-mount`
36. `container-misconfig`

### IaC (checked when Terraform/HCL or Dockerfile files are present)
37. `iac-misconfig`

### AI/ML (checked when ML framework imports or LLM API calls are present)
38. `ml-model-integrity`
39. `prompt-injection`

### Memory safety (C/C++/Rust only)
40. `buffer-overflow`
41. `out-of-bounds-write`
42. `out-of-bounds-read`
43. `use-after-free`
44. `integer-overflow`
45. `format-string`
46. `rust-unsafe`
