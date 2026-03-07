# Bug Classes Reference

Canonical IDs and short descriptions for vulnerability discovery. Use these IDs when resolving user terms (e.g. "sql injection" → `sql-injection`) and when tagging findings.

| ID | Name | Brief description |
|----|------|-------------------|
| `deserialization` | Insecure deserialization | Untrusted data deserialized without validation; can lead to RCE or object-injection (e.g. pickle, Java ObjectInputStream, .NET BinaryFormatter, PHP unserialize). |
| `sql-injection` | SQL injection | User input concatenated or formatted into SQL; unsanitized input can alter query logic. |
| `nosql-injection` | NoSQL injection | Same idea for MongoDB, CouchDB, etc.; operator injection or JSON injection in query objects. |
| `prototype-pollution` | Prototype pollution | (JS/TS) Assigning to `__proto__`, `constructor.prototype`, or merge into object that reaches prototype; affects all objects. |
| `command-injection` | Command / OS injection | User input passed into shell/process execution (exec, system, ProcessBuilder, etc.) without sanitization. |
| `xss` | Cross-site scripting | Unescaped user/source data in HTML/JS context (reflected, stored, or DOM). |
| `path-traversal` | Path / directory traversal | User-controlled path segments (e.g. `../`) used in file operations without normalization or allowlisting. |
| `ssrf` | Server-Side Request Forgery | Server issues HTTP/other requests using user-controlled URL or host; can reach internal services or cloud metadata. |
| `idor` | Insecure direct object reference | Access to objects (e.g. by ID) without authorization checks; user can change ID to access others’ data. |
| `hardcoded-secrets` | Hardcoded secrets | Passwords, API keys, tokens, or private keys in source or config. |
| `xxe` | XML External Entity | XML parser processes external entities or DTD that can read files or trigger SSRF. |
| `ldap-injection` | LDAP injection | User input used in LDAP filter or DN without escaping. |
| `ssti` | Server-side template injection | User input in template engine (Jinja2, Twig, Freemarker, etc.) can lead to RCE or data exposure. |
| `open-redirect` | Open redirect | Redirect URL or target is user-controlled and not validated against an allowlist. |
| `weak-crypto` | Weak crypto / randomness | Weak or predictable randomness (e.g. `Math.random()` for security), deprecated ciphers, or bad key handling. |
| `mass-assignment` | Mass assignment | Request body/params bound to model without allowlist; attacker sets privileged fields. |
| `insecure-file-upload` | Insecure file upload | Uploads not validated (type, size, content); stored with executable extension or in web-accessible path. |
| `auth-bypass` | Authentication / authorization bypass | Missing or incorrect checks for login or permission; logic flaws allowing access without proper auth. |

## User term → ID mapping

- "deserialization", "unsafe deserialize", "pickle", "unserialize" → `deserialization`
- "sql injection", "sqli", "sql injection" → `sql-injection`
- "nosql", "mongo injection" → `nosql-injection`
- "prototype pollution", "proto pollution" → `prototype-pollution`
- "command injection", "os command", "shell injection" → `command-injection`
- "xss", "cross-site scripting" → `xss`
- "path traversal", "directory traversal", "lfi" → `path-traversal`
- "ssrf", "server-side request forgery" → `ssrf`
- "idor", "idor", "direct object reference" → `idor`
- "secrets", "credentials", "api key", "hardcoded" → `hardcoded-secrets`
- "xxe", "xml external entity" → `xxe`
- "ldap injection" → `ldap-injection`
- "ssti", "template injection", "jinja", "twig" → `ssti`
- "open redirect", "redirect" → `open-redirect`
- "weak crypto", "random", "crypto" → `weak-crypto`
- "mass assignment", "parameter binding" → `mass-assignment`
- "file upload", "upload" → `insecure-file-upload`
- "auth bypass", "authorization", "access control" → `auth-bypass`

## ALL list (ordered)

When user specifies "ALL", check for these IDs in order:

1. `deserialization`
2. `sql-injection`
3. `nosql-injection`
4. `prototype-pollution`
5. `command-injection`
6. `xss`
7. `path-traversal`
8. `ssrf`
9. `idor`
10. `hardcoded-secrets`
11. `xxe`
12. `ldap-injection`
13. `ssti`
14. `open-redirect`
15. `weak-crypto`
16. `mass-assignment`
17. `insecure-file-upload`
18. `auth-bypass`
