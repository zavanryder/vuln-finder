# Vulnerability Report

**Target:** [snippet | path to codebase]
**Bug classes:** [comma-separated IDs]
**Languages:** [e.g. Python, Ruby, JavaScript]
**Date:** [date and timestamp]

---

## Summary

| ID | Title | Bug Class | Severity | Confidence | CWE |
|----|-------|-----------|----------|------------|-----|
| F1 | [short title] | `[bug-class-id]` | Critical/High/Medium/Low/Info | Confirmed/High/Medium/Low | CWE-NNN |
| F2 | ... | ... | ... | ... | ... |

---

## Findings

### F1: [FINDING_TITLE] -- `[bug-class-id]`

- **Severity:** Critical | High | Medium | Low | Info
- **CWE:** [e.g. CWE-89]
- **Confidence:** Confirmed | High | Medium | Low
- **Location:** [file path or "snippet" and line/region]
- **Source:** [where attacker-controlled data enters, e.g. `req.body.username`, `$_GET['id']`, stdin]
- **Sink:** [dangerous function/API, e.g. `db.query(sql)`, `eval(input)`, `pickle.loads(data)`]
- **Sanitizer / guard:** [present | absent | insufficient -- describe what exists]

**Code (relevant excerpt):**

```[lang]
[paste 5-15 lines showing source-to-sink flow]
```

**Description:**
[One or two sentences: how user/source data reaches the sink and why it is unsafe.]

**Why exploitable:**
[What makes this a real risk, not just a theoretical pattern match. E.g. "User input from the login form reaches the SQL query without parameterization. No WAF or input validation intervenes."]

**Impact:**
[Concrete impact: data exfiltration, RCE, account takeover, DoS, etc.]

**Remediation:**
[Concrete fix: e.g. use parameterized queries, allowlist redirect URLs, pin JWT algorithm, add CSRF middleware.]

**PoC path:**
[Brief note on how to verify: e.g. "Send `' OR 1=1--` in the username field", "Create PR with injected title", "Upload crafted ZIP file".]

---

*Repeat the "Findings" block for each issue, incrementing the ID (F1, F2, F3, ...).*

---

## Exploit chain (optional)

*Include this section only when two or more findings can be chained for greater impact. See [references/exploit-chains.md](../references/exploit-chains.md) for patterns and flow format.*

### Chain: [Short name, e.g. SSRF -> metadata -> RCE]

- **Objective:** [e.g. Remote code execution on app server]
- **Prerequisites:** [e.g. Unauthenticated access to /api/fetch]

**Flow:**

1. **Step 1** ([bug-class], FN): [Action and outcome.]
2. **Step 2** ([bug-class], FM): [Action and outcome.]
3. **Step 3** (optional): [Continue until final impact.]

**Result:** [Final impact: RCE, full data exfiltration, privilege escalation, etc.]

**Feasibility:** [Viable | Potential chain (needs verification). If theoretical, note gaps.]

---

## Proof of concept (Critical / High only)

*For any Critical or High finding, or chain with Critical/High result: suggest a PoC payload and offer to build a functional script. Use the appropriate PoC guide:*
- *HTTP/API: [references/poc-web.md](../references/poc-web.md)*
- *File/archive: [references/poc-local-file.md](../references/poc-local-file.md)*
- *CI/CD: [references/poc-ci-cd.md](../references/poc-ci-cd.md)*
- *Memory corruption: [references/poc-memory.md](../references/poc-memory.md)*

*Ask the user for target details, then build the script from [poc-script-template.py](poc-script-template.py).*
