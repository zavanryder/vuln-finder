# Vulnerability Report

**Target:** [snippet | path to codebase]  
**Bug classes:** [comma-separated IDs]  
**Languages:** [e.g. Python, JavaScript]  
**Date:** [optional]

---

## Summary

| Severity | Count |
|----------|--------|
| Critical | N |
| High     | N |
| Medium   | N |
| Low / Info | N |

---

## Findings

### [FINDING_TITLE] — `[bug-class-id]`

- **Severity:** Critical | High | Medium | Low | Info
- **Location:** [file path or "snippet" and line/region]
- **Sink / pattern:** [e.g. `pickle.loads(user_input)`]

**Code (relevant excerpt):**

```[lang]
[paste 5–15 lines showing sink and, if visible, source]
```

**Description:**  
[One or two sentences: how user/source data reaches the sink and why it is unsafe.]

**Remediation:**  
[Concrete fix: e.g. use parameterized queries, allowlist redirect URLs, avoid unsafe deserialization, encode output.]

---

*Repeat the "Findings" block for each issue. Use the same structure (title, bug-class-id, severity, location, sink, code, description, remediation).*

---

## Exploit chain (optional)

*Include this section only when two or more findings can be chained for greater impact (e.g. RCE, critical data exfiltration). See [references/exploit-chains.md](../references/exploit-chains.md) for patterns and flow format.*

### Chain: [Short name, e.g. SSRF → metadata → RCE]

- **Objective:** [e.g. Remote code execution on app server]
- **Prerequisites:** [e.g. Unauthenticated access to /api/fetch]

**Flow:**

1. **Step 1** ([bug-class], Finding #N): [Action and outcome.]
2. **Step 2** ([bug-class], Finding #M): [Action and outcome.]
3. **Step 3** (optional): [Continue until final impact.]

**Result:** [Final impact: RCE, full data exfiltration, privilege escalation, etc.]

**Feasibility:** [Viable | Potential chain (needs verification). If theoretical, note gaps.]

---

## Proof of concept (Critical / High only)

*For any Critical or High finding, or chain with Critical/High result: suggest a PoC payload and offer to build a functional Python script. Use [references/poc-guide.md](../references/poc-guide.md); ask the user for base URL, endpoint, and the parameter(s) where user-controlled data is injected, then build the script from [poc-script-template.py](poc-script-template.py).*
