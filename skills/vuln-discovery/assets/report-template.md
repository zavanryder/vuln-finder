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
- **CVSS v3.1:** `CVSS:3.1/AV:?/AC:?/PR:?/UI:?/S:?/C:?/I:?/A:?` -- Base score X.Y (Critical/High/Medium/Low). Required for every finding. Score the bug as it exists in the code, not the worst-case if combined with other bugs.
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

**Remediation (summary):**
[One-line concrete fix: e.g. use parameterized queries, allowlist redirect URLs, pin JWT algorithm, add CSRF middleware.]

**Remediation (detailed):** *(opt-in: include only when the caller requests remediation depth, e.g. via `--remediation-poc`)*
- **Root cause:** [Why the bug exists, phrased as a defect rather than a symptom. E.g. "User-supplied `name` is interpolated into SQL string; parameterization was never introduced on this code path."]
- **Principle:** [The security principle the fix enforces. E.g. "Separate data from control: queries must be parameterized so user input cannot alter query structure."]
- **Fix-in-depth layers:** [List of layered mitigations, ordered primary -> defense-in-depth. E.g. 1) Parameterize the query. 2) Input-validate `name` to `[A-Za-z0-9 _-]{1,64}`. 3) Use a least-privilege DB role so even a successful injection has minimal impact. 4) Log parameterized query usage for audit.]
- **What NOT to do:** [Common wrong fixes to avoid. E.g. "Do not blocklist quotes -- bypassable via encoding and comment tricks."]
- **Verification:** [Concrete evidence the fix works. E.g. "Re-run PoC-F1 against the patched binary; expect HTTP 400 with `invalid name` and no DB query executed."]

**PoC path:**
[Brief note on how to verify the exploit: e.g. "Send `' OR 1=1--` in the username field", "Create PR with injected title", "Upload crafted ZIP file".]

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

*Each PoC entry uses this shape:*

### PoC-F[n] -- [title]

**Run:** `[exact command, e.g. uv run poc_f1.py --base-url http://localhost:8080]`
**Language/runtime:** [Python 3 (uv) | Node/TypeScript (tsx) | C (gcc) | bash | ...]
**Dependencies:** `[e.g. uv add requests]` or `none`

```[lang]
[PoC code]
```

**Expected result:** [what success looks like -- stdout fragment, status code, file created, callback received]

*For exploit chains, prefer a single end-to-end script (Python/uv) covering all steps. If not feasible, state why and provide per-step PoCs each with its own `Run:` line.*

---

## Remediation proof of concept (opt-in)

*Include this section only when the caller requests remediation PoC (e.g. via the harness `--remediation-poc` flag or explicit user instruction). When requested, include a RemPoC for every finding regardless of severity: the fixed code plus a verification test. For Critical/High, the test re-runs the exploit and proves it now fails. For Medium/Low/Info, the test exercises the equivalent unsafe-input case and proves it is now rejected or handled safely. When not requested, omit this section -- the summary-remediation line is sufficient.*

*Each remediation PoC entry uses this shape:*

### RemPoC-F[n] -- [title]

**Run (verify fix):** `[exact command that exercises the fixed code path, e.g. uv run verify_f1_fix.py --base-url http://localhost:8080]`
**Language/runtime:** [Python 3 (uv) | Node/TypeScript (tsx) | C (gcc) | bash | ...]
**Dependencies:** `[e.g. uv add requests]` or `none`

**Fixed code (diff or full replacement):**

```[lang]
[Show the corrected code. Prefer a unified diff against the vulnerable excerpt shown in the finding. If a diff is unreadable (e.g. config templating), show the full fixed block. Annotate WHY each change matters with short inline comments.]
```

**Verification test:**

```[lang]
[For Critical/High: test script that runs the same payload as PoC-F[n] against the patched code and asserts the exploit no longer works -- e.g. HTTP 400 instead of 200, parameterized query prevents SQL error, file-write denied, etc.
For Medium/Low/Info (no PoC-F[n] to mirror): test script that submits the equivalent unsafe-input case and asserts the fix rejects or neutralizes it -- e.g. malformed config is now rejected at load, tainted value is now escaped in output, weak cipher is now refused.
Every test must produce a clear pass/fail signal.]
```

**Expected result:** [What success of the fix looks like -- specific status code, error message, denied operation, or state that did NOT change. For Critical/High, contrast explicitly with the exploit's expected result so the before/after is obvious.]

**Regression notes:** [Any behaviors the fix intentionally breaks (e.g. "legacy clients relying on non-ASCII usernames must migrate"). Write "None" if the fix is fully backwards-compatible.]

*For exploit chains, provide one remediation PoC per finding in the chain OR a single combined fix if one mitigation closes the whole chain (state which).*
