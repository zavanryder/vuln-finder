# PoC Guide: Web / HTTP / API Vulnerabilities

Use this when a finding is **Critical** or **High** and involves an HTTP endpoint, API, or web-accessible service.

## When to use

- SQL injection, NoSQL injection, SSRF, XSS, CSRF, command injection, code injection, deserialization, SSTI, path traversal, open redirect, IDOR/BOLA, auth bypass, JWT issues via HTTP endpoints.

## What to ask the user

Ask for the minimum needed to send a real request and inject the payload.

| What to ask | Example / notes |
|-------------|------------------|
| **Base URL** | `https://api.example.com` or `http://localhost:8080` |
| **Endpoint / path** | `/api/search`, `/admin/users`, `/webhook` |
| **HTTP method** | GET, POST, PUT, etc. For POST: JSON body, form, or raw? |
| **Parameter / header / body field** | The user-controlled input that reaches the sink |
| **Authentication** | None, API key, Bearer token, cookie, basic auth. Ask for a test placeholder. |
| **Other headers or body shape** | Content-Type, required headers, fixed JSON structure |
| **Chain steps (if applicable)** | URL/params for each step in a multi-step exploit |

## Workflow

1. **Propose a concrete payload** tied to the finding (e.g. SQLi sleep, SSRF to metadata URL, deserialization gadget).
2. **Get user confirmation** or adjustment.
3. **Build the script** from [assets/poc-script-template.py](../assets/poc-script-template.py):
   - Config at top: BASE_URL, endpoint, params, auth placeholder.
   - Request logic using `requests`.
   - Print status code, relevant headers, and body snippet (first 500 chars).
4. **Iterate**: "Run this against your test instance. Share the response or error and we can adjust."
5. For chains: implement step 1, verify, then add step 2 (parse output from step 1).

## Verification hints by bug class

- **SQLi**: Time-based: response delay matches injected `SLEEP`/`pg_sleep`. Union-based: extra data in response. Error-based: SQL error message visible.
- **SSRF**: Response contains internal service data, cloud metadata, or different response time for internal vs external URLs.
- **XSS**: Reflected payload visible in response HTML. For stored: payload renders in subsequent page load.
- **Command injection**: Response contains command output, or out-of-band callback received (DNS, HTTP).
- **Deserialization**: RCE verified via callback, file creation, or response change.
- **Path traversal**: Response contains file contents (e.g. `/etc/passwd`, `web.config`).
- **IDOR**: Changing ID parameter returns different user's data.
- **Auth bypass**: Request without credentials returns protected data.
