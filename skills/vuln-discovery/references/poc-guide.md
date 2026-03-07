# Proof-of-Concept (PoC) Guide

Use this when a finding is **Critical** or **High**, or when an **exploit chain** has Critical/High impact (e.g. RCE, high-value data exfiltration). Always suggest a PoC payload and work with the user to build a **fully functional Python PoC script**.

## When to offer a PoC

- Any **single finding** with severity **Critical** or **High**.
- Any **exploit chain** whose **Result** is Critical or High (RCE, critical data exfiltration, full auth bypass, etc.).

Do **not** build full PoC scripts for Medium/Low/Info-only findings unless the user explicitly asks.

## What to ask the user (gather before coding)

Ask for the minimum needed to send a real request and inject the payload. Request one at a time if it keeps the conversation clear.

| What to ask | Example / notes |
|-------------|------------------|
| **Base URL** | `https://api.example.com` or `http://localhost:8080` — where the app is reachable. |
| **Endpoint / path** | e.g. `/api/deserialize`, `/search`, `/webhook` — the route that receives user-controlled data. |
| **HTTP method** | GET, POST, PUT, etc. If POST, ask whether body is JSON, form, or raw. |
| **Parameter / header / body field** | The name(s) of the user-controlled input that reaches the vulnerable sink (e.g. `data`, `q`, `url`, `id`, `Cookie: session`). |
| **Authentication** | None, API key (header/query), Bearer token, cookie, basic auth — and where to put it. Ask the user to provide a test token or placeholder; never hardcode real secrets. |
| **Other headers or body shape** | Content-Type, required headers, or fixed JSON structure so the server accepts the request. |
| **Chain steps (if applicable)** | For chains: URL/params for each step (e.g. first request returns a token, second request uses it). |

Example prompts to use:

- “To build a PoC I need the URL where [finding] can be triggered. What’s the base URL and path (e.g. `https://target.com/api/endpoint`)?”
- “Which parameter or header is user-controlled and fed into [sink]? For example query param `q`, or JSON body field `payload`.”
- “Does this endpoint require auth? If so, how (e.g. `Authorization: Bearer <token>`, or a cookie)? You can use a placeholder; we won’t store real secrets.”

## Suggesting the payload first

Before writing the script:

1. **Propose a concrete PoC payload** that demonstrates the issue (e.g. SQLi sleep, deserialization gadget, SSRF to metadata URL, prototype-pollution JSON).
2. **Tie it to the finding**: “For Finding #2 (SSRF), a minimal PoC payload is `url=http://169.254.169.254/latest/meta-data/`.”
3. **Invite the user** to confirm or adjust, then implement that payload in the Python script.

## Building the Python PoC script

1. **Start from** [assets/poc-script-template.py](assets/poc-script-template.py): config at top (BASE_URL, endpoint, params, auth placeholder), then request logic, then optional response checks.
2. **Implement one finding (or one chain step) per script** unless the user wants a single script that runs the full chain.
3. **Use `requests`** (or `urllib` if no deps desired): build the request (URL, method, params, headers, body) and inject the payload into the user-controlled parameter/header/body field.
4. **Print or return** enough to show success: status code, relevant response headers, and a snippet of the body (e.g. first 500 chars). For RCE, “success” might be a visible side effect (e.g. callback, DNS, or delayed response); document how the user can verify.
5. **Safety**: Add a short comment at the top: use only against targets you are authorized to test. Do not include real credentials; use placeholders or env vars.

## Iterating with the user

- After a first version: “Run this against your test instance. If you get 403/404 or the payload isn’t reflected, share the response or error and we can adjust URL/method/params.”
- If the chain has multiple steps: implement step 1, verify with the user, then add step 2 (e.g. parse token from step 1 and send it in step 2).
- Keep the script minimal: no unnecessary dependencies, clear variable names (e.g. `PAYLOAD_SQLI`, `SSRF_URL`), and a single entry point (e.g. `main()` or running at module level).

## Output and verification

- Script should print whether it sent the request and what it received (status, body excerpt).
- For data exfiltration PoCs, parsing and printing a small subset of exfiltrated data is enough to prove the concept; avoid dumping huge payloads by default.
- Document in comments or docstring how to interpret success (e.g. “If RCE: check callback server or response delay.”).
