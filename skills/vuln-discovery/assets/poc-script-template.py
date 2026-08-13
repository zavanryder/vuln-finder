#!/usr/bin/env python3
"""
Proof-of-Concept script for [FINDING_TITLE / CHAIN_NAME].
Use only against targets you are authorized to test.
Replace placeholders (BASE_URL, payload, auth) with values provided by the user.

Run:
    uv run poc_[finding].py --base-url http://localhost:8080

Dependencies:
    uv add requests
"""

import argparse
import sys

try:
    import requests
except ImportError:
    print("Install requests: uv add requests", file=sys.stderr)
    sys.exit(1)

# --- Config (fill from user) ---
BASE_URL = "https://example.com"  # Ask user for base URL
ENDPOINT = "/api/endpoint"        # Path that receives user-controlled data
METHOD = "POST"                   # GET, POST, etc.
USER_CONTROLLED_PARAM = "data"    # Query param, JSON key, or header name where payload goes

# Optional: auth placeholder — user supplies real value for their test env
AUTH_HEADER = None  # e.g. "Bearer YOUR_TOKEN" or None
# API_KEY = ""

# --- Payload ---
# Replace with the actual PoC payload for this finding (e.g. SSRF URL, SQLi snippet, deserialization blob)
PAYLOAD = ""

# --- Request logic ---
def build_headers():
    headers = {"User-Agent": "PoC-Script/1.0"}
    if AUTH_HEADER:
        headers["Authorization"] = AUTH_HEADER
    return headers

def send_poc():
    url = BASE_URL.rstrip("/") + "/" + ENDPOINT.lstrip("/")
    headers = build_headers()

    if METHOD.upper() == "GET":
        params = {USER_CONTROLLED_PARAM: PAYLOAD}
        resp = requests.get(url, params=params, headers=headers, timeout=15)
    elif METHOD.upper() == "POST":
        # Adjust: JSON body vs form vs raw
        json_body = {USER_CONTROLLED_PARAM: PAYLOAD}
        resp = requests.post(url, json=json_body, headers=headers, timeout=15)
    else:
        # Extend as needed (PUT, PATCH, etc.)
        resp = requests.request(METHOD, url, json={USER_CONTROLLED_PARAM: PAYLOAD}, headers=headers, timeout=15)

    return resp

def main():
    parser = argparse.ArgumentParser(description="PoC for [finding/chain]")
    parser.add_argument("--base-url", default=BASE_URL, help="Target base URL")
    parser.add_argument("--payload", default=PAYLOAD, help="Override payload (optional)")
    args = parser.parse_args()

    global BASE_URL, PAYLOAD
    BASE_URL = args.base_url
    if args.payload:
        PAYLOAD = args.payload

    print(f"[*] Sending {METHOD} to {BASE_URL}{ENDPOINT}")
    print(f"[*] Payload in '{USER_CONTROLLED_PARAM}': {PAYLOAD[:80]}{'...' if len(PAYLOAD) > 80 else ''}")
    try:
        r = send_poc()
        print(f"[+] Status: {r.status_code}")
        print(f"[+] Response (first 500 chars):\n{r.text[:500]}")
        # Add verification hint, e.g.: "For SSRF, check if response contains metadata."
    except requests.RequestException as e:
        print(f"[-] Request failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
