# PoC Guide: Memory Corruption Vulnerabilities (C/C++)

Use this when a finding is **Critical** or **High** and involves buffer overflow, out-of-bounds read/write, use-after-free, integer overflow, or format string vulnerabilities in C/C++ code.

## When to use

- Buffer overflow (stack or heap), out-of-bounds write/read, use-after-free, double free, integer overflow leading to memory corruption, format string vulnerabilities.

## Key differences from web PoCs

- PoC may be a C program, Python script generating crafted input, or a combination.
- Exploitation often requires knowledge of binary layout, compiler, OS, and mitigations (ASLR, stack canaries, NX).
- PoC goal is often to demonstrate the crash or control of execution flow, not necessarily full exploitation.

## What to ask the user

| What to ask | Example / notes |
|-------------|------------------|
| **How input reaches the vulnerable code** | Network socket, file parsing, CLI argument, environment variable, IPC |
| **Target binary** | Path to the compiled binary or how to build it |
| **Platform** | OS, architecture (x86_64, ARM), compiler (GCC, Clang, MSVC) |
| **Mitigations** | ASLR, stack canaries, NX, FORTIFY_SOURCE, AddressSanitizer enabled? |
| **Crash or control?** | Is demonstrating a crash sufficient, or does the user want controlled execution? |

## Workflow

1. **Craft input** that triggers the vulnerability:
   - Buffer overflow: input longer than buffer size.
   - Format string: input containing `%x%x%x%x` or `%n`.
   - Integer overflow: input with large numeric value that wraps.
   - Use-after-free: sequence of operations that triggers free then use.

2. **Build with sanitizers** for clear confirmation:
   ```bash
   gcc -fsanitize=address -g -o target target.c
   ./target < malicious_input.bin
   ```
   AddressSanitizer will print the exact error type, location, and stack trace.

3. **Verify the crash** or sanitizer output.

## Python script for generating crafted input

```python
#!/usr/bin/env python3
"""PoC: [finding title]. Generates crafted input to trigger [vuln type]."""

import struct
import sys

def generate_payload():
    # Buffer overflow example: fill buffer + overwrite saved return address
    buf_size = 64
    padding = b"A" * buf_size
    # Overwrite saved RBP
    rbp = b"B" * 8
    # Overwrite return address (placeholder -- adjust per target)
    ret = struct.pack("<Q", 0x4141414141414141)
    return padding + rbp + ret

def main():
    output = sys.argv[1] if len(sys.argv) > 1 else "payload.bin"
    payload = generate_payload()
    with open(output, "wb") as f:
        f.write(payload)
    print(f"Payload written to {output} ({len(payload)} bytes)")
    print(f"Run: ./target < {output}")

if __name__ == "__main__":
    main()
```

## Verification

- **Crash**: Segfault (signal 11) at a controlled address confirms control of instruction pointer.
- **AddressSanitizer**: Reports exact error type (heap-buffer-overflow, stack-buffer-overflow, use-after-free, etc.) with source location.
- **Format string**: `%x` output leaks stack values; `%n` causes write (often crash if not carefully targeted).
- **Integer overflow**: Allocation succeeds with small size, subsequent write overflows the undersized buffer.

## Important notes

- Memory corruption PoCs are inherently platform-specific. Always note the target architecture, OS, and compiler.
- AddressSanitizer is the fastest way to confirm a vulnerability without full exploitation.
- Full exploitation (shell, code execution) requires bypassing mitigations and is out of scope for initial PoC. Focus on demonstrating the memory corruption.
