# Memory Safety Patterns (C/C++)

Patterns for buffer overflow, out-of-bounds read/write, use-after-free, integer overflow, and format string vulnerabilities in C and C++ code.

---

## Table of contents

1. [Buffer overflow](#buffer-overflow)
2. [Out-of-bounds write](#out-of-bounds-write)
3. [Out-of-bounds read](#out-of-bounds-read)
4. [Use-after-free](#use-after-free)
5. [Integer overflow / wraparound](#integer-overflow--wraparound)
6. [Format string](#format-string)
7. [General search strategy](#general-search-strategy)

---

## Buffer overflow

### Stack-based (CWE-121)
- `strcpy`, `strcat`, `sprintf`, `gets` -- unbounded copies into fixed-size stack buffers.
- `scanf("%s", buf)` without width specifier.
- Array declared on stack with fixed size, indexed by user-controlled value.
- `alloca(user_size)` with unchecked size.

### Heap-based (CWE-122)
- `malloc(size)` followed by `memcpy(buf, src, len)` where `len > size`.
- `realloc` return value not checked (could be NULL, but old pointer still used).
- `strdup`/`strndup` result used without null check.

### Safer alternatives to look for (absence is a signal)
- `strncpy`, `strncat`, `snprintf` -- bounded but still require correct size calculation.
- `strlcpy`, `strlcat` (BSD) -- better but not universally available.
- C++ `std::string`, `std::vector`, `std::array` -- generally safe if not mixed with raw pointers.

---

## Out-of-bounds write

- Array indexed by user-controlled or computed index without bounds check.
- Loop writing to buffer with off-by-one: `for (i = 0; i <= len; i++)` instead of `< len`.
- `memcpy`, `memmove`, `memset` with user-controlled length or destination offset.
- Write through pointer arithmetic: `*(buf + offset) = val` where offset is unchecked.

---

## Out-of-bounds read

- `memcmp`, `memcpy` reading past buffer end when length exceeds actual data.
- String functions on non-null-terminated buffers.
- `read()` return value not checked -- buffer may have fewer bytes than expected.
- Struct field access after partial read from network/file.
- Heartbleed pattern: length field from protocol message used to read from memory without validation.

---

## Use-after-free

- `free(ptr)` followed by dereference of `ptr` (not set to NULL).
- Object freed in one code path, used in another (conditional free).
- Iterator invalidation in C++: element erased from container while iterating, then iterator dereferenced.
- Destructor called explicitly, then object used.
- Returning pointer to local variable (dangling pointer).
- `delete this` followed by member access.
- Double free: `free(ptr)` called twice on same pointer.

### Search signals
- `free()` or `delete` not followed by `= NULL` / `= nullptr`.
- Error/cleanup paths that free resources but continue to use them.
- Callbacks or event handlers that reference objects with uncertain lifetime.

---

## Integer overflow / wraparound

- Arithmetic on user-controlled integers used for:
  - `malloc(count * size)` -- if `count * size` wraps, small allocation + large copy.
  - Array index calculation.
  - Loop bound calculation.
  - Length/size fields in protocol parsing.
- Signed-to-unsigned conversion: negative value becomes large positive when cast to `size_t`.
- `int` used where `size_t` is needed for sizes/lengths.
- Subtraction resulting in negative value used as unsigned.
- Truncation: `uint32_t` value assigned to `uint16_t` without range check.

### Search signals
- Cast between signed and unsigned types near allocation or bounds checks.
- Multiplication of two values used in `malloc`/`calloc` without overflow check.
- Missing check: `if (a + b < a)` pattern absent before use.

---

## Format string

- `printf(user_input)`, `fprintf(f, user_input)`, `sprintf(buf, user_input)` -- user controls the format string.
- `syslog(priority, user_input)` without format specifier.
- `snprintf(buf, size, user_input)` -- same risk.
- `err`, `warn`, `warnx` with user-controlled first argument.

### Impact
- `%x` reads from stack (information disclosure).
- `%n` writes to memory (arbitrary write, code execution).
- `%s` reads from arbitrary address (crash or info disclosure).

### Safe pattern
- Always use `printf("%s", user_input)` instead of `printf(user_input)`.

---

## General search strategy

### High-signal grep patterns for C/C++
```
strcpy|strcat|sprintf|gets|scanf.*%s
malloc|calloc|realloc|alloca
memcpy|memmove|memset
free\s*\(|delete\s+|delete\[\]
printf\s*\(|fprintf\s*\(|snprintf\s*\(|syslog\s*\(
(int|short|char)\s+.*\*\s*(size|len|count|offset|index)
```

### Analysis approach
1. **Find dangerous sinks** using the patterns above.
2. **Trace the size/length/index value** back to its source. Is it user-controlled (network input, file content, command-line argument)?
3. **Check for bounds validation** between source and sink. Is the value checked against the buffer size? Is the check correct (off-by-one, signed comparison)?
4. **Check for safe alternatives** being used elsewhere in the codebase. Inconsistent use of safe vs unsafe functions is a signal.
5. **Check compiler and runtime mitigations**: ASLR, stack canaries (`-fstack-protector`), FORTIFY_SOURCE, AddressSanitizer. These are mitigations, not fixes -- report the vulnerability and note mitigations if present.
