# Memory Safety Patterns (C/C++/Rust)

Patterns for buffer overflow, out-of-bounds read/write, use-after-free, integer overflow, and format string vulnerabilities in C and C++ code, plus unsafe Rust patterns.

---

## Table of contents

1. [Buffer overflow](#buffer-overflow)
2. [Out-of-bounds write](#out-of-bounds-write)
3. [Out-of-bounds read](#out-of-bounds-read)
4. [Use-after-free](#use-after-free)
5. [Integer overflow / wraparound](#integer-overflow--wraparound)
6. [Format string](#format-string)
7. [Rust unsafe patterns](#rust-unsafe-patterns)
8. [General search strategy](#general-search-strategy)

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

## Rust unsafe patterns

Rust's ownership system prevents most memory safety bugs at compile time, but `unsafe` blocks opt out of these guarantees. Vulnerabilities concentrate in `unsafe` code, FFI boundaries, and incorrect use of raw pointers.

### Dangerous patterns

**Raw pointer dereference:**
```rust
// VULNERABLE: dereferencing raw pointer without bounds validation
unsafe {
    let val = *ptr;             // raw pointer deref
    let slice = &*raw_slice;    // raw slice deref
    ptr.write(value);           // write through raw pointer
    ptr.offset(n);              // pointer arithmetic
}
```

**Transmute and type punning:**
```rust
// VULNERABLE: reinterprets memory layout -- UB if types incompatible
let val: T = unsafe { std::mem::transmute(bytes) };

// VULNERABLE: transmuting references can violate aliasing rules
let mutable: &mut T = unsafe { std::mem::transmute(shared_ref) };
```

**FFI boundaries:**
```rust
// VULNERABLE: C function returns pointer with unknown lifetime/validity
extern "C" { fn get_data() -> *mut u8; }
let data = unsafe { &*get_data() };  // may be null, dangling, or unaligned

// VULNERABLE: passing Rust data to C without ensuring it lives long enough
let s = CString::new(input).unwrap();
unsafe { c_function(s.as_ptr()); }
// s could be dropped here while C code still holds the pointer
```

**ManuallyDrop and forget misuse:**
```rust
// VULNERABLE: ManuallyDrop leaks resources or creates use-after-free
let mut data = ManuallyDrop::new(vec![1, 2, 3]);
unsafe { ManuallyDrop::drop(&mut data); }
// data is now dangling -- any subsequent access is UB
```

**Unchecked indexing:**
```rust
// VULNERABLE: bypasses bounds checking
let val = unsafe { slice.get_unchecked(index) };
let val = unsafe { *slice.as_ptr().add(index) };
```

**Unsafe trait implementations:**
```rust
// VULNERABLE: incorrectly implementing Send/Sync for non-thread-safe types
unsafe impl Send for MyType {}
unsafe impl Sync for MyType {}
```

### What to check
- Every `unsafe` block: is the safety invariant documented and upheld?
- FFI boundaries (`extern "C"`): lifetime management, null checks, alignment.
- `transmute`: are source and target types compatible in layout?
- Raw pointers: provenance, alignment, and validity at point of dereference.
- `Send`/`Sync` impls: does the type actually satisfy thread-safety requirements?

### Search signals
```
unsafe\s*\{|unsafe\s+fn|unsafe\s+impl
\*mut\s|\*const\s|\.as_ptr\(\)|\.as_mut_ptr\(\)
transmute|ManuallyDrop|forget\(
get_unchecked|\.offset\(|\.add\(
extern\s+"C"|#\[no_mangle\]
```

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

### High-signal grep patterns for Rust
```
unsafe\s*\{|unsafe\s+fn|unsafe\s+impl
transmute|ManuallyDrop|forget\(
\*mut\s|\*const\s|\.as_ptr|\.as_mut_ptr
get_unchecked|\.offset\(|\.add\(
extern\s+"C"|#\[no_mangle\]
```

### Analysis approach
1. **Find dangerous sinks** using the patterns above.
2. **Trace the size/length/index value** back to its source. Is it user-controlled (network input, file content, command-line argument)?
3. **Check for bounds validation** between source and sink. Is the value checked against the buffer size? Is the check correct (off-by-one, signed comparison)?
4. **Check for safe alternatives** being used elsewhere in the codebase. Inconsistent use of safe vs unsafe functions is a signal.
5. **For Rust**: focus on `unsafe` blocks. Check that safety invariants are documented and upheld. Pay special attention to FFI boundaries and `transmute`.
6. **Check compiler and runtime mitigations**: ASLR, stack canaries (`-fstack-protector`), FORTIFY_SOURCE, AddressSanitizer. These are mitigations, not fixes -- report the vulnerability and note mitigations if present.
