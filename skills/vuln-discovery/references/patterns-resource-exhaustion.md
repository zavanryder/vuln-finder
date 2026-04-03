# Resource Exhaustion Patterns

Patterns for ReDoS, unbounded queries, upload size abuse, GraphQL depth/complexity abuse, and other denial-of-service vectors caused by missing resource limits.

---

## Table of contents

1. [ReDoS (Regular expression DoS)](#redos)
2. [Unbounded queries and pagination](#unbounded-queries-and-pagination)
3. [Upload size and count](#upload-size-and-count)
4. [GraphQL abuse](#graphql-abuse)
5. [General resource limits](#general-resource-limits)

---

## ReDoS

Regular expressions with catastrophic backtracking when given adversarial input.

### Vulnerable regex patterns
- **Nested quantifiers**: `(a+)+`, `(a*)*`, `(a|a)+` -- exponential backtracking.
- **Overlapping alternation**: `(a|ab)+` with long string of `a`s.
- **Greedy + lazy in sequence**: `.*?.*` in certain engines.

### By language
- **JavaScript**: V8's regex engine is vulnerable to ReDoS. Common in Express route params, validation middleware, `String.match()`, `String.replace()` with user input.
- **Python**: `re` module is vulnerable. `re.match(pattern, user_input)` with bad pattern. Use `re2` or `regex` module with timeout for untrusted patterns.
- **Java**: `java.util.regex` is vulnerable. `Pattern.compile(userPattern).matcher(input)`.
- **Go**: `regexp` package uses RE2 (linear time) -- generally safe from ReDoS. But `regexp/syntax` with PCRE features can be slow.
- **Ruby**: Onigmo engine is vulnerable. `/pattern/ =~ user_input`.
- **PHP**: PCRE engine has backtrack limits (`pcre.backtrack_limit`) but default is high.

### Search strategy
1. Find regex patterns applied to user input.
2. Check for nested quantifiers, overlapping alternation.
3. Check if the pattern itself is user-controlled (much worse -- allows arbitrary ReDoS).

---

## Unbounded queries and pagination

API endpoints that return all matching records without limits.

### Common patterns
- **No LIMIT clause**: `SELECT * FROM table WHERE ...` without `LIMIT`.
- **Unbounded `find()`**: MongoDB `collection.find(query)` without `.limit()`.
- **Missing pagination**: REST endpoint returns all records; no `page`/`limit` query params.
- **Client-controlled page size**: `?limit=999999` accepted without server-side cap.
- **Cursor-based pagination without depth limit**: Client can keep paginating indefinitely.

### By framework
- **Django**: `Model.objects.all()` serialized without pagination class. DRF without `DEFAULT_PAGINATION_CLASS`.
- **Rails**: `Model.all` without `.limit()`. API response without Kaminari/will_paginate.
- **Express + Mongoose**: `Model.find(query)` without `.limit()`. `req.query.limit` passed directly to `.limit(parseInt(req.query.limit))` without cap.
- **Spring**: `JpaRepository.findAll()` without `Pageable`. `@RequestParam Integer size` without `@Max`.

---

## Upload size and count

Missing or insufficient limits on file uploads.

### Common patterns
- **No size limit**: Upload middleware accepts files of any size.
- **No count limit**: Multipart form accepts unlimited number of files.
- **No content validation**: Server accepts any content type, enabling resource waste.
- **Decompression bomb**: Archive uploaded and extracted without checking expanded size (zip bomb, gzip bomb).

### By framework
- **Express + multer**: `multer()` without `limits: { fileSize, files }` option.
- **Django**: `FILE_UPLOAD_MAX_MEMORY_SIZE` and `DATA_UPLOAD_MAX_MEMORY_SIZE` defaults may be too large; no per-field size check.
- **Flask**: `MAX_CONTENT_LENGTH` not set in config.
- **Rails**: No `content_length` check in controller; Active Storage without size validation.
- **Spring**: `spring.servlet.multipart.max-file-size` not configured or set too high.
- **Go**: `http.MaxBytesReader` not used; `r.ParseMultipartForm(maxMemory)` with large `maxMemory`.

---

## GraphQL abuse

### Query depth and complexity
- **No depth limit**: Deeply nested query like `{ user { posts { comments { author { posts { ... } } } } } }` causes N+1 queries or exponential data fetching.
- **No complexity limit**: Single query touches many resolvers with expensive operations.
- **Introspection enabled in production**: `__schema` and `__type` queries expose full API schema to attackers.
- **Batch query abuse**: Multiple operations in a single request without limit.

### Search patterns
- Apollo Server: Check for `validationRules` including `depthLimit` and `costAnalysis`. Missing = vulnerable.
- graphql-yoga / Helix: Check for query depth/complexity plugins.
- Hasura: Check `HASURA_GRAPHQL_MAX_QUERY_DEPTH` env var.
- Schema stitching / federation: Each subgraph may lack its own depth limits.

### Authorization in resolvers
- Resolver returns data without checking the requesting user's access.
- Field-level authorization missing: user can query sensitive fields (email, SSN) on objects they can see but shouldn't see all fields of.

---

## General resource limits

### Patterns to check
- **No rate limiting**: API endpoints without rate limiting middleware (express-rate-limit, Django Ratelimit, Spring Bucket4j, etc.).
- **Expensive operations without queueing**: Synchronous processing of compute-heavy requests (image resize, PDF generation, report generation) without job queue or timeout.
- **Recursive data processing**: Processing user-supplied JSON/XML/YAML with no depth limit; deeply nested structures cause stack overflow.
- **Long-running connections**: WebSocket or SSE connections without idle timeout or connection limit.
- **DNS rebinding**: Server makes HTTP request to user-controlled hostname; hostname resolves to internal IP after initial DNS check.
- **Hash collision DoS**: Hash tables with user-controlled keys in languages with predictable hashing (mostly historical, but still relevant for some runtimes).
