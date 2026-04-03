# Access Control Patterns

Patterns for authentication, authorization, CSRF, CORS, JWT/session issues, and related access-control vulnerabilities. Organized by bug class, then by language/framework.

The access-control classes are intentionally granular because they require different search strategies and have different severity/remediation profiles.

---

## Table of contents

1. [Missing authentication](#missing-authentication)
2. [Missing authorization](#missing-authorization)
3. [Incorrect authorization](#incorrect-authorization)
4. [Object-level authorization (BOLA/IDOR)](#object-level-authorization)
5. [Object-property authorization (BOPLA/mass assignment)](#object-property-authorization)
6. [Function-level authorization (BFLA)](#function-level-authorization)
7. [CSRF](#csrf)
8. [CORS misconfiguration](#cors-misconfiguration)
9. [JWT / session issues](#jwt--session-issues)

---

## Missing authentication

Look for routes, endpoints, or handlers that are accessible without any authentication middleware or check.

### General strategy
- Map all route definitions and check which ones lack auth middleware.
- Look for `@Public`, `@AllowAnonymous`, `skip_before_action`, or equivalent annotations that exempt routes.
- Check API gateways and reverse proxy configs for auth bypass.

### By framework

- **Express (JS/TS)**: Routes registered without `passport.authenticate`, `jwt` middleware, or custom auth middleware. Check `app.use` ordering -- auth middleware after route registration is ineffective.
- **Spring (Java/Kotlin)**: Endpoints without `@PreAuthorize`, `@Secured`, or not covered by `SecurityFilterChain` `requestMatchers`. Check `WebSecurityConfigurerAdapter` or `SecurityFilterChain` for `.permitAll()` on sensitive paths.
- **Django (Python)**: Views without `@login_required`, `LoginRequiredMixin`, or `permission_required`. Check `urls.py` for views that skip authentication. `REST_FRAMEWORK` default permission/authentication classes set to `AllowAny`.
- **Flask (Python)**: Routes without `@login_required` (Flask-Login) or custom auth decorators. Check `before_request` hooks.
- **FastAPI (Python)**: Endpoints without `Depends(get_current_user)` or equivalent dependency. Check `APIRouter` for missing dependencies.
- **Rails (Ruby)**: Controllers without `before_action :authenticate_user!`; `skip_before_action :authenticate_user!` on sensitive actions.
- **ASP.NET (C#)**: Controllers/actions without `[Authorize]`; `[AllowAnonymous]` on sensitive endpoints.
- **Go**: HTTP handlers without auth middleware in the handler chain; routes registered outside the authenticated middleware group.

---

## Missing authorization

Authentication is present but no check verifies the user has permission for the specific resource or action.

### General strategy
- After identifying authenticated endpoints, check whether they verify the user's role, group, or ownership before acting.
- Look for endpoints that take a resource ID and perform operations without checking the requesting user's relationship to that resource.

### By framework

- **Express**: Authenticated route that reads `req.params.id` and queries the database without filtering by `req.user.id`.
- **Spring**: `@PreAuthorize` is absent; method uses path variable directly without ownership check. `@Secured("ROLE_USER")` allows any authenticated user.
- **Django**: `get_object_or_404(Model, pk=pk)` without filtering by `request.user`. DRF `ViewSet` without `get_queryset` filtering.
- **Rails**: `Model.find(params[:id])` without `current_user.models.find(params[:id])`.
- **ASP.NET**: `[Authorize]` present but no policy or resource-based authorization.
- **Go**: Handler checks `ctx.Value("user")` exists but doesn't verify ownership of the requested resource.

---

## Incorrect authorization

Authorization check exists but is flawed.

### Common patterns (any language)
- Client-side role checks (hidden UI elements but no server-side enforcement).
- Role comparison using string equality that's case-sensitive or truncated.
- JWT role claim trusted without signature verification.
- `isAdmin` flag set from request body or cookie without server-side validation.
- OR logic instead of AND for multi-condition checks: `if (isAdmin || isOwner)` when both should be required.
- Path-based authorization bypassed via URL encoding, trailing slashes, path parameters, or case differences (`/admin` vs `/Admin` vs `/admin/`).

---

## Object-level authorization

Classic IDOR / BOLA. User can access other users' objects by changing an ID.

### Search strategy
1. Find endpoints that accept an object ID (path param, query param, body field).
2. Check whether the query filters by the authenticated user's identity or ownership.
3. Look for direct database lookups: `Model.findById(id)` vs `Model.findOne({_id: id, userId: req.user.id})`.

### Framework patterns
- **Express + Mongoose**: `Model.findById(req.params.id)` without `.where('user', req.user._id)`.
- **Django DRF**: `get_object()` without `get_queryset()` filtering by `self.request.user`.
- **Rails**: `Model.find(params[:id])` without scoping to `current_user`.
- **Spring**: `repository.findById(id)` without ownership verification in service layer.
- **GraphQL**: Resolver fetches by ID without checking the requesting user's access.

---

## Object-property authorization

BOPLA / mass assignment. User can set properties they shouldn't be able to (e.g. `role`, `isAdmin`, `price`).

### Search strategy
1. Find endpoints that accept a JSON/form body and bind it to a model or database record.
2. Check whether a property allowlist is enforced (e.g. strong params, DTO, schema validation).
3. Flag any pattern that passes the entire request body to a create/update operation.

### Framework patterns
- **Express + Mongoose**: `Model.create(req.body)` or `doc.set(req.body)` without schema-level field restriction.
- **Django DRF**: Serializer without explicit `fields` list (or using `fields = '__all__'` on models with sensitive fields).
- **Rails**: `Model.new(params.permit!)` or `params.require(:model).permit(:role, :admin)` with overly broad permit list.
- **Spring**: DTO with setter for `role` or `isAdmin` bound directly from `@RequestBody` without `@JsonIgnore` or allowlist.
- **ASP.NET**: Model binding without `[BindNever]` on sensitive properties; `TryUpdateModel` with user input.
- **FastAPI**: Pydantic model includes privileged fields accepted from request body.

---

## Function-level authorization

BFLA. User accesses admin or privileged functionality they shouldn't reach.

### Search strategy
1. Find admin, management, or internal endpoints (URL patterns: `/admin`, `/internal`, `/manage`, `/debug`).
2. Check whether these routes require elevated roles/permissions.
3. Look for feature flags or environment-based access that can be manipulated.

### Common patterns
- Admin routes share the same middleware as user routes.
- `if (req.user.role === 'admin')` check in the handler body but the route itself is accessible.
- Different HTTP methods on the same path with different authorization (e.g. GET is public, PUT requires admin -- but DELETE is unprotected).

---

## CSRF

State-changing requests (POST, PUT, DELETE) that rely solely on cookies for authentication without CSRF token or SameSite enforcement.

### Search strategy
1. Identify state-changing endpoints.
2. Check whether CSRF middleware is enabled globally.
3. Look for exemptions: `@csrf_exempt`, `csrf: false`, `VerifyCsrfToken` except list.

### Framework patterns
- **Express**: No `csurf` or equivalent middleware; or `csurf` is installed but not applied to specific routes. SameSite cookie attribute not set.
- **Django**: `@csrf_exempt` on state-changing views; `CSRF_COOKIE_HTTPONLY` or `CSRF_TRUSTED_ORIGINS` misconfigured; DRF with `SessionAuthentication` but CSRF disabled.
- **Rails**: `skip_before_action :verify_authenticity_token` on state-changing actions; `protect_from_forgery with: :null_session` in API controllers that still use cookies.
- **Spring**: `csrf().disable()` in `SecurityFilterChain`; CSRF disabled for all endpoints instead of just stateless API routes.
- **ASP.NET**: `[IgnoreAntiforgeryToken]` on state-changing actions; missing `@Html.AntiForgeryToken()` in forms.

---

## CORS misconfiguration

Overly permissive CORS that allows cross-origin requests with credentials.

### Search strategy
1. Search for CORS middleware configuration.
2. Flag: reflecting `Origin` header as `Access-Control-Allow-Origin`, wildcard `*` with credentials, trusting `null` origin, regex that doesn't anchor properly.

### Common patterns (any language)
- `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` (browsers reject this, but it signals intent to be permissive).
- Origin reflected from request header without allowlist check: `res.setHeader('Access-Control-Allow-Origin', req.headers.origin)`.
- Regex like `/example\.com/` that matches `evilexample.com`.
- Express `cors({ origin: true, credentials: true })`.
- Django `CORS_ALLOW_ALL_ORIGINS = True` with `CORS_ALLOW_CREDENTIALS = True`.
- Spring `@CrossOrigin` without `origins` restriction.
- Rails `rack-cors` with `origins '*'` and `credentials: true`.

---

## JWT / session issues

### Search strategy
1. Find JWT verification code. Check that signature is verified, algorithm is pinned, and claims (exp, aud, iss) are validated.
2. Find session configuration. Check cookie attributes (HttpOnly, Secure, SameSite).

### Common patterns
- **`alg=none` bypass**: Library accepts `alg: none` in JWT header; attacker removes signature. Search for `algorithms` option not being pinned: `jwt.verify(token, secret)` without `{ algorithms: ['HS256'] }`.
- **Weak secret**: JWT secret is short, predictable, or hardcoded (e.g. `"secret"`, `"changeme"`).
- **Key confusion**: RSA public key used as HMAC secret (`RS256` token verified as `HS256`).
- **Missing expiration check**: JWT decoded without checking `exp` claim.
- **Session fixation**: Session ID not regenerated after login.
- **Insecure cookies**: Session cookie missing `HttpOnly`, `Secure`, or `SameSite` attributes.

### By library
- **jsonwebtoken (Node)**: `jwt.verify(token, secret)` without `algorithms` option. `jwt.decode` (no verification) used where `jwt.verify` is needed.
- **PyJWT (Python)**: `jwt.decode(token, secret, algorithms=["HS256"])` -- verify `algorithms` is present and doesn't include `none`.
- **java-jwt / jjwt**: Check that `JwtParser` specifies expected algorithm; `Jwts.parser().setSigningKey(key)` without `.requireAudience()` or `.requireIssuer()`.
- **Spring Security**: `JwtDecoder` configuration without audience/issuer validation.
- **Ruby (ruby-jwt)**: `JWT.decode(token, secret, true, algorithm: 'HS256')` -- check that verification is `true` and algorithm is pinned.
