# Expression Language Injection Patterns

Source-to-sink patterns for Expression Language (EL) injection across Java
ecosystems. Use these when scanning for the `el-injection` bug class
(CWE-917 / CWE-1336). EL injection is distinct from generic SSTI because the
expression language is evaluated against Java objects with reflection
capabilities, typically leading directly to RCE.

## Common sinks

All of these evaluate a string as an EL expression. If the string is
user-controlled, any of them is an RCE sink.

### OGNL (Struts, MyBatis, EhCache, Tapestry)

- `com.opensymphony.xwork2.util.reflection.ReflectionProvider.evaluate(...)`
- `ognl.Ognl.parseExpression(userInput)` + `Ognl.getValue(expr, context, root)`
- `ognl.Ognl.getValue(userInput, ctx, root)`
- `ActionContext.getContext().getValueStack().findValue(userInput)`
- In Struts tags: `<s:property value="%{#session.user}"/>` — if any `value`,
  `test`, or attribute of a Struts tag takes a `%{...}` expression built
  from a user-controlled string, evaluation is unsafe.
- `org.apache.ibatis.ognl.Ognl.parseExpression` (MyBatis uses OGNL for
  dynamic SQL `<if test="${expr}">`).

### SpEL (Spring)

- `org.springframework.expression.spel.standard.SpelExpressionParser.parseExpression(userInput).getValue(...)`
- `new SpelExpressionParser().parseExpression(userInput).getValue(ctx)`
- `@Value("#{${userInput}}")` or `@Value("#{systemProperties['user.name']}")`
  where the outer `${...}` is user-controlled → SpEL evaluation of injected text.
- `StandardEvaluationContext` with user input — dangerous by default
  (full reflection). `SimpleEvaluationContext.forReadOnlyDataBinding().build()`
  is the safe variant; treat absence of `SimpleEvaluationContext` as a red flag.
- Spring Security `@PreAuthorize("hasRole('" + userInput + "')")` — SpEL
  evaluation of concatenated user data.
- Spring Cloud Function `spring.cloud.function.routing-expression` header
  (CVE-2022-22963): `RoutingFunction` parses the header as SpEL with
  `StandardEvaluationContext` and `BeanFactoryResolver`.
- Spring Data `@Query` with SpEL fragments built from request data
  (rare but occurs in custom repository bases).
- Thymeleaf in Spring views: `th:text="${param.x}"` is safe (escaped), but
  `th:utext`, `th:attr`, or concatenating user input into a Thymeleaf
  expression string is an SSTI/EL sink.

### JSP / Jakarta EL

- `javax.el.ELProcessor.eval(userInput)` / `jakarta.el.ELProcessor.eval(userInput)`
- `ExpressionFactory.createValueExpression(ctx, userInput, Object.class).getValue(ctx)`
- Any EL expression inside a JSP/JSPX/JSF that is **built** from user input
  (not merely rendering a user value). Compare:
  - Safe: `<c:out value="${user.name}"/>` — EL evaluates the static expression
    `user.name` and escapes the result.
  - Unsafe: `<c:out value="${param.expr}"/>` where the app later `include`s
    a page whose source line is `${__${userSupplied}__}` — double evaluation.
  - Unsafe: `pageContext.getAttribute(param)` where `param` is attacker-chosen
    and the attribute value is later fed back into EL evaluation.

### ADF EL (Oracle ADF / JSFF / JSPX)

- `oracle.jbo.common.JboEL.evaluate(userInput, bindingContext)`
- `AdfmfJavaUtilities.evaluateELExpression(userInput)`
- `javax.faces.el.ValueBinding` / `FacesContext.getApplication().createValueBinding(userInput)`
- Any `#{...}` construction in JSPX/JSFF markup where the expression string
  itself is derived from a managed-bean field that holds user input.
  Example unsafe pattern: `<af:outputText value="#{bindings[userParam].inputValue}"/>`
  where `userParam` is an attacker-supplied request parameter used as the
  binding-lookup key.

### JEXL, MVEL, Camel Simple

- `org.apache.commons.jexl3.JexlEngine.createExpression(userInput).evaluate(ctx)`
- `org.apache.commons.jexl3.JexlEngine.createScript(userInput).execute(ctx)`
- `org.mvel2.MVEL.eval(userInput, ctx)`
- `org.mvel2.compiler.CompiledExpression.getValue(...)` on a compiled
  user-controlled expression.
- Apache Camel `.simple(userInput)` in a route — Camel Simple is a
  lightweight EL and permits method invocation by default.
- Drools DRL / SpEL-style rule text built from user input.

## Common sources

- HTTP request parameters, headers, body fields (Spring MVC `@RequestParam`,
  `@RequestHeader`, `@RequestBody`; Struts `ActionForm`; ADF managed-bean
  request attributes).
- User-editable configuration surfaces reaching the server: admin UI
  inputs, file uploads, webhook payloads.
- Second-order: user input stored in a DB column / cache / JMS message
  whose later consumer evaluates the stored string as EL.
- CI/CD: build parameters interpolated into a Groovy / Jenkins pipeline
  that then evaluates them (Jenkinsfile `${params.X}` inside a `script { }`
  block followed by `evaluate()`).

## Known-exploited fingerprints

Flag any of these verbatim patterns as likely Critical:

| CVE / ID | Fingerprint | Reason |
|---|---|---|
| S2-045 / CVE-2017-5638 | `Content-Type` header evaluated through `JakartaMultiPartRequest` / `LocalizedTextUtil.findText` with `${...}` | Struts OGNL in multipart Content-Type. |
| S2-057 / CVE-2018-11776 | `<action ... name="...">` with `alwaysSelectFullNamespace="true"` and namespace derived from URL | Struts OGNL via URL-namespace evaluation. |
| S2-053 / CVE-2017-12611 | `<s:include value="%{attr}"/>` in Freemarker view with user-controllable attr | Struts Freemarker + OGNL. |
| Spring4Shell / CVE-2022-22965 | `@ModelAttribute`-bound POJO that exposes `class.module.classLoader.resources.context.parent.pipeline.first.*` through nested property binding | Binding traversal to ClassLoader → disk write. |
| CVE-2022-22963 | `spring.cloud.function.routing-expression` request header | Spring Cloud Function RoutingFunction SpEL eval. |
| CVE-2022-33980 | Apache Commons Configuration `interpolator` with `${script:...}` / `${dns:...}` | Log4Shell-style prefix interpolation. |
| Camel Simple CVE-2022-33980 derivatives | `.simple("${headers.x}")` in a route where `headers.x` is attacker-controlled | Camel EL eval of header. |

## High-signal grep patterns

Quick triage for a repo scan. A hit is not a finding on its own, but warrants
source-to-sink tracing.

```
# SpEL -- most common Oracle Java sink
grep -rnE "SpelExpressionParser|parseExpression\(|StandardEvaluationContext|createValueExpression" --include='*.java'

# OGNL / Struts
grep -rnE "Ognl\.(parseExpression|getValue)|findValue\s*\(|ActionContext.*getValueStack" --include='*.java'
grep -rnE '<s:[a-zA-Z]+[^>]+(value|test|href)="%\{' --include='*.jsp' --include='*.jspx'

# JSP / Jakarta EL programmatic eval
grep -rnE "ELProcessor|\.createValueExpression|javax\.el\.|jakarta\.el\." --include='*.java'

# ADF
grep -rnE "JboEL|evaluateELExpression|createValueBinding" --include='*.java' --include='*.jspx' --include='*.jsff'

# JEXL / MVEL / Camel Simple
grep -rnE "JexlEngine|MVEL\.eval|\.simple\(\"\\\$\{" --include='*.java'

# SpEL in annotations with concatenation
grep -rnE '@(Value|PreAuthorize|PostAuthorize|Cacheable|EventListener)\s*\(' --include='*.java' | grep -E '\+\s*[a-z]'
```

## How to rate severity

- **Critical**: EL sink reachable from an unauthenticated network source
  without sanitization (covers most Struts / Spring CVEs above). Score
  CVSS `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8.
- **High**: requires authenticated but broadly available role (any
  tenant user); or requires network adjacency; or the EL engine is
  sandboxed (e.g. `SimpleEvaluationContext` for SpEL) but sandbox is
  incompletely configured.
- **Medium**: second-order via stored input requiring prior privileged
  write; or the sink is in a non-production code path.
- **Low**: user input flows to a safe method-call-by-name interface with
  allowlisted method names (e.g. a workflow engine that only permits
  `workflow.*` method calls).

## How to fix

| Engine | Fix |
|---|---|
| SpEL | Use `SimpleEvaluationContext.forReadOnlyDataBinding().build()`; never pass user input into `parseExpression`. |
| OGNL (Struts) | Upgrade Struts; keep `struts.ognl.allowStaticMethodAccess=false`; avoid `%{...}` around user-controlled values. |
| JSP/Jakarta EL | Never call `ELProcessor.eval()` on user input. Escape output with `<c:out/>` or `fn:escapeXml`. |
| ADF EL | Do not build `#{...}` expression strings from request data; use static bindings only. |
| JEXL | Use `JexlBuilder().permissions(JexlPermissions.RESTRICTED)` sandbox; prefer non-user input. |
| MVEL | Use `ParserContext` with no imports and a restricted method allowlist; better yet, avoid on user input. |
| Camel Simple | Use `constant(...)` or bound headers; never interpolate untrusted strings into `.simple(...)`. |

## Related bug classes

- `ssti` — generic template engine injection (Jinja2, Twig, Freemarker text
  mode). EL injection is the Java-ecosystem specialisation.
- `code-injection` — broader class (eval, reflection, dynamic compile).
  Prefer `el-injection` when the sink is an expression-language engine.
- `deserialization` — overlaps where SpEL / OGNL gadgets are used in
  deserialization chains.
