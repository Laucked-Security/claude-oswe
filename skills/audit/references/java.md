# Java / Spring — Source→Sink Reference

## Sources (attacker-controllable)
- Spring MVC: `@RequestParam`, `@RequestBody`, `@PathVariable`, `@RequestHeader`, `@CookieValue`,
  `@ModelAttribute`, `HttpServletRequest.getParameter/getHeader/getCookies/getInputStream`.
- Servlet: `request.getParameter`, `request.getQueryString`, `request.getReader`.

## Dangerous sinks by class
- **Java deserialization → RCE**: `ObjectInputStream.readObject()` on attacker bytes; `XMLDecoder`,
  `XStream.fromXML`, Jackson with default typing / polymorphic `@JsonTypeInfo`, `SnakeYAML` `Yaml.load`.
  With a vulnerable **gadget chain** on the classpath (CommonsCollections, Spring, etc.) this is RCE —
  read `vendor/`/dependency jars **on demand** to confirm a chain; lockfiles (`pom.xml`,
  `build.gradle`) give the versions.
- **Expression-language (SpEL/OGNL/MVEL) injection → RCE**: `SpelExpressionParser().parseExpression(input)`
  `.getValue()`, `@Value("#{...}")` built from input, Struts/OGNL, `MVEL.eval`. Payload
  `T(java.lang.Runtime).getRuntime().exec(...)`.
- **Command injection**: `Runtime.getRuntime().exec(string)`, `ProcessBuilder` with a built shell string
  (`sh -c "... " + input`). Safe form: a fixed program + argument **list**, no shell.
- **SQLi**: string-concatenated JDBC `Statement.execute`, `@Query(value = "... " + ..., nativeQuery=true)`,
  `EntityManager.createNativeQuery` with concatenation.
- **XXE**: `DocumentBuilderFactory` / `SAXParserFactory` / `XMLInputFactory` without
  `disallow-doctype-decl` / external-entity features disabled.
- **SSRF**: `RestTemplate`, `HttpClient`, `URL.openConnection`, `WebClient` to an attacker host.
- **Path traversal**: `new File(base, input)` / `Files.newInputStream` without `..` containment.

## Auth boundaries (Spring Security)
- `@PreAuthorize` / `@Secured` / `@RolesAllowed` on controllers/methods; `SecurityFilterChain` /
  `HttpSecurity` config. A route without a guard is unauthenticated-reachable.
- **Trusting proxy/client headers** for identity (e.g. `request.getHeader("X-User-Role")`,
  `X-Forwarded-User`) without validation is an auth bypass — the header is attacker-controllable unless
  a trusted proxy strips/sets it.
- JWT: `alg:none` acceptance, unverified signature, weak/hardcoded secret → forgeable token.

## Sanitizers and why they often fail
- HTML/`HtmlUtils.htmlEscape` is output encoding (XSS) — irrelevant to deserialization/SpEL/exec sinks.
- Parameterized `PreparedStatement` is the SQLi fix; its absence around concatenation is the smell.
- Blacklisting class names for deserialization is bypassable — only an allow-list / not deserializing
  attacker data is safe.
