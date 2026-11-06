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
- **SQLi**: string-concatenated JDBC `Statement.execute/executeQuery/executeUpdate`, a concatenated
  string handed to `prepareStatement` (a PreparedStatement built from concatenation is still
  injectable), `JdbcTemplate.query*/update/batchUpdate` with concatenation, `@Query(value = "... " +
  ..., nativeQuery=true)`, `EntityManager.createNativeQuery` with concatenation.
- **XXE**: `DocumentBuilderFactory` / `SAXParserFactory` / `XMLInputFactory` / `TransformerFactory` /
  `SchemaFactory` / JAXB `Unmarshaller` without `disallow-doctype-decl` / external-entity features
  disabled.
- **SSRF**: `RestTemplate`, `HttpClient`, `URL.openConnection/openStream`, `WebClient` to an
  attacker host.
- **Path traversal**: `new File(base, input)` / `Files.newInputStream` / `FileInputStream` /
  `Files.write/copy`, `MultipartFile.transferTo` without `..` containment.
- **Trust-boundary (CWE-501):** attacker-controlled data written into session/cookie/trusted server state (`HttpSession.setAttribute`/`putValue`, `response.addCookie`) — a **hygiene** finding (Low/Info), not an RCE sink and never a chain member.

## Auth boundaries (Spring Security, servlets)
- `@PreAuthorize` / `@Secured` / `@RolesAllowed` on controllers/methods; `SecurityFilterChain` /
  `HttpSecurity` config (`requestMatchers(...).permitAll()/authenticated()/hasRole(...)`,
  `anyRequest()`, `securityMatcher` scoping, `web.ignoring()`). A route without a guard is
  unauthenticated-reachable. Plain servlets: `@ServletSecurity` / `@RolesAllowed` on the servlet,
  `web.xml` `<security-constraint>` (the graph reads it at `WEB-INF/web.xml` under the usual webapp
  roots, as a whole-app hint, not per url-pattern), or an auth `Filter` (`@WebFilter`, `HttpFilter` /
  `OncePerRequestFilter` subclasses) — read `web.xml` and the filters before calling a servlet route
  unauthenticated. A Spring Boot app with `spring-boot-starter-security` and no `SecurityFilterChain`
  runs Boot's default chain: everything authenticated.
- **Trusting proxy/client headers** for identity (e.g. `request.getHeader("X-User-Role")`,
  `X-Forwarded-User`) without validation is an auth bypass — the header is attacker-controllable unless
  a trusted proxy strips/sets it.
- JWT: `alg:none` acceptance, unverified signature, weak/hardcoded secret → forgeable token.

## Sanitizers and why they often fail
- HTML/`HtmlUtils.htmlEscape` is output encoding (XSS) — irrelevant to deserialization/SpEL/exec sinks.
- Parameterized `PreparedStatement` is the SQLi fix; its absence around concatenation is the smell.
- Blacklisting class names for deserialization is bypassable — only an allow-list / not deserializing
  attacker data is safe.

```surface
{
  "sources": ["@RequestParam", "@RequestBody", "@PathVariable", "@RequestHeader", "@CookieValue", "@ModelAttribute", "getParameter", "getParameterValues", "getParameterMap", "getHeader", "getCookies", "getInputStream", "getQueryString", "getReader", "getPart(", "getRequestURI", "getPathInfo", "X-User-Role", "X-Forwarded-User"],
  "sinks": ["ObjectInputStream", ".readObject(", "XMLDecoder", "XStream", "@JsonTypeInfo", "Yaml.load", "parseExpression(", "Ognl.getValue", "createValueExpression(", "MVEL.eval", "Runtime.getRuntime().exec", "Runtime.exec", "ProcessBuilder", "Statement.execute", "executeQuery(", "executeUpdate(", "executeLargeUpdate(", "prepareStatement(", "queryForList(", "queryForObject(", "queryForMap(", "queryForRowSet(", "batchUpdate(", "createNativeQuery", "nativeQuery", "createQuery", "createSQLQuery(", "DocumentBuilder", "DocumentBuilderFactory.newInstance", "SAXParser", "SAXParserFactory.newInstance", "XMLInputFactory", "XMLInputFactory.newInstance", "createXMLStreamReader(", "XMLReader", "TransformerFactory", "TransformerFactory.newInstance", "SchemaFactory", "SchemaFactory.newInstance", "Unmarshaller", "createUnmarshaller(", ".unmarshal(", "openConnection(", "openStream(", "RestTemplate", "WebClient", "HttpClient", "getForObject(", "getForEntity(", "postForObject(", "postForEntity(", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "Files.newInputStream", "Files.newOutputStream", "Files.readAllBytes", "Files.readAllLines", "Files.readString", "Files.lines", "Files.write", "Files.writeString", "Files.copy", "FileCopyUtils.copy", "createNewFile(", "setAttribute", "putValue", "addCookie"],
  "sanitizers": ["PreparedStatement", "setString(", "ESAPI", "OWASP", "getCanonicalPath"],
  "auth_markers": ["@PreAuthorize", "@Secured", "@RolesAllowed", "@ServletSecurity", "SecurityFilterChain", "@EnableWebSecurity"]
}
```