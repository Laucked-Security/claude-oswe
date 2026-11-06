// Java language module for the SP10 application graph (spec §2.3), Spring. extractFile walks one
// parsed tree (web-tree-sitter, see ../parser.mjs) and emits the per-file Extract described in
// ./javascript.mjs: functions, calls (+ the receiver hints resolve.mjs needs, spec §1.4), imports,
// exports, classes, namespace, routes, and surface-pattern sources / sinks.
//
// Java specifics:
//   functions  `method_declaration` / constructors -> "method" (`<Class>.<name>`, a constructor is
//              named after its class; overloads differ by start_byte); in an anonymous class body
//              (`new C() {...}`, an enum constant's body) the class is null and the qualified name
//              `<enclosing>.<anon>@<line>:<col>.<name>`; a lambda -> "lambda", named by the local it
//              initialises (`Runnable r = () -> ...` -> `<enclosing>.r`), else
//              `<enclosing>.<anon>@<line>:<col>`, and carries `class_start_byte` (its innermost class
//              body) for resolve.mjs's lexical-this walk. exported = every enclosing type and the
//              method are public (interface members are implicitly public). `param_count` is null
//              with varargs; `lang.overloads: true` lets resolve.mjs pick overloads by arity.
//   classes    class / interface / enum / record declarations, nested ones by their simple name;
//              `extends` is the superclass's base name (`a.B<T>` -> `B`); `implements` is only noted.
//   exports    every public top-level type. namespace = the `package` declaration.
//   imports    `import a.b.Z;` -> named binding Z of "a.b.Z"; `import a.b.*;` -> namespace binding of
//              "a.b"; `import static a.b.Z.m;` -> named binding m of "a.b.Z". resolveImportSpecifier
//              maps "a.b.Z" to the file declaring package a.b named Z.java (Extract.namespace, passed
//              in as `namespaces`).
//   calls      `lang.callableLocals: false`: methods and variables are separate namespaces, so a
//              local never shadows a bare call and every call has `scope_names: []`;
//              `lang.implicitThisCalls: true`: a bare `m()` is left to the resolver's same-class
//              step. Receivers: `this.m()` -> "this"; `x.m()` -> the declared type of x (the
//              innermost local / parameter / loop / catch / resource / lambda variable, else a field
//              of an enclosing class, else x itself when it is capitalised: a static call);
//              `this.f.m()` -> the declared type of field f; `new C().m()` -> C; `super.m()` -> the
//              enclosing class's superclass; generics and qualifiers reduce to the base name.
//              Annotation arguments are never calls. A nested
//              class body is a barrier: code in a local / anonymous class's field initializer or
//              initializer block has no enclosing function (`enclosing_start_byte: null`).
//   sinks      Java's surface tokens are written against declared types (`Statement.execute`), so a
//              call whose receiver has a known class T is also matched as `T.<method>`; the sink's
//              callee keeps the source text (`st.execute`).
//   routes     Spring `@GetMapping / @PostMapping / @PutMapping / @DeleteMapping / @PatchMapping` and
//              `@RequestMapping(method = ...)` on a method, prefixed by the class's
//              `@RequestMapping`; `@PreAuthorize / @Secured / @RolesAllowed` on the class, then on
//              the method, are the middleware texts; one route per literal path (several paths of
//              one annotation each sit at their literal; several class prefixes: the first, noted).
//              Servlets: a class annotated `@WebServlet("/p")` / `(value = ...)` / `(urlPatterns =
//              {...})` yields one route per `doGet / doPost / doPut / doDelete / doHead / doOptions`
//              (that verb) and `service` (ANY) method it declares, at the method, on the class's
//              FIRST literal pattern (more are noted "route(multiple servlet patterns)"), framework
//              "servlet"; the class's then the method's auth annotations (`@ServletSecurity` too)
//              are its middleware texts. A `@WebFilter` / `implements Filter` class is noted
//              "servlet(filter)" (build-graph then calls unmarked servlet routes `unknown`).
//   security   `security_chains`: one entry per method returning a `SecurityFilterChain` or
//              `configure(HttpSecurity)` override: `{ line, start_byte, scope, rules }` with the
//              request rules in source order. A rule is a `requestMatchers / antMatchers /
//              mvcMatchers (HttpMethod.X,)? "p"...` or `anyRequest()` (= `/**`) matcher inside an
//              `authorizeHttpRequests(...)` / `authorizeRequests()` call, and its auth is the call
//              chained directly on the matcher: `permitAll / anonymous` -> "unauthenticated";
//              `authenticated / fullyAuthenticated / rememberMe / hasRole / hasAnyRole /
//              hasAuthority / hasAnyAuthority / denyAll` -> "authenticated"; `access` or any other
//              call (`hasIpAddress`, `not`) -> "unknown". `requestMatchers(antMatcher("/p"))` reads
//              the factory's literal. A matcher with a non-literal pattern (or `regexMatchers`) has
//              `patterns: null` (it may match anything: build-graph treats it as matching every
//              later route with auth "unknown"), noted "security(non-literal matcher)"; so does a
//              call the extractor cannot see into — the HttpSecurity handed to a helper, `http.with
//              / apply(dsl)`, an authorize call given a method reference or a value. `scope` = the
//              chain's `securityMatcher(s)` / `antMatcher` matchers `{ http_method, patterns }`
//              (also `securityMatchers(m -> m.requestMatchers(...))`), null when unscoped;
//              `scope_unknown` when one is not literal or the zero-argument opener was used (noted).
//              A chain is emitted even without a rule (noted "security(unread chain)"): it votes
//              `unknown` in build-graph. A method returning a `WebSecurityCustomizer` or
//              `configure(WebSecurity)` whose `web.ignoring()` names literal matchers is a chain
//              scoped to them whose rules permit exactly them, verb kept (Spring applies no
//              security there). A file naming a security type (SECURITY_TYPES:
//              SecurityFilterChain, WebFlux's SecurityWebFilterChain, WebSecurityConfigurerAdapter,
//              @EnableWebSecurity...) without any chain is noted "SecurityFilterChain matchers":
//              build-graph's file-level `unknown` hint (spec §2.4).
//              `super.m()` carries the enclosing class's superclass as receiver class.
//
// Same TreeCursor walk as the JavaScript module (see its header for why not tree-sitter queries).
// PURE: no I/O. `sourceText` is never copied into the output — only identifier / literal text.
import { posix } from "node:path";
import { normalizeToken } from "../surface.mjs";
import {
  lookup, field, namedOf as namedNodes, childrenOfType, lineOf, anonLabel, byStart, matchEmitter, walk, receiverClass, lastSegment,
  newFrame, NO_FRAME, bind, innermostFunction, innermostClassScope, innermostClass, enclosingName, pathsByBasename
} from "./common.mjs";

export const lang = { id: "java", stack: "java", langIds: ["java"], frameworks: ["spring", "servlet"], implicitThisCalls: true, submoduleImports: false, callableLocals: false, overloads: true };

// ---- node-type tables -----------------------------------------------------------------------------

// An identifier in one of these `<parent type>.<field>` slots, or under one of these parents, names a
// declaration, a method / field of a chain (the enclosing call is the candidate), an annotation or a
// package path: it is not a value reference.
const NON_REFERENCE_SLOTS = new Set([
  "method_invocation.object", "method_invocation.name", "field_access.object", "field_access.field",
  "variable_declarator.name", "formal_parameter.name", "catch_formal_parameter.name", "enhanced_for_statement.name",
  "resource.name", "lambda_expression.parameters", "method_declaration.name", "constructor_declaration.name",
  "compact_constructor_declaration.name", "class_declaration.name", "interface_declaration.name", "enum_declaration.name",
  "record_declaration.name", "annotation_type_declaration.name", "annotation_type_element_declaration.name",
  "enum_constant.name", "annotation.name", "marker_annotation.name"
]);
const NON_REFERENCE_PARENTS = new Set([
  "inferred_parameters", "scoped_identifier", "package_declaration", "import_declaration", "method_reference",
  "labeled_statement", "break_statement", "continue_statement"
]);
// Annotations on these declarations are request-parameter sources (`@RequestParam`, `@ModelAttribute`).
const SOURCE_ANNOTATION_OWNERS = new Set(["formal_parameter", "method_declaration"]);

const MAPPING_VERBS = new Map([["RequestMapping", null], ["GetMapping", "GET"], ["PostMapping", "POST"], ["PutMapping", "PUT"], ["DeleteMapping", "DELETE"], ["PatchMapping", "PATCH"]]);
const AUTH_ANNOTATIONS = new Set(["PreAuthorize", "Secured", "RolesAllowed", "ServletSecurity"]);
// `@WebServlet` handler methods and the verb each serves.
const SERVLET_HANDLERS = new Map([["doGet", "GET"], ["doPost", "POST"], ["doPut", "PUT"], ["doDelete", "DELETE"], ["doHead", "HEAD"], ["doOptions", "OPTIONS"], ["service", "ANY"]]);
const SERVLET_FILTER_NOTE = "servlet(filter)";
// Servlet filter base classes: a subclass is a filter even without `implements Filter`.
const FILTER_BASES = new Set(["HttpFilter", "GenericFilter", "OncePerRequestFilter", "GenericFilterBean"]);
// Spring Security request-rule DSL (lambda and legacy forms alike). A matcher inside an authorize
// call is a rule: its authorization is the call chained directly on it. `anyRequest()` is `/**`.
const SECURITY_MATCHERS = new Set(["requestMatchers", "antMatchers", "mvcMatchers", "regexMatchers", "anyRequest"]);
const SECURITY_AUTHORIZE = new Set(["authorizeHttpRequests", "authorizeRequests"]);
const SECURITY_SCOPES = new Set(["securityMatcher", "securityMatchers", "antMatcher", "mvcMatcher", "regexMatcher"]);
const SECURITY_SCOPE_LAMBDA = "securityMatchers"; // securityMatchers(m -> m.requestMatchers(...))
const SECURITY_IGNORING = "ignoring"; // web.ignoring().requestMatchers(...)
const SECURITY_APPLY = new Set(["apply", "with"]); // http.apply(dsl) / http.with(dsl, ...): rules the extractor cannot see
// `requestMatchers(antMatcher("/p"))`: a RequestMatcher factory whose literal arguments are the pattern.
const MATCHER_FACTORIES = new Set(["antMatcher", "mvcMatcher"]);
const SECURITY_RULES = new Map([
  ["permitAll", "unauthenticated"], ["anonymous", "unauthenticated"],
  ["authenticated", "authenticated"], ["fullyAuthenticated", "authenticated"], ["rememberMe", "authenticated"],
  ["hasRole", "authenticated"], ["hasAnyRole", "authenticated"], ["hasAuthority", "authenticated"], ["hasAnyAuthority", "authenticated"],
  ["denyAll", "authenticated"], ["access", "unknown"]
]);
// A method returning one of the first, or a `configure` taking one of the second, is a chain
// ("chain": request rules; "ignoring": paths Spring Security leaves alone).
const SECURITY_RETURNS = { SecurityFilterChain: "chain", WebSecurityCustomizer: "ignoring" };
const SECURITY_CONFIGURE_PARAMS = { HttpSecurity: "chain", WebSecurity: "ignoring" };
// Seeing one of these names (a type, an import, an annotation) in a file that yields no chain is the
// file-level hint of spec §2.4: some security config exists that the extractor could not read.
const SECURITY_TYPES = new Set(["SecurityFilterChain", "SecurityWebFilterChain", "ServerHttpSecurity", "WebSecurityConfigurerAdapter", "EnableWebSecurity", "EnableWebFluxSecurity", "WebSecurityCustomizer"]);
const NO_RULES_NOTE = "SecurityFilterChain matchers";
const UNREAD_CHAIN_NOTE = "security(unread chain)";
const NON_LITERAL_NOTE = "security(non-literal matcher)";
const SOURCE_KINDS = {
  RequestParam: "query", RequestBody: "body", PathVariable: "params", RequestHeader: "header", CookieValue: "cookie", ModelAttribute: "body",
  getParameter: "query", getParameterValues: "query", getParameterMap: "query", getQueryString: "query", getHeader: "header", getCookies: "cookie",
  getInputStream: "body", getReader: "body", getPart: "body", getRequestURI: "params", getPathInfo: "params",
  "X-User-Role": "header", "X-Forwarded-User": "header"
};

// ---- small AST helpers ----------------------------------------------------------------------------

// Named children without Java's line / block comments.
const namedOf = (node) => namedNodes(node).filter((c) => c.type !== "line_comment" && c.type !== "block_comment");
const hasModifier = (node, keyword) => childrenOfType(node, "modifiers")[0]?.children.some((c) => c.type === keyword) ?? false;
const annotationsOf = (node) => namedOf(childrenOfType(node, "modifiers")[0]).filter((c) => c.type === "annotation" || c.type === "marker_annotation");

// `a.b.c` of an identifier / scoped_identifier (package, import and annotation names).
function dottedName(node) {
  if (node?.type === "identifier") return node.text;
  if (node?.type !== "scoped_identifier") return null;
  const scope = dottedName(field(node, "scope"));
  const name = field(node, "name")?.text;
  return scope && name ? `${scope}.${name}` : null;
}
const annotationName = (annotation) => {
  const name = dottedName(field(annotation, "name"));
  return name ? lastSegment(name) : null;
};

// The dotted text of a class type with its type arguments dropped (`java.util.List<X>` ->
// `java.util.List`); null for primitive, array and other types.
function typeText(node) {
  switch (node?.type) {
    case "type_identifier":
      return node.text;
    case "scoped_type_identifier": {
      const parts = namedOf(node).map(typeText).filter(Boolean);
      return parts.length ? parts.join(".") : null;
    }
    case "generic_type":
      return typeText(namedOf(node)[0]);
    default:
      return null;
  }
}

// The class a declaration binds its name to: the base name of the declared type, or for `var` the
// class an initialising `new C(...)` constructs.
function declaredClass(type, value = null) {
  const text = typeText(type);
  if (text === "var") return value?.type === "object_creation_expression" ? declaredClass(field(value, "type")) : null;
  return text ? lastSegment(text) : null;
}

// Callee text with call arguments dropped (`a.b(x).c` -> `a.b.c`); `new C<T>(...)` reads as `C`.
function render(node) {
  switch (node.type) {
    case "method_invocation": {
      const object = field(node, "object");
      const name = field(node, "name");
      if (!name) return node.text;
      return object ? `${render(object)}.${name.text}` : name.text;
    }
    case "field_access": {
      const object = field(node, "object");
      const name = field(node, "field");
      return object && name ? `${render(object)}.${name.text}` : node.text;
    }
    case "object_creation_expression":
      return typeText(field(node, "type")) ?? node.text;
    case "parenthesized_expression": {
      const inner = namedOf(node)[0];
      return inner ? render(inner) : node.text;
    }
    default:
      return node.text;
  }
}
const textOf = (node) => normalizeToken(render(node));
const stringContent = (node) => (node.text.startsWith('"""') ? node.text.slice(3, -3) : node.text.slice(1, -1));

// ---- state ----------------------------------------------------------------------------------------

// Every scope is a frame of `bindings` / `classOf` (see common.mjs receiverClass): a method or lambda
// (`fn: true`, with its start byte and qualified name), a block-like statement, or a class body
// (`cls`, whose frame holds the class's fields), innermost last (common.mjs innermostFunction).
function newState(path, surface) {
  return {
    moduleName: path.split("/").at(-1).replace(/\.[^.]*$/, ""),
    surface: { sources: surface?.sources ?? [], sinks: surface?.sinks ?? [] },
    functions: [], calls: [], imports: [], exports: [], classes: [], routes: [], sources: [], sinks: [],
    securityChains: [],
    securityTypeSeen: false,
    notExtracted: new Set(),
    namespace: null,
    scopes: [],
    annotationDepth: 0
  };
}

// ---- sources and sinks ----------------------------------------------------------------------------

const sourceKind = (pattern) => lookup(SOURCE_KINDS, pattern.normalized) ?? "body";

const emitMatches = matchEmitter("java", sourceKind); // see common.mjs

// A declared type (local, field, parameter, loop / resource variable) as a sink candidate.
function typeCandidate(type, st) {
  const text = typeText(type);
  if (text && text !== "var") emitMatches(type, [{ category: "type", text: normalizeToken(text) }], st, { sinks: true });
}

const noteSecurityFilterChain = (text, st) => {
  if (SECURITY_TYPES.has(text)) st.securityTypeSeen = true;
};

// onIdentifier / onTypeIdentifier receive the TreeCursor rather than a Node (see javascript.mjs).
function onIdentifier(cursor, st, ctx) {
  const text = cursor.nodeText;
  noteSecurityFilterChain(text, st);
  if (NON_REFERENCE_PARENTS.has(ctx.parentType) || NON_REFERENCE_SLOTS.has(`${ctx.parentType}.${ctx.field}`)) return;
  emitMatches(cursor, [{ category: "identifier", text }], st, { sources: true, sinks: true });
}

function onTypeIdentifier(cursor, st) {
  noteSecurityFilterChain(cursor.nodeText, st);
}

function onString(node, st) {
  emitMatches(node, [{ category: "literal", text: normalizeToken(stringContent(node)) }], st, { sources: true, sinks: true });
}

function onNew(node, st) {
  const type = field(node, "type");
  const text = typeText(type);
  if (text) emitMatches(node, [{ category: "new", text: normalizeToken(text) }], st, { sinks: true, sinkAt: type });
}

// An annotation is a decorator candidate (a source only on a parameter or a method); nothing inside
// its arguments is a call.
function onAnnotation(node, st) {
  const name = annotationName(node);
  if (name) {
    const owner = node.parent?.type === "modifiers" ? node.parent.parent?.type : null;
    emitMatches(node, [{ category: "decorator", text: name }], st, { sources: SOURCE_ANNOTATION_OWNERS.has(owner), sinks: true });
  }
  st.annotationDepth++;
  return () => st.annotationDepth--;
}

// ---- scopes and declarations ----------------------------------------------------------------------

function addParameters(node, frame, st) {
  const params = field(node, "parameters");
  if (params?.type === "identifier") return bind(frame, params.text, null); // `x -> ...`
  for (const param of namedOf(params)) {
    if (param.type === "identifier") bind(frame, param.text, null); // inferred `(x, y) -> ...`
    else if (param.type === "formal_parameter") {
      bind(frame, field(param, "name")?.text, declaredClass(field(param, "type")));
      typeCandidate(field(param, "type"), st);
    } else if (param.type === "spread_parameter") bind(frame, field(childrenOfType(param, "variable_declarator")[0], "name")?.text, null);
  }
}

function onLocalDeclaration(node, st) {
  const type = field(node, "type");
  typeCandidate(type, st);
  const frame = st.scopes.at(-1)?.frame;
  for (const declarator of node.childrenForFieldName("declarator")) {
    const cls = field(declarator, "dimensions") ? null : declaredClass(type, field(declarator, "value"));
    bind(frame, field(declarator, "name")?.text, cls);
  }
}

// Block-like statements open a scope; a loop / catch variable is bound in its statement's scope.
function onScope(node, st) {
  const frame = newFrame();
  if (node.type === "enhanced_for_statement") {
    bind(frame, field(node, "name")?.text, field(node, "dimensions") ? null : declaredClass(field(node, "type")));
    typeCandidate(field(node, "type"), st);
  } else if (node.type === "catch_clause") {
    const param = childrenOfType(node, "catch_formal_parameter")[0];
    const types = namedOf(childrenOfType(param, "catch_type")[0]);
    bind(frame, field(param, "name")?.text, types.length === 1 ? declaredClass(types[0]) : null);
  }
  st.scopes.push({ frame });
  return () => st.scopes.pop();
}

function onResource(node, st) {
  const type = field(node, "type");
  if (!type) return; // a plain `try (existing)` resource
  typeCandidate(type, st);
  bind(st.scopes.at(-1)?.frame, field(node, "name")?.text, declaredClass(type, field(node, "value")));
}

// ---- classes --------------------------------------------------------------------------------------

const membersOf = (body) => (body?.type === "enum_body" ? namedOf(childrenOfType(body, "enum_body_declarations")[0]) : namedOf(body));

// The class body's frame: each field (record components and enum constants included) bound to its
// declared class.
function fieldFrame(node, body, name) {
  const frame = newFrame();
  for (const member of membersOf(body)) {
    if (member.type !== "field_declaration" && member.type !== "constant_declaration") continue;
    for (const declarator of member.childrenForFieldName("declarator")) {
      const cls = field(declarator, "dimensions") ? null : declaredClass(field(member, "type"), field(declarator, "value"));
      bind(frame, field(declarator, "name")?.text, cls);
    }
  }
  if (node.type === "record_declaration") {
    for (const param of childrenOfType(field(node, "parameters"), "formal_parameter")) bind(frame, field(param, "name")?.text, declaredClass(field(param, "type")));
  }
  for (const constant of childrenOfType(body, "enum_constant")) bind(frame, field(constant, "name")?.text, name);
  return frame;
}

// A mapping's literal paths as [{ path, node }] (node: the string literal, null when the annotation
// names no path); null when any listed path is not a string literal.
function mappingPaths(annotation) {
  const items = namedOf(field(annotation, "arguments"));
  const pair = items.find((i) => i.type === "element_value_pair" && ["value", "path"].includes(field(i, "key")?.text));
  const value = pair ? field(pair, "value") : items.find((i) => i.type !== "element_value_pair") ?? null;
  const literals = !value ? [] : value.type === "element_value_array_initializer" ? namedOf(value) : [value];
  if (literals.length === 0) return [{ path: "", node: null }];
  return literals.every((l) => l.type === "string_literal") ? literals.map((l) => ({ path: stringContent(l), node: l })) : null;
}

// A class's `@WebServlet` literal url patterns: `@WebServlet("/p")`, `(value = "/p")`, `(urlPatterns =
// {"/p", "/q"})`; [] when the annotation names no pattern (`name = ...` only); null (noted) when a
// listed pattern is not a string literal.
function servletPatterns(annotation) {
  const items = namedOf(field(annotation, "arguments"));
  const pair = items.find((i) => i.type === "element_value_pair" && ["value", "urlPatterns"].includes(field(i, "key")?.text));
  const value = pair ? field(pair, "value") : items.find((i) => i.type !== "element_value_pair") ?? null;
  const literals = !value ? [] : value.type === "element_value_array_initializer" ? namedOf(value) : [value];
  return literals.every((l) => l.type === "string_literal") ? literals.map(stringContent) : null;
}

// The base names a type implements: a class / enum / record's `implements` list, an interface's
// `extends` list (`p.J<S>` -> `J`).
function implementedTypes(node) {
  const clause = field(node, "interfaces") ?? childrenOfType(node, "extends_interfaces")[0] ?? null;
  return namedOf(childrenOfType(clause, "type_list")[0]).map((t) => declaredClass(t)).filter(Boolean);
}

function onType(node, st) {
  const name = field(node, "name")?.text ?? null;
  const body = field(node, "body");
  const outer = innermostClass(st);
  const isPublic = hasModifier(node, "public");
  if (name) {
    const superclass = namedOf(field(node, "superclass"))[0];
    const methods = [...new Set(membersOf(body).filter((m) => m.type === "method_declaration").map((m) => field(m, "name")?.text).filter(Boolean))];
    st.classes.push({ name, extends: superclass ? declaredClass(superclass) : null, implements: implementedTypes(node), methods, start_byte: node.startIndex });
    if (!outer && isPublic) st.exports.push({ name, start_byte: node.startIndex });
  }
  const annotations = annotationsOf(node);
  const mapping = annotations.find((a) => annotationName(a) === "RequestMapping");
  const prefixes = mapping ? mappingPaths(mapping) : [{ path: "" }];
  if (prefixes === null) st.notExtracted.add("route(non-literal path)");
  else if (prefixes.length > 1) st.notExtracted.add("route(multiple class prefixes)"); // the first is used
  const prefix = prefixes?.[0].path ?? "";
  const webServlet = annotations.find((a) => annotationName(a) === "WebServlet");
  const servlet = webServlet ? servletPatterns(webServlet) : null;
  if (webServlet && servlet === null) st.notExtracted.add("route(non-literal path)");
  // a servlet filter (`@WebFilter`, `implements Filter`, a filter base class) may guard any servlet
  // route: noted, so that build-graph calls an unmarked servlet route `unknown` rather than `unauthenticated`
  const superclass = namedOf(field(node, "superclass"))[0];
  const superName = superclass ? declaredClass(superclass) : null;
  if (annotations.some((a) => annotationName(a) === "WebFilter") || implementedTypes(node).includes("Filter") || FILTER_BASES.has(superName)) st.notExtracted.add(SERVLET_FILTER_NOTE);
  st.scopes.push({
    frame: fieldFrame(node, body, name),
    cls: {
      name,
      start: node.startIndex,
      qualifiedName: name ?? `${enclosingName(st)}.${anonLabel(node)}`,
      exported: outer ? outer.exported && isPublic : isPublic,
      isInterface: node.type === "interface_declaration",
      prefix,
      auth: annotations.map(annotationName).filter((n) => AUTH_ANNOTATIONS.has(n)),
      servlet: servlet?.length ? servlet : null,
      superclass: superName
    }
  });
  return () => st.scopes.pop();
}

// The body of an anonymous class (`new C() {...}`) or of an enum constant: a class without a name.
function onClassBody(node, st, ctx) {
  if (ctx.parentType !== "object_creation_expression" && ctx.parentType !== "enum_constant") return;
  st.notExtracted.add("anonymous class");
  const cls = { name: null, start: node.startIndex, qualifiedName: `${enclosingName(st)}.${anonLabel(node.parent)}`, exported: false, isInterface: false, prefix: "", auth: [], servlet: null, superclass: null };
  st.scopes.push({ frame: fieldFrame(node, node, null), cls });
  return () => st.scopes.pop();
}

// ---- functions and routes -------------------------------------------------------------------------

// Declared parameters (`param_count`): null with a varargs parameter; a compact constructor takes
// its record's components.
function parameterCount(node) {
  const params = node.type === "compact_constructor_declaration" ? field(node.parent?.parent, "parameters") : field(node, "parameters");
  if (params?.type === "identifier") return 1; // `x -> ...`
  const list = namedOf(params).filter((p) => p.type !== "receiver_parameter");
  return list.some((p) => p.type === "spread_parameter") ? null : list.length;
}

function lambdaName(node, ctx) {
  if (ctx.parentType !== "variable_declarator" || ctx.field !== "value" || node.parent.parent?.type !== "local_variable_declaration") return null;
  return field(node.parent, "name")?.text ?? null;
}

function onFunction(node, st, ctx) {
  const owner = st.scopes.at(-1)?.cls ?? null;
  let fn;
  if (node.type === "lambda_expression") {
    const local = lambdaName(node, ctx);
    const qualifiedName = `${enclosingName(st)}.${local ?? anonLabel(node)}`;
    // a lambda named by the local it initialises binds that name in the enclosing scope (resolve.mjs's
    // nested definitions)
    fn = { name: local ?? "<anon>", qualified_name: qualifiedName, kind: "lambda", exported: false, class: null, classStart: innermostClass(st)?.start ?? null, bindsName: local !== null };
  } else {
    const name = field(node, "name")?.text ?? "<anon>";
    const isPublic = owner?.isInterface || hasModifier(node, "public");
    fn = { name, qualified_name: `${owner?.qualifiedName ?? st.moduleName}.${name}`, kind: "method", exported: Boolean(owner?.exported && isPublic), class: owner?.name ?? null };
  }
  st.functions.push({
    name: fn.name,
    qualified_name: fn.qualified_name,
    line_start: lineOf(node),
    line_end: node.endPosition.row + 1,
    start_byte: node.startIndex,
    end_byte: node.endIndex,
    param_count: parameterCount(node),
    kind: fn.kind,
    exported: fn.exported,
    class: fn.class,
    ...(fn.bindsName ? { binds_name: true } : {}),
    // a lambda's lexical class body: resolve.mjs inherits a containing method's class only within it
    ...(fn.kind === "lambda" ? { class_start_byte: fn.classStart } : {}),
    // an interface method without a default body, an abstract (or native) method: resolve.mjs never
    // grades a call to it exact
    ...(node.type === "method_declaration" && !field(node, "body") ? { bodiless: true } : {})
  });
  if (node.type === "method_declaration" && owner?.name) {
    springRoutes(node, owner, fn.qualified_name, st);
    if (owner.servlet) servletRoutes(node, owner, fn.qualified_name, st);
  }
  const frame = newFrame(node.startIndex, fn.qualified_name);
  addParameters(node, frame, st);
  const kind = node.type === "method_declaration" ? securityMethodKind(node) : null;
  const httpParams = new Set(childrenOfType(field(node, "parameters"), "formal_parameter").filter((p) => declaredClass(field(p, "type")) === "HttpSecurity").map((p) => field(p, "name")?.text));
  const security = kind ? { kind, start: node.startIndex, line: lineOf(node), httpParams, rules: [], scope: [], scopeUnknown: false, ignored: [], ignoredUnknown: false, authorizeRanges: [], scopeRanges: [] } : null;
  st.scopes.push({ frame, fn: true, security });
  return () => {
    st.scopes.pop();
    if (security) finishSecurity(security, st);
  };
}

// One route per `@WebServlet` handler method, at the method, on the class's first literal pattern;
// further patterns are noted (a route id is its start byte, so one method cannot carry two). The
// class's then the method's auth annotations are the middleware texts.
function servletRoutes(node, owner, qualifiedName, st) {
  const verb = SERVLET_HANDLERS.get(field(node, "name")?.text);
  if (!verb) return;
  if (owner.servlet.length > 1) st.notExtracted.add("route(multiple servlet patterns)");
  st.routes.push({
    line: lineOf(node),
    start_byte: node.startIndex,
    http_method: verb,
    path_pattern: joinPath("", owner.servlet[0]),
    handler_text: qualifiedName,
    middleware_texts: [...owner.auth, ...annotationsOf(node).map(annotationName).filter((n) => AUTH_ANNOTATIONS.has(n))],
    framework: "servlet"
  });
}

// ---- Spring Security request rules ----------------------------------------------------------------

// "chain" for a method with a body returning a SecurityFilterChain or the `configure(HttpSecurity)`
// override, "ignoring" for one returning a WebSecurityCustomizer or `configure(WebSecurity)`; null
// otherwise (a helper taking an HttpSecurity is not a chain: its rules belong to the bean that
// hands it the HttpSecurity, where that call is an unreadable rule, see securityCall).
function securityMethodKind(node) {
  if (!field(node, "body")) return null;
  const byReturn = lookup(SECURITY_RETURNS, declaredClass(field(node, "type")));
  if (byReturn) return byReturn;
  if (field(node, "name")?.text !== "configure") return null;
  const params = childrenOfType(field(node, "parameters"), "formal_parameter").map((p) => lookup(SECURITY_CONFIGURE_PARAMS, declaredClass(field(p, "type"))));
  return params.find(Boolean) ?? null;
}

// `HttpMethod.X` -> "X", else null.
function httpMethodOf(arg) {
  if (arg?.type !== "field_access" || field(arg, "object")?.text !== "HttpMethod" || field(arg, "field")?.type !== "identifier") return null;
  return field(arg, "field").text.toUpperCase();
}

// A matcher's arguments: `(HttpMethod.X,)? "p", "q"...`, or RequestMatcher factories
// `antMatcher((HttpMethod.X,)? "p")` / `mvcMatcher(...)` -> { http_method, patterns }; patterns null
// when any argument is something else (a RequestMatcher object, a constant, `regexMatcher`), or when
// the factories disagree on the verb; no pattern at all (`requestMatchers(HttpMethod.POST)`) is `/**`.
function matcherArguments(node) {
  const args = namedOf(field(node, "arguments"));
  const verbs = new Set();
  const patterns = [];
  const leading = httpMethodOf(args[0]);
  if (leading) {
    verbs.add(leading);
    args.shift();
  }
  for (const arg of args) {
    if (arg.type === "string_literal") patterns.push(stringContent(arg));
    else if (arg.type === "method_invocation" && !field(arg, "object") && MATCHER_FACTORIES.has(field(arg, "name")?.text)) {
      const inner = matcherArguments(arg);
      if (inner.patterns === null) return { http_method: null, patterns: null };
      if (inner.http_method) verbs.add(inner.http_method);
      patterns.push(...inner.patterns);
    } else return { http_method: null, patterns: null };
  }
  if (verbs.size > 1) return { http_method: null, patterns: null };
  const http_method = verbs.size ? [...verbs][0] : null;
  return { http_method, patterns: patterns.length ? patterns : ["/**"] };
}

// The calls a call is chained on (`http.a().b().c()` at c -> [b(), a()]), and their names.
function receiverChain(node) {
  const calls = [];
  for (let object = field(node, "object"); object?.type === "method_invocation"; object = field(object, "object")) calls.push(object);
  return calls;
}
const receiverChainNames = (node) => receiverChain(node).map((c) => field(c, "name")?.text ?? "");
// The legacy form: chained on a zero-argument `authorizeRequests()` / `authorizeHttpRequests()`.
const legacyAuthorize = (node) => receiverChain(node).some((c) => SECURITY_AUTHORIZE.has(field(c, "name")?.text) && namedOf(field(c, "arguments")).length === 0);
const argumentRange = (node) => {
  const args = field(node, "arguments");
  return args ? [args.startIndex, args.endIndex] : [node.startIndex, node.endIndex];
};

const within = (ranges, at) => ranges.some(([start, end]) => at > start && at < end);
const sameNode = (a, b) => a?.type === b?.type && a?.startIndex === b?.startIndex && a?.endIndex === b?.endIndex;
const unknownRule = (name) => ({ line: lineOf(name), start_byte: name.startIndex, http_method: null, patterns: null, auth: "unknown" });

// Scope / ignore matchers keep their verb and source position (the walk visits a chain outermost first).
function addMatcher(security, key, at, { http_method, patterns }, st) {
  if (patterns === null) {
    security[`${key}Unknown`] = true;
    st.notExtracted.add(NON_LITERAL_NOTE);
  } else security[key].push({ start: at, http_method, patterns });
}
const sortedMatchers = (entries) => entries.sort((a, b) => a.start - b.start).map(({ http_method, patterns }) => ({ http_method, patterns }));

// One call inside a security method. The walk is pre-order, so an authorize / securityMatchers call
// is recorded (the range of its ARGUMENTS: its receiver chain, `http.securityMatcher(..)`, is not
// inside it) before the calls inside its lambda; a legacy chain (`http.authorizeRequests()
// .antMatchers(...)`) is recognised by the zero-argument authorize call it is chained on. A matcher inside an authorize call
// is a rule whose authorization is the call chained DIRECTLY on it (`.requestMatchers("/a")
// .permitAll()`): any other call there (`hasIpAddress`, `not`, ...) makes the rule "unknown".
// Matchers elsewhere (`requiresChannel`, `csrf.ignoringRequestMatchers`) are not rules; a rule call
// elsewhere (`formLogin(l -> l.permitAll())`) is nothing. Rules the extractor cannot see — the
// chain's HttpSecurity handed to another method (`common(http)`), a DSL applied to it (`http.with(
// dsl)`), an authorize call given a method reference or a Customizer value — are an unreadable rule
// at that position: first-match then makes every route not settled before it `unknown`.
function securityCall(node, name, security, st) {
  const text = name.text;
  const at = name.startIndex;
  const args = namedOf(field(node, "arguments"));
  const object = field(node, "object");
  const chained = receiverChainNames(node);
  const inAuthorize = legacyAuthorize(node) || within(security.authorizeRanges, at);
  const onHttp = object?.type === "identifier" && security.httpParams.has(object.text);
  if (args.some((a) => a.type === "identifier" && security.httpParams.has(a.text)) || (onHttp && SECURITY_APPLY.has(text))) {
    security.rules.push(unknownRule(name));
    return;
  }
  if (SECURITY_AUTHORIZE.has(text)) {
    security.authorizeRanges.push(argumentRange(node));
    if (args.length && !args.some((a) => a.type === "lambda_expression")) security.rules.push(unknownRule(name));
    return;
  }
  if (text === SECURITY_SCOPE_LAMBDA && args.some((a) => a.type === "lambda_expression")) {
    security.scopeRanges.push(argumentRange(node));
    return;
  }
  // a scope call: not inside an authorize call, not an argument (`requestMatchers(antMatcher("/p"))`
  // is read by matcherArguments); the zero-argument openers (`securityMatchers().requestMatchers(..)`,
  // Spring 5 `http.requestMatchers().antMatchers(..)`) leave the scope unknown
  // (a regex scope / ignore is not an Ant pattern: unreadable)
  const opener = text === "requestMatchers" && args.length === 0;
  if ((SECURITY_SCOPES.has(text) || opener) && !inAuthorize && node.parent?.type !== "argument_list" && !chained.includes(SECURITY_IGNORING) && !within(security.scopeRanges, at)) {
    addMatcher(security, "scope", at, args.length === 0 || text === "regexMatcher" ? { http_method: null, patterns: null } : matcherArguments(node), st);
    return;
  }
  if (!SECURITY_MATCHERS.has(text)) return;
  if (chained.includes(SECURITY_IGNORING)) {
    addMatcher(security, "ignored", at, text === "regexMatchers" ? { http_method: null, patterns: null } : matcherArguments(node), st);
    return;
  }
  if (within(security.scopeRanges, at)) {
    addMatcher(security, "scope", at, matcherArguments(node), st);
    return;
  }
  if (!inAuthorize) return;
  const { http_method, patterns } = text === "anyRequest" ? { http_method: null, patterns: ["/**"] } : text === "regexMatchers" ? { http_method: null, patterns: null } : matcherArguments(node);
  if (patterns === null) st.notExtracted.add(NON_LITERAL_NOTE);
  const parent = node.parent;
  const rule = parent?.type === "method_invocation" && sameNode(field(parent, "object"), node) ? field(parent, "name")?.text : null;
  security.rules.push({ line: lineOf(name), start_byte: at, http_method, patterns, auth: SECURITY_RULES.get(rule) ?? "unknown" });
}

// A "chain" method is always emitted (rules in source order; no rule -> noted "security(unread
// chain)", it votes unknown in build-graph). `scope` lists its securityMatcher matchers
// (`{ http_method, patterns }`, source order), null when unscoped; `scope_unknown` says a scope
// could not be read (build-graph then lets the chain vote on every route). An "ignoring" method with
// literal matchers is a chain scoped to them whose rules permit exactly them (verb kept: other verbs
// of the same path stay unsettled, unknown); a non-literal ignore is only noted.
function finishSecurity(security, st) {
  const { line, start_byte } = { line: security.line, start_byte: security.start };
  if (security.kind === "ignoring") {
    if (!security.ignored.length || security.ignoredUnknown) return;
    const scope = sortedMatchers(security.ignored);
    st.securityChains.push({ line, start_byte, scope, scope_unknown: false, rules: scope.map((m) => ({ line, start_byte, http_method: m.http_method, patterns: m.patterns, auth: "unauthenticated" })) });
    return;
  }
  if (security.rules.length === 0) st.notExtracted.add(UNREAD_CHAIN_NOTE);
  st.securityChains.push({
    line,
    start_byte,
    scope: security.scope.length && !security.scopeUnknown ? sortedMatchers(security.scope) : null,
    scope_unknown: security.scopeUnknown,
    rules: security.rules.sort(byStart)
  });
}

// `@RequestMapping(method = RequestMethod.X)` -> X; ANY when absent or listing several.
function requestMethod(annotation) {
  const pair = namedOf(field(annotation, "arguments")).find((i) => i.type === "element_value_pair" && field(i, "key")?.text === "method");
  const value = pair ? field(pair, "value") : null;
  const listed = value?.type === "element_value_array_initializer" ? namedOf(value) : value ? [value] : [];
  if (listed.length !== 1) return "ANY";
  const method = listed[0].type === "field_access" ? field(listed[0], "field") : listed[0];
  return method?.type === "identifier" ? method.text.toUpperCase() : "ANY";
}

const joinPath = (prefix, path) => ("/" + [prefix, path].filter(Boolean).join("/")).replace(/\/{2,}/g, "/");

function springRoutes(node, owner, qualifiedName, st) {
  const annotations = annotationsOf(node);
  const auth = annotations.map(annotationName).filter((n) => AUTH_ANNOTATIONS.has(n));
  for (const annotation of annotations) {
    const name = annotationName(annotation);
    if (!MAPPING_VERBS.has(name)) continue;
    const paths = mappingPaths(annotation);
    if (paths === null) {
      st.notExtracted.add("route(non-literal path)");
      continue;
    }
    // one route per literal path; several routes of one annotation sit at their own literal
    for (const { path, node: literal } of paths) {
      const at = paths.length > 1 ? literal : annotation;
      st.routes.push({
        line: lineOf(at),
        start_byte: at.startIndex,
        http_method: MAPPING_VERBS.get(name) ?? requestMethod(annotation),
        path_pattern: joinPath(owner.prefix, path),
        handler_text: qualifiedName,
        middleware_texts: [...owner.auth, ...auth],
        framework: "spring"
      });
    }
  }
}

// ---- calls ----------------------------------------------------------------------------------------

// The class a plain identifier receiver is bound to: its declaration in the innermost scope binding
// it (fields are the class scopes' bindings), else the name itself when capitalised (a static call;
// resolve.mjs verifies it names a class).
function identifierClass(name, st) {
  const frames = st.scopes.map((s) => s.frame);
  if (frames.some((f) => f.bindings.has(name))) return receiverClass(name, frames, NO_FRAME);
  return /^[A-Z]/.test(name) ? name : null;
}

function receiverHints(object, st) {
  const none = { receiver: null, receiverClass: null };
  switch (object?.type) {
    case "this":
      return { receiver: "this", receiverClass: null };
    case "super": // `super.m()`: the enclosing class's superclass (null in an anonymous class)
      return { receiver: null, receiverClass: innermostClass(st)?.superclass ?? null };
    case "identifier":
      return { receiver: null, receiverClass: identifierClass(object.text, st) };
    case "field_access": {
      const name = field(object, "field");
      if (field(object, "object")?.type !== "this" || name?.type !== "identifier") return none;
      return { receiver: null, receiverClass: innermostClassScope(st)?.frame.classOf.get(name.text) ?? null };
    }
    case "object_creation_expression":
      return { receiver: null, receiverClass: declaredClass(field(object, "type")) };
    default:
      return none; // super, deeper chains, any other expression
  }
}

function onCall(node, st) {
  const name = field(node, "name");
  if (st.annotationDepth || !name) return;
  const security = st.scopes.findLast((s) => s.security)?.security ?? null;
  if (security) securityCall(node, name, security, st);
  const calleeText = textOf(node);
  const { receiver, receiverClass: cls } = receiverHints(field(node, "object"), st);
  st.calls.push({
    line: lineOf(name),
    start_byte: name.startIndex,
    callee_text: calleeText,
    arg_count: namedOf(field(node, "arguments")).length,
    enclosing_start_byte: innermostFunction(st)?.startIndex ?? null,
    receiver,
    receiver_class: cls,
    scope_names: []
  });
  const candidates = [{ category: "call", text: calleeText }];
  if (cls) candidates.push({ category: "call", text: `${cls}.${name.text}` });
  emitMatches(node, candidates, st, { sources: true, sinks: true, sinkAt: name });
}

// ---- imports --------------------------------------------------------------------------------------

function onImport(node, st) {
  const dotted = dottedName(namedOf(node).find((c) => c.type === "scoped_identifier" || c.type === "identifier"));
  if (!dotted) return;
  const isStatic = node.children.some((c) => c.type === "static");
  if (isStatic) st.notExtracted.add("static import");
  if (childrenOfType(node, "asterisk").length) {
    st.notExtracted.add("wildcard import");
    st.imports.push({ line: lineOf(node), specifier: dotted, bindings: "namespace", local: dotted });
    return;
  }
  const cut = dotted.lastIndexOf(".");
  const imported = dotted.slice(cut + 1);
  st.imports.push({ line: lineOf(node), specifier: isStatic && cut > 0 ? dotted.slice(0, cut) : dotted, bindings: [{ imported, local: imported }], local: null });
}

function onPackage(node, st) {
  st.namespace = dottedName(namedOf(node).find((c) => c.type === "scoped_identifier" || c.type === "identifier"));
}

// ---- walk -----------------------------------------------------------------------------------------

const HANDLERS = new Map([
  ["class_declaration", onType],
  ["interface_declaration", onType],
  ["enum_declaration", onType],
  ["record_declaration", onType],
  ["class_body", onClassBody],
  ["method_declaration", onFunction],
  ["constructor_declaration", onFunction],
  ["compact_constructor_declaration", onFunction],
  ["lambda_expression", onFunction],
  ["block", onScope],
  ["for_statement", onScope],
  ["enhanced_for_statement", onScope],
  ["catch_clause", onScope],
  ["try_with_resources_statement", onScope],
  ["switch_block", onScope],
  ["local_variable_declaration", onLocalDeclaration],
  ["field_declaration", (node, st) => typeCandidate(field(node, "type"), st)],
  ["resource", onResource],
  ["method_invocation", onCall],
  ["object_creation_expression", onNew],
  ["annotation", onAnnotation],
  ["marker_annotation", onAnnotation],
  ["string_literal", onString],
  ["import_declaration", onImport],
  ["package_declaration", onPackage]
]);
const CURSOR_HANDLERS = new Map([
  ["identifier", onIdentifier],
  ["type_identifier", onTypeIdentifier]
]);

export function extractFile({ tree, path, surface }) {
  const st = newState(path, surface);
  walk(tree, st, HANDLERS, CURSOR_HANDLERS);
  if (st.securityTypeSeen && st.securityChains.length === 0) st.notExtracted.add(NO_RULES_NOTE);
  return {
    functions: st.functions.sort(byStart),
    calls: st.calls.sort(byStart),
    imports: st.imports,
    exports: st.exports.sort(byStart),
    classes: st.classes.sort(byStart),
    namespace: st.namespace,
    routes: st.routes.sort(byStart),
    sources: st.sources.sort(byStart),
    sinks: st.sinks.sort(byStart),
    security_chains: st.securityChains.sort(byStart),
    not_extracted: [...st.notExtracted].sort()
  };
}

// ---- import resolution ----------------------------------------------------------------------------

// "a.b.Z" names the file Z.java declaring `package a.b;` (`namespaces`: path -> Extract.namespace);
// a file whose namespace is unknown matches by its path ending in a/b/Z.java ("heuristic"). Several
// matches yield the first by path, "heuristic". A package / wildcard specifier (no capitalised last
// segment) names no file. `fromPath` / `configs` are part of the shared contract; Java ignores them.
// resolve.mjs memoises resolveImportSpecifier per run on this key: the result depends on the specifier
// alone (fromPath is not consulted).
export const importCacheKey = ({ specifier }) => specifier;

export function resolveImportSpecifier({ specifier, filePaths, namespaces }) {
  if (typeof specifier !== "string") return null;
  const segments = specifier.split(".");
  if (segments.length < 2 || segments.some((s) => s === "") || !/^[A-Z]/.test(segments.at(-1))) return null;
  const pkg = segments.slice(0, -1).join(".");
  const fileName = `${segments.at(-1)}.java`;
  const candidates = pathsByBasename(filePaths).get(fileName) ?? []; // sorted
  const exact = candidates.filter((p) => namespaces?.get(p) === pkg);
  if (exact.length) return { path: exact[0], confidence: exact.length === 1 ? "exact" : "heuristic" };
  const suffix = `${segments.slice(0, -1).join("/")}/${fileName}`;
  const guess = candidates.find((p) => !namespaces?.has(p) && (p === suffix || p.endsWith(`/${suffix}`)));
  return guess ? { path: guess, confidence: "heuristic" } : null;
}
