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
//              `<enclosing>.<anon>@<line>:<col>`. exported = the enclosing top-level type is public
//              and the method is public (interface members are implicitly public).
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
//              `this.f.m()` -> the declared type of field f; `new C().m()` -> C; generics and
//              qualifiers reduce to the base name. Annotation arguments are never calls.
//   sinks      Java's surface tokens are written against declared types (`Statement.execute`), so a
//              call whose receiver has a known class T is also matched as `T.<method>`; the sink's
//              callee keeps the source text (`st.execute`).
//   routes     Spring `@GetMapping / @PostMapping / @PutMapping / @DeleteMapping / @PatchMapping` and
//              `@RequestMapping(method = ...)` on a method, prefixed by the class's
//              `@RequestMapping`; `@PreAuthorize / @Secured / @RolesAllowed` on the class, then on
//              the method, are the middleware texts. `SecurityFilterChain` config is only noted.
//
// Same TreeCursor walk as the JavaScript module (see its header for why not tree-sitter queries).
// PURE: no I/O. `sourceText` is never copied into the output — only identifier / literal text.
import { posix } from "node:path";
import { normalizeToken } from "../surface.mjs";
import { sinkClassFor } from "../sink-classes.mjs";
import { lookup, field, namedOf, childrenOfType, lineOf, anonLabel, firstMatch, byStart, walk, receiverClass } from "./common.mjs";

export const lang = { id: "java", stack: "java", langIds: ["java"], frameworks: ["spring"], implicitThisCalls: true, submoduleImports: false, callableLocals: false };

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
const AUTH_ANNOTATIONS = new Set(["PreAuthorize", "Secured", "RolesAllowed"]);
const SOURCE_KINDS = {
  RequestParam: "query", RequestBody: "body", PathVariable: "params", RequestHeader: "header", CookieValue: "cookie", ModelAttribute: "body",
  getParameter: "query", getQueryString: "query", getHeader: "header", getCookies: "cookie", getInputStream: "body", getReader: "body",
  "X-User-Role": "header", "X-Forwarded-User": "header"
};

// ---- small AST helpers ----------------------------------------------------------------------------

const lastSegment = (text) => text.slice(text.lastIndexOf(".") + 1);
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
// (`cls`, whose frame holds the class's fields), innermost last.
const newFrame = (startIndex = null, qualifiedName = null) => ({ startIndex, qualifiedName, bindings: new Set(), classOf: new Map() });
const NO_FRAME = newFrame();

function newState(path, surface) {
  return {
    moduleName: path.split("/").at(-1).replace(/\.[^.]*$/, ""),
    surface: { sources: surface?.sources ?? [], sinks: surface?.sinks ?? [] },
    functions: [], calls: [], imports: [], exports: [], classes: [], routes: [], sources: [], sinks: [],
    notExtracted: new Set(),
    namespace: null,
    scopes: [],
    annotationDepth: 0
  };
}

const innermostFunction = (st) => st.scopes.findLast((s) => s.fn)?.frame ?? null;
const innermostClassScope = (st) => st.scopes.findLast((s) => s.cls) ?? null;
const innermostClass = (st) => innermostClassScope(st)?.cls ?? null;
const enclosingName = (st) => innermostFunction(st)?.qualifiedName ?? innermostClass(st)?.qualifiedName ?? st.moduleName;

function bind(frame, name, cls) {
  if (!frame || !name) return;
  frame.bindings.add(name);
  if (cls) frame.classOf.set(name, cls);
  else frame.classOf.delete(name);
}

// ---- sources and sinks ----------------------------------------------------------------------------

const sourceKind = (pattern) => lookup(SOURCE_KINDS, pattern.normalized) ?? "body";

// At most one source and one sink per AST node: the first matching pattern in surface order. A sink
// derived from a call / `new` is positioned at the method name / the type (`sinkAt`).
function emitMatches(node, candidates, st, { sources = false, sinks = false, sinkAt = node }) {
  const source = sources ? firstMatch(st.surface.sources, candidates) : null;
  const sink = sinks ? firstMatch(st.surface.sinks, candidates) : null;
  if (source) st.sources.push({ line: lineOf(node), start_byte: node.startIndex, kind: sourceKind(source), pattern: source.raw });
  if (sink) st.sinks.push({ line: lineOf(sinkAt), start_byte: sinkAt.startIndex, class: sinkClassFor(sink.normalized, "java"), callee: candidates[0].text, pattern: sink.raw });
}

// A declared type (local, field, parameter, loop / resource variable) as a sink candidate.
function typeCandidate(type, st) {
  const text = typeText(type);
  if (text && text !== "var") emitMatches(type, [{ category: "type", text: normalizeToken(text) }], st, { sinks: true });
}

const noteSecurityFilterChain = (text, st) => {
  if (text === "SecurityFilterChain") st.notExtracted.add("SecurityFilterChain matchers");
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

// A literal mapping path: "" when the annotation names none, null when it is not one string literal.
function mappingPath(annotation) {
  const items = namedOf(field(annotation, "arguments"));
  const pair = items.find((i) => i.type === "element_value_pair" && ["value", "path"].includes(field(i, "key")?.text));
  const value = pair ? field(pair, "value") : items.find((i) => i.type !== "element_value_pair") ?? null;
  if (!value) return "";
  const literals = value.type === "element_value_array_initializer" ? namedOf(value) : [value];
  if (literals.length === 0) return "";
  return literals.length === 1 && literals[0].type === "string_literal" ? stringContent(literals[0]) : null;
}

function onType(node, st) {
  const name = field(node, "name")?.text ?? null;
  const body = field(node, "body");
  const outer = innermostClass(st);
  const isPublic = hasModifier(node, "public");
  if (name) {
    const superclass = namedOf(field(node, "superclass"))[0];
    const methods = [...new Set(membersOf(body).filter((m) => m.type === "method_declaration").map((m) => field(m, "name")?.text).filter(Boolean))];
    st.classes.push({ name, extends: superclass ? declaredClass(superclass) : null, methods, start_byte: node.startIndex });
    if (!outer && isPublic) st.exports.push({ name, start_byte: node.startIndex });
  }
  if (field(node, "interfaces")) st.notExtracted.add("implements clause");
  const annotations = annotationsOf(node);
  const mapping = annotations.find((a) => annotationName(a) === "RequestMapping");
  let prefix = mapping ? mappingPath(mapping) : "";
  if (prefix === null) {
    st.notExtracted.add("route(non-literal path)");
    prefix = "";
  }
  st.scopes.push({
    frame: fieldFrame(node, body, name),
    cls: {
      name,
      qualifiedName: name ?? `${enclosingName(st)}.${anonLabel(node)}`,
      exported: outer ? outer.exported : isPublic,
      isInterface: node.type === "interface_declaration",
      prefix,
      auth: annotations.map(annotationName).filter((n) => AUTH_ANNOTATIONS.has(n))
    }
  });
  return () => st.scopes.pop();
}

// The body of an anonymous class (`new C() {...}`) or of an enum constant: a class without a name.
function onClassBody(node, st, ctx) {
  if (ctx.parentType !== "object_creation_expression" && ctx.parentType !== "enum_constant") return;
  st.notExtracted.add("anonymous class");
  const cls = { name: null, qualifiedName: `${enclosingName(st)}.${anonLabel(node.parent)}`, exported: false, isInterface: false, prefix: "", auth: [] };
  st.scopes.push({ frame: fieldFrame(node, node, null), cls });
  return () => st.scopes.pop();
}

// ---- functions and routes -------------------------------------------------------------------------

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
    fn = { name: local ?? "<anon>", qualified_name: qualifiedName, kind: "lambda", exported: false, class: null };
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
    kind: fn.kind,
    exported: fn.exported,
    class: fn.class
  });
  if (node.type === "method_declaration" && owner?.name) springRoutes(node, owner, fn.qualified_name, st);
  const frame = newFrame(node.startIndex, fn.qualified_name);
  addParameters(node, frame, st);
  st.scopes.push({ frame, fn: true });
  return () => st.scopes.pop();
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
    const path = mappingPath(annotation);
    if (path === null) {
      st.notExtracted.add("route(non-literal path)");
      continue;
    }
    st.routes.push({
      line: lineOf(annotation),
      start_byte: annotation.startIndex,
      http_method: MAPPING_VERBS.get(name) ?? requestMethod(annotation),
      path_pattern: joinPath(owner.prefix, path),
      handler_text: qualifiedName,
      middleware_texts: [...owner.auth, ...auth],
      framework: "spring"
    });
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
  const calleeText = textOf(node);
  const { receiver, receiverClass: cls } = receiverHints(field(node, "object"), st);
  st.calls.push({
    line: lineOf(name),
    start_byte: name.startIndex,
    callee_text: calleeText,
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
    not_extracted: [...st.notExtracted].sort()
  };
}

// ---- import resolution ----------------------------------------------------------------------------

// "a.b.Z" names the file Z.java declaring `package a.b;` (`namespaces`: path -> Extract.namespace);
// a file whose namespace is unknown matches by its path ending in a/b/Z.java ("heuristic"). Several
// matches yield the first by path, "heuristic". A package / wildcard specifier (no capitalised last
// segment) names no file. `fromPath` / `configs` are part of the shared contract; Java ignores them.
export function resolveImportSpecifier({ specifier, filePaths, namespaces }) {
  if (typeof specifier !== "string") return null;
  const segments = specifier.split(".");
  if (segments.length < 2 || segments.some((s) => s === "") || !/^[A-Z]/.test(segments.at(-1))) return null;
  const pkg = segments.slice(0, -1).join(".");
  const fileName = `${segments.at(-1)}.java`;
  const candidates = [...filePaths].filter((p) => posix.basename(p) === fileName).sort();
  const exact = candidates.filter((p) => namespaces?.get(p) === pkg);
  if (exact.length) return { path: exact[0], confidence: exact.length === 1 ? "exact" : "heuristic" };
  const suffix = `${segments.slice(0, -1).join("/")}/${fileName}`;
  const guess = candidates.find((p) => !namespaces?.has(p) && (p === suffix || p.endsWith(`/${suffix}`)));
  return guess ? { path: guess, confidence: "heuristic" } : null;
}
