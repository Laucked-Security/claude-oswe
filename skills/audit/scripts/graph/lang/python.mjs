// Python language module for the SP10 application graph (spec §2.3), Flask / Django / FastAPI.
// extractFile walks one parsed tree (web-tree-sitter, see ../parser.mjs) and emits the per-file
// Extract described in ./javascript.mjs: functions, calls (+ the scope / receiver hints resolve.mjs
// needs, spec §1.4), imports, exports, classes, routes, and surface-pattern sources / sinks.
//
// Python specifics:
//   functions  `def` at module level -> "function"; in a class body -> "method" (`<Class>.<name>`);
//              nested -> "function" (`<outer>.<name>`); `lambda` -> "lambda", named by the target
//              of `x = lambda: ...`, else `<enclosing>.<anon>@<line>:<col>`.
//   exports    Python has no export statement: every top-level def / class whose name does not
//              start with `_` — or, when the module sets `__all__` to a list of string literals,
//              only those of them it names. A method is exported with its class.
//   imports    `lang.submoduleImports: true`: `from pkg import sub` may name the module pkg.sub, which
//              resolve.mjs tries when pkg does not export `sub`.
//   classes    `extends` is the last dotted segment of the first base (`object` and keyword
//              arguments ignored); further bases are only noted ("multiple inheritance").
//   scopes     scope_names are the bindings of every enclosing def / lambda (parameters,
//              assignment / loop / with / except / walrus / comprehension targets, nested def and
//              class names) plus the module's assignment targets. Imports and module-level def /
//              class names never shadow. A class body binds nothing visible to its methods.
//   receivers  `self.m()` / `cls.m()` -> receiver "this"; `self.a.m()` -> the declared class of
//              attribute a; `x.m()` -> the class x is bound to (`x = C(...)`, `x: C`, parameter
//              `x: C`) in the innermost scope that binds x. A name bound twice to different
//              things carries no class.
//   routes     Flask `@<x>.route(path, methods=[...])` / `@<x>.<verb>(path)`; FastAPI the same
//              verbs on a FastAPI / APIRouter receiver (or in a file importing fastapi), plus
//              `Depends.<name>` middleware texts; Django module-level `urlpatterns` `path()` /
//              `re_path()` items (method "ANY"), `include("a.urls")` as a "USE" mount backed by a
//              namespace import of "a.urls" so build-graph prefixes the included file's routes.
//
// Same TreeCursor walk as the JavaScript module (see its header for why not tree-sitter queries).
// PURE: no I/O. `sourceText` is never copied into the output — only identifier / literal text.
import { posix } from "node:path";
import { normalizeToken } from "../surface.mjs";
import { sinkClassFor } from "../sink-classes.mjs";
import { matchesPattern } from "../match.mjs";

export const lang = { id: "python", stack: "python", langIds: ["python"], frameworks: ["flask", "django", "fastapi"], implicitThisCalls: false, submoduleImports: true };

// ---- node-type tables -----------------------------------------------------------------------------

// A node in one of these (parent type, field) slots is part of a callee / attribute chain: the
// enclosing chain node is the candidate, so the part never yields a source or sink on its own.
const CHAIN_SLOTS = new Map([["attribute", "object"], ["call", "function"]]);
// An identifier in one of these slots (or under one of these parents) declares a name, names an
// attribute / keyword, or spells a type annotation: it is not a value reference.
const BINDING_SLOTS = new Map([
  ["function_definition", "name"], ["class_definition", "name"], ["default_parameter", "name"], ["typed_default_parameter", "name"],
  ["keyword_argument", "name"], ["attribute", "attribute"], ["assignment", "left"], ["augmented_assignment", "left"],
  ["named_expression", "name"], ["for_statement", "left"], ["for_in_clause", "left"], ["aliased_import", "alias"]
]);
const BINDING_PARENTS = new Set([
  "parameters", "lambda_parameters", "typed_parameter", "list_splat_pattern", "dictionary_splat_pattern", "pattern_list",
  "tuple_pattern", "list_pattern", "as_pattern_target", "dotted_name", "global_statement", "nonlocal_statement", "type"
]);
const PATTERN_CONTAINERS = new Set(["pattern_list", "tuple_pattern", "list_pattern", "list_splat_pattern", "as_pattern_target"]);

const ROUTE_VERBS = { get: "GET", post: "POST", put: "PUT", patch: "PATCH", delete: "DELETE", head: "HEAD", options: "OPTIONS" };
const FASTAPI_CLASSES = new Set(["FastAPI", "APIRouter"]);
const DJANGO_ROUTE_FUNCTIONS = new Set(["path", "re_path"]);
const SOURCE_KINDS = {
  args: "query", GET: "query",
  form: "body", json: "body", data: "body", get_json: "body", values: "body", POST: "body", body: "body",
  headers: "header", META: "header", cookies: "cookie", COOKIES: "cookie", files: "file", FILES: "file", environ: "env"
};

const lookup = (table, key) => (key != null && Object.hasOwn(table, key) ? table[key] : null);

// ---- small AST helpers ----------------------------------------------------------------------------

const field = (node, name) => node?.childForFieldName(name) ?? null;
const namedOf = (node) => (node ? node.namedChildren.filter((c) => c.type !== "comment") : []);
const childrenOfType = (node, type) => (node ? node.namedChildren.filter((c) => c.type === type) : []);
const lineOf = (node) => node.startPosition.row + 1;
const anonLabel = (node) => `<anon>@${node.startPosition.row + 1}:${node.startPosition.column + 1}`;
const lastSegment = (text) => text.slice(text.lastIndexOf(".") + 1);
const positionalArgs = (call) => namedOf(field(call, "arguments")).filter((a) => a.type !== "keyword_argument");
const keywordArg = (call, name) => namedOf(field(call, "arguments")).find((a) => a.type === "keyword_argument" && field(a, "name")?.text === name) ?? null;

// The value of a plain string literal (prefixes and quotes dropped); null for an f-string with
// interpolations or any other node.
function stringValue(node) {
  if (node?.type !== "string" || childrenOfType(node, "interpolation").length) return null;
  return childrenOfType(node, "string_content").map((c) => c.text).join("");
}

// Callee / attribute text with call arguments and subscripts dropped (`a.b(x).c` -> `a.b.c`,
// `a[0].c` -> `a.c`).
function render(node) {
  switch (node.type) {
    case "attribute": {
      const object = field(node, "object");
      const attribute = field(node, "attribute");
      return object && attribute ? `${render(object)}.${attribute.text}` : node.text;
    }
    case "call": {
      const fn = field(node, "function");
      return fn ? render(fn) : node.text;
    }
    case "subscript": {
      const value = field(node, "value");
      return value ? render(value) : node.text;
    }
    case "parenthesized_expression": {
      const inner = namedOf(node)[0];
      return inner ? render(inner) : node.text;
    }
    default:
      return node.text;
  }
}
const textOf = (node) => normalizeToken(render(node));
const dottedText = (node) => namedOf(node).map((c) => c.text).join(".");

// Every name a binding target declares (`a`, `a, (b, c)`, `[d, *e]`); attributes / subscripts none.
function patternNames(node, out = []) {
  if (!node) return out;
  if (node.type === "identifier") out.push(node.text);
  else if (PATTERN_CONTAINERS.has(node.type)) for (const child of namedOf(node)) patternNames(child, out);
  return out;
}

// The class named by a type annotation: `C` / `mod.C` -> `C`; anything else (generics, strings) null.
function typeName(node) {
  switch (node?.type) {
    case "type":
      return typeName(namedOf(node)[0]);
    case "identifier":
      return node.text;
    case "attribute":
      return field(node, "attribute")?.text ?? null;
    default:
      return null;
  }
}

// The class a value constructs: a call whose callee is a capitalised name or a dotted name ending in
// a capitalised segment (`C(...)`, `pkg.C(...)`; resolve.mjs verifies it names a class). A chained
// assignment `a = b = C()` reads through to its final value.
function constructedClass(value) {
  let node = value;
  while (node?.type === "assignment") node = field(node, "right");
  if (node?.type !== "call") return null;
  const fn = field(node, "function");
  const name = fn?.type === "identifier" ? fn.text : fn?.type === "attribute" ? field(fn, "attribute")?.text : null;
  return name && /^[A-Z]/.test(name) ? name : null;
}

// ---- state ----------------------------------------------------------------------------------------

const newFrame = (startIndex, qualifiedName) => ({ startIndex, qualifiedName, bindings: new Set(), classOf: new Map() });

function newState(path, surface) {
  return {
    moduleName: path.split("/").at(-1).replace(/\.[^.]*$/, ""),
    surface: { sources: surface?.sources ?? [], sinks: surface?.sinks ?? [] },
    functions: [], calls: [], imports: [], classes: [], routes: [], sources: [], sinks: [],
    notExtracted: new Set(),
    topLevel: [], // [name, start byte] of module-level def / class, in source order
    allNames: null, // the module's `__all__` string list, when it has one
    classBases: new Map(), // class name -> base texts, for Django class-based views
    importsFastapi: false,
    module: newFrame(null, null),
    scopes: [] // innermost last: { frame } for a def / lambda, { cls } for a class body
  };
}

const functionFrames = (st) => st.scopes.filter((s) => s.frame).map((s) => s.frame);
const innermostFrame = (st) => st.scopes.findLast((s) => s.frame)?.frame ?? null;
const innermostClass = (st) => st.scopes.findLast((s) => s.cls)?.cls ?? null;
const atModule = (st) => st.scopes.length === 0;

// Record `name` as bound in `frame`; a second binding to a different class (or to no class) drops
// the class: the name is then demonstrably bound, but not to one class.
function addBinding(frame, name, cls) {
  if (!frame.bindings.has(name)) {
    frame.bindings.add(name);
    if (cls) frame.classOf.set(name, cls);
  } else if (frame.classOf.get(name) !== cls) frame.classOf.delete(name);
}

// Bind in the innermost scope. A class body binds nothing (its names are attributes, invisible to
// its methods); at module level only assignment targets are recorded (`assignment: true`).
function bind(st, name, { cls = null, assignment = false } = {}) {
  const top = st.scopes.at(-1);
  if (top?.cls) return;
  if (top) addBinding(top.frame, name, cls);
  else if (assignment) addBinding(st.module, name, cls);
}

// ---- sources and sinks ----------------------------------------------------------------------------

const firstMatch = (patterns, candidates) => patterns.find((p) => candidates.some((c) => matchesPattern(p, c))) ?? null;
const sourceKind = (pattern) => lookup(SOURCE_KINDS, lastSegment(pattern.normalized)) ?? "body";

// At most one source and one sink per AST node: the first matching pattern in surface order. A sink
// derived from a call is positioned at the callee anchor (`sinkAt`, see calleeAnchor).
function emitMatches(node, candidates, st, { sources = false, sinks = false, sinkAt = node }) {
  const source = sources ? firstMatch(st.surface.sources, candidates) : null;
  const sink = sinks ? firstMatch(st.surface.sinks, candidates) : null;
  if (source) st.sources.push({ line: lineOf(node), start_byte: node.startIndex, kind: sourceKind(source), pattern: source.raw });
  if (sink) st.sinks.push({ line: lineOf(sinkAt), start_byte: sinkAt.startIndex, class: sinkClassFor(sink.normalized, "python"), callee: candidates[0].text, pattern: sink.raw });
}

const inChain = (ctx) => CHAIN_SLOTS.get(ctx.parentType) === ctx.field || ctx.parentType === "decorator";
const isBinding = (ctx) => BINDING_PARENTS.has(ctx.parentType) || BINDING_SLOTS.get(ctx.parentType) === ctx.field;

// onAttribute / onIdentifier receive the TreeCursor rather than a Node (see javascript.mjs). A
// subscript is never a candidate: in `request.args["x"]` the attribute `request.args` is.
function onAttribute(cursor, st, ctx) {
  if (inChain(ctx) || ctx.parentType === "type") return;
  const node = cursor.currentNode;
  emitMatches(node, [{ category: "member", text: textOf(node) }], st, { sources: true, sinks: true });
}

function onIdentifier(cursor, st, ctx) {
  if (inChain(ctx) || isBinding(ctx)) return;
  emitMatches(cursor, [{ category: "identifier", text: cursor.nodeText }], st, { sources: true, sinks: true });
}

function onString(node, st, ctx) {
  if (ctx.parentType === "pair" && ctx.field === "key") return; // a key, handled by onPair
  const text = childrenOfType(node, "string_content").map((c) => c.text).join("");
  emitMatches(node, [{ category: "literal", text: normalizeToken(text) }], st, { sinks: true });
}

function onPair(node, st) {
  const key = stringValue(field(node, "key"));
  if (key) emitMatches(field(node, "key"), [{ category: "key", text: normalizeToken(key) }], st, { sinks: true });
}

function decoratorInfo(decorator) {
  const expr = namedOf(decorator)[0];
  if (!expr) return { name: "", call: null };
  if (expr.type === "call") return { name: textOf(field(expr, "function") ?? expr), call: expr };
  return { name: textOf(expr), call: null };
}

function onDecorator(node, st) {
  const { name } = decoratorInfo(node);
  if (name) emitMatches(node, [{ category: "decorator", text: name }], st, { sources: true });
}

// ---- scopes and functions -------------------------------------------------------------------------

// The identifier a parameter declares (`a`, `a: T`, `a=1`, `a: T = 1`, `*a`, `**a`, `*a: T`).
function parameterName(param) {
  switch (param?.type) {
    case "identifier":
      return param;
    case "default_parameter":
    case "typed_default_parameter":
      return field(param, "name");
    case "typed_parameter":
      return parameterName(namedOf(param)[0]);
    case "list_splat_pattern":
    case "dictionary_splat_pattern":
      return childrenOfType(param, "identifier")[0] ?? null;
    default:
      return null;
  }
}

function addParameters(node, frame) {
  for (const param of namedOf(field(node, "parameters"))) {
    const name = parameterName(param);
    if (name?.type === "identifier") addBinding(frame, name.text, typeName(field(param, "type")));
  }
}

function functionName(node, ctx) {
  if (node.type === "function_definition") return field(node, "name")?.text ?? null;
  if (ctx.parentType === "assignment" && ctx.field === "right") {
    const target = field(node.parent, "left");
    if (target?.type === "identifier") return target.text;
  }
  return null;
}

function onFunction(node, st, ctx) {
  const enclosing = innermostFrame(st);
  const top = st.scopes.at(-1);
  const cls = node.type === "function_definition" && top?.cls ? top.cls.name : null;
  let name = functionName(node, ctx);
  let qualifiedName;
  if (!name) {
    name = "<anon>";
    qualifiedName = `${enclosing?.qualifiedName ?? st.moduleName}.${anonLabel(node)}`;
  } else if (cls) {
    qualifiedName = `${cls}.${name}`;
  } else {
    qualifiedName = enclosing ? `${enclosing.qualifiedName}.${name}` : name;
  }
  if (node.type === "function_definition") {
    if (atModule(st)) st.topLevel.push([name, node.startIndex]);
    else bind(st, name);
  }
  st.functions.push({
    name,
    qualified_name: qualifiedName,
    line_start: lineOf(node),
    line_end: node.endPosition.row + 1,
    start_byte: node.startIndex,
    end_byte: node.endIndex,
    kind: node.type === "lambda" ? "lambda" : cls ? "method" : "function",
    exported: false,
    class: cls
  });
  if (ctx.parentType === "decorated_definition") decoratorRoutes(childrenOfType(node.parent, "decorator"), node, qualifiedName, st);
  const frame = newFrame(node.startIndex, qualifiedName);
  addParameters(node, frame);
  st.scopes.push({ frame });
  return () => st.scopes.pop();
}

function onAssignment(node, st) {
  const left = field(node, "left");
  const right = field(node, "right");
  const cls = left?.type === "identifier" ? typeName(field(node, "type")) ?? constructedClass(right) : null;
  for (const name of patternNames(left)) bind(st, name, { cls, assignment: true });
  if (!atModule(st) || left?.type !== "identifier") return;
  if (left.text === "__all__" && (right?.type === "list" || right?.type === "tuple")) {
    const names = namedOf(right).map(stringValue);
    if (names.every((n) => n !== null)) st.allNames = names;
  }
  if (left.text === "urlpatterns" && right?.type === "list") djangoRoutes(right, st);
}

function onAugmentedAssignment(node, st) {
  const left = field(node, "left");
  for (const name of patternNames(left)) bind(st, name, { assignment: true });
  const right = field(node, "right");
  if (atModule(st) && left?.type === "identifier" && left.text === "urlpatterns" && right?.type === "list") djangoRoutes(right, st);
}

function onWalrus(node, st) {
  const name = field(node, "name");
  if (name) bind(st, name.text, { assignment: true });
}

// `for` / comprehension `for ... in` targets and `with ... as` / `except ... as` targets.
function onLoopOrAsTarget(node, st) {
  const target = node.type === "as_pattern_target" ? node : field(node, "left");
  for (const name of patternNames(target)) bind(st, name);
}

// ---- classes --------------------------------------------------------------------------------------

// Declared class of each `self.<attr>` receiver, first source wins: (i) a class-level annotation
// `attr: C`, (ii) an annotated assignment `self.attr: C = ...`, (iii) `self.attr = C(...)`.
function fieldTypes(body) {
  const types = new Map();
  const add = (attr, type) => attr && type && !types.has(attr) && types.set(attr, type);
  for (const statement of childrenOfType(body, "expression_statement")) {
    for (const assignment of childrenOfType(statement, "assignment")) {
      const left = field(assignment, "left");
      if (left?.type === "identifier") add(left.text, typeName(field(assignment, "type")));
    }
  }
  const selfAssignments = (body?.descendantsOfType("assignment") ?? []).filter((a) => {
    const left = field(a, "left");
    return left?.type === "attribute" && field(left, "object")?.type === "identifier" && field(left, "object").text === "self";
  });
  for (const a of selfAssignments) add(field(field(a, "left"), "attribute")?.text, typeName(field(a, "type")));
  for (const a of selfAssignments) add(field(field(a, "left"), "attribute")?.text, constructedClass(field(a, "right")));
  return types;
}

const definedFunction = (node) => (node.type === "decorated_definition" ? field(node, "definition") : node);

function onClass(node, st) {
  const name = field(node, "name")?.text ?? null;
  const body = field(node, "body");
  const bases = namedOf(field(node, "superclasses"))
    .filter((b) => !["keyword_argument", "list_splat", "dictionary_splat"].includes(b.type))
    .map(textOf)
    .filter((t) => t !== "object");
  if (bases.length > 1) st.notExtracted.add("multiple inheritance");
  if (name) {
    const methods = namedOf(body).map(definedFunction).filter((d) => d?.type === "function_definition").map((d) => field(d, "name")?.text).filter(Boolean);
    st.classes.push({ name, extends: bases.length ? lastSegment(bases[0]) : null, methods, start_byte: node.startIndex });
    if (!st.classBases.has(name)) st.classBases.set(name, bases);
    if (atModule(st)) st.topLevel.push([name, node.startIndex]);
    else bind(st, name);
  }
  st.scopes.push({ cls: { name, fieldTypes: fieldTypes(body) } });
  return () => st.scopes.pop();
}

// ---- routes ---------------------------------------------------------------------------------------

function joinDjangoPath(pattern) {
  return pattern.startsWith("/") ? pattern : `/${pattern}`;
}

// `Depends(x)` -> `Depends.<x>`; anything else contributes nothing.
function dependsText(node) {
  if (node?.type !== "call" || lastSegment(textOf(field(node, "function") ?? node)) !== "Depends") return [];
  const target = positionalArgs(node)[0];
  return target ? [`Depends.${textOf(target)}`] : [];
}

function routeMethod(info, verb) {
  if (verb !== "route") return ROUTE_VERBS[verb];
  const methods = field(keywordArg(info.call, "methods"), "value");
  if (!methods) return "GET";
  const listed = ["list", "tuple", "set"].includes(methods.type) ? namedOf(methods).map(stringValue) : [null];
  return listed.length === 1 && listed[0] ? listed[0].toUpperCase() : "ANY";
}

function routeFramework(receiver, st) {
  const cls = receiver?.type === "identifier" ? st.module.classOf.get(receiver.text) : null;
  if (cls) return FASTAPI_CLASSES.has(cls) ? "fastapi" : "flask";
  return st.importsFastapi ? "fastapi" : "flask";
}

// Flask / FastAPI decorator routes on one function: every `@<x>.route(...)` / `@<x>.<verb>(...)`
// is a route; the function's other decorators are its middleware texts, in source order.
function decoratorRoutes(decorators, fnNode, qualifiedName, st) {
  const infos = decorators.map((d) => ({ node: d, ...decoratorInfo(d) }));
  const isRoute = (info) => {
    const verb = lastSegment(info.name);
    return info.call && field(info.call, "function")?.type === "attribute" && (verb === "route" || lookup(ROUTE_VERBS, verb) !== null);
  };
  const routeInfos = infos.filter(isRoute);
  if (!routeInfos.length) return;
  const others = infos.filter((i) => !isRoute(i) && i.name).map((i) => i.name);
  const paramDepends = namedOf(field(fnNode, "parameters")).flatMap((p) => dependsText(field(p, "value")));
  for (const info of routeInfos) {
    const pathArg = positionalArgs(info.call)[0];
    if (!pathArg) continue;
    const path = stringValue(pathArg);
    if (path === null) {
      st.notExtracted.add("route(non-literal path)");
      continue;
    }
    const framework = routeFramework(field(field(info.call, "function"), "object"), st);
    const dependencies = field(keywordArg(info.call, "dependencies"), "value");
    st.routes.push({
      line: lineOf(info.node),
      start_byte: info.node.startIndex,
      http_method: routeMethod(info, lastSegment(info.name)),
      path_pattern: path,
      handler_text: qualifiedName,
      middleware_texts: framework === "fastapi" ? [...others, ...namedOf(dependencies).flatMap(dependsText), ...paramDepends] : others,
      framework
    });
  }
}

// Django `urlpatterns` items: `path(pattern, view)` / `re_path(pattern, view)`. `include("a.urls")`
// is a USE mount plus a namespace import of "a.urls" (build-graph resolves the mount through it);
// `X.as_view()` of a same-file class takes the class's bases as middleware texts (auth mixins).
function djangoRoutes(list, st) {
  for (const item of namedOf(list)) {
    if (item.type !== "call" || !DJANGO_ROUTE_FUNCTIONS.has(lastSegment(textOf(field(item, "function") ?? item)))) continue;
    const [patternArg, view] = positionalArgs(item);
    const pattern = stringValue(patternArg);
    if (pattern === null || !view) {
      st.notExtracted.add("urlpatterns(non-literal path)");
      continue;
    }
    const route = { line: lineOf(item), start_byte: item.startIndex, http_method: "ANY", path_pattern: joinDjangoPath(pattern), handler_text: textOf(view), middleware_texts: [], framework: "django" };
    const callee = view.type === "call" ? field(view, "function") : null;
    if (callee && lastSegment(textOf(callee)) === "include") {
      const module = stringValue(positionalArgs(view)[0]);
      if (module === null) {
        st.notExtracted.add("include(non-literal)");
        continue;
      }
      st.imports.push({ line: lineOf(view), specifier: module, bindings: "namespace", local: module });
      st.routes.push({ ...route, http_method: "USE", handler_text: module });
      continue;
    }
    if (callee?.type === "attribute" && field(callee, "attribute")?.text === "as_view") {
      st.notExtracted.add("class-based view dispatch");
      route.middleware_texts = [...(st.classBases.get(textOf(field(callee, "object"))) ?? [])];
    }
    st.routes.push(route);
  }
}

// ---- calls ----------------------------------------------------------------------------------------

// Position of a call: the callee's final identifier (the attribute of an attribute callee), so
// chained calls (`a.b().c()`) and their sinks get distinct offsets; any other callee shape falls
// back to the argument list, or to the call itself.
function calleeAnchor(callee, call) {
  if (callee.type === "identifier") return callee;
  if (callee.type === "attribute") return field(callee, "attribute") ?? callee;
  return field(call, "arguments") ?? call;
}

const isSelf = (node) => node?.type === "identifier" && (node.text === "self" || node.text === "cls");

// Receiver hints for an attribute callee (spec §1.4 rules 1b and 3): `self.m()` -> "this"; `x.m()`
// -> the name x, resolved against the scopes when the walk ends; `self.a.m()` -> the declared class
// of attribute a on the enclosing class. Deeper chains carry no hint.
function receiverOf(fn, st) {
  const none = { receiver: null, receiverName: null, fieldClass: null };
  if (fn.type !== "attribute") return none;
  const object = field(fn, "object");
  if (isSelf(object)) return { ...none, receiver: "this" };
  if (object?.type === "identifier") return { ...none, receiverName: object.text };
  if (object?.type === "attribute" && isSelf(field(object, "object"))) {
    return { ...none, fieldClass: innermostClass(st)?.fieldTypes.get(field(object, "attribute")?.text) ?? null };
  }
  return none;
}

function onCall(node, st, ctx) {
  if (ctx.parentType === "decorator") return; // decorator metadata, modelled by routes / sources
  const fn = field(node, "function");
  if (!fn) return;
  const calleeText = textOf(fn);
  const anchor = calleeAnchor(fn, node);
  st.calls.push({ anchor, calleeText, ...receiverOf(fn, st), frames: functionFrames(st) });
  emitMatches(node, [{ category: "call", text: calleeText }], st, { sources: true, sinks: true, sinkAt: anchor });
}

// ---- imports --------------------------------------------------------------------------------------

const noteFastapi = (specifier, st) => {
  if (specifier === "fastapi" || specifier.startsWith("fastapi.")) st.importsFastapi = true;
};

function onImport(node, st) {
  for (const part of node.childrenForFieldName("name")) {
    const dotted = part.type === "aliased_import" ? field(part, "name") : part;
    const specifier = dottedText(dotted);
    noteFastapi(specifier, st);
    st.imports.push({ line: lineOf(node), specifier, bindings: "namespace", local: part.type === "aliased_import" ? field(part, "alias")?.text ?? specifier : specifier });
  }
}

function onImportFrom(node, st) {
  const module = field(node, "module_name");
  const specifier = module?.type === "relative_import"
    ? childrenOfType(module, "import_prefix")[0].text.replace(/\s+/g, "") + dottedText(childrenOfType(module, "dotted_name")[0])
    : dottedText(module);
  noteFastapi(specifier, st);
  const bindings = node.childrenForFieldName("name").map((part) => {
    const imported = dottedText(part.type === "aliased_import" ? field(part, "name") : part);
    return { imported, local: part.type === "aliased_import" ? field(part, "alias")?.text ?? imported : imported };
  });
  if (childrenOfType(node, "wildcard_import").length) st.notExtracted.add("star import");
  st.imports.push({ line: lineOf(node), specifier, bindings, local: null });
}

// ---- walk -----------------------------------------------------------------------------------------

const HANDLERS = new Map([
  ["function_definition", onFunction],
  ["lambda", onFunction],
  ["class_definition", onClass],
  ["assignment", onAssignment],
  ["augmented_assignment", onAugmentedAssignment],
  ["named_expression", onWalrus],
  ["for_statement", onLoopOrAsTarget],
  ["for_in_clause", onLoopOrAsTarget],
  ["as_pattern_target", onLoopOrAsTarget],
  ["call", onCall],
  ["string", onString],
  ["pair", onPair],
  ["decorator", onDecorator],
  ["import_statement", onImport],
  ["import_from_statement", onImportFrom]
]);
const CURSOR_HANDLERS = new Map([
  ["attribute", onAttribute],
  ["identifier", onIdentifier]
]);

// Pre-order walk. A handler may return an exit callback, run when the walk leaves that node.
function walk(tree, st) {
  const cursor = tree.walk();
  const types = [];
  const exits = [];
  let depth = 0;
  try {
    for (;;) {
      const type = (types[depth] = cursor.nodeType);
      const handler = HANDLERS.get(type);
      const cursorHandler = handler ? undefined : CURSOR_HANDLERS.get(type);
      if ((handler || cursorHandler) && cursor.nodeIsNamed) {
        const ctx = { parentType: depth > 0 ? types[depth - 1] : null, field: cursor.currentFieldName };
        const exit = handler ? handler(cursor.currentNode, st, ctx) : cursorHandler(cursor, st, ctx);
        if (exit) exits.push({ depth, exit });
      }
      if (cursor.gotoFirstChild()) {
        depth++;
        continue;
      }
      for (;;) {
        while (exits.length && exits.at(-1).depth >= depth) exits.pop().exit();
        if (cursor.gotoNextSibling()) break;
        if (!cursor.gotoParent()) return;
        depth--;
      }
    }
  } finally {
    cursor.delete();
  }
}

// ---- finish ---------------------------------------------------------------------------------------

// The class a receiver name is demonstrably bound to: the innermost scope binding the name wins (a
// plain parameter or local shadows an outer `C()` binding).
function receiverClass(name, frames, moduleFrame) {
  for (const frame of [...frames].reverse()) {
    if (frame.classOf.has(name)) return frame.classOf.get(name);
    if (frame.bindings.has(name)) return null;
  }
  return moduleFrame.classOf.get(name) ?? null;
}

function finishCall({ anchor, calleeText, receiver, receiverName, fieldClass, frames }, st) {
  const names = new Set(st.module.bindings);
  for (const frame of frames) for (const name of frame.bindings) names.add(name);
  return {
    line: lineOf(anchor),
    start_byte: anchor.startIndex,
    callee_text: calleeText,
    enclosing_start_byte: frames.at(-1)?.startIndex ?? null,
    receiver,
    receiver_class: fieldClass ?? (receiverName ? receiverClass(receiverName, frames, st.module) : null),
    scope_names: [...names].sort()
  };
}

const byStart = (a, b) => a.start_byte - b.start_byte;

// One export per top-level def / class name (its first definition), filtered by `__all__` when set.
function moduleExports(st) {
  const listed = st.allNames ? new Set(st.allNames) : null;
  const exports = new Map();
  for (const [name, start] of st.topLevel) {
    if (exports.has(name) || (listed ? !listed.has(name) : name.startsWith("_"))) continue;
    exports.set(name, { name, start_byte: start });
  }
  return [...exports.values()];
}

function finish(st) {
  const exports = moduleExports(st);
  const exported = new Set(exports.map((e) => e.name));
  for (const fn of st.functions) fn.exported = fn.class ? exported.has(fn.class) : fn.qualified_name === fn.name && exported.has(fn.name);
  return {
    functions: st.functions.sort(byStart),
    calls: st.calls.map((c) => finishCall(c, st)).sort(byStart),
    imports: st.imports,
    exports: exports.sort(byStart),
    classes: st.classes.sort(byStart),
    namespace: null,
    routes: st.routes.sort(byStart),
    sources: st.sources.sort(byStart),
    sinks: st.sinks.sort(byStart),
    not_extracted: [...st.notExtracted].sort()
  };
}

export function extractFile({ tree, path, surface }) {
  const st = newState(path, surface);
  walk(tree, st);
  return finish(st);
}

// ---- import resolution ----------------------------------------------------------------------------

// Repo-relative normal form; null when the path escapes the repository root.
function repoPath(path) {
  const normal = posix.normalize(path);
  if (normal === ".." || normal.startsWith("../") || posix.isAbsolute(normal)) return null;
  return normal === "." ? "" : normal;
}

// A module `base` is `base.py` or the package `base/__init__.py`; a bare package reference
// (`from . import x`) is only the package.
function probe(base, filePaths, packageOnly) {
  if (base === null) return null;
  const candidates = [...(packageOnly ? [] : [`${base}.py`]), posix.join(base, "__init__.py")];
  return candidates.find((c) => filePaths.has(c)) ?? null;
}

// Ancestor directories of `fromPath` that are packages (contain `__init__.py`), nearest first.
function packageAncestors(fromPath, filePaths) {
  const out = [];
  for (let dir = posix.dirname(fromPath); dir !== "." && dir !== "/" && dir !== ""; dir = posix.dirname(dir)) {
    if (filePaths.has(`${dir}/__init__.py`)) out.push(dir);
  }
  return out;
}

// A relative specifier (leading dots) resolves from the importing file's directory, one level up
// per extra dot; a dotted specifier from the scope root, then from `src/` (the src layout), then
// from each package ancestor of the importing file. `configs` / `namespaces` are part of the shared contract; Python ignores them.
export function resolveImportSpecifier({ specifier, fromPath, filePaths }) {
  if (typeof specifier !== "string" || specifier === "") return null;
  const dots = /^\.*/.exec(specifier)[0].length;
  const rest = specifier.slice(dots);
  if (rest !== "" && rest.split(".").some((segment) => segment === "")) return null;
  const modulePath = rest.split(".").join("/");
  const roots = dots ? [[posix.dirname(fromPath), ...Array(dots - 1).fill("..")].join("/")] : ["", "src", ...packageAncestors(fromPath, filePaths)];
  for (const root of roots) {
    const hit = probe(repoPath(posix.join(root, modulePath)), filePaths, rest === "");
    if (hit) return { path: hit, confidence: "exact" };
  }
  return null;
}
