// PHP language module for the SP10 application graph (spec §2.3), Laravel and Symfony. extractFile
// walks one parsed tree (web-tree-sitter, see ../parser.mjs) and emits the per-file Extract described
// in ./javascript.mjs: functions, calls (+ the receiver hints resolve.mjs needs, spec §1.4), imports,
// exports, classes, namespace, routes, and surface-pattern sources / sinks.
//
// PHP specifics:
//   functions  `function_definition` -> "function" (nested: `<outer>.<name>`); `method_declaration` ->
//              "method" (`<Class>.<name>`; in an anonymous class `<enclosing>.<anon>@<line>:<col>.<name>`
//              with a null class); a closure -> "lambda", `fn () =>` -> "arrow", both `<anon>` named
//              `<enclosing>.<anon>@<line>:<col>` with `class_start_byte` (a non-static closure binds
//              `$this` lexically) — except a Laravel route handler, named by its bare label (its
//              handler_text). exported = every top-level function / type and the public (default)
//              methods of a named type. `param_count` is null with a variadic or a default value.
//   classes    class / interface / trait / enum declarations; `extends` is the base name of the first
//              parent (`\Base\P` -> `P`); `implements` and a `use SomeTrait;` are only noted.
//   exports    every top-level class / interface / trait / enum / function. namespace = the first
//              `namespace A\B;` declaration.
//   imports    `use A\B\C;` -> named binding C of "A\B\C" (`as Z` -> local Z; a grouped `use X\{A, B}`
//              -> one entry per name); `use function` / `use const` are only noted. `require` /
//              `include` (and the `_once` forms) of a string literal, or of `__DIR__ . '<literal>'`,
//              is an import of the literal (a file dependency, resolved relative to the including
//              file's directory) and never a sink; any other argument is an `include` sink.
//              resolveImportSpecifier maps a class name through composer.json's PSR-4 map (longest
//              prefix first), else to the file `<C>.php` declaring namespace `A\B` (`namespaces`).
//   calls      `lang.callableLocals: false` (a bare `foo()` always names a function) and
//              `lang.implicitThisCalls: false`: every call has `scope_names: []`. `->` and `::` read as
//              `.`; a qualified callee / class reads as its last `\` segment. Receivers: `$this->m()`,
//              `self::m()`, `static::m()` -> "this"; `parent::m()` -> none; `$this->p->m()` -> the class
//              of property p (a typed property, a promoted constructor parameter, else the class every
//              `$this->p = new C()` in the class constructs); `$x->m()` -> the class of $x (a typed
//              parameter or `$x = new C()` in the function, or outward through closures / arrows up to
//              the nearest named function, else at module level); `X::m()` -> X; `(new C)->m()` -> C;
//              `?T` / `T|null` reduce to the first class named. A variable call (`$cb()`,
//              `$o->$m()`, `call_user_func(...)`) is no call entry, only noted.
//   sinks      as in Java, a call whose receiver has a known class T is also matched as `T.<method>`
//              (`DB $db; $db->select()` -> `DB::select`); the sink's callee keeps the source text.
//   routes     Laravel: `Route::get|post|put|patch|delete|options|any|match(path, handler)` (`any` /
//              `match` -> ANY); handler `[X::class, 'm']` / `'X@m'` -> `X.m`, `X::class` -> `X.__invoke`,
//              a closure -> its `<anon>@l:c`; chained `->middleware(...)` names are the middleware texts;
//              `Route::middleware / prefix / controller(...)->group(fn)` and `Route::group([...], fn)`
//              prepend their middleware and prefix to every route in the closure (groups nest; a
//              controller group names the class of a bare `'m'` handler); `Route::resource /
//              apiResource` are only noted. Symfony: `#[Route(path, methods: [...])]` on a method,
//              prefixed by the class's `#[Route]`; one method -> that verb, none / several -> ANY; the
//              class's then the method's `#[IsGranted]` / `#[Security]` are the middleware texts.
//
// Same TreeCursor walk as the JavaScript module (see its header for why not tree-sitter queries).
// PURE: no I/O. `sourceText` is never copied into the output — only identifier / literal text.
import { posix } from "node:path";
import { normalizeToken } from "../surface.mjs";
import {
  lookup, field, namedOf, childrenOfType, lineOf, anonLabel, byStart, matchEmitter, walk, receiverClass, repoPath,
  newFrame, NO_FRAME, bind, innermostFunction, innermostClass, enclosingName
} from "./common.mjs";

export const lang = { id: "php", stack: "php", langIds: ["php"], frameworks: ["laravel", "symfony"], implicitThisCalls: false, submoduleImports: false, callableLocals: false, overloads: false };

// ---- node-type tables -----------------------------------------------------------------------------

const MEMBER_CALLS = new Set(["member_call_expression", "nullsafe_member_call_expression"]);
const MEMBER_ACCESSES = new Set(["member_access_expression", "nullsafe_member_access_expression"]);
const CLOSURES = new Set(["anonymous_function_creation_expression", "arrow_function"]);
const PARAMETERS = new Set(["simple_parameter", "variadic_parameter", "property_promotion_parameter"]);
// A variable in one of these parents declares a name (or captures one): it is not a reference.
const NON_REFERENCE_VARIABLE_PARENTS = new Set([...PARAMETERS, "property_element", "anonymous_function_use_clause"]);
const VARIABLE_CALLEES = new Set(["call_user_func", "call_user_func_array"]);
const INCLUDES = { require_expression: "require", require_once_expression: "require_once", include_expression: "include", include_once_expression: "include_once" };

const LARAVEL_VERBS = { get: "GET", post: "POST", put: "PUT", patch: "PATCH", delete: "DELETE", options: "OPTIONS", any: "ANY", match: "ANY" };
const LARAVEL_RESOURCES = new Set(["resource", "apiResource"]);
const SYMFONY_AUTH = new Set(["IsGranted", "Security"]);
const HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const SOURCE_KINDS = {
  $_GET: "query", "$request.query": "query", "$request.query.get": "query",
  $_POST: "body", $_REQUEST: "body", "php://input": "body", "$request.input": "body", "$request.all": "body", "$request.request.get": "body",
  $_COOKIE: "cookie", $_FILES: "file",
  $_SERVER: "header", getallheaders: "header", "$request.headers.get": "header"
};

// ---- small AST helpers ----------------------------------------------------------------------------

// The last `\` segment of a (qualified) name: `\App\Services\Runner` -> `Runner`.
const baseName = (text) => text.slice(text.lastIndexOf("\\") + 1);
const isName = (node) => node?.type === "name" || node?.type === "qualified_name";
const unwrap = (node) => (node?.type === "parenthesized_expression" ? unwrap(namedOf(node)[0]) : node);
const hasKeyword = (node, ...keywords) => node.children.some((c) => keywords.includes(c.type));

// The content of a string literal without interpolation (escape sequences kept as written); null for
// anything else.
function stringValue(node) {
  if (node?.type !== "string" && node?.type !== "encapsed_string") return null;
  const parts = namedOf(node);
  return parts.every((p) => p.type === "string_content" || p.type === "escape_sequence") ? parts.map((p) => p.text).join("") : null;
}

// The class a type names: its base name; `?T` and `T|null` reduce to the first class in them.
function typeClass(node) {
  switch (node?.type) {
    case "named_type": {
      const name = namedOf(node)[0];
      return isName(name) ? baseName(name.text) : null;
    }
    case "optional_type":
      return typeClass(namedOf(node)[0]);
    case "union_type":
      return namedOf(node).map(typeClass).find(Boolean) ?? null;
    default:
      return null; // primitive, intersection and other types
  }
}

// The class `new C(...)` constructs (null for `new $x` / an anonymous class).
const newClass = (node) => {
  const name = namedOf(node)[0];
  return isName(name) ? baseName(name.text) : null;
};
// `X::class` (or a class-name string) -> X.
function classRef(node) {
  if (node?.type === "class_constant_access_expression") {
    const [scope, member] = namedOf(node);
    return isName(scope) && member?.text === "class" ? baseName(scope.text) : null;
  }
  const text = stringValue(node);
  return text ? baseName(text) : null;
}

// Call / attribute arguments as [{ name (a named argument's), value }]; spread marks `...$a`.
const argumentsOf = (node) => namedOf(node).map((a) => ({ name: field(a, "name")?.text ?? null, value: namedOf(a).at(-1) ?? null, type: a.type }));
// Array entries as [{ key: string | null, value }].
const arrayEntries = (node) =>
  node?.type !== "array_creation_expression" ? [] : childrenOfType(node, "array_element_initializer").map((e) => {
    const parts = namedOf(e);
    return parts.length === 2 ? { key: stringValue(parts[0]), value: parts[1] } : { key: null, value: parts[0] ?? null };
  });
// A string or an array of strings (Symfony `methods:`, Laravel middleware names) as a list.
const stringList = (node) => (node?.type === "array_creation_expression" ? arrayEntries(node).map((e) => e.value) : [node]).map(stringValue).filter((s) => s !== null);

const attributesOf = (node) => childrenOfType(field(node, "attributes"), "attribute_group").flatMap((g) => childrenOfType(g, "attribute"));
const attributeName = (attribute) => {
  const name = namedOf(attribute)[0];
  return isName(name) ? baseName(name.text) : null;
};
const isPublic = (node) => {
  const visibility = childrenOfType(node, "visibility_modifier")[0];
  return !visibility || visibility.text === "public";
};

// Callee text with call arguments dropped (`$a->b(x)->c` -> `$a.b.c`); qualified names by their last
// segment; `(new C)` reads as `C`.
function render(node) {
  switch (node.type) {
    case "name":
    case "qualified_name":
      return baseName(node.text);
    case "member_call_expression":
    case "nullsafe_member_call_expression":
    case "member_access_expression":
    case "nullsafe_member_access_expression": {
      const object = field(node, "object");
      const name = field(node, "name");
      return object && name ? `${render(object)}.${name.text}` : node.text;
    }
    case "scoped_call_expression":
    case "scoped_property_access_expression": {
      const scope = field(node, "scope");
      const name = field(node, "name");
      return scope && name ? `${render(scope)}.${name.text}` : node.text;
    }
    case "class_constant_access_expression": {
      const [scope, member] = namedOf(node);
      return scope && member ? `${render(scope)}.${member.text}` : node.text;
    }
    case "function_call_expression": {
      const fn = field(node, "function");
      return fn ? render(fn) : node.text;
    }
    case "object_creation_expression":
      return newClass(node) ?? node.text;
    case "parenthesized_expression": {
      const inner = namedOf(node)[0];
      return inner ? render(inner) : node.text;
    }
    default:
      return node.text;
  }
}
const textOf = (node) => normalizeToken(render(node));

// ---- state ----------------------------------------------------------------------------------------

// Scopes, innermost last: a function (`fn: true`, with a frame of `bindings` / `classOf` for its
// variables, see common.mjs receiverClass; `barrier` for a named function / method, whose variables
// are its own) or a class body (`cls`, with its properties' classes). Module-level variables live in
// `moduleFrame`. innermostFunction / innermostClass / enclosingName: see common.mjs.

function newState(path, surface) {
  return {
    moduleName: path.split("/").at(-1).replace(/\.[^.]*$/, ""),
    surface: { sources: surface?.sources ?? [], sinks: surface?.sinks ?? [] },
    functions: [], calls: [], imports: [], exports: [], classes: [], routes: [], sources: [], sinks: [],
    notExtracted: new Set(),
    namespace: null,
    scopes: [],
    moduleFrame: newFrame(),
    groups: [], // enclosing Laravel route groups: { middleware, prefix, controller }
    anonNames: new Map() // closure start byte -> its route-handler label
  };
}

// Where an assignment binds: the innermost function's frame, the module frame at top level, nowhere
// directly in a class body.
const currentFrame = (st) => (st.scopes.length === 0 ? st.moduleFrame : st.scopes.at(-1).frame ?? null);

// The class of variable `name`: the innermost frame binding it, looking outward through closures /
// arrows up to (and including) the nearest named function or method; the module frame only when no
// function or class encloses the code.
function variableClass(name, st) {
  const frames = [];
  let moduleFrame = st.moduleFrame;
  for (let i = st.scopes.length - 1; i >= 0; i--) {
    const scope = st.scopes[i];
    if (!scope.fn || scope.barrier) moduleFrame = NO_FRAME;
    if (scope.cls) break;
    frames.unshift(scope.frame);
    if (scope.barrier) break;
  }
  return receiverClass(name, frames, moduleFrame);
}

// ---- sources and sinks ----------------------------------------------------------------------------

const sourceKind = (pattern) => lookup(SOURCE_KINDS, pattern.normalized) ?? "body";

const emitMatches = matchEmitter("php", sourceKind); // see common.mjs

// onVariable receives the TreeCursor rather than a Node (see javascript.mjs); `$_GET['x']` matches
// through its variable.
function onVariable(cursor, st, ctx) {
  if (NON_REFERENCE_VARIABLE_PARENTS.has(ctx.parentType)) return;
  emitMatches(cursor, [{ category: "identifier", text: cursor.nodeText }], st, { sources: true, sinks: true });
}

function onString(node, st) {
  const value = stringValue(node);
  if (value !== null) emitMatches(node, [{ category: "literal", text: normalizeToken(value) }], st, { sources: true, sinks: true });
}

// `X::CONST`, `X::class`, `X::$p`.
function onClassReference(node, st) {
  emitMatches(node, [{ category: "identifier", text: textOf(node) }], st, { sources: true, sinks: true });
}

function onAttribute(node, st) {
  const name = attributeName(node);
  if (name) emitMatches(node, [{ category: "decorator", text: name }], st, { sources: true, sinks: true });
}

function onNew(node, st) {
  const name = namedOf(node)[0];
  if (isName(name)) emitMatches(node, [{ category: "new", text: baseName(name.text) }], st, { sinks: true, sinkAt: name });
}

// ---- classes --------------------------------------------------------------------------------------

// Property name -> class: typed properties and promoted constructor parameters, else (untyped) the
// class every `$this->p = new C()` in the body constructs (null when they disagree).
function propertyClasses(body) {
  const declared = new Map();
  for (const member of namedOf(body)) {
    if (member.type === "property_declaration") {
      const cls = typeClass(field(member, "type"));
      for (const element of childrenOfType(member, "property_element")) {
        const variable = childrenOfType(element, "variable_name")[0];
        if (variable) declared.set(variable.text.slice(1), cls);
      }
    } else if (member.type === "method_declaration" && field(member, "name")?.text === "__construct") {
      for (const param of childrenOfType(field(member, "parameters"), "property_promotion_parameter")) {
        const variable = field(param, "name");
        if (variable) declared.set(variable.text.slice(1), typeClass(field(param, "type")));
      }
    }
  }
  const assigned = new Map();
  for (const assignment of body ? body.descendantsOfType("assignment_expression") : []) {
    const property = thisProperty(field(assignment, "left"));
    if (!property) continue;
    const right = unwrap(field(assignment, "right"));
    const cls = right?.type === "object_creation_expression" ? newClass(right) : null;
    assigned.set(property, assigned.has(property) && assigned.get(property) !== cls ? null : cls);
  }
  const classes = new Map([...assigned].filter(([p]) => !declared.get(p)));
  for (const [property, cls] of declared) if (cls) classes.set(property, cls);
  return classes;
}

// `$this->p` -> "p"; null for anything else.
function thisProperty(node) {
  if (!MEMBER_ACCESSES.has(node?.type)) return null;
  const name = field(node, "name");
  return field(node, "object")?.text === "$this" && name?.type === "name" ? name.text : null;
}

function onType(node, st) {
  const name = field(node, "name")?.text ?? null;
  const body = field(node, "body");
  const topLevel = st.scopes.length === 0;
  if (name) {
    const parent = namedOf(childrenOfType(node, "base_clause")[0])[0];
    const methods = [...new Set(childrenOfType(body, "method_declaration").map((m) => field(m, "name")?.text).filter(Boolean))];
    st.classes.push({ name, extends: isName(parent) ? baseName(parent.text) : null, methods, start_byte: node.startIndex });
    if (topLevel) st.exports.push({ name, start_byte: node.startIndex });
  }
  if (childrenOfType(node, "class_interface_clause").length) st.notExtracted.add("implements clause");
  const attributes = attributesOf(node);
  const route = attributes.find((a) => attributeName(a) === "Route");
  const prefix = route ? routePath(route) : "";
  if (prefix === null) st.notExtracted.add("route(non-literal path)");
  st.scopes.push({
    frame: null,
    cls: {
      name,
      start: node.startIndex,
      qualifiedName: name ?? `${enclosingName(st)}.${anonLabel(node)}`,
      exported: topLevel,
      isInterface: node.type === "interface_declaration",
      properties: propertyClasses(body),
      prefix: prefix ?? "",
      auth: attributes.map(attributeName).filter((n) => SYMFONY_AUTH.has(n))
    }
  });
  return () => st.scopes.pop();
}

// The body of an anonymous class (`new class {...}`): a class without a name.
function onClassBody(node, st, ctx) {
  if (ctx.parentType !== "object_creation_expression") return;
  st.notExtracted.add("anonymous class");
  const cls = { name: null, start: node.startIndex, qualifiedName: `${enclosingName(st)}.${anonLabel(node.parent)}`, exported: false, isInterface: false, properties: propertyClasses(node), prefix: "", auth: [] };
  st.scopes.push({ frame: null, cls });
  return () => st.scopes.pop();
}

// ---- functions ------------------------------------------------------------------------------------

const parametersOf = (node) => namedOf(field(node, "parameters")).filter((p) => PARAMETERS.has(p.type));
// Declared parameters; null with a variadic parameter or a default value.
function parameterCount(node) {
  const params = parametersOf(node);
  return params.some((p) => p.type === "variadic_parameter" || field(p, "default_value")) ? null : params.length;
}

function onFunction(node, st) {
  const owner = st.scopes.at(-1)?.cls ?? null;
  let fn;
  if (node.type === "method_declaration") {
    const name = field(node, "name")?.text ?? "<anon>";
    const exported = Boolean(owner?.name && owner.exported && (owner.isInterface || isPublic(node)));
    fn = { name, qualified_name: `${owner?.qualifiedName ?? st.moduleName}.${name}`, kind: "method", exported, class: owner?.name ?? null };
  } else if (node.type === "function_definition") {
    const name = field(node, "name")?.text ?? "<anon>";
    const outer = innermostFunction(st);
    fn = { name, qualified_name: outer ? `${outer.qualifiedName}.${name}` : name, kind: "function", exported: st.scopes.length === 0, class: null };
    if (fn.exported) st.exports.push({ name, start_byte: node.startIndex });
  } else {
    const label = st.anonNames.get(node.startIndex);
    const kind = node.type === "arrow_function" ? "arrow" : "lambda";
    fn = { name: "<anon>", qualified_name: label ?? `${enclosingName(st)}.${anonLabel(node)}`, kind, exported: false, class: null, classStart: innermostClass(st)?.start ?? null };
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
    // a closure's lexical class body: resolve.mjs inherits a containing method's class only within it
    ...(CLOSURES.has(node.type) ? { class_start_byte: fn.classStart } : {})
  });
  if (node.type === "method_declaration" && owner?.name) symfonyRoutes(node, owner, fn.qualified_name, st);
  const frame = newFrame(node.startIndex, fn.qualified_name);
  for (const param of parametersOf(node)) bind(frame, field(param, "name")?.text, param.type === "variadic_parameter" ? null : typeClass(field(param, "type")));
  st.scopes.push({ frame, fn: true, barrier: !CLOSURES.has(node.type) });
  return () => st.scopes.pop();
}

// `$x = ...` binds $x once the right-hand side has been walked: to C for `new C(...)`, else to no class.
function onAssignment(node, st) {
  const left = field(node, "left");
  if (left?.type !== "variable_name") return;
  const right = unwrap(field(node, "right"));
  const cls = right?.type === "object_creation_expression" ? newClass(right) : null;
  const frame = currentFrame(st);
  return () => bind(frame, left.text, cls);
}

// ---- routes ---------------------------------------------------------------------------------------

const joinPath = (parts) => ("/" + parts.join("/")).replace(/\/{2,}/g, "/");
// Laravel trims a URI's trailing slash.
const laravelPath = (parts) => joinPath(parts).replace(/(.)\/$/, "$1");

// A Laravel chain `Route::a(...)->b(...)...` as its links [{ name, args }] from `Route::a` outwards;
// null when the chain does not start at the Route facade.
function routeChain(node) {
  const links = [];
  let current = node;
  while (MEMBER_CALLS.has(current?.type)) {
    links.unshift({ name: field(current, "name")?.text, args: argumentsOf(field(current, "arguments")) });
    current = field(current, "object");
  }
  const scope = field(current, "scope");
  if (current?.type !== "scoped_call_expression" || !isName(scope) || baseName(scope.text) !== "Route") return null;
  links.unshift({ name: field(current, "name")?.text, args: argumentsOf(field(current, "arguments")) });
  return links;
}

// The middleware names / prefixes / controller a run of chain links sets (`group([...])` options too).
function routeAttributes(links) {
  const attrs = { middleware: [], prefix: [], controller: null };
  const set = (key, value) => {
    if (key === "middleware") attrs.middleware.push(...(value?.type === "class_constant_access_expression" ? [classRef(value)].filter(Boolean) : stringList(value)));
    else if (key === "prefix") attrs.prefix.push(...[stringValue(value)].filter((p) => p !== null));
    else if (key === "controller") attrs.controller = classRef(value) ?? attrs.controller;
  };
  for (const { name, args } of links) {
    if (name === "group") for (const { key, value } of arrayEntries(args[0]?.value)) set(key, value);
    else if (name === "middleware") for (const { value } of args) set(name, value);
    else set(name, args[0]?.value);
  }
  return attrs;
}

// A Laravel handler argument as its handler text (null when it names none).
function routeHandler(node, controller, st) {
  const value = unwrap(node);
  if (CLOSURES.has(value?.type)) {
    const label = anonLabel(value);
    st.anonNames.set(value.startIndex, label);
    return label;
  }
  if (value?.type === "array_creation_expression") {
    const [cls, method] = arrayEntries(value).map((e) => e.value);
    const name = stringValue(method);
    return classRef(cls) && name ? `${classRef(cls)}.${name}` : null;
  }
  if (value?.type === "class_constant_access_expression") return classRef(value) && `${classRef(value)}.__invoke`;
  const text = stringValue(value);
  if (!text) return null;
  if (text.includes("@")) return `${baseName(text.slice(0, text.indexOf("@")))}.${text.slice(text.indexOf("@") + 1)}`;
  return controller ? `${controller}.${text}` : `${baseName(text)}.__invoke`;
}

// The outermost call of a `Route::...` chain: a route, a group (whose closure the returned exit
// callback scopes), a noted resource route, or nothing (`Route::view`, `Route::redirect`, ...).
function laravelChain(node, st) {
  const links = routeChain(node);
  if (!links) return;
  if (links.some((l) => LARAVEL_RESOURCES.has(l.name))) return void st.notExtracted.add("resource route");
  const verbAt = links.findIndex((l) => Object.hasOwn(LARAVEL_VERBS, l.name));
  if (verbAt !== -1) return void laravelRoute(node, links, verbAt, st);
  const groupAt = links.findIndex((l) => l.name === "group");
  if (groupAt === -1) return;
  if (!links[groupAt].args.some((a) => CLOSURES.has(a.value?.type))) return void st.notExtracted.add("route group(non-closure)");
  st.groups.push(routeAttributes(links.slice(0, groupAt + 1)));
  return () => st.groups.pop();
}

function laravelRoute(node, links, verbAt, st) {
  const verb = links[verbAt];
  const pathAt = verb.name === "match" ? 1 : 0;
  const path = stringValue(verb.args[pathAt]?.value);
  if (path === null) return void st.notExtracted.add("route(non-literal path)");
  const groups = [...st.groups, routeAttributes(links.slice(0, verbAt))];
  const controller = groups.findLast((g) => g.controller)?.controller ?? null;
  const handler = verb.args[pathAt + 1] ? routeHandler(verb.args[pathAt + 1].value, controller, st) : null;
  if (!handler) return void st.notExtracted.add("route(non-literal handler)");
  st.routes.push({
    line: lineOf(node),
    start_byte: node.startIndex,
    http_method: LARAVEL_VERBS[verb.name],
    path_pattern: laravelPath([...groups.flatMap((g) => g.prefix), path]),
    handler_text: handler,
    middleware_texts: [...groups.flatMap((g) => g.middleware), ...routeAttributes(links.slice(verbAt + 1)).middleware],
    framework: "laravel"
  });
}

// A `#[Route]`'s literal path (`path:` or the first positional argument; "" when absent); null when
// not a string literal.
function routePath(attribute) {
  const args = argumentsOf(field(attribute, "parameters"));
  const arg = args.find((a) => a.name === "path") ?? args.find((a) => a.name === null);
  return arg ? stringValue(arg.value) : "";
}

function routeMethod(attribute) {
  const arg = argumentsOf(field(attribute, "parameters")).find((a) => a.name === "methods");
  const methods = arg ? stringList(arg.value).map((m) => m.toUpperCase()) : [];
  return methods.length === 1 && HTTP_METHODS.has(methods[0]) ? methods[0] : "ANY";
}

function symfonyRoutes(node, owner, qualifiedName, st) {
  const attributes = attributesOf(node);
  const auth = [...owner.auth, ...attributes.map(attributeName).filter((n) => SYMFONY_AUTH.has(n))];
  for (const attribute of attributes) {
    if (attributeName(attribute) !== "Route") continue;
    const path = routePath(attribute);
    if (path === null) {
      st.notExtracted.add("route(non-literal path)");
      continue;
    }
    st.routes.push({
      line: lineOf(attribute),
      start_byte: attribute.startIndex,
      http_method: routeMethod(attribute),
      path_pattern: joinPath([owner.prefix, path]),
      handler_text: qualifiedName,
      middleware_texts: auth,
      framework: "symfony"
    });
  }
}

// ---- calls ----------------------------------------------------------------------------------------

const NO_RECEIVER = { receiver: null, receiverClass: null };

function memberReceiver(node, st) {
  const object = unwrap(node);
  switch (object?.type) {
    case "variable_name":
      return object.text === "$this" ? { receiver: "this", receiverClass: null } : { receiver: null, receiverClass: variableClass(object.text, st) };
    case "member_access_expression":
    case "nullsafe_member_access_expression": {
      const property = thisProperty(object);
      return { receiver: null, receiverClass: property ? innermostClass(st)?.properties.get(property) ?? null : null };
    }
    case "object_creation_expression":
      return { receiver: null, receiverClass: newClass(object) };
    default:
      return NO_RECEIVER; // deeper chains, any other expression
  }
}

function scopedReceiver(scope) {
  if (scope?.type === "relative_scope") return scope.text === "parent" ? NO_RECEIVER : { receiver: "this", receiverClass: null };
  return isName(scope) ? { receiver: null, receiverClass: baseName(scope.text) } : NO_RECEIVER;
}

// Arguments; null with a spread (`...$a`) or a first-class callable (`f(...)`).
function argCount(args) {
  const items = argumentsOf(args);
  return items.some((a) => a.type === "variadic_placeholder" || a.value?.type === "variadic_unpacking") ? null : items.filter((a) => a.type === "argument").length;
}

function pushCall(node, anchor, { receiver, receiverClass: cls }, st) {
  const calleeText = textOf(node);
  st.calls.push({
    line: lineOf(anchor),
    start_byte: anchor.startIndex,
    callee_text: calleeText,
    arg_count: argCount(field(node, "arguments")),
    enclosing_start_byte: innermostFunction(st)?.startIndex ?? null,
    receiver,
    receiver_class: cls,
    scope_names: []
  });
  const candidates = [{ category: "call", text: calleeText }];
  if (cls) candidates.push({ category: "call", text: `${cls}.${anchor.text}` });
  emitMatches(node, candidates, st, { sources: true, sinks: true, sinkAt: anchor });
}

const noteVariableCall = (st) => void st.notExtracted.add("variable call");

function onFunctionCall(node, st) {
  const fn = field(node, "function");
  if (!isName(fn) || VARIABLE_CALLEES.has(baseName(fn.text))) return noteVariableCall(st);
  pushCall(node, fn, NO_RECEIVER, st);
}

// A member / static call; the outermost call of a chain is also checked for a Laravel route.
function onChainCall(node, st, ctx) {
  const name = field(node, "name");
  if (name?.type !== "name") return noteVariableCall(st);
  const hints = node.type === "scoped_call_expression" ? scopedReceiver(field(node, "scope")) : memberReceiver(field(node, "object"), st);
  pushCall(node, name, hints, st);
  if (!(MEMBER_CALLS.has(ctx.parentType) && ctx.field === "object")) return laravelChain(node, st);
}

// ---- imports --------------------------------------------------------------------------------------

function pushUse(st, line, specifier, alias) {
  const imported = baseName(specifier);
  st.imports.push({ line, specifier, bindings: [{ imported, local: alias ?? imported }], local: null });
}
const aliasOf = (clause) => namedOf(childrenOfType(clause, "namespace_aliasing_clause")[0])[0]?.text ?? null;
const clauseName = (clause) => namedOf(clause).find((c) => isName(c) || c.type === "namespace_name")?.text.replace(/^\\/, "") ?? null;

function onUse(node, st) {
  const line = lineOf(node);
  if (hasKeyword(node, "function", "const")) return void st.notExtracted.add("use function/const");
  const group = childrenOfType(node, "namespace_use_group")[0];
  const prefix = group ? childrenOfType(node, "namespace_name")[0]?.text.replace(/^\\/, "") ?? "" : null;
  for (const clause of group ? childrenOfType(group, "namespace_use_group_clause") : childrenOfType(node, "namespace_use_clause")) {
    if (hasKeyword(clause, "function", "const")) {
      st.notExtracted.add("use function/const");
      continue;
    }
    const name = clauseName(clause);
    if (name) pushUse(st, line, prefix ? `${prefix}\\${name}` : name, aliasOf(clause));
  }
}

// `require 'x.php'` / `require __DIR__ . '/x.php'` -> the literal; null for any other argument.
function includeSpecifier(arg) {
  const literal = stringValue(arg);
  if (literal !== null) return literal;
  const left = field(arg, "left");
  if (arg?.type !== "binary_expression" || field(arg, "operator")?.type !== "." || left?.type !== "name" || left.text !== "__DIR__") return null;
  return stringValue(unwrap(field(arg, "right")));
}

function onInclude(node, st) {
  const specifier = includeSpecifier(unwrap(namedOf(node)[0]));
  if (specifier !== null) return void st.imports.push({ line: lineOf(node), specifier, bindings: [], local: null });
  st.notExtracted.add("dynamic include");
  emitMatches(node, [{ category: "call", text: INCLUDES[node.type] }], st, { sinks: true });
}

function onNamespace(node, st) {
  st.namespace ??= field(node, "name")?.text.replace(/^\\/, "") ?? null;
}

// ---- walk -----------------------------------------------------------------------------------------

const HANDLERS = new Map([
  ["class_declaration", onType],
  ["interface_declaration", onType],
  ["trait_declaration", onType],
  ["enum_declaration", onType],
  ["declaration_list", onClassBody],
  ["use_declaration", (node, st) => void st.notExtracted.add("trait use")],
  ["function_definition", onFunction],
  ["method_declaration", onFunction],
  ["anonymous_function_creation_expression", onFunction],
  ["arrow_function", onFunction],
  ["assignment_expression", onAssignment],
  ["function_call_expression", onFunctionCall],
  ["member_call_expression", onChainCall],
  ["nullsafe_member_call_expression", onChainCall],
  ["scoped_call_expression", onChainCall],
  ["object_creation_expression", onNew],
  ["attribute", onAttribute],
  ["string", onString],
  ["encapsed_string", onString],
  ["class_constant_access_expression", onClassReference],
  ["scoped_property_access_expression", onClassReference],
  ["namespace_use_declaration", onUse],
  ["namespace_definition", onNamespace],
  ...Object.keys(INCLUDES).map((type) => [type, onInclude])
]);
const CURSOR_HANDLERS = new Map([["variable_name", onVariable]]);

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

// A file specifier (from require / include) has a `/` or an extension; anything else is a class name.
const isFileSpecifier = (specifier) => specifier.includes("/") || /\.[A-Za-z0-9]+$/.test(specifier);

// The PSR-4 candidate paths of class `A\B\C` from composer.json's `autoload.psr-4` map, longest
// matching prefix first (a prefix maps to one directory or a list of them).
function psr4Paths(specifier, composerJson) {
  const map = composerJson?.autoload?.["psr-4"];
  if (!map || typeof map !== "object") return [];
  const prefixes = Object.keys(map).filter((p) => specifier.startsWith(p)).sort((a, b) => b.length - a.length);
  return prefixes.flatMap((prefix) => {
    const rest = `${specifier.slice(prefix.length).split("\\").join("/")}.php`;
    return [map[prefix]].flat().filter((dir) => typeof dir === "string").map((dir) => repoPath(posix.join(dir, rest)));
  });
}

// A class name `A\B\C` -> its PSR-4 file when parsed, else the file C.php declaring namespace A\B
// (`namespaces`: path -> Extract.namespace; several: the first by path, "heuristic"). A file
// specifier -> the path relative to the including file's directory, when parsed. Otherwise null.
export function resolveImportSpecifier({ specifier, fromPath, filePaths, configs, namespaces }) {
  if (typeof specifier !== "string" || specifier === "") return null;
  if (isFileSpecifier(specifier)) {
    const path = repoPath(posix.join(posix.dirname(fromPath ?? ""), specifier));
    return path && filePaths.has(path) ? { path, confidence: "exact" } : null;
  }
  const psr4 = psr4Paths(specifier, configs?.composerJson).find((p) => p && filePaths.has(p));
  if (psr4) return { path: psr4, confidence: "exact" };
  const cut = specifier.lastIndexOf("\\");
  const namespace = cut === -1 ? null : specifier.slice(0, cut);
  const fileName = `${specifier.slice(cut + 1)}.php`;
  const matches = [...filePaths].filter((p) => posix.basename(p) === fileName && (namespaces?.get(p) ?? null) === namespace).sort();
  return matches.length ? { path: matches[0], confidence: matches.length === 1 ? "exact" : "heuristic" } : null;
}
