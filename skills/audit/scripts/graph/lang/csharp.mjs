// C# language module for the SP10 application graph (spec §2.3), ASP.NET Core and classic ASP.NET.
// extractFile walks one parsed tree (web-tree-sitter, see ../parser.mjs) and emits the per-file
// Extract described in ./javascript.mjs: functions, calls (+ the receiver hints resolve.mjs needs,
// spec §1.4), imports, exports, classes, namespace, routes, and surface-pattern sources / sinks.
//
// C# specifics:
//   functions  `method_declaration` / constructors -> "method" (`<Class>.<name>`, a constructor is
//              named after its class; overloads differ by start_byte; expression-bodied members too);
//              a local function -> "function" (`<outer>.<name>`) whose class is the enclosing type's
//              (it captures `this`: resolve.mjs's same-class steps apply inside it); a lambda or an anonymous method
//              (`delegate { }`) -> "lambda", named by the local it initialises (`Action a = () => ...`
//              -> `<enclosing>.a`), by its bare `<anon>@<line>:<col>` label when it is a minimal-API
//              route handler (the route's handler_text), else `<enclosing>.<anon>@<line>:<col>`; a
//              lambda carries `class_start_byte` (its innermost class body) for resolve.mjs's
//              lexical-this walk. Property / indexer bodies are no functions (noted). exported = every
//              enclosing type and the method are public (interface members are implicitly public).
//              `param_count` is null with a `params` array or an optional parameter;
//              `lang.overloads: true` lets resolve.mjs pick overloads by arity.
//   classes    class / struct / record / interface / enum declarations, nested ones by their simple
//              name; `extends` is the first base type's base name unless it looks like an interface
//              (`I[A-Z]...`); every other base is only noted ("implements clause").
//   exports    every public top-level (namespace-level) type. namespace = the first `namespace X.Y;` /
//              `namespace X.Y { }` declaration, deepened by blocks nested in it (`namespace A {
//              namespace B { } }` -> "A.B"); a sibling declaration is noted.
//   imports    `using X.Y;` / `global using X.Y;` -> "X.Y" binding nothing (a file-level dependency:
//              class references resolve through resolve.mjs's unique-class-name rule);
//              `using static X.Y.Z;` the same, noted; `using A = X.Y.Z;` -> named binding Z, local A.
//              resolveImportSpecifier maps "X.Y.Z" to the file Z.cs declaring namespace X.Y (exact),
//              else "X.Y" to the first file (by path) declaring namespace X.Y (heuristic).
//   calls      `lang.callableLocals: false`: methods and variables are separate namespaces, so every
//              call has `scope_names: []`; `lang.implicitThisCalls: true`: a bare `M()` is left to the
//              resolver's same-class step. Receivers: `this.M()` -> "this"; `x.M()` / `x?.M()` -> the
//              declared type of x (the innermost local / parameter / loop / catch / lambda variable,
//              a top-level-statement local outside any type, else a field / property / record
//              parameter of an enclosing type, else x itself when it is capitalised: a static call);
//              `this.f.M()` -> the declared type of field f; `new C().M()` -> C; `base.M()` and deeper
//              chains -> none; generics, nullables and qualifiers reduce to the base name, arrays to
//              none. Attribute arguments and `nameof(...)` are never calls; a computed callee
//              (`f()()`, `(f)()`) is no call entry, only noted. A nested type body is a barrier:
//              code in its field initializers has no enclosing function (`enclosing_start_byte: null`).
//   sinks      as in Java, a call whose receiver has a known class T is also matched as `T.<method>`
//              (`Process p; p.Start()` -> `Process.Start`); the sink's callee keeps the source text.
//   sinks      also the member name assigned to (`psi.UseShellExecute = true`, read as the identifier
//              `UseShellExecute` like the object-initializer form).
//   sources    member-access chains and call callees, each matched through every suffix sub-chain
//              (`HttpContext.Request.Form["x"]` -> `Request.Form`; at most one source per chain),
//              attributes on a parameter or a method (`[FromBody]`), identifiers and string literals.
//   routes     attribute routing, one route per template (see actionRoutes): `[HttpGet]` / `[HttpPost]` /
//              `[HttpPut]` / `[HttpDelete]` / `[HttpPatch]` / `[HttpHead]` / `[HttpOptions]` (optionally
//              with a template; a template-less verb takes the method's `[Route]` template), a method
//              `[Route("x")]` (the action's one verb, else ANY), and in a type with a literal `[Route]`
//              every public, non-static, non-`[NonAction]` action without either (ANY, at the prefix);
//              each prefixed by the type's `[Route]` (a template starting with `/` or `~/` is not); the
//              `[controller]` token is the class name without its `Controller` suffix, `[action]` the
//              method name; the class's then the method's `[Authorize]` / `[AllowAnonymous]` are the
//              middleware texts. A `...Controller` class without `[Route]` whose public action carries
//              no routing attribute is only noted ("conventional routing"); one deriving from a base
//              other than `Controller` / `ControllerBase` is noted ("inherited controller attributes":
//              the base's attributes are not read). Minimal APIs: `x.MapGet / MapPost / MapPut /
//              MapDelete / MapPatch(path, handler)`, `x.Map` / `x.MapMethods` -> ANY; a lambda handler is
//              its `<anon>@l:c` label; a method group `X.M` its text, `this.M` -> `<Class>.M`, a bare `M`
//              the local function `<enclosing>.M` (`Program.M` at top level) or method `<Class>.M` the
//              file defines, else `M`; chained `.RequireAuthorization(...)` / `.AllowAnonymous()` are
//              the middleware texts. `MapGroup` / `MapControllers` are only noted ("route group"):
//              routes inside a group keep their own path.
//
// Known grammar limits (vendored tree-sitter-c_sharp, tree-sitter-wasms 0.1.13): C# 12 class / struct
// primary constructors (`class X(Runner r) { }`) do not parse — the tree has an ERROR node there,
// noted "primary constructor", and the parameters bind nothing (record parameters do parse and bind);
// raw string literals (`"""..."""`) do not parse either.
//
// Same TreeCursor walk as the JavaScript module (see its header for why not tree-sitter queries).
// PURE: no I/O. `sourceText` is never copied into the output — only identifier / literal text.
import { posix } from "node:path";
import { normalizeToken } from "../surface.mjs";
import {
  lookup, field, namedOf, childrenOfType, lineOf, anonLabel, byStart, matchEmitter, walk, receiverClass, lastSegment,
  newFrame, NO_FRAME, bind, innermostFunction, innermostClassScope, innermostClass, enclosingName, pathsByBasename, pathsByNamespace
} from "./common.mjs";

export const lang = { id: "csharp", stack: "dotnet", langIds: ["c_sharp"], frameworks: ["aspnet"], implicitThisCalls: true, submoduleImports: false, callableLocals: false, overloads: true };

// ---- node-type tables -----------------------------------------------------------------------------

const TYPE_DECLARATIONS = ["class_declaration", "struct_declaration", "interface_declaration", "record_declaration", "record_struct_declaration", "enum_declaration"];
const LAMBDAS = new Set(["lambda_expression", "anonymous_method_expression"]);

// An identifier in a `type` field, in one of these `<parent type>.<field>` slots or under one of
// these parents names a type, a declaration, a member of a chain (the enclosing call / member access
// is the candidate), an attribute or a namespace: it is not a value reference.
const NON_REFERENCE_SLOTS = new Set([
  "member_access_expression.name", "member_binding_expression.name", "invocation_expression.function",
  "parameter.name", "parameter_list.name", "for_each_statement.left", "catch_declaration.name",
  "declaration_expression.name", "type_parameter.name", "type_parameter_constraints_clause.target", "attribute.name",
  ...[
    ...TYPE_DECLARATIONS, "enum_member_declaration", "delegate_declaration", "method_declaration", "constructor_declaration",
    "destructor_declaration", "local_function_statement", "property_declaration", "event_declaration", "namespace_declaration",
    "file_scoped_namespace_declaration"
  ].map((type) => `${type}.name`)
]);
const NON_REFERENCE_PARENTS = new Set([
  "variable_declarator", "qualified_name", "generic_name", "type_argument_list", "nullable_type", "array_type", "pointer_type",
  "base_list", "primary_constructor_base_type", "type_parameter_constraint", "using_directive", "name_equals", "name_colon",
  "explicit_interface_specifier", "alias_qualified_name", "extern_alias_directive", "labeled_statement", "goto_statement"
]);
// Attributes on these declarations are request-parameter sources (`[FromBody]`).
const SOURCE_ATTRIBUTE_OWNERS = new Set(["parameter", "method_declaration"]);

const HTTP_VERB_ATTRIBUTES = new Map([["HttpGet", "GET"], ["HttpPost", "POST"], ["HttpPut", "PUT"], ["HttpDelete", "DELETE"], ["HttpPatch", "PATCH"], ["HttpHead", "HEAD"], ["HttpOptions", "OPTIONS"]]);
const ROUTING_ATTRIBUTES = new Set([...HTTP_VERB_ATTRIBUTES.keys(), "Route", "NonAction"]);
const MVC_BASES = new Set(["Controller", "ControllerBase"]);
const AUTH_ATTRIBUTES = new Set(["Authorize", "AllowAnonymous"]);
const MINIMAL_VERBS = { MapGet: "GET", MapPost: "POST", MapPut: "PUT", MapDelete: "DELETE", MapPatch: "PATCH", Map: "ANY", MapMethods: "ANY" };
const ROUTE_GROUPS = new Set(["MapGroup", "MapControllers"]);
const CHAINED_AUTH = new Set(["RequireAuthorization", "AllowAnonymous"]);
const SOURCE_KINDS = {
  "Request.Query": "query", "Request.QueryString": "query", "Request.Params": "query", FromQuery: "query",
  "Request.Form": "body", "Request.Body": "body", FromBody: "body", FromForm: "body",
  "Request.Cookies": "cookie", "Request.Headers": "header", "Request.RouteValues": "params", FromRoute: "params"
};

// ---- small AST helpers ----------------------------------------------------------------------------

const hasModifier = (node, keyword) => childrenOfType(node, "modifier").some((m) => m.text === keyword);
const attributesOf = (node) => childrenOfType(node, "attribute_list").flatMap((list) => childrenOfType(list, "attribute"));
const sameNode = (a, b) => Boolean(a && b) && a.startIndex === b.startIndex && a.endIndex === b.endIndex;

// The dotted text of a (type) name with type arguments and `?` dropped (`System.Collections.List<X>?`
// -> `System.Collections.List`); null for predefined, array, tuple and other types.
function nameText(node) {
  switch (node?.type) {
    case "identifier":
      return node.text;
    case "qualified_name": {
      const parts = namedOf(node).map(nameText);
      return parts.length && parts.every(Boolean) ? parts.join(".") : null;
    }
    case "generic_name":
    case "nullable_type":
      return nameText(namedOf(node)[0]);
    default:
      return null;
  }
}

// `[Microsoft.AspNetCore.Mvc.HttpGetAttribute]` -> `HttpGet`.
const attributeName = (attribute) => {
  const name = nameText(field(attribute, "name"));
  return name ? lastSegment(name).replace(/(.)Attribute$/, "$1") : null;
};

// The class a declaration binds its name to: the base name of the declared type, or for `var` the
// class an initialising `new C(...)` constructs.
function declaredClass(type, value = null) {
  if (type?.type === "implicit_type") return value?.type === "object_creation_expression" ? declaredClass(field(value, "type")) : null;
  const text = nameText(type);
  return text ? lastSegment(text) : null;
}

// A variable_declaration's declarators as [{ name, value }].
const declaratorsOf = (declaration) =>
  childrenOfType(declaration, "variable_declarator").map((d) => ({
    name: childrenOfType(d, "identifier")[0]?.text ?? null,
    value: namedOf(childrenOfType(d, "equals_value_clause")[0])[0] ?? null
  }));

// An argument's expression (after any `name:`).
const argumentValues = (list) => childrenOfType(list, "argument").map((a) => namedOf(a).filter((c) => c.type !== "name_colon").at(-1) ?? null);

function stringValue(node) {
  if (node?.type === "string_literal") return node.text.slice(1, -1);
  if (node?.type === "verbatim_string_literal") return node.text.slice(2, -1);
  return null;
}

const memberName = (name) => (name?.type === "generic_name" ? namedOf(name)[0]?.text : name?.text) ?? null;

// Callee text with call arguments and type arguments dropped (`a.B(x).C<T>` -> `a.B.C`); `x?.M`
// reads as `x.M`, `new C<T>(...)` as `C`.
function render(node) {
  switch (node.type) {
    case "invocation_expression":
      return render(field(node, "function"));
    case "member_access_expression": {
      const expression = field(node, "expression");
      const name = memberName(field(node, "name"));
      return expression && name ? `${render(expression)}.${name}` : node.text;
    }
    case "conditional_access_expression": {
      const [condition, rest] = namedOf(node);
      return condition && rest ? `${render(condition)}.${render(rest)}` : node.text;
    }
    case "member_binding_expression":
    case "generic_name":
      return memberName(node.type === "generic_name" ? node : field(node, "name")) ?? node.text;
    case "object_creation_expression":
      return nameText(field(node, "type")) ?? node.text;
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

// Scopes, innermost last (see common.mjs innermostFunction): a method / local function / lambda
// (`fn: true`), a block-like statement, or a type body (`cls`, whose frame holds its fields,
// properties and record parameters). Top-level-statement locals live in `moduleFrame`.
function newState(path, surface) {
  return {
    moduleName: path.split("/").at(-1).replace(/\.[^.]*$/, ""),
    surface: { sources: surface?.sources ?? [], sinks: surface?.sinks ?? [] },
    functions: [], calls: [], imports: [], exports: [], classes: [], routes: [], sources: [], sinks: [],
    notExtracted: new Set(),
    namespace: null,
    namespaceSeen: false,
    scopes: [],
    moduleFrame: newFrame(),
    attributeDepth: 0,
    anonNames: new Map(), // lambda start byte -> its minimal-API route-handler label
    bareHandlers: [], // minimal-API routes with a bare method-group handler: { route, candidates }
    namespaces: [] // the enclosing namespace blocks' full dotted names
  };
}

// Where a local binds: the innermost scope's frame, the module frame for a top-level statement.
const currentFrame = (st) => (st.scopes.length ? st.scopes.at(-1).frame : st.moduleFrame);

// ---- sources and sinks ----------------------------------------------------------------------------

const sourceKind = (pattern) => lookup(SOURCE_KINDS, pattern.normalized) ?? "body";

const emitMatches = matchEmitter("dotnet", sourceKind); // see common.mjs

// A declared type (local, field, property, parameter, loop variable) as a sink candidate.
function typeCandidate(type, st) {
  const text = nameText(type);
  if (text) emitMatches(type, [{ category: "type", text: normalizeToken(text) }], st, { sinks: true });
}

// onIdentifier receives the TreeCursor rather than a Node (see javascript.mjs).
function onIdentifier(cursor, st, ctx) {
  if (ctx.parentType === "lambda_expression" && ctx.field !== "body") return; // the parameter of `x => ...`
  if (ctx.field === "type" || NON_REFERENCE_PARENTS.has(ctx.parentType) || NON_REFERENCE_SLOTS.has(`${ctx.parentType}.${ctx.field}`)) return;
  emitMatches(cursor, [{ category: "identifier", text: cursor.nodeText }], st, { sources: true, sinks: true });
}

function onString(node, st) {
  emitMatches(node, [{ category: "literal", text: normalizeToken(stringValue(node)) }], st, { sources: true, sinks: true });
}

function onNew(node, st) {
  const type = field(node, "type");
  const text = nameText(type);
  if (text) emitMatches(node, [{ category: "new", text: normalizeToken(text) }], st, { sinks: true, sinkAt: type });
}

// A chain's text and every suffix sub-chain (`a.b.c`, `b.c`, `c`) as source candidates: a source
// pattern may name the tail of a longer chain (`HttpContext.Request.Form` -> `Request.Form`).
const suffixCandidates = (category, text) => text.split(".").map((_, i, parts) => ({ category, text: parts.slice(i).join(".") }));

// The longest member-access chain that is not a call's callee (`Request.Query` of `Request.Query["x"]`):
// a source through any suffix, a sink as a whole. The member name assigned to (`psi.UseShellExecute =
// true`) is also a sink candidate as an identifier, like the object-initializer form.
function onMember(node, st, ctx) {
  if (ctx.parentType === "assignment_expression" && ctx.field === "left") {
    const name = field(node, "name");
    if (name?.type === "identifier") emitMatches(name, [{ category: "identifier", text: name.text }], st, { sinks: true });
  }
  if ((ctx.parentType === "member_access_expression" && ctx.field === "expression") || (ctx.parentType === "invocation_expression" && ctx.field === "function")) return;
  const text = textOf(node);
  emitMatches(node, suffixCandidates("member", text), st, { sources: true });
  emitMatches(node, [{ category: "member", text }], st, { sinks: true });
}

// Nothing inside an attribute list is a call.
function onAttributeList(node, st) {
  st.attributeDepth++;
  return () => st.attributeDepth--;
}

// An attribute is a decorator candidate (a source only on a parameter or a method).
function onAttribute(node, st) {
  const name = attributeName(node);
  if (!name) return;
  const owner = node.parent?.parent?.type ?? null;
  emitMatches(node, [{ category: "decorator", text: name }], st, { sources: SOURCE_ATTRIBUTE_OWNERS.has(owner), sinks: true });
}

// ---- scopes and declarations ----------------------------------------------------------------------

function onVariableDeclaration(node, st, ctx) {
  const type = field(node, "type");
  typeCandidate(type, st);
  if (ctx.parentType === "field_declaration" || ctx.parentType === "event_field_declaration") return; // bound in the type's frame
  for (const { name, value } of declaratorsOf(node)) bind(currentFrame(st), name, declaredClass(type, value));
}

// Block-like statements open a scope; a loop / catch variable is bound in its statement's scope.
function onScope(node, st) {
  const frame = newFrame();
  if (node.type === "for_each_statement") {
    const left = field(node, "left");
    if (left?.type === "identifier") bind(frame, left.text, declaredClass(field(node, "type")));
    typeCandidate(field(node, "type"), st);
  } else if (node.type === "catch_clause") {
    const declaration = childrenOfType(node, "catch_declaration")[0];
    bind(frame, field(declaration, "name")?.text, declaredClass(field(declaration, "type")));
  }
  st.scopes.push({ frame });
  return () => st.scopes.pop();
}

// A property / indexer: its type is a sink candidate; a body (accessor or `=> expr`) is no function.
function onProperty(node, st) {
  typeCandidate(field(node, "type"), st);
  const accessors = childrenOfType(field(node, "accessors"), "accessor_declaration");
  if (field(node, "value")?.type === "arrow_expression_clause" || accessors.some((a) => field(a, "body"))) st.notExtracted.add("property body");
}

// ---- types ----------------------------------------------------------------------------------------

// The type body's frame: each field, property and record / primary-constructor parameter bound to
// its declared class.
function fieldFrame(node, members) {
  const frame = newFrame();
  for (const member of members) {
    if (member.type === "field_declaration" || member.type === "event_field_declaration") {
      const declaration = childrenOfType(member, "variable_declaration")[0];
      for (const { name, value } of declaratorsOf(declaration)) bind(frame, name, declaredClass(field(declaration, "type"), value));
    } else if (member.type === "property_declaration") bind(frame, field(member, "name")?.text, declaredClass(field(member, "type")));
  }
  for (const param of childrenOfType(field(node, "parameters"), "parameter")) bind(frame, field(param, "name")?.text, declaredClass(field(param, "type")));
  return frame;
}

// A routing attribute's template: "" without a positional argument, null when it is not a string
// literal.
function templateOf(attribute) {
  const positional = childrenOfType(childrenOfType(attribute, "attribute_argument_list")[0], "attribute_argument")
    .filter((a) => !childrenOfType(a, "name_equals").length && !childrenOfType(a, "name_colon").length);
  return positional.length ? stringValue(namedOf(positional[0]).at(-1)) : "";
}

const joinPath = (...parts) => ("/" + parts.filter(Boolean).join("/")).replace(/\/{2,}/g, "/");

function onType(node, st) {
  const name = field(node, "name")?.text ?? null;
  const body = field(node, "body");
  const members = body?.type === "declaration_list" ? namedOf(body) : [];
  const outer = innermostClass(st);
  const isPublic = hasModifier(node, "public");
  const bases = node.type === "enum_declaration" ? [] : namedOf(field(node, "bases"));
  const first = bases[0]?.type === "primary_constructor_base_type" ? namedOf(bases[0])[0] : bases[0];
  const firstClass = first ? declaredClass(first) : null;
  const superclass = firstClass && !/^I[A-Z]/.test(firstClass) ? firstClass : null;
  // every base but the superclass is an interface (C# allows one base class, listed first)
  const interfaces = bases.slice(superclass ? 1 : 0).map((b) => declaredClass(b)).filter(Boolean);
  const methods = members.filter((m) => m.type === "method_declaration");
  if (name) {
    st.classes.push({ name, extends: superclass, implements: interfaces, methods: [...new Set(methods.map((m) => field(m, "name")?.text).filter(Boolean))], start_byte: node.startIndex });
    if (!outer && isPublic) st.exports.push({ name, start_byte: node.startIndex });
  }
  const attributes = attributesOf(node);
  const prefixes = attributes.filter((a) => attributeName(a) === "Route").map(templateOf);
  if (prefixes.length > 1) st.notExtracted.add("route(multiple class prefixes)"); // the first is used
  if (prefixes[0] === null) st.notExtracted.add("route(non-literal path)");
  if (name?.endsWith("Controller") && prefixes.length === 0 && methods.some(isUnroutedAction)) st.notExtracted.add("conventional routing");
  if (name?.endsWith("Controller") && superclass && !MVC_BASES.has(superclass)) st.notExtracted.add("inherited controller attributes");
  st.scopes.push({
    frame: fieldFrame(node, members),
    cls: {
      name,
      start: node.startIndex,
      qualifiedName: name,
      exported: outer ? outer.exported && isPublic : isPublic,
      isInterface: node.type === "interface_declaration",
      prefix: prefixes[0] ?? "",
      routedPrefix: prefixes.length > 0 && prefixes[0] !== null, // its unattributed actions are routed at the prefix
      controller: name?.replace(/(.)Controller$/, "$1") ?? "",
      auth: attributes.map(attributeName).filter((n) => AUTH_ATTRIBUTES.has(n))
    }
  });
  return () => st.scopes.pop();
}

// ---- functions and routes -------------------------------------------------------------------------

// The single parameter of `x => ...`: a bare identifier before the lambda's body (no parameter list).
function implicitParameter(node) {
  if (node.type !== "lambda_expression" || field(node, "parameters")) return null;
  const head = namedOf(node).find((c) => c.type !== "modifier");
  return head?.type === "identifier" && !sameNode(head, field(node, "body")) ? head : null;
}

// Declared parameters (`param_count`): null with a `params` array or an optional parameter; none for
// `delegate { ... }`.
function parameterCount(node) {
  const params = field(node, "parameters");
  if (!params) return implicitParameter(node) ? 1 : 0;
  if (params.children.some((c) => c.type === "params")) return null;
  const list = childrenOfType(params, "parameter");
  return list.some((p) => childrenOfType(p, "equals_value_clause").length) ? null : list.length;
}

function addParameters(node, frame) {
  const implicit = implicitParameter(node);
  if (implicit) return bind(frame, implicit.text, null);
  for (const param of namedOf(field(node, "parameters"))) {
    if (param.type === "parameter") bind(frame, field(param, "name")?.text, declaredClass(field(param, "type")));
    else if (param.type === "identifier") bind(frame, param.text, null); // a `params T[] name` array
  }
}

// `Action a = () => ...` -> "a" (a local's initialiser only).
function lambdaName(node) {
  const declarator = node.parent?.type === "equals_value_clause" ? node.parent.parent : null;
  if (declarator?.type !== "variable_declarator" || declarator.parent?.parent?.type !== "local_declaration_statement") return null;
  return childrenOfType(declarator, "identifier")[0]?.text ?? null;
}

function onFunction(node, st) {
  const owner = st.scopes.at(-1)?.cls ?? null;
  let fn;
  if (LAMBDAS.has(node.type)) {
    const label = st.anonNames.get(node.startIndex) ?? null;
    const local = label ? null : lambdaName(node);
    const qualifiedName = label ?? `${enclosingName(st)}.${local ?? anonLabel(node)}`;
    // a lambda named by the local it initialises binds that name in the enclosing scope (resolve.mjs's
    // nested definitions: `Action a = () => ...; a();`)
    fn = { name: local ?? "<anon>", qualified_name: qualifiedName, kind: "lambda", exported: false, class: null, classStart: innermostClass(st)?.start ?? null, bindsName: local !== null };
  } else if (node.type === "local_function_statement") {
    const name = field(node, "name")?.text ?? "<anon>";
    fn = { name, qualified_name: `${enclosingName(st)}.${name}`, kind: "function", exported: false, class: innermostClass(st)?.name ?? null };
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
    // an interface method without a default body, an abstract / extern / partial declaration:
    // resolve.mjs never grades a call to it exact
    ...(node.type === "method_declaration" && !childrenOfType(node, "block").length && !childrenOfType(node, "arrow_expression_clause").length ? { bodiless: true } : {})
  });
  if (node.type === "method_declaration" && owner?.name) attributeRoutes(node, owner, fn, st);
  const frame = newFrame(node.startIndex, fn.qualified_name);
  addParameters(node, frame);
  st.scopes.push({ frame, fn: true });
  return () => st.scopes.pop();
}

// A public, non-static action carrying no routing attribute (`[NonAction]` counts as one).
const isUnroutedAction = (m) => hasModifier(m, "public") && !hasModifier(m, "static") && !attributesOf(m).some((a) => ROUTING_ATTRIBUTES.has(attributeName(a)));

// The routes of an action as [{ at, method, template }]: each templated verb at its own template; a
// template-less verb at the first method `[Route]` template (else at the prefix); every other method
// `[Route]` at its template, constrained to the action's one verb (else ANY); an unattributed action of
// a `[Route]`-prefixed type at the prefix (ANY), anchored at its name.
function actionRoutes(node, attributes, names, owner) {
  const verbs = attributes.filter((a, i) => HTTP_VERB_ATTRIBUTES.has(names[i]));
  const routes = attributes.filter((a, i) => names[i] === "Route");
  const verbOf = (a) => HTTP_VERB_ATTRIBUTES.get(attributeName(a));
  const bare = verbs.filter((v) => templateOf(v) === "");
  const specs = verbs.map((v) => ({ at: v, method: verbOf(v), template: templateOf(v) !== "" ? templateOf(v) : routes.length ? templateOf(routes[0]) : "" }));
  const constraint = verbs.length === 1 ? verbOf(verbs[0]) : "ANY";
  routes.forEach((r, i) => {
    if (!(bare.length && i === 0)) specs.push({ at: r, method: constraint, template: templateOf(r) });
  });
  if (!specs.length && owner.routedPrefix && isUnroutedAction(node)) specs.push({ at: field(node, "name"), method: "ANY", template: "" });
  return specs;
}

function attributeRoutes(node, owner, fn, st) {
  const attributes = attributesOf(node);
  const names = attributes.map(attributeName);
  const auth = names.filter((n) => AUTH_ATTRIBUTES.has(n));
  for (const { at, method, template } of actionRoutes(node, attributes, names, owner)) {
    if (template === null) {
      st.notExtracted.add("route(non-literal path)");
      continue;
    }
    const absolute = /^~?\//.test(template);
    const path = (absolute ? joinPath(template.replace(/^~/, "")) : joinPath(owner.prefix, template))
      .replace(/\[controller\]/gi, owner.controller)
      .replace(/\[action\]/gi, fn.name);
    st.routes.push({
      line: lineOf(at),
      start_byte: at.startIndex,
      http_method: method,
      path_pattern: path,
      handler_text: fn.qualified_name,
      middleware_texts: [...owner.auth, ...auth],
      framework: "aspnet"
    });
  }
}

// A minimal-API handler argument as its handler text (null when it names none): a lambda's label;
// `this.M` -> `<Class>.M` inside a type; a bare `M` stays as is until the walk ends (see
// qualifyHandlers); any other method group its text.
function routeHandler(value, st) {
  if (LAMBDAS.has(value?.type)) {
    const label = anonLabel(value);
    st.anonNames.set(value.startIndex, label);
    return label;
  }
  const cls = innermostClass(st);
  if (value?.type === "member_access_expression" && field(value, "expression")?.type === "this_expression" && cls?.qualifiedName) {
    return `${cls.qualifiedName}.${memberName(field(value, "name"))}`;
  }
  return value?.type === "identifier" || value?.type === "member_access_expression" ? textOf(value) : null;
}

// A bare method-group handler `M` names the local function `<enclosing>.M` of its scope (a top-level
// `Program.M` included), else the method `<Class>.M` of the enclosing type, when the file defines it
// (local functions may follow the registration, hence after the walk).
function qualifyHandlers(st) {
  const defined = new Set(st.functions.map((f) => f.qualified_name));
  for (const { route, candidates } of st.bareHandlers) {
    const hit = candidates.find((c) => c && defined.has(c));
    if (hit) route.handler_text = hit;
  }
}

// The `.RequireAuthorization(...)` / `.AllowAnonymous()` calls chained onto a route registration.
function chainedAuth(node) {
  const texts = [];
  for (let current = node; ; ) {
    const access = current.parent;
    const call = access?.parent;
    if (access?.type !== "member_access_expression" || !sameNode(field(access, "expression"), current)) break;
    if (call?.type !== "invocation_expression" || !sameNode(field(call, "function"), access)) break;
    const name = memberName(field(access, "name"));
    if (CHAINED_AUTH.has(name)) texts.push(name);
    current = call;
  }
  return texts;
}

// `x.MapGet("/p", handler)` and friends. A `Map` whose path is not a literal is no route at all
// (AutoMapper's `mapper.Map(src, dst)`).
function minimalApiRoute(node, name, st) {
  const args = argumentValues(field(node, "arguments"));
  const handlerAt = name === "MapMethods" ? 2 : 1;
  if (args.length <= handlerAt) return;
  const path = stringValue(args[0]);
  if (path === null) {
    if (name !== "Map") st.notExtracted.add("route(non-literal path)");
    return;
  }
  const handler = routeHandler(args[handlerAt], st);
  if (!handler) return void st.notExtracted.add("route(non-literal handler)");
  const route = {
    line: lineOf(node),
    start_byte: node.startIndex,
    http_method: MINIMAL_VERBS[name],
    path_pattern: joinPath(path),
    handler_text: handler,
    middleware_texts: chainedAuth(node),
    framework: "aspnet"
  };
  st.routes.push(route);
  if (args[handlerAt].type === "identifier") {
    const cls = innermostClass(st);
    st.bareHandlers.push({ route, candidates: [`${enclosingName(st)}.${handler}`, cls?.qualifiedName ? `${cls.qualifiedName}.${handler}` : null] });
  }
}

// ---- calls ----------------------------------------------------------------------------------------

// The class a plain identifier receiver is bound to: its declaration in the innermost scope binding
// it (fields are the type scopes' bindings; top-level-statement locals only outside any type), else
// the name itself when capitalised (a static call; resolve.mjs verifies it names a class).
function identifierClass(name, st) {
  const frames = st.scopes.map((s) => s.frame);
  const moduleFrame = st.scopes.some((s) => s.cls) ? NO_FRAME : st.moduleFrame;
  if (moduleFrame.bindings.has(name) || frames.some((f) => f.bindings.has(name))) return receiverClass(name, frames, moduleFrame);
  return /^[A-Z]/.test(name) ? name : null;
}

function receiverHints(object, st) {
  const none = { receiver: null, receiverClass: null };
  switch (object?.type) {
    case "this_expression":
      return { receiver: "this", receiverClass: null };
    case "identifier":
      return { receiver: null, receiverClass: identifierClass(object.text, st) };
    case "member_access_expression": {
      const name = field(object, "name");
      if (field(object, "expression")?.type !== "this_expression" || name?.type !== "identifier") return none;
      return { receiver: null, receiverClass: innermostClassScope(st)?.frame.classOf.get(name.text) ?? null };
    }
    case "object_creation_expression":
      return { receiver: null, receiverClass: declaredClass(field(object, "type")) };
    default:
      return none; // base, deeper chains, any other expression
  }
}

// The callee's parts: { name (the anchor node), object (the receiver expression, null when bare) };
// null for a computed callee.
function calleeOf(fn) {
  switch (fn?.type) {
    case "identifier":
    case "generic_name":
      return { name: fn, object: null };
    case "member_access_expression":
      return { name: field(fn, "name"), object: field(fn, "expression") };
    case "conditional_access_expression": {
      const [condition, binding] = namedOf(fn);
      return binding?.type === "member_binding_expression" ? { name: field(binding, "name"), object: condition } : null;
    }
    default:
      return null;
  }
}

function onCall(node, st) {
  if (st.attributeDepth) return;
  const fn = field(node, "function");
  if (fn?.type === "identifier" && fn.text === "nameof") return;
  const callee = calleeOf(fn);
  const methodName = memberName(callee?.name);
  if (!methodName) return void st.notExtracted.add("computed callee");
  const calleeText = textOf(fn);
  const { receiver, receiverClass: cls } = receiverHints(callee.object, st);
  st.calls.push({
    line: lineOf(callee.name),
    start_byte: callee.name.startIndex,
    callee_text: calleeText,
    arg_count: childrenOfType(field(node, "arguments"), "argument").length,
    enclosing_start_byte: innermostFunction(st)?.startIndex ?? null,
    receiver,
    receiver_class: cls,
    scope_names: []
  });
  if (callee.object && callee.name.type === "identifier") {
    if (Object.hasOwn(MINIMAL_VERBS, methodName)) minimalApiRoute(node, methodName, st);
    else if (ROUTE_GROUPS.has(methodName)) st.notExtracted.add("route group");
  }
  const candidates = [{ category: "call", text: calleeText }];
  if (cls) candidates.push({ category: "call", text: `${cls}.${methodName}` });
  emitMatches(node, suffixCandidates("call", calleeText), st, { sources: true });
  emitMatches(node, candidates, st, { sinks: true, sinkAt: callee.name });
}

// ---- imports --------------------------------------------------------------------------------------

function onUsing(node, st) {
  const specifier = nameText(namedOf(node).find((c) => c.type !== "name_equals"));
  if (!specifier) return;
  if (node.children.some((c) => c.type === "static")) st.notExtracted.add("using static");
  const alias = namedOf(childrenOfType(node, "name_equals")[0])[0]?.text ?? null;
  st.imports.push({ line: lineOf(node), specifier, bindings: alias ? [{ imported: lastSegment(specifier), local: alias }] : [], local: null });
}

// The file's namespace is the first declaration's full dotted name, deepened by a block nested
// directly in it (`namespace A { namespace B { } }` -> "A.B"); any other declaration is noted.
function onNamespace(node, st) {
  const own = nameText(field(node, "name"));
  const outer = st.namespaces.at(-1) ?? null;
  const full = outer && own ? `${outer}.${own}` : own;
  if (!st.namespaceSeen) st.namespace = full;
  else if (outer !== null && outer === st.namespace) st.namespace = full;
  else st.notExtracted.add("multiple namespaces");
  st.namespaceSeen = true;
  st.namespaces.push(full);
  return () => st.namespaces.pop();
}

// A C# 12 primary constructor the vendored grammar cannot parse: an ERROR node standing for the
// parameter list of a type declaration, or a `class X(...)` / `struct X(...)` left unparsed.
function onError(node, st, ctx) {
  const kinds = node.children.map((c) => c.type);
  const unparsedType = (kinds.includes("class") || kinds.includes("struct")) && kinds.includes("parameter_list");
  if ((TYPE_DECLARATIONS.includes(ctx.parentType) && node.text.startsWith("(")) || unparsedType) st.notExtracted.add("primary constructor");
}

// ---- walk -----------------------------------------------------------------------------------------

const HANDLERS = new Map([
  ...TYPE_DECLARATIONS.map((type) => [type, onType]),
  ["method_declaration", onFunction],
  ["constructor_declaration", onFunction],
  ["local_function_statement", onFunction],
  ["lambda_expression", onFunction],
  ["anonymous_method_expression", onFunction],
  ["property_declaration", onProperty],
  ["indexer_declaration", onProperty],
  ["block", onScope],
  ["for_statement", onScope],
  ["for_each_statement", onScope],
  ["catch_clause", onScope],
  ["using_statement", onScope],
  ["switch_body", onScope],
  ["variable_declaration", onVariableDeclaration],
  ["parameter", (node, st) => typeCandidate(field(node, "type"), st)],
  ["invocation_expression", onCall],
  ["object_creation_expression", onNew],
  ["member_access_expression", onMember],
  ["attribute_list", onAttributeList],
  ["attribute", onAttribute],
  ["string_literal", onString],
  ["verbatim_string_literal", onString],
  ["using_directive", onUsing],
  ["namespace_declaration", onNamespace],
  ["file_scoped_namespace_declaration", onNamespace],
  ["ERROR", onError]
]);
const CURSOR_HANDLERS = new Map([["identifier", onIdentifier]]);

export function extractFile({ tree, path, surface }) {
  const st = newState(path, surface);
  walk(tree, st, HANDLERS, CURSOR_HANDLERS);
  qualifyHandlers(st);
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

// "X.Y.Z" names the file Z.cs declaring `namespace X.Y` (`namespaces`: path -> Extract.namespace):
// exact, or the first by path, heuristic, when several do. Otherwise "X.Y" names a namespace: the
// first file (by path) declaring it, heuristic (a `using` names every file of the namespace; class
// references then resolve through resolve.mjs's unique-class-name rule). `fromPath` / `configs` are
// part of the shared contract; C# ignores them.
// resolve.mjs memoises resolveImportSpecifier per run on this key: the result depends on the specifier
// alone (fromPath is not consulted).
export const importCacheKey = ({ specifier }) => specifier;

export function resolveImportSpecifier({ specifier, filePaths, namespaces }) {
  if (typeof specifier !== "string") return null;
  const segments = specifier.split(".");
  if (segments.some((s) => s === "")) return null;
  if (segments.length >= 2) {
    const namespace = segments.slice(0, -1).join(".");
    const fileName = `${segments.at(-1)}.cs`;
    const typed = (pathsByBasename(filePaths).get(fileName) ?? []).filter((p) => namespaces?.get(p) === namespace);
    if (typed.length) return { path: typed[0], confidence: typed.length === 1 ? "exact" : "heuristic" };
  }
  const declaring = (pathsByNamespace(namespaces, filePaths).get(specifier) ?? [])[0];
  return declaring ? { path: declaring, confidence: "heuristic" } : null;
}
