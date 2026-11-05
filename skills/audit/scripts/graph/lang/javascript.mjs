// JavaScript / TypeScript / TSX language module for the SP10 application graph (spec §2.3).
// extractFile walks one parsed tree (web-tree-sitter, see ../parser.mjs) and emits the per-file
// Extract: functions, calls (+ the scope / receiver hints resolve.mjs needs, spec §1.4), imports,
// exports, classes, Express + Nest routes, and surface-pattern sources / sinks. The three grammars
// share one code path: the TypeScript node types are a superset of JavaScript's.
//
// The tree is walked once with a TreeCursor, dispatching on node type, instead of running
// tree-sitter Query objects: in web-tree-sitter 0.25 `Language.query` is deprecated (it logs a
// warning on every call); `new Query` would need the vendored loader imported here, so this module
// would fail to load when the parser is unavailable (parser.mjs's parserAvailable contract); and the
// handlers need each node's parent type and field, which a cursor walk carries for free (a capture
// query plus a parent lookup per capture measured ~2x slower).
//
// PURE: no I/O. `sourceText` is never copied into the output — only identifier / literal text.
import { posix } from "node:path";
import { normalizeToken } from "../surface.mjs";
import { lookup, field, namedOf, childrenOfType, lineOf, anonLabel, byStart, matchEmitter, walk, receiverClass, repoPath } from "./common.mjs";

export const lang = { id: "javascript", stack: "node", langIds: ["javascript", "typescript", "tsx"], frameworks: ["express", "nest"], implicitThisCalls: false, submoduleImports: false, callableLocals: true, overloads: false };

// ---- node-type tables -----------------------------------------------------------------------------

const FUNCTION_TYPES = ["function_declaration", "generator_function_declaration", "function_expression", "function", "generator_function", "arrow_function", "method_definition"];
const DECLARATION_FUNCTIONS = new Set(["function_declaration", "generator_function_declaration"]);
const CLASS_TYPES = ["class_declaration", "class", "abstract_class_declaration"];
const DEFINITION_VALUES = new Set(["arrow_function", "function_expression", "function", "generator_function", "class"]);
const EXPORTABLE_DECLARATIONS = new Set(["function_declaration", "generator_function_declaration", "class_declaration", "abstract_class_declaration", "interface_declaration"]);

// A node in one of these (parent type, field) slots is part of a callee / member chain: the
// enclosing chain node is the candidate, so the part never yields a source or sink on its own.
const CHAIN_SLOTS = new Map([["member_expression", "object"], ["subscript_expression", "object"], ["call_expression", "function"], ["new_expression", "constructor"]]);
// An identifier in one of these slots declares a name; it is not a reference.
const BINDING_SLOTS = new Map([
  ["variable_declarator", "name"], ["function_declaration", "name"], ["generator_function_declaration", "name"],
  ["function_expression", "name"], ["function", "name"], ["generator_function", "name"], ["class_declaration", "name"],
  ["class", "name"], ["arrow_function", "parameter"], ["assignment_pattern", "left"], ["pair_pattern", "value"],
  ["catch_clause", "parameter"], ["required_parameter", "pattern"], ["optional_parameter", "pattern"], ["for_in_statement", "left"]
]);
const BINDING_PARENTS = new Set(["formal_parameters", "array_pattern", "rest_pattern", "import_specifier", "import_clause", "namespace_import", "export_specifier", "import_require_clause"]);

const EXPRESS_VERBS = { get: "GET", post: "POST", put: "PUT", patch: "PATCH", delete: "DELETE", head: "HEAD", options: "OPTIONS", all: "ANY", use: "USE" };
const NEST_VERBS = { Get: "GET", Post: "POST", Put: "PUT", Patch: "PATCH", Delete: "DELETE", Head: "HEAD", Options: "OPTIONS", All: "ANY" };
const SOURCE_KINDS = { query: "query", body: "body", params: "params", param: "params", headers: "header", cookies: "cookie", files: "file", env: "env" };

// ---- small AST helpers ----------------------------------------------------------------------------

const stringContent = (node) => node.text.slice(1, -1);

// Callee / member text with call arguments dropped (`a.b(x).c` -> `a.b.c`) and a string subscript
// read as a member (`h['x']` -> `h.x`); other subscripts collapse to their object.
function render(node) {
  switch (node.type) {
    case "member_expression": {
      const object = field(node, "object");
      const property = field(node, "property");
      return object && property ? `${render(object)}.${property.text}` : node.text;
    }
    case "call_expression": {
      const fn = field(node, "function");
      return fn ? render(fn) : node.text;
    }
    case "subscript_expression": {
      const object = field(node, "object");
      const index = field(node, "index");
      if (!object) return node.text;
      return index?.type === "string" ? `${render(object)}.${stringContent(index)}` : render(object);
    }
    case "parenthesized_expression":
    case "non_null_expression": {
      const inner = namedOf(node)[0];
      return inner ? render(inner) : node.text;
    }
    default:
      return node.text;
  }
}
const textOf = (node) => normalizeToken(render(node));

// Every name a binding pattern declares (`{ a, b: c, ...d }`, `[e = 1]`, TS `x: T`).
function patternNames(node, out = []) {
  if (!node) return out;
  switch (node.type) {
    case "identifier":
    case "shorthand_property_identifier_pattern":
      out.push(node.text);
      break;
    case "object_pattern":
    case "array_pattern":
      for (const child of node.namedChildren) patternNames(child, out);
      break;
    case "pair_pattern":
      patternNames(field(node, "value"), out);
      break;
    case "assignment_pattern":
    case "object_assignment_pattern":
      patternNames(field(node, "left"), out);
      break;
    case "rest_pattern":
      patternNames(node.namedChildren[0], out);
      break;
    case "required_parameter":
    case "optional_parameter":
      patternNames(field(node, "pattern"), out);
      break;
  }
  return out;
}

const isRequireCall = (node) =>
  node?.type === "call_expression" && field(node, "function")?.type === "identifier" && field(node, "function").text === "require" && namedOf(field(node, "arguments"))[0]?.type === "string";

// ---- state ----------------------------------------------------------------------------------------

const newFrame = (startIndex, qualifiedName) => ({ startIndex, qualifiedName, bindings: new Set(), classOf: new Map() });

function newState(path, surface) {
  return {
    moduleName: path.split("/").at(-1).replace(/\.[^.]*$/, ""),
    surface: { sources: surface?.sources ?? [], sinks: surface?.sinks ?? [] },
    functions: [], calls: [], imports: [], exports: [], defaultRefs: [], classes: [], routes: [], sources: [], sinks: [],
    notExtracted: new Set(),
    anonNames: new Map(), // function start index -> qualified name given by a route argument
    requireImports: new Set(), // start index of require() calls already recorded by their declarator
    topLevel: new Map(), // module-level function / class name -> start byte of its definition
    ctorClasses: new Map(), // constructor-style class name -> { start: its function's start | null, methods: [] }
    module: newFrame(null, null),
    fnStack: [],
    classStack: []
  };
}
const currentFrame = (st) => st.fnStack.at(-1) ?? st.module;

// ---- sources and sinks ----------------------------------------------------------------------------

const sourceKind = (pattern) => lookup(SOURCE_KINDS, pattern.normalized.split(".").at(-1).toLowerCase()) ?? "body";

const emitMatches = matchEmitter("node", sourceKind); // see common.mjs

const inChain = (ctx) => CHAIN_SLOTS.get(ctx.parentType) === ctx.field || ctx.parentType === "decorator";
const isBinding = (ctx) => BINDING_PARENTS.has(ctx.parentType) || BINDING_SLOTS.get(ctx.parentType) === ctx.field;

// onMember / onIdentifier receive the TreeCursor rather than a Node: they are the most frequent node
// types, and most occurrences are chain parts or bindings that are skipped without materialising one.
function onMember(cursor, st, ctx) {
  if (inChain(ctx)) return;
  const node = cursor.currentNode;
  emitMatches(node, [{ category: "member", text: textOf(node) }], st, { sources: true, sinks: true });
}

function onIdentifier(cursor, st, ctx) {
  if (inChain(ctx) || isBinding(ctx)) return;
  emitMatches(cursor, [{ category: "identifier", text: cursor.nodeText }], st, { sources: true, sinks: true });
}

function onNew(node, st) {
  const ctor = field(node, "constructor");
  if (!ctor) return;
  const text = textOf(ctor);
  // The surface spells constructor sinks `new Function`, which normalizes to `newFunction`.
  emitMatches(node, [{ category: "new", text }, { category: "new", text: `new${text}` }], st, { sinks: true, sinkAt: calleeAnchor(ctor, node) });
}

function onString(node, st, ctx) {
  if (ctx.parentType === "pair" && ctx.field === "key") return; // a key, handled by onPair
  emitMatches(node, [{ category: "literal", text: normalizeToken(stringContent(node)) }], st, { sinks: true });
}

function onPair(node, st) {
  const key = field(node, "key");
  const text = key?.type === "property_identifier" ? key.text : key?.type === "string" ? stringContent(key) : null;
  if (text) emitMatches(key, [{ category: "key", text: normalizeToken(text) }], st, { sinks: true });
}

function decoratorInfo(decorator) {
  const expr = namedOf(decorator)[0];
  if (!expr) return { name: "", args: [] };
  if (expr.type === "call_expression") return { name: textOf(field(expr, "function") ?? expr), args: namedOf(field(expr, "arguments")) };
  return { name: textOf(expr), args: [] };
}

function onDecorator(node, st) {
  const { name } = decoratorInfo(node);
  if (name) emitMatches(node, [{ category: "decorator", text: name }], st, { sources: true });
}

// ---- scopes and functions -------------------------------------------------------------------------

// The base class name of a TypeScript type or a `new` target: `Repo<T>` / `ns.Repo` / `ns.Repo<T>`
// -> `Repo`; anything else (unions, arrays, predefined types) -> null.
function typeName(node) {
  switch (node?.type) {
    case "type_annotation":
      return typeName(namedOf(node)[0]);
    case "type_identifier":
    case "identifier":
      return node.text;
    case "generic_type":
    case "nested_type_identifier":
      return typeName(field(node, "name"));
    case "member_expression":
      return field(node, "property")?.text ?? null;
    default:
      return null;
  }
}

// Declared parameters (`param_count`): null with a rest parameter (`...a`, TS `...a: T[]`) or a
// default value (`a = 1`, TS `a: T = 1`).
function parameterCount(node) {
  const single = field(node, "parameter");
  const params = single ? [single] : namedOf(field(node, "parameters"));
  const uncounted = (p) => p.type === "rest_pattern" || p.type === "assignment_pattern" || field(p, "pattern")?.type === "rest_pattern" || field(p, "value") !== null;
  return params.some(uncounted) ? null : params.length;
}

function addParameters(node, frame) {
  const single = field(node, "parameter");
  const params = single ? [single] : namedOf(field(node, "parameters"));
  for (const param of params) {
    for (const name of patternNames(param)) frame.bindings.add(name);
    const pattern = field(param, "pattern");
    const type = typeName(field(param, "type"));
    if (pattern?.type === "identifier" && type) frame.classOf.set(pattern.text, type);
  }
}

function functionName(node, ctx) {
  const own = field(node, "name");
  if (own) return own.text;
  if (ctx.parentType === "variable_declarator" && ctx.field === "value") {
    const declared = field(node.parent, "name");
    if (declared?.type === "identifier") return declared.text;
  }
  return null;
}

// ---- constructor-style classes (NodeGoat: `function F(db) { this.m = (req, res) => {...}; }`) -----

const CTOR_METHOD_VALUES = new Set(["function_expression", "function", "arrow_function", "generator_function"]);
const PROTOTYPE_METHOD = /^([A-Za-z_$][\w$]*)\.prototype\.([A-Za-z_$][\w$]*)$/;

// A top-level `function F(...)` / `const F = function (...)` whose body assigns `this.<m> = <function |
// arrow>` (a direct statement of its body) is a constructor-style class F.
function isConstructorStyle(node, ctx, enclosing) {
  if (enclosing || !(node.type === "function_declaration" || ((node.type === "function_expression" || node.type === "function") && ctx.parentType === "variable_declarator"))) return false;
  return namedOf(field(node, "body")).some((statement) => {
    const assignment = statement.type === "expression_statement" ? namedOf(statement)[0] : null;
    const left = assignment?.type === "assignment_expression" ? field(assignment, "left") : null;
    return left?.type === "member_expression" && field(left, "object")?.type === "this" && CTOR_METHOD_VALUES.has(field(assignment, "right")?.type);
  });
}

// The constructor-style method a function defines, as { cls, name }: the value of `this.<m> = ...` in a
// constructor-style function's own body, or of a module-level `F.prototype.<m> = ...`; else null.
function constructorMethod(node, ctx, st, enclosing) {
  if (ctx.parentType !== "assignment_expression" || ctx.field !== "right") return null;
  const left = field(node.parent, "left");
  if (left?.type !== "member_expression") return null;
  const property = field(left, "property")?.text;
  if (field(left, "object")?.type === "this") return enclosing?.ctorName && property ? { cls: enclosing.ctorName, name: property } : null;
  const prototype = enclosing ? null : PROTOTYPE_METHOD.exec(textOf(left));
  return prototype ? { cls: prototype[1], name: prototype[2] } : null;
}

const ctorClass = (st, name) => (st.ctorClasses.has(name) ? st.ctorClasses.get(name) : st.ctorClasses.set(name, { start: null, methods: [] }).get(name));

function onFunction(node, st, ctx) {
  const enclosing = st.fnStack.at(-1) ?? null;
  const isMethod = node.type === "method_definition";
  const ctorMethod = constructorMethod(node, ctx, st, enclosing);
  const cls = isMethod && ctx.parentType === "class_body" ? st.classStack.at(-1)?.name ?? null : ctorMethod?.cls ?? null;
  let name = ctorMethod?.name ?? functionName(node, ctx);
  if (ctorMethod) {
    const entry = ctorClass(st, ctorMethod.cls);
    if (!entry.methods.includes(ctorMethod.name)) entry.methods.push(ctorMethod.name);
  }
  let qualifiedName;
  if (ctorMethod) {
    qualifiedName = `${cls}.${name}`;
  } else if (st.anonNames.has(node.startIndex)) {
    name = "<anon>";
    qualifiedName = st.anonNames.get(node.startIndex);
  } else if (!name) {
    name = "<anon>";
    qualifiedName = `${enclosing?.qualifiedName ?? st.moduleName}.${anonLabel(node)}`;
  } else if (cls) {
    qualifiedName = `${cls}.${name}`;
  } else {
    qualifiedName = enclosing ? `${enclosing.qualifiedName}.${name}` : name;
  }
  if (DECLARATION_FUNCTIONS.has(node.type) && name !== "<anon>") {
    if (enclosing) enclosing.bindings.add(name);
    else st.topLevel.set(name, node.startIndex);
  }
  st.functions.push({
    name,
    qualified_name: qualifiedName,
    line_start: lineOf(node),
    line_end: node.endPosition.row + 1,
    start_byte: node.startIndex,
    end_byte: node.endIndex,
    param_count: parameterCount(node),
    kind: isMethod || ctorMethod ? "method" : node.type === "arrow_function" ? "arrow" : "function",
    exported: false,
    class: cls,
    // an arrow's lexical class body: resolve.mjs inherits a containing method's class only within it
    ...(node.type === "arrow_function" && !ctorMethod ? { class_start_byte: st.classStack.at(-1)?.start ?? null } : {})
  });
  const frame = newFrame(node.startIndex, qualifiedName);
  if (isConstructorStyle(node, ctx, enclosing)) {
    frame.ctorName = name;
    ctorClass(st, name).start = node.startIndex;
  }
  addParameters(node, frame);
  st.fnStack.push(frame);
  return () => st.fnStack.pop();
}

function onDeclarator(node, st) {
  const nameNode = field(node, "name");
  const value = field(node, "value");
  if (isRequireCall(value)) {
    st.requireImports.add(value.startIndex);
    st.imports.push(requireImport(nameNode, value));
    return;
  }
  if (!st.fnStack.length && value && DEFINITION_VALUES.has(value.type)) {
    if (nameNode?.type === "identifier") st.topLevel.set(nameNode.text, value.startIndex); // a definition, not a local
    return;
  }
  const frame = currentFrame(st);
  for (const name of patternNames(nameNode)) frame.bindings.add(name);
  // a declared type (`let r: Repo`) wins over the constructed class (`= new C()`)
  const cls = typeName(field(node, "type")) ?? (value?.type === "new_expression" ? typeName(field(value, "constructor")) : null);
  if (nameNode?.type === "identifier" && cls) frame.classOf.set(nameNode.text, cls);
}

function onCatchOrForIn(node, st) {
  const target = field(node, node.type === "catch_clause" ? "parameter" : "left");
  const frame = currentFrame(st);
  for (const name of patternNames(target)) frame.bindings.add(name);
}

// ---- classes and Nest routes ----------------------------------------------------------------------

function classHeritage(node) {
  const heritage = childrenOfType(node, "class_heritage")[0];
  if (!heritage) return null;
  // TypeScript wraps the targets in extends_clause / implements_clause; `implements` is not `extends`.
  const clauses = namedOf(heritage).filter((c) => c.type === "extends_clause" || c.type === "implements_clause");
  const target = clauses.length ? field(clauses.find((c) => c.type === "extends_clause"), "value") : namedOf(heritage)[0];
  return target ? textOf(target) : null;
}

// The TypeScript `implements` targets of a class (`implements Repo, ns.K<X>` -> Repo, K), or the
// `extends` targets of an interface.
function implementedTypes(node) {
  const clause = node.type === "interface_declaration"
    ? childrenOfType(node, "extends_type_clause")[0]
    : childrenOfType(childrenOfType(node, "class_heritage")[0], "implements_clause")[0];
  return namedOf(clause).map(typeName).filter(Boolean);
}

function onClass(node, st, ctx) {
  let name = field(node, "name")?.text ?? null;
  if (!name && ctx.parentType === "variable_declarator" && ctx.field === "value") {
    const declared = field(node.parent, "name");
    name = declared?.type === "identifier" ? declared.text : null;
  }
  const body = field(node, "body");
  if (name) {
    const methods = [...new Set(namedOf(body).filter((m) => m.type === "method_definition" || m.type === "abstract_method_signature").map((m) => field(m, "name")?.text).filter(Boolean))];
    st.classes.push({ name, extends: classHeritage(node), implements: implementedTypes(node), methods, start_byte: node.startIndex });
    if (!st.fnStack.length) st.topLevel.set(name, node.startIndex);
    nestRoutes(node, name, body, st);
  }
  st.classStack.push({ name, start: node.startIndex, fieldTypes: fieldTypes(body) });
  return () => st.classStack.pop();
}

// A TypeScript interface is a class whose methods are all bodiless signatures (resolve.mjs: a call
// to one is name-only, to its single implementation when it has one).
function onInterface(node, st) {
  const name = field(node, "name")?.text ?? null;
  const body = field(node, "body");
  if (name) {
    const methods = [...new Set(childrenOfType(body, "method_signature").map((m) => field(m, "name")?.text).filter(Boolean))];
    st.classes.push({ name, extends: null, implements: implementedTypes(node), methods, start_byte: node.startIndex });
    if (!st.fnStack.length) st.topLevel.set(name, node.startIndex);
  }
  st.classStack.push({ name, start: node.startIndex, fieldTypes: new Map() });
  return () => st.classStack.pop();
}

// A bodiless method: an interface's method signature, or a class's abstract method. (A class body's
// own `method_signature` is an overload signature of the method_definition that follows it, which
// stays the method's one definition.)
function onSignature(node, st, ctx) {
  const inInterface = node.type === "method_signature" && ctx.parentType === "interface_body";
  const isAbstract = node.type === "abstract_method_signature" && ctx.parentType === "class_body";
  const cls = st.classStack.at(-1)?.name ?? null;
  const name = field(node, "name")?.text ?? null;
  if (!(inInterface || isAbstract) || !cls || !name) return;
  st.functions.push({
    name,
    qualified_name: `${cls}.${name}`,
    line_start: lineOf(node),
    line_end: node.endPosition.row + 1,
    start_byte: node.startIndex,
    end_byte: node.endIndex,
    param_count: parameterCount(node),
    kind: "method",
    exported: false,
    class: cls,
    bodiless: true
  });
}

// Declared class of each `this.<prop>` receiver, first source wins: (i) a typed property declaration
// `private svc: S;`, (ii) a constructor parameter property `constructor(private svc: S)`, (iii) an
// assignment `this.svc = new S()` anywhere in the class body.
function fieldTypes(body) {
  const types = new Map();
  const add = (prop, type) => prop && type && !types.has(prop) && types.set(prop, type);
  for (const member of namedOf(body)) {
    if (member.type === "public_field_definition") add(field(member, "name")?.text, typeName(field(member, "type")));
    if (member.type === "method_definition" && field(member, "name")?.text === "constructor") {
      for (const param of namedOf(field(member, "parameters"))) {
        const isProperty = param.children.some((c) => c.type === "accessibility_modifier" || c.type === "readonly");
        const pattern = field(param, "pattern");
        if (isProperty && pattern?.type === "identifier") add(pattern.text, typeName(field(param, "type")));
      }
    }
  }
  for (const assignment of body?.descendantsOfType("assignment_expression") ?? []) {
    const left = field(assignment, "left");
    const right = field(assignment, "right");
    if (left?.type === "member_expression" && field(left, "object")?.type === "this" && right?.type === "new_expression") {
      add(field(left, "property")?.text, typeName(field(right, "constructor")));
    }
  }
  return types;
}

// Class decorators sit on the class, or on the wrapping `export` statement.
function classDecorators(node) {
  const outer = node.parent?.type === "export_statement" ? childrenOfType(node.parent, "decorator") : [];
  return [...outer, ...childrenOfType(node, "decorator")];
}

function joinRoutePath(prefix, path) {
  const joined = `/${prefix}/${path}`.replace(/\/{2,}/g, "/");
  return joined.length > 1 ? joined.replace(/\/$/, "") : joined;
}

function nestPath(arg, st) {
  if (!arg) return "";
  if (arg.type === "string") return stringContent(arg);
  const pathPair = childrenOfType(arg, "pair").find((p) => field(p, "key")?.text === "path" && field(p, "value")?.type === "string");
  if (arg.type === "object" && pathPair) return stringContent(field(pathPair, "value"));
  st.notExtracted.add("nest route(non-literal path)");
  return "";
}

// Each guard is emitted as `UseGuards.<Guard>`: the surface auth marker `@UseGuards` (a decorator
// pattern, matched on the first segment) then decides auth, and the guard name stays readable.
const guardTexts = (infos, st) =>
  infos.filter((i) => i.name === "UseGuards").flatMap((i) => i.args.flatMap((a) => argTexts(a, st)).map((g) => `UseGuards.${g}`));

function nestRoutes(classNode, className, body, st) {
  const classInfos = classDecorators(classNode).map(decoratorInfo);
  const controller = classInfos.find((i) => i.name === "Controller");
  if (!controller || !body) return;
  const prefix = nestPath(controller.args[0], st);
  const classGuards = guardTexts(classInfos, st);
  let pending = []; // TypeScript puts method decorators before the method, as class_body children
  for (const child of body.namedChildren) {
    if (child.type === "decorator") pending.push(child);
    else if (child.type === "method_definition") {
      const decorators = [...pending, ...childrenOfType(child, "decorator")];
      const infos = decorators.map(decoratorInfo);
      const middleware = [...classGuards, ...guardTexts(infos, st)];
      infos.forEach((info, i) => {
        const verb = lookup(NEST_VERBS, info.name);
        if (!verb) return;
        st.routes.push({
          line: lineOf(decorators[i]),
          start_byte: decorators[i].startIndex,
          http_method: verb,
          path_pattern: joinRoutePath(prefix, nestPath(info.args[0], st)),
          handler_text: `${className}.${field(child, "name")?.text}`,
          middleware_texts: middleware,
          framework: "nest"
        });
      });
      pending = [];
    } else if (child.type !== "comment") pending = [];
  }
}

// ---- calls and Express routes ---------------------------------------------------------------------

// Route / guard argument -> the names it contributes. An inline anonymous function is named
// `<anon>@<line>:<col>`, which also becomes that function's qualified_name.
function argTexts(node, st) {
  switch (node.type) {
    case "identifier":
    case "member_expression":
    case "subscript_expression":
      return [textOf(node)];
    case "call_expression":
      return [textOf(field(node, "function") ?? node)];
    case "new_expression":
      return [textOf(field(node, "constructor") ?? node)];
    case "arrow_function":
    case "function_expression":
    case "function": {
      const own = field(node, "name");
      if (own) return [own.text];
      const label = anonLabel(node);
      st.anonNames.set(node.startIndex, label);
      return [label];
    }
    case "array":
      return namedOf(node).flatMap((el) => argTexts(el, st));
    default:
      return [];
  }
}

// The class of `obj` for an `obj.method` handler argument, from the scopes' bindings; null otherwise.
function handlerReceiverClass(arg, st) {
  if (arg?.type !== "member_expression") return null;
  const object = field(arg, "object");
  return object?.type === "identifier" ? receiverClass(object.text, st.fnStack, st.module) : null;
}

function expressRoute(call, fn, args, st) {
  const verb = lookup(EXPRESS_VERBS, field(fn, "property")?.text);
  if (!verb) return;
  const object = field(fn, "object");
  if (object?.type === "call_expression" && field(field(object, "function"), "property")?.text === "route") {
    st.notExtracted.add("router.route().chain");
    return;
  }
  let path = null;
  let rest = args;
  if (args[0]?.type === "string") [path, rest] = [stringContent(args[0]), args.slice(1)];
  else if (args[0]?.type === "regex") {
    st.notExtracted.add(verb === "USE" ? "app.use(regex)" : "route(regex)");
    return;
  }
  if (verb === "USE") path ??= "/";
  else if (path === null || !path.startsWith("/")) return;
  if (rest.length === 0) return;
  const last = argTexts(rest.at(-1), st); // a handler must be function-ish (not an options object)
  if (last.length === 0) return;
  const receiverCls = handlerReceiverClass(rest.at(-1), st);
  st.routes.push({
    line: lineOf(call),
    start_byte: call.startIndex,
    http_method: verb,
    path_pattern: path,
    handler_text: last.at(-1),
    middleware_texts: [...rest.slice(0, -1).flatMap((a) => argTexts(a, st)), ...last.slice(0, -1)],
    framework: "express",
    // `obj.method` on a receiver of a demonstrable class (`const obj = new F(...)`, a typed parameter):
    // build-graph resolves the handler as a call on that class (`F.method`)
    ...(receiverCls ? { handler_receiver_class: receiverCls } : {})
  });
}

// Position of a call / `new`: the callee's final identifier (the property of a member callee), so
// chained calls (`a.b().c()`) and their sinks get distinct offsets. Any other callee shape (`f()()`,
// `(0, f)()`) falls back to the argument list, or to the expression itself.
function calleeAnchor(callee, expression) {
  if (callee.type === "identifier") return callee;
  if (callee.type === "member_expression") return field(callee, "property") ?? callee;
  return field(expression, "arguments") ?? expression;
}

// Receiver hints for a member callee (spec §1.4 rules 1b and 3): `this.m()` -> receiver "this";
// `x.m()` -> the name x, resolved against the scopes when the walk ends; `this.p.m()` -> the
// declared class of field p on the enclosing class. Deeper chains carry no hint.
function receiverOf(fn, st) {
  const none = { receiver: null, receiverName: null, fieldClass: null };
  if (fn.type !== "member_expression") return none;
  const object = field(fn, "object");
  if (object?.type === "this") return { ...none, receiver: "this" };
  if (object?.type === "identifier") return { ...none, receiverName: object.text };
  if (object?.type === "member_expression" && field(object, "object")?.type === "this") {
    const prop = field(object, "property")?.text;
    return { ...none, fieldClass: st.classStack.at(-1)?.fieldTypes.get(prop) ?? null };
  }
  return none;
}

function onCall(node, st, ctx) {
  if (ctx.parentType === "decorator") return; // decorator metadata, modelled by routes / sources
  const fn = field(node, "function");
  if (!fn) return;
  const argsNode = field(node, "arguments");
  const args = argsNode?.type === "arguments" ? namedOf(argsNode) : [];
  if (fn.type === "import") {
    if (args[0]?.type === "string") st.imports.push({ line: lineOf(node), specifier: stringContent(args[0]), bindings: [], local: null });
    else st.notExtracted.add("dynamic import");
    return;
  }
  const calleeText = textOf(fn);
  // `require('literal')` is an import, never a sink; only a dynamic require is an `include` sink.
  const literalRequire = calleeText === "require" && args[0]?.type === "string";
  if (calleeText === "require" && !st.requireImports.has(node.startIndex)) {
    if (literalRequire) st.imports.push({ line: lineOf(node), specifier: stringContent(args[0]), bindings: [], local: null });
    else st.notExtracted.add("dynamic require");
  }
  const anchor = calleeAnchor(fn, node);
  // arguments at the call site (`arg_count`): null with a spread argument or a tagged template
  const argCount = argsNode?.type === "arguments" && !args.some((a) => a.type === "spread_element") ? args.length : null;
  st.calls.push({ anchor, calleeText, argCount, ...receiverOf(fn, st), frames: [...st.fnStack] });
  emitMatches(node, [{ category: "call", text: calleeText }], st, { sources: true, sinks: !literalRequire, sinkAt: anchor });
  if (fn.type === "member_expression") expressRoute(node, fn, args, st);
}

// ---- imports and exports --------------------------------------------------------------------------

function requireImport(nameNode, call) {
  const entry = { line: lineOf(call), specifier: stringContent(namedOf(field(call, "arguments"))[0]), bindings: [], local: null };
  if (nameNode?.type === "identifier") return { ...entry, bindings: "namespace", local: nameNode.text };
  if (nameNode?.type !== "object_pattern") return entry;
  for (const part of namedOf(nameNode)) {
    if (part.type === "shorthand_property_identifier_pattern") entry.bindings.push({ imported: part.text, local: part.text });
    else if (part.type === "object_assignment_pattern" && field(part, "left")) entry.bindings.push({ imported: field(part, "left").text, local: field(part, "left").text });
    else if (part.type === "pair_pattern" && field(part, "value")?.type === "identifier") {
      const key = field(part, "key");
      entry.bindings.push({ imported: key.type === "string" ? stringContent(key) : key.text, local: field(part, "value").text });
    }
  }
  return entry;
}

function onImport(node, st) {
  const line = lineOf(node);
  const source = field(node, "source");
  if (!source) {
    const clause = childrenOfType(node, "import_require_clause")[0]; // TS `import x = require('y')`
    const id = childrenOfType(clause, "identifier")[0];
    const spec = field(clause, "source");
    if (id && spec) st.imports.push({ line, specifier: stringContent(spec), bindings: "namespace", local: id.text });
    return;
  }
  const specifier = stringContent(source);
  const clause = childrenOfType(node, "import_clause")[0];
  if (!clause) {
    st.imports.push({ line, specifier, bindings: [], local: null });
    return;
  }
  for (const part of namedOf(clause)) {
    if (part.type === "identifier") st.imports.push({ line, specifier, bindings: "default", local: part.text });
    else if (part.type === "namespace_import") {
      const id = childrenOfType(part, "identifier")[0];
      if (id) st.imports.push({ line, specifier, bindings: "namespace", local: id.text });
    } else if (part.type === "named_imports") {
      const bindings = childrenOfType(part, "import_specifier").map((s) => {
        const imported = field(s, "name")?.text;
        return { imported, local: field(s, "alias")?.text ?? imported };
      });
      st.imports.push({ line, specifier, bindings, local: null });
    }
  }
}

const exportName = (node) => (node.type === "string" ? stringContent(node) : node.text);

function onExport(node, st) {
  const declaration = field(node, "declaration");
  const source = field(node, "source");
  const clause = childrenOfType(node, "export_clause")[0];
  if (source) st.imports.push({ line: lineOf(node), specifier: stringContent(source), bindings: [], local: null });
  if (node.children.some((c) => c.type === "default")) {
    pushDefaultExport(declaration ?? field(node, "value"), node, st);
    return;
  }
  if (declaration?.type === "lexical_declaration" || declaration?.type === "variable_declaration") {
    for (const declarator of childrenOfType(declaration, "variable_declarator")) {
      for (const name of patternNames(field(declarator, "name"))) st.exports.push({ name, start_byte: declarator.startIndex });
    }
  } else if (EXPORTABLE_DECLARATIONS.has(declaration?.type) && field(declaration, "name")) {
    st.exports.push({ name: field(declaration, "name").text, start_byte: declaration.startIndex });
  }
  for (const spec of childrenOfType(clause, "export_specifier")) {
    const named = field(spec, "alias") ?? field(spec, "name");
    if (named) st.exports.push({ name: exportName(named), start_byte: spec.startIndex });
  }
  if (source && !clause) st.notExtracted.add("export * from");
}

// A single "default" export. Its start_byte is the definition's when the exported value is a
// same-file function / class (inline, or an identifier naming a top-level one, fixed up in finish),
// so resolve.mjs can bind `default` by offset; otherwise the export statement's.
function pushDefaultExport(value, statement, st) {
  const definition = DEFINITION_VALUES.has(value?.type) || EXPORTABLE_DECLARATIONS.has(value?.type);
  const entry = { name: "default", start_byte: definition ? value.startIndex : statement.startIndex };
  st.exports.push(entry);
  if (value?.type === "identifier") st.defaultRefs.push({ entry, name: value.text });
}

function moduleExportsObject(object, st) {
  for (const member of namedOf(object)) {
    let key = null;
    if (member.type === "shorthand_property_identifier") key = member;
    else if (member.type === "pair") key = field(member, "key");
    else if (member.type === "method_definition") key = field(member, "name");
    if (key && key.type !== "computed_property_name") st.exports.push({ name: exportName(key), start_byte: member.startIndex });
  }
}

function onAssignment(node, st) {
  const left = field(node, "left");
  const right = field(node, "right");
  if (left?.type !== "member_expression" || !right) return;
  const target = textOf(left);
  if (target === "module.exports") {
    if (right.type === "object") return moduleExportsObject(right, st);
    pushDefaultExport(right, node, st);
    return;
  }
  const named = /^(?:module\.)?exports\.([^.]+)$/.exec(target);
  if (named) st.exports.push({ name: named[1], start_byte: node.startIndex });
}

// ---- walk -----------------------------------------------------------------------------------------

const HANDLERS = new Map([
  ...FUNCTION_TYPES.map((t) => [t, onFunction]),
  ...CLASS_TYPES.map((t) => [t, onClass]),
  ["interface_declaration", onInterface],
  ["method_signature", onSignature],
  ["abstract_method_signature", onSignature],
  ["variable_declarator", onDeclarator],
  ["catch_clause", onCatchOrForIn],
  ["for_in_statement", onCatchOrForIn],
  ["call_expression", onCall],
  ["new_expression", onNew],
  ["string", onString],
  ["pair", onPair],
  ["decorator", onDecorator],
  ["import_statement", onImport],
  ["export_statement", onExport],
  ["assignment_expression", onAssignment]
]);
const CURSOR_HANDLERS = new Map([
  ["member_expression", onMember],
  ["subscript_expression", onMember],
  ["identifier", onIdentifier],
  ["shorthand_property_identifier", onIdentifier]
]);

// ---- finish ---------------------------------------------------------------------------------------

function finishCall({ anchor, calleeText, argCount, receiver, receiverName, fieldClass, frames }, st) {
  const names = new Set(st.module.bindings);
  for (const frame of frames) for (const name of frame.bindings) names.add(name);
  return {
    line: lineOf(anchor),
    start_byte: anchor.startIndex,
    callee_text: calleeText,
    arg_count: argCount,
    enclosing_start_byte: frames.at(-1)?.startIndex ?? null,
    receiver,
    receiver_class: fieldClass ?? (receiverName ? receiverClass(receiverName, frames, st.module) : null),
    scope_names: [...names].sort()
  };
}

// Constructor-style classes become classes[] entries anchored at their function's start byte (so a
// default export of the function anchors the class too); a `F.prototype.m` target needs F to be a
// module-level definition of this file, and a real `class F` keeps its own entry.
function pushConstructorClasses(st) {
  const declared = new Set(st.classes.map((c) => c.name));
  for (const [name, { start, methods }] of st.ctorClasses) {
    const start_byte = start ?? st.topLevel.get(name) ?? null;
    if (start_byte === null || declared.has(name)) continue;
    st.classes.push({ name, extends: null, implements: [], methods, start_byte });
  }
}

function finish(st) {
  pushConstructorClasses(st);
  for (const { entry, name } of st.defaultRefs) if (st.topLevel.has(name)) entry.start_byte = st.topLevel.get(name);
  const exported = new Set(st.exports.map((e) => e.name));
  const defaultStarts = new Set(st.exports.filter((e) => e.name === "default").map((e) => e.start_byte));
  const classStart = new Map(st.classes.map((c) => [c.name, c.start_byte]));
  for (const fn of st.functions) {
    // a method is exported with its class; a function when top-level (qualified_name === name) and
    // named in exports, or when it is the default export's definition
    fn.exported = fn.class
      ? exported.has(fn.class) || defaultStarts.has(classStart.get(fn.class))
      : (fn.qualified_name === fn.name && exported.has(fn.name)) || defaultStarts.has(fn.start_byte);
  }
  return {
    functions: st.functions.sort(byStart),
    calls: st.calls.map((c) => finishCall(c, st)).sort(byStart),
    imports: st.imports,
    exports: st.exports.sort(byStart),
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
  walk(tree, st, HANDLERS, CURSOR_HANDLERS);
  return finish(st);
}

// ---- import resolution ----------------------------------------------------------------------------

const PROBE_EXTENSIONS = [".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts"];

function probe(base, filePaths) {
  if (base === null) return null;
  const candidates = [
    ...(base ? [base, ...PROBE_EXTENSIONS.map((ext) => base + ext)] : []),
    ...PROBE_EXTENSIONS.map((ext) => posix.join(base, `index${ext}`))
  ];
  return candidates.find((c) => filePaths.has(c)) ?? null;
}

// tsconfig `paths` targets for a specifier: an exact key, else keys with one trailing `*`, longest
// prefix first.
function pathTargets(specifier, paths) {
  if (!paths || typeof paths !== "object") return [];
  const entries = Object.entries(paths).filter(([, targets]) => Array.isArray(targets));
  const exact = entries.find(([key]) => key === specifier);
  if (exact) return exact[1].filter((t) => typeof t === "string");
  const wildcard = entries
    .filter(([key]) => key.indexOf("*") === key.length - 1 && specifier.startsWith(key.slice(0, -1)))
    .sort(([a], [b]) => b.length - a.length)[0];
  if (!wildcard) return [];
  const rest = specifier.slice(wildcard[0].length - 1);
  return wildcard[1].filter((t) => typeof t === "string").map((t) => t.replace("*", rest));
}

// `namespaces` is part of the shared contract (Java / PHP / C#); JavaScript ignores it.
// resolve.mjs memoises resolveImportSpecifier per run on this key: a relative specifier resolves from the
// importing file's directory; any other depends on the specifier (and the run's tsconfig) alone.
export const importCacheKey = ({ specifier, fromPath }) =>
  typeof specifier === "string" && (specifier === "." || specifier === ".." || specifier.startsWith("./") || specifier.startsWith("../")) ? `${posix.dirname(fromPath)}\u0000${specifier}` : specifier;

export function resolveImportSpecifier({ specifier, fromPath, filePaths, configs }) {
  if (typeof specifier !== "string" || specifier === "") return null;
  if (specifier === "." || specifier === ".." || specifier.startsWith("./") || specifier.startsWith("../")) {
    const hit = probe(repoPath(posix.join(posix.dirname(fromPath), specifier)), filePaths);
    return hit ? { path: hit, confidence: "exact" } : null;
  }
  const options = configs?.tsconfig?.compilerOptions;
  if (!options) return null;
  const baseUrl = typeof options.baseUrl === "string" ? options.baseUrl : ".";
  for (const target of pathTargets(specifier, options.paths)) {
    const hit = probe(repoPath(posix.join(baseUrl, target)), filePaths);
    if (hit) return { path: hit, confidence: "exact" };
  }
  if (typeof options.baseUrl === "string") {
    const hit = probe(repoPath(posix.join(baseUrl, specifier)), filePaths);
    if (hit) return { path: hit, confidence: "heuristic" };
  }
  return null;
}
