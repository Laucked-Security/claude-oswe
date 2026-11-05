// Helpers shared verbatim by the SP10 language modules (javascript.mjs, python.mjs, ...): small AST
// accessors, the source / sink emitter, the pre-order TreeCursor walk, the receiver-class scope
// lookup and the repo-relative path normal form. Language specifics (node types, handlers, frames' extra fields) stay in each
// module. PURE: no I/O.
import { posix } from "node:path";
import { matchesPattern } from "../match.mjs";
import { sinkClassFor } from "../sink-classes.mjs";

export { lastSegment } from "../text.mjs";

export const lookup = (table, key) => (key != null && Object.hasOwn(table, key) ? table[key] : null);

// ---- small AST helpers ----------------------------------------------------------------------------

export const field = (node, name) => node?.childForFieldName(name) ?? null;
export const namedOf = (node) => (node ? node.namedChildren.filter((c) => c.type !== "comment") : []);
export const childrenOfType = (node, type) => (node ? node.namedChildren.filter((c) => c.type === type) : []);
export const lineOf = (node) => node.startPosition.row + 1;
export const anonLabel = (node) => `<anon>@${node.startPosition.row + 1}:${node.startPosition.column + 1}`;

export const firstMatch = (patterns, candidates) => patterns.find((p) => candidates.some((c) => matchesPattern(p, c))) ?? null;
export const byStart = (a, b) => a.start_byte - b.start_byte;

// ---- sources and sinks ----------------------------------------------------------------------------

// A module's emitter: `emitMatches(node, candidates, st, { sources, sinks, sinkAt })` pushes at most one
// source and one sink per AST node — the first matching pattern in surface order — onto st.sources /
// st.sinks (patterns from st.surface). A source sits at `node` with kind `sourceKind(pattern)`; a sink
// at `sinkAt` (default `node`; a call's callee anchor), with the `stack`'s sink class and the first
// candidate's text as callee. `node` may be a TreeCursor (startIndex / startPosition).
export function matchEmitter(stack, sourceKind) {
  return (node, candidates, st, { sources = false, sinks = false, sinkAt = node } = {}) => {
    const source = sources ? firstMatch(st.surface.sources, candidates) : null;
    const sink = sinks ? firstMatch(st.surface.sinks, candidates) : null;
    if (source) st.sources.push({ line: lineOf(node), start_byte: node.startIndex, kind: sourceKind(source), pattern: source.raw });
    if (sink) st.sinks.push({ line: lineOf(sinkAt), start_byte: sinkAt.startIndex, class: sinkClassFor(sink.normalized, stack), callee: candidates[0].text, pattern: sink.raw });
  };
}

// ---- walk -----------------------------------------------------------------------------------------

// Pre-order walk. `handlers` (type -> fn(node, st, ctx)) receive a Node, `cursorHandlers` the
// TreeCursor itself (for the most frequent node types, most of which are skipped without
// materialising a Node); both get ctx = { parentType, field } and only run on named nodes. A handler
// may return an exit callback, run when the walk leaves that node.
export function walk(tree, st, handlers, cursorHandlers) {
  const cursor = tree.walk();
  const types = [];
  const exits = [];
  let depth = 0;
  try {
    for (;;) {
      const type = (types[depth] = cursor.nodeType);
      const handler = handlers.get(type);
      const cursorHandler = handler ? undefined : cursorHandlers.get(type);
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

// ---- scopes ---------------------------------------------------------------------------------------

// A scope's frame of `bindings` / `classOf` (see receiverClass): a function's (with its start byte
// and qualified name), a block's or a class body's. NO_FRAME binds nothing; it is never written to.
export const newFrame = (startIndex = null, qualifiedName = null) => ({ startIndex, qualifiedName, bindings: new Set(), classOf: new Map() });
export const NO_FRAME = newFrame();

export function bind(frame, name, cls) {
  if (!frame || !name) return;
  frame.bindings.add(name);
  if (cls) frame.classOf.set(name, cls);
  else frame.classOf.delete(name);
}

// For the modules whose state keeps `st.scopes` (innermost last: `{ frame, fn: true }` for a
// function, `{ frame, cls }` for a class body, `{ frame }` for a block) and `st.moduleName` (Java,
// PHP, C#). innermostFunction is the innermost function's frame, unless a class body lies in between:
// code in a nested / anonymous class's initializer belongs to no function (module level).
export function innermostFunction(st) {
  for (let i = st.scopes.length - 1; i >= 0; i--) {
    if (st.scopes[i].fn) return st.scopes[i].frame;
    if (st.scopes[i].cls) return null;
  }
  return null;
}
export const innermostClassScope = (st) => st.scopes.findLast((s) => s.cls) ?? null;
export const innermostClass = (st) => innermostClassScope(st)?.cls ?? null;
export const enclosingName = (st) => innermostFunction(st)?.qualifiedName ?? innermostClass(st)?.qualifiedName ?? st.moduleName;

// The class a receiver name is demonstrably bound to: the innermost scope binding the name wins (a
// plain parameter or local shadows an outer constructed / annotated binding). Frames carry
// `bindings: Set<name>` and `classOf: Map<name, class>`.
export function receiverClass(name, frames, moduleFrame) {
  for (const frame of [...frames].reverse()) {
    if (frame.classOf.has(name)) return frame.classOf.get(name);
    if (frame.bindings.has(name)) return null;
  }
  return moduleFrame.classOf.get(name) ?? null;
}

// ---- import resolution ----------------------------------------------------------------------------

// Repo-relative normal form; null when the path escapes the repository root.
export function repoPath(path) {
  const normal = posix.normalize(path);
  if (normal === ".." || normal.startsWith("../") || posix.isAbsolute(normal)) return null;
  return normal === "." ? "" : normal;
}
