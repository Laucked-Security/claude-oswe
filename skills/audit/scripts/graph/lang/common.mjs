// Helpers shared verbatim by the SP10 language modules (javascript.mjs, python.mjs, ...): small AST
// accessors, the pre-order TreeCursor walk, the receiver-class scope lookup and the repo-relative
// path normal form. Language specifics (node types, handlers, frames' extra fields) stay in each
// module. PURE: no I/O.
import { posix } from "node:path";
import { matchesPattern } from "../match.mjs";

export const lookup = (table, key) => (key != null && Object.hasOwn(table, key) ? table[key] : null);

// ---- small AST helpers ----------------------------------------------------------------------------

export const field = (node, name) => node?.childForFieldName(name) ?? null;
export const namedOf = (node) => (node ? node.namedChildren.filter((c) => c.type !== "comment") : []);
export const childrenOfType = (node, type) => (node ? node.namedChildren.filter((c) => c.type === type) : []);
export const lineOf = (node) => node.startPosition.row + 1;
export const anonLabel = (node) => `<anon>@${node.startPosition.row + 1}:${node.startPosition.column + 1}`;

export const firstMatch = (patterns, candidates) => patterns.find((p) => candidates.some((c) => matchesPattern(p, c))) ?? null;
export const byStart = (a, b) => a.start_byte - b.start_byte;

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
