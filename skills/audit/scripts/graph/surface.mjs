// Surface-pattern classification for the SP10 application graph. The `surface` token blocks in
// skills/audit/references/<stack>.md are plain grep-style strings (`eval(`, `.query(`, `@RequestParam`,
// `$_GET`, `php://input`, ...). The per-language extractors need to know WHICH AST node category each
// token can match, so every token is classified into one of seven shapes:
//   call       dotted/bare callee, matched as a suffix of the call's callee text
//   member     `.name` / `->name` member access or method name
//   decorator  annotation / attribute / decorator name (`@X`, `[X]`, `#[X`)
//   chain      dotted access path (`req.body`, `$_GET`), matched as a prefix
//   key        a Mongo-style operator key (`$where`)
//   word       a bare identifier
//   literal    a URL-ish or header-name string (`php://input`, `X-User-Role`)
// PURE: no I/O beyond reading the reference page through the SP3 loader. No LLM, no network.
import { loadSurfaceBlock } from "../surface-scan.mjs";

const ROLES = ["sources", "sinks", "sanitizers", "auth_markers"];
// Dotted/`$` tokens are call targets for sinks/sanitizers and access paths for sources/auth markers.
const CALL_ROLES = new Set(["sinks", "sanitizers"]);

const LITERAL_HEADER_RE = /^[A-Z][A-Za-z0-9]*(-[A-Za-z0-9]+)+$/;
const DECORATOR_PREFIX_RE = /^(#\[|@|\[)/;
const KEY_RE = /^\$[a-z]+$/;

// The one shared normal form. Extractors apply it to callee / member / decorator AST text before
// comparing, so `Runtime.getRuntime().exec` (AST) and the pattern `Runtime.getRuntime().exec` both
// become `Runtime.getRuntime.exec`, and `$this->authorize` becomes `$this.authorize`.
export function normalizeToken(text) {
  return text.replace(/\s+/g, "").replaceAll("()", "").replaceAll("::", ".").replaceAll("->", ".");
}

// First matching rule wins. Returns [shape, text-before-normalizeToken].
function shapeOf(token, role) {
  if (token.includes("://") || LITERAL_HEADER_RE.test(token)) return ["literal", token];
  if (DECORATOR_PREFIX_RE.test(token)) return ["decorator", token.replace(DECORATOR_PREFIX_RE, "").replace(/[(\]]+$/, "")];
  if (KEY_RE.test(token)) return ["key", token];
  if (token.startsWith(".") || token.startsWith("->")) {
    // strip the prefix, then a trailing `(` or a `('...` fragment (`->middleware('auth` -> `middleware`)
    return ["member", token.replace(/^(\.|->)/, "").replace(/\((['"].*)?$/, "")];
  }
  if (token.endsWith("(")) return ["call", token.slice(0, -1)];
  if (token.includes(".") || token.includes("::") || token.includes("->") || token.startsWith("$")) {
    return [CALL_ROLES.has(role) ? "call" : "chain", token];
  }
  return ["word", token];
}

export function classifyPattern(token, role) {
  if (typeof token !== "string") throw new TypeError(`surface token must be a string, got ${typeof token}`);
  if (!ROLES.includes(role)) throw new TypeError(`unknown surface role: ${String(role)}`);
  const [shape, text] = shapeOf(token, role);
  const normalized = normalizeToken(text);
  if (normalized === "") throw new TypeError(`surface token ${JSON.stringify(token)} has no pattern text`);
  return { raw: token, shape, normalized };
}

// Same semantics as loadSurfaceBlock (which carries the stack-name path-traversal guard): null for an
// invalid stack name or a stack without a reference page / surface block. Otherwise each role is the
// block's token list, classified, in the block's original order; an absent role (sanitizers is
// optional) yields [].
export function loadSurface(stack, referencesDir) {
  const block = loadSurfaceBlock(stack, referencesDir);
  if (!block) return null;
  return Object.fromEntries(ROLES.map((role) => [role, (block[role] ?? []).map((t) => classifyPattern(t, role))]));
}
