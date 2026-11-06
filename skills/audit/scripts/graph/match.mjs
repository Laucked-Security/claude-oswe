// Shape-aware surface-pattern matching for the SP10 application graph, shared by every language
// extractor. A pattern is a classified surface token from surface.mjs (`{ raw, shape, normalized }`);
// a candidate is `{ category, text }` built by an extractor from one AST node, where `text` has
// already been through normalizeToken. Each shape accepts a fixed set of candidate categories and
// compares on `.`-separated segments (spec §2.5):
//   call       call/new/member        text equals the pattern or ends with "." + pattern; a bare
//                                     pattern (`exec(`, `Template(`) never matches a callee whose first
//                                     segment is a self-like receiver (`self.exec`, `$this.exec`) —
//                                     a method of the same name — while `jinja2.Template` still matches
//   member     call                   last segment equals the pattern
//   decorator  decorator              first segment equals the pattern
//   chain      member/identifier/call text equals the pattern or starts with pattern + "."
//   key        key                    equality
//   word       identifier/type/call/new  last segment equals the pattern
//   literal    literal                equality
// `member` patterns (`.query(`, `->raw(`) name a method being CALLED, so a plain member reference such
// as `req.query` never matches them.
// PURE: no I/O. An unknown shape or category never matches.
import { lastSegment } from "./text.mjs";

const CATEGORIES_BY_SHAPE = {
  call: new Set(["call", "new", "member"]),
  member: new Set(["call"]),
  decorator: new Set(["decorator"]),
  chain: new Set(["member", "identifier", "call"]),
  key: new Set(["key"]),
  word: new Set(["identifier", "type", "call", "new"]),
  literal: new Set(["literal"])
};

const firstSegment = (text) => text.split(".", 1)[0];
// Receivers naming the object itself (normalized: `$this->x` is `$this.x`, `super().x` is `super.x`).
const SELF_LIKE = new Set(["self", "cls", "this", "$this", "super"]);

const COMPARE_BY_SHAPE = {
  call: (text, p) => text === p || (text.endsWith("." + p) && (p.includes(".") || !SELF_LIKE.has(firstSegment(text)))),
  member: (text, p) => lastSegment(text) === p,
  decorator: (text, p) => firstSegment(text) === p,
  chain: (text, p) => text === p || text.startsWith(p + "."),
  key: (text, p) => text === p,
  word: (text, p) => lastSegment(text) === p,
  literal: (text, p) => text === p
};

export function matchesPattern(pattern, candidate) {
  if (!Object.hasOwn(CATEGORIES_BY_SHAPE, pattern.shape)) return false;
  if (!CATEGORIES_BY_SHAPE[pattern.shape].has(candidate.category)) return false;
  return COMPARE_BY_SHAPE[pattern.shape](candidate.text, pattern.normalized);
}
