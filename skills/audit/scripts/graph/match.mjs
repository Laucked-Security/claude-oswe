// Shape-aware surface-pattern matching for the SP10 application graph, shared by every language
// extractor. A pattern is a classified surface token from surface.mjs (`{ raw, shape, normalized }`);
// a candidate is `{ category, text }` built by an extractor from one AST node, where `text` has
// already been through normalizeToken. Each shape accepts a fixed set of candidate categories and
// compares on `.`-separated segments (spec §2.5):
//   call       call/new/member        a dotted pattern: text equals it or ends with "." + pattern;
//                                     a bare pattern (`eval(`, `exec(`): text equals it — a bare builtin
//                                     never matches a method of the same name (`self.exec`)
//   member     call                   last segment equals the pattern
//   decorator  decorator              first segment equals the pattern
//   chain      member/identifier/call text equals the pattern or starts with pattern + "."
//   key        key                    equality
//   word       identifier/type/call/new  last segment equals the pattern
//   literal    literal                equality
// `member` patterns (`.query(`, `->raw(`) name a method being CALLED, so a plain member reference such
// as `req.query` never matches them.
// PURE: no I/O. An unknown shape or category never matches.

const CATEGORIES_BY_SHAPE = {
  call: new Set(["call", "new", "member"]),
  member: new Set(["call"]),
  decorator: new Set(["decorator"]),
  chain: new Set(["member", "identifier", "call"]),
  key: new Set(["key"]),
  word: new Set(["identifier", "type", "call", "new"]),
  literal: new Set(["literal"])
};

const lastSegment = (text) => text.slice(text.lastIndexOf(".") + 1);
const firstSegment = (text) => text.split(".", 1)[0];

const COMPARE_BY_SHAPE = {
  call: (text, p) => text === p || (p.includes(".") && text.endsWith("." + p)),
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
