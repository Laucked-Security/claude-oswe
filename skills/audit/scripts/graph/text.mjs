// Tiny text helpers shared by the SP10 graph modules (match.mjs, resolve.mjs, lang/*). PURE.

// The last `.`-separated segment of a dotted name (`a.b.C` -> `C`; no dot -> the whole text).
export const lastSegment = (text) => text.slice(text.lastIndexOf(".") + 1);
