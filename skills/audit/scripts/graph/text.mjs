// Tiny text helpers shared by the SP10 graph modules (match.mjs, resolve.mjs, lang/*) and the graph
// consumers (check-chain-structure, partition-graph, enumerate-paths, write-report). PURE.

// The last `.`-separated segment of a dotted name (`a.b.C` -> `C`; no dot -> the whole text).
export const lastSegment = (text) => text.slice(text.lastIndexOf(".") + 1);

// THE repo-relative path normal form every helper compares paths in: backslashes -> "/", leading
// "./" segments stripped. pathKey adds the one case policy: folded on win32 only (its file system is
// case-insensitive), kept everywhere else. null / undefined -> "".
export const normalizeRepoPath = (p) => String(p ?? "").replace(/\\/g, "/").replace(/^(\.\/)+/, "");
export const pathKeyFor = (platform) => (platform === "win32" ? (p) => normalizeRepoPath(p).toLowerCase() : normalizeRepoPath);
export const pathKey = pathKeyFor(process.platform);
