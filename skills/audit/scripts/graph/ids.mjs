// Deterministic identities for the SP10 application graph (spec §1.3). A node id is the first 12 hex
// characters of SHA-1 over a per-type identity string that carries the AST start offset, so two
// constructs on one line never collide:
//   function  "fn:<path>:<qualified_name>:<start_byte>"     source  "source:<path>:<start_byte>"
//   sink      "sink:<path>:<start_byte>"                     route   "route:<path>:<start_byte>"
//   file      "file:<path>"
// edgeKey(type, from, to, line, start_byte) is the edge identity used to de-duplicate edges; it is
// never emitted. PURE: no I/O.
import { createHash } from "node:crypto";

const IDENTITY = {
  function: (path, qualifiedName, startByte) => `fn:${path}:${qualifiedName}:${startByte}`,
  source: (path, startByte) => `source:${path}:${startByte}`,
  sink: (path, startByte) => `sink:${path}:${startByte}`,
  route: (path, startByte) => `route:${path}:${startByte}`,
  file: (path) => `file:${path}`
};

export function nodeId(type, ...parts) {
  if (!Object.hasOwn(IDENTITY, type)) throw new TypeError(`unknown node type: ${String(type)}`);
  return createHash("sha1").update(IDENTITY[type](...parts)).digest("hex").slice(0, 12);
}

export function edgeKey(type, from, to, line, startByte) {
  return JSON.stringify([type, from, to ?? null, line ?? null, startByte ?? null]);
}
