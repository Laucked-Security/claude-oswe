import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseSurfaceBlock, loadSurfaceBlock, scanPartition, contentKey } from "../surface-scan.mjs";

const BLOCK = {
  sources: ["request.args", "request.get_json"],
  sinks: ["render_template_string", "eval(", "os.system"],
  sanitizers: ["shlex.quote"],
  // includes a BARE word-token ("permission_required") so both-side boundary matching is exercised —
  // every token ending in "(" or starting with "@" would mask the left-boundary check.
  auth_markers: ["@login_required", "login_required(", "permission_required"]
};

function project(filesByName) {
  const root = mkdtempSync(join(tmpdir(), "oswe-surface-"));
  for (const [rel, body] of Object.entries(filesByName)) {
    const abs = join(root, rel);
    mkdirSync(join(abs, ".."), { recursive: true });
    writeFileSync(abs, body);
  }
  return root;
}

test("parseSurfaceBlock extracts the JSON from a ```surface fence; null when absent", () => {
  const md = "# ref\nprose\n```surface\n{ \"sources\": [\"x\"], \"sinks\": [], \"sanitizers\": [], \"auth_markers\": [] }\n```\nmore prose";
  assert.deepEqual(parseSurfaceBlock(md).sources, ["x"]);
  assert.equal(parseSurfaceBlock("no block here"), null);
});

test("a source+sink file with no auth marker -> counts set, source_and_auth_files 0", () => {
  const root = project({ "app.py": "x = request.args\nrender_template_string(x)\n" });
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["app.py"] }, BLOCK, root);
  assert.equal(v.scannable, true);
  assert.equal(v.sources, 1);
  assert.equal(v.sinks, 1);
  assert.equal(v.auth_markers, 0);
  assert.equal(v.source_and_auth_files, 0);
  assert.ok(typeof v.content_key === "string" && v.content_key.length === 64); // sha256 hex
});

test("source∧auth co-location: a file with BOTH source and auth marker increments source_and_auth_files", () => {
  const root = project({ "v.py": "@login_required\ndef f(): return request.args\nrender_template_string(1)\n" });
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["v.py"] }, BLOCK, root);
  assert.equal(v.sources, 1);
  assert.equal(v.auth_markers, 1);
  assert.equal(v.source_and_auth_files, 1); // the source file is itself gated
});

test("auth markers in a NON-source file do not raise source_and_auth_files", () => {
  const root = project({
    "open.py": "x = request.args\nos.system(x)\n",        // source+sink, ungated
    "mw.py": "@login_required\ndef guard(): pass\n"        // auth marker, but no source
  });
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["open.py", "mw.py"] }, BLOCK, root);
  assert.equal(v.sources, 1);
  assert.equal(v.auth_markers, 1);
  assert.equal(v.source_and_auth_files, 0); // the source file (open.py) is NOT gated
});

test("sink_hits is a TRUE total (not per-file capped) so density survives", () => {
  const root = project({ "dense.py": "eval(1); eval(2); eval(3); eval(4); eval(5)\n" });
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["dense.py"] }, BLOCK, root);
  assert.equal(v.sinks, 1);        // file-count (presence)
  assert.equal(v.sink_hits, 5);    // true total occurrences
});

test("auth matching is strict on the RIGHT boundary: a longer identifier does not match", () => {
  const root = project({ "x.py": "permission_required_NOT = 1\n" }); // bare token + trailing word char
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["x.py"] }, BLOCK, root);
  assert.equal(v.auth_markers, 0); // "permission_required" embedded in a longer identifier → no match
});

test("auth matching is strict on the LEFT boundary too (suppressor must not over-match)", () => {
  // a word char BEFORE the token must reject it — otherwise a fake auth marker suppresses the fail-safe
  const root = project({ "y.py": "xx@login_required\nz = request.args\nrender_template_string(z)\n" });
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["y.py"] }, BLOCK, root);
  assert.equal(v.auth_markers, 0);        // "@login_required" preceded by word-char "x" is not a decorator
  assert.equal(v.source_and_auth_files, 0); // so the source file is correctly seen as ungated
});

test("a real decorator at line start (non-word before) DOES match", () => {
  const root = project({ "ok.py": "@login_required\ndef f(): return request.args\n" });
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["ok.py"] }, BLOCK, root);
  assert.equal(v.auth_markers, 1); // boundary check doesn't break the legitimate case
});

test("an unreadable/escaping file is skipped, not fatal (cannot raise risk by skipping)", () => {
  const root = project({ "real.py": "render_template_string(request.args)\n" });
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["real.py", "../escapes.py", "missing.py"] }, BLOCK, root);
  assert.equal(v.scannable, true);
  assert.equal(v.sinks, 1); // real.py counted; the escaping/missing files silently skipped
});

test("no surface block (unsupported stack) -> scannable:false, no counts", () => {
  const root = project({ "a.pl": "system($x)\n" });
  const v = scanPartition({ partition_id: "p", stack: "perl", files: ["a.pl"] }, null, root);
  assert.equal(v.scannable, false);
  assert.equal(v.sources, undefined);
});

test("contentKey is order-independent and stable", () => {
  assert.equal(contentKey(["b.py", "a.py"]), contentKey(["a.py", "b.py"]));
  assert.equal(contentKey(["a.py"]).length, 64);
});

test("an empty-string auth_marker token does NOT hang the scan (regression: indexOf('',0)===0)", () => {
  const root = project({ "x.py": "x = 1\nrequest.args\nos.system(x)\n" });
  const bad = { ...BLOCK, auth_markers: ["@login_required", ""] }; // typo: trailing empty token
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["x.py"] }, bad, root);
  // hang would timeout the whole node --test process; reaching this assertion proves no infinite loop.
  assert.equal(v.scannable, true);
  assert.equal(v.auth_markers, 0); // the empty token contributes nothing
});

test("an empty-string source/sink token is also a no-op (defensive)", () => {
  const root = project({ "x.py": "request.args\nos.system(1)\n" });
  const bad = { ...BLOCK, sinks: ["os.system", ""], sources: ["request.args", ""] };
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["x.py"] }, bad, root);
  assert.equal(v.sinks, 1);    // os.system counted once, empty token contributes nothing
  assert.equal(v.sources, 1);
});

test("loadSurfaceBlock rejects a traversal-attempt stack name (path-traversal guard)", () => {
  // STACK_RE = /^[a-z0-9_-]+$/ — anything containing /, ., or path separators must return null
  // BEFORE join(referencesDir, ...) — the FS is never touched.
  assert.equal(loadSurfaceBlock("../../../etc/passwd", "/anywhere"), null);
  assert.equal(loadSurfaceBlock("../x", "/anywhere"), null);
  assert.equal(loadSurfaceBlock("python/extra", "/anywhere"), null);
  assert.equal(loadSurfaceBlock(".", "/anywhere"), null);
  assert.equal(loadSurfaceBlock("", "/anywhere"), null);
  assert.equal(loadSurfaceBlock(null, "/anywhere"), null);
});
