import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseSource, loadLanguage, langIdForFile, parserAvailable, LANG_IDS, VENDOR_DIR } from "../../graph/parser.mjs";

test("every LANG_ID loads and parses a one-line snippet", async () => {
  const snippets = [
    ["javascript", "f(1)"],
    ["typescript", "f(1)"],
    ["tsx", "<a/>"],
    ["python", "f(1)"],
    ["java", "class A{}"],
    ["php", "<?php f(1);"],
    ["c_sharp", "class A{}"]
  ];
  assert.deepEqual(snippets.map(([id]) => id), LANG_IDS);
  for (const [id, src] of snippets) {
    const tree = await parseSource(id, src);
    assert.equal(tree.rootNode.hasError, false, id);
  }
});

test("langIdForFile maps extensions and returns null otherwise", () => {
  assert.equal(langIdForFile("a/b.mjs"), "javascript");
  assert.equal(langIdForFile("a/b.cs"), "c_sharp");
  assert.equal(langIdForFile("a/b.rb"), null);
});

test("parserAvailable reports ok:false with a reason on a missing vendor dir, never throws", async () => {
  const r = await parserAvailable({ vendorDir: join(tmpdir(), "nope") });
  assert.equal(r.ok, false);
  assert.ok(r.reason.length > 0);
});

test("a failed probe of a bad vendor dir does not poison loads from the real vendor dir", async () => {
  assert.equal((await parserAvailable({ vendorDir: join(tmpdir(), "nope") })).ok, false);
  assert.deepEqual(await parserAvailable(), { ok: true });
  assert.equal(VENDOR_DIR.replaceAll("\\", "/").endsWith("/skills/audit/vendor/tree-sitter"), true);
});

test("a returned tree stays usable and exposes the syntax structure", async () => {
  const tree = await parseSource("python", "def f(x):\n    return g(x)\n");
  const call = tree.rootNode.descendantsOfType("call")[0];
  assert.equal(call.childForFieldName("function").text, "g");
  assert.deepEqual([call.startPosition.row, call.startPosition.column], [1, 11]);
});

test("loadLanguage rejects an unsupported language id; a parse error is reported via hasError", async () => {
  await assert.rejects(loadLanguage("ruby"), /unsupported language id: ruby/);
  const tree = await parseSource("javascript", "f(((");
  assert.equal(tree.rootNode.hasError, true);
});

test("grammars are committed gzipped and load from the .gz files", async () => {
  for (const id of LANG_IDS) {
    assert.equal(existsSync(join(VENDOR_DIR, `tree-sitter-${id}.wasm.gz`)), true, `${id}.wasm.gz`);
    assert.equal(existsSync(join(VENDOR_DIR, `tree-sitter-${id}.wasm`)), false, `raw ${id}.wasm must not be vendored`);
  }
  const python = await loadLanguage("python");
  assert.ok(python.abiVersion > 0);
  assert.equal((await parseSource("python", "f(1)")).rootNode.hasError, false);
});
