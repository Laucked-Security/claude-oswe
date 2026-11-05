import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { walkFiles, DEFAULT_EXCLUDES } from "../../graph/walk.mjs";

// Real temp dirs: `base/project` is the audited root, `base/outside` is a sibling escape target.
// Both are removed when the test ends.
function fixture(t) {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "oswe-walk-")));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const root = join(base, "project");
  const outside = join(base, "outside");
  mkdirSync(root, { recursive: true });
  mkdirSync(outside, { recursive: true });
  return { base, root, outside };
}

function put(root, rel, content = "// x\n") {
  const abs = join(root, ...rel.split("/"));
  mkdirSync(join(abs, ".."), { recursive: true });
  writeFileSync(abs, content);
  return abs;
}

// Symlinks need elevated privileges on some Windows machines: skip (not fail) when EPERM.
function link(t, target, path, type) {
  try {
    symlinkSync(target, path, type);
    return true;
  } catch (e) {
    if (e.code === "EPERM") {
      t.skip("symlinks need elevated privileges on this machine");
      return false;
    }
    throw e;
  }
}

const walk = (root, extra = {}) => walkFiles({ projectDir: root, scopeRealpath: realpathSync(root), ...extra });
const byPath = (files) => Object.fromEntries(files.map((f) => [f.path, f]));
const DIR_LINK = process.platform === "win32" ? "junction" : "dir";

test("DEFAULT_EXCLUDES is the documented list", () => {
  assert.deepEqual(DEFAULT_EXCLUDES, ["vendor", "node_modules", "dist", "build", "out", "target", "bin", "obj", ".git", ".oswe"]);
});

test("excluded directories are skipped entirely, at any depth, and never listed", (t) => {
  const { root } = fixture(t);
  put(root, "src/app.js");
  put(root, "node_modules/lib/index.js");
  put(root, "a/b/node_modules/c.js");
  put(root, "vendor/x.php");
  put(root, ".git/hooks/pre.js");
  put(root, "dist/bundle.js");
  put(root, "src/build/gen.py");
  assert.deepEqual(walk(root).map((f) => f.path), ["src/app.js"]);
});

test("excludes can be overridden", (t) => {
  const { root } = fixture(t);
  put(root, "src/app.js");
  put(root, "node_modules/lib/index.js");
  put(root, "custom/skip.js");
  const files = walk(root, { excludes: ["custom"] });
  assert.deepEqual(files.map((f) => f.path), ["node_modules/lib/index.js", "src/app.js"]);
});

test("*.min.js / *.min.mjs / *.min.cjs are skipped as minified; admin.js is not", (t) => {
  const { root } = fixture(t);
  put(root, "a.min.js", "var a=1;");
  put(root, "b.min.mjs", "var b=1;");
  put(root, "c.min.cjs", "var c=1;");
  put(root, "admin.js", "var d=1;");
  const files = byPath(walk(root));
  for (const p of ["a.min.js", "b.min.mjs", "c.min.cjs"]) {
    assert.equal(files[p].status, "skipped", p);
    assert.equal(files[p].skip_reason, "minified", p);
    assert.equal(files[p].langId, "javascript", p);
  }
  assert.equal(files["admin.js"].status, "ok");
  assert.equal("skip_reason" in files["admin.js"], false);
});

test("a file of exactly 1 MiB is ok, 1 MiB + 1 byte is skipped as too_large", (t) => {
  const { root } = fixture(t);
  put(root, "exact.js", "a".repeat(1048576));
  put(root, "big.js", "a".repeat(1048576 + 1));
  const files = byPath(walk(root));
  assert.equal(files["exact.js"].status, "ok");
  assert.equal(files["exact.js"].bytes, 1048576);
  assert.equal(files["big.js"].status, "skipped");
  assert.equal(files["big.js"].skip_reason, "too_large");
  assert.equal(files["big.js"].bytes, 1048577);
});

test("maxBytes is configurable", (t) => {
  const { root } = fixture(t);
  put(root, "small.py", "x = 1\n");
  const [f] = walk(root, { maxBytes: 3 });
  assert.equal(f.status, "skipped");
  assert.equal(f.skip_reason, "too_large");
});

test("minified is reported ahead of too_large", (t) => {
  const { root } = fixture(t);
  put(root, "huge.min.js", "a".repeat(2000));
  const [f] = walk(root, { maxBytes: 10 });
  assert.equal(f.skip_reason, "minified");
  assert.equal(f.bytes, 2000);
});

test("a symlink to a file outside the root is skipped as out_of_scope", (t) => {
  const { root, outside } = fixture(t);
  put(root, "src/app.js");
  const secret = put(outside, "secret.js", "module.exports = 'secret';");
  if (!link(t, secret, join(root, "src", "evil.js"), "file")) return;
  const files = byPath(walk(root));
  assert.equal(files["src/app.js"].status, "ok");
  assert.equal(files["src/evil.js"].status, "skipped");
  assert.equal(files["src/evil.js"].skip_reason, "out_of_scope");
  assert.equal(files["src/evil.js"].langId, "javascript");
  assert.equal(files["src/evil.js"].bytes, 0);
});

test("a symlink to a file inside the root is treated like any other file", (t) => {
  const { root } = fixture(t);
  const real = put(root, "src/real.js", "f(1);\n");
  if (!link(t, real, join(root, "alias.js"), "file")) return;
  const files = byPath(walk(root));
  assert.equal(files["alias.js"].status, "ok");
  assert.equal(files["alias.js"].bytes, 6);
  assert.equal(files["src/real.js"].status, "ok");
});

test("a dangling symlink is skipped as unreadable", (t) => {
  const { root } = fixture(t);
  if (!link(t, join(root, "gone.js"), join(root, "dangling.js"), "file")) return;
  const [f] = walk(root);
  assert.equal(f.path, "dangling.js");
  assert.equal(f.status, "skipped");
  assert.equal(f.skip_reason, "unreadable");
  assert.equal(f.bytes, 0);
});

test("a directory symlink / junction is never followed", (t) => {
  const { root, outside } = fixture(t);
  put(root, "src/app.js");
  put(root, "inner/in.js");
  put(outside, "leak/secret.js");
  if (!link(t, join(outside, "leak"), join(root, "linked-out"), DIR_LINK)) return;
  if (!link(t, join(root, "inner"), join(root, "linked-in"), DIR_LINK)) return;
  assert.deepEqual(walk(root).map((f) => f.path), ["inner/in.js", "src/app.js"]);
});

test("only supported-language files are listed; .rb and .png never are", (t) => {
  const { root } = fixture(t);
  put(root, "script.rb", "puts 1");
  put(root, "logo.png", "PNG");
  put(root, "Makefile", "all:");
  put(root, "README.md", "# hi");
  put(root, "app.js");
  put(root, "app.ts");
  put(root, "view.tsx");
  put(root, "tool.py");
  put(root, "Main.java");
  put(root, "index.php");
  put(root, "Svc.cs");
  assert.deepEqual(
    walk(root).map((f) => [f.path, f.langId]),
    [
      ["Main.java", "java"], ["Svc.cs", "c_sharp"], ["app.js", "javascript"], ["app.ts", "typescript"],
      ["index.php", "php"], ["tool.py", "python"], ["view.tsx", "tsx"]
    ]
  );
});

test("a file with a BOM and CRLF line endings is ok", (t) => {
  const { root } = fixture(t);
  const content = "﻿const a = 1;\r\nconst b = 2;\r\n";
  put(root, "bom.js", content);
  const [f] = walk(root);
  assert.equal(f.status, "ok");
  assert.equal("skip_reason" in f, false);
  assert.equal(f.bytes, Buffer.byteLength(content));
});

test("output is sorted by plain string comparison and uses forward slashes", (t) => {
  const { root } = fixture(t);
  for (const p of ["b.js", "Beta.js", "a/z.js", "a/b/c.py", "a-b.js", "Z.js"]) put(root, p);
  const paths = walk(root).map((f) => f.path);
  assert.deepEqual(paths, ["Beta.js", "Z.js", "a-b.js", "a/b/c.py", "a/z.js", "b.js"]);
  assert.ok(paths.every((p) => !p.includes("\\")));
});

test("abs is the absolute path; path is relative to projectDir", (t) => {
  const { root } = fixture(t);
  const abs = put(root, "src/deep/app.js");
  const [f] = walk(root);
  assert.equal(f.path, "src/deep/app.js");
  assert.equal(f.abs, abs);
});

test("walking a sub-scope lists only that subtree, with paths still relative to projectDir", (t) => {
  const { root } = fixture(t);
  put(root, "top.js");
  put(root, "svc/api/h.py");
  put(root, "svc/other.py");
  const files = walkFiles({ projectDir: root, scopeRealpath: realpathSync(join(root, "svc", "api")) });
  assert.deepEqual(files.map((f) => f.path), ["svc/api/h.py"]);
});

test("an empty project yields an empty list", (t) => {
  const { root } = fixture(t);
  assert.deepEqual(walk(root), []);
});
