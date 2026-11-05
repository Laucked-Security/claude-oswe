// SP10 graph conformance suite: every language module must pass the same cases (a)-(h) against its
// fixture tree under test-fixtures/graph/<stack>/. One test per case letter, so a failing language
// names its gap. Later tasks grow IMPLEMENTED; the cases themselves do not change per language.
import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { extname, join, dirname, relative, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseSource, langIdForFile } from "../graph/parser.mjs";
import { loadSurface } from "../graph/surface.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..", "..");
const FIXTURES_DIR = join(REPO_ROOT, "test-fixtures", "graph");
const REFERENCES_DIR = join(REPO_ROOT, "skills", "audit", "references");

// [stack, language module id under graph/lang/]
const IMPLEMENTED = [["node", "javascript"], ["python", "python"], ["java", "java"]];

// Unbalanced braces/parens: a syntax error in every supported grammar (PHP needs its open tag,
// otherwise the text is inline HTML).
const brokenSource = (ext) => (ext === ".php" ? "<?php\n" : "") + "class Broken {\n  m( {\n    {{\n";

function listSupportedFiles(dir) {
  const out = [];
  const visit = (abs) => {
    for (const entry of readdirSync(abs, { withFileTypes: true })) {
      const child = join(abs, entry.name);
      if (entry.isDirectory()) visit(child);
      else if (entry.isFile() && langIdForFile(entry.name)) out.push(relative(dir, child).split(sep).join("/"));
    }
  };
  visit(dir);
  return out.sort();
}

async function extractTree(mod, stack, dir) {
  const surface = loadSurface(stack, REFERENCES_DIR);
  const files = [];
  for (const path of listSupportedFiles(dir)) {
    // CRLF checkouts are read as LF so offsets match the committed (eol=lf) fixture on every platform.
    const sourceText = readFileSync(join(dir, path), "utf8").replace(/\r\n/g, "\n");
    const tree = await parseSource(langIdForFile(path), sourceText);
    try {
      const extract = mod.extractFile({ tree, path, sourceText, frameworks: mod.lang.frameworks, surface });
      files.push({ path, hasError: tree.rootNode.hasError, extract });
    } finally {
      tree.delete();
    }
  }
  return files;
}

const all = (files, key) => files.flatMap((f) => f.extract[key].map((item) => ({ path: f.path, ...item })));

for (const [stack, moduleId] of IMPLEMENTED) {
  const fixtureDir = join(FIXTURES_DIR, stack);
  let loaded = null;
  const load = () =>
    (loaded ??= (async () => {
      const mod = await import(pathToFileURL(join(HERE, "..", "graph", "lang", `${moduleId}.mjs`)).href);
      return { mod, files: await extractTree(mod, stack, fixtureDir) };
    })());

  test(`${stack}: fixture files parse without errors and extract every field`, async () => {
    const { files } = await load();
    assert.ok(files.length >= 2, "fixture has at least two supported files");
    for (const f of files) {
      assert.equal(f.hasError, false, `${f.path} parses cleanly`);
      for (const key of ["functions", "calls", "imports", "exports", "classes", "routes", "sources", "sinks", "not_extracted"]) {
        assert.ok(Array.isArray(f.extract[key]), `${f.path}: ${key} is an array`);
      }
      assert.ok(f.extract.namespace === null || typeof f.extract.namespace === "string", `${f.path}: namespace`);
    }
  });

  test(`${stack}: (a) at least one method and one arrow/lambda function`, async () => {
    const fns = all((await load()).files, "functions");
    assert.ok(fns.some((f) => f.kind === "method"), "a function with kind method");
    assert.ok(fns.some((f) => f.kind === "arrow" || f.kind === "lambda"), "a function with kind arrow or lambda");
  });

  test(`${stack}: (b) an import specifier resolves to another fixture file`, async () => {
    const { mod, files } = await load();
    const filePaths = new Set(files.map((f) => f.path));
    const namespaces = new Map(files.map((f) => [f.path, f.extract.namespace]));
    const resolved = files.flatMap((f) =>
      f.extract.imports
        .map((imp) => mod.resolveImportSpecifier({ specifier: imp.specifier, fromPath: f.path, filePaths, configs: {}, namespaces }))
        .filter((r) => r && r.path !== f.path && filePaths.has(r.path))
    );
    assert.ok(resolved.length >= 1, "at least one import resolves to another fixture file");
    for (const r of resolved) assert.ok(["exact", "heuristic"].includes(r.confidence));
  });

  test(`${stack}: (c) a POST route, and a route with non-empty middleware_texts`, async () => {
    const routes = all((await load()).files, "routes");
    assert.ok(routes.some((r) => r.http_method === "POST"), "a route with http_method POST");
    assert.ok(routes.some((r) => r.middleware_texts.length > 0), "a route with middleware_texts");
  });

  test(`${stack}: (d) a source with kind params or query`, async () => {
    const sources = all((await load()).files, "sources");
    assert.ok(sources.some((s) => s.kind === "params" || s.kind === "query"));
  });

  test(`${stack}: (e) a sink with class cmd-exec`, async () => {
    const sinks = all((await load()).files, "sinks");
    assert.ok(sinks.some((s) => s.class === "cmd-exec"));
  });

  // A language whose bare calls can never name a variable (lang.callableLocals false: Java, C#, PHP)
  // emits no scope names at all, so the resolver's shadowing rule never fires for it.
  test(`${stack}: (f) a call whose scope_names shadow its callee_text (none at all without callable locals)`, async () => {
    const { mod, files } = await load();
    const calls = all(files, "calls");
    if (mod.lang.callableLocals) assert.ok(calls.some((c) => c.scope_names.includes(c.callee_text)));
    else {
      assert.ok(calls.length > 0, "the fixture has calls");
      for (const c of calls) assert.equal(c.scope_names.length, 0, `${c.path}: ${c.callee_text}`);
    }
  });

  test(`${stack}: (g) a class with a non-null extends`, async () => {
    const classes = all((await load()).files, "classes");
    assert.ok(classes.some((c) => typeof c.extends === "string" && c.extends.length > 0));
  });

  test(`${stack}: (h) a broken file reports hasError and extraction does not throw`, async () => {
    const { mod } = await load();
    const tmp = mkdtempSync(join(tmpdir(), `oswe-graph-conf-${stack}-`));
    try {
      cpSync(fixtureDir, tmp, { recursive: true });
      const ext = extname(listSupportedFiles(fixtureDir)[0]);
      writeFileSync(join(tmp, `broken${ext}`), brokenSource(ext));
      const files = await extractTree(mod, stack, tmp);
      const broken = files.find((f) => f.path === `broken${ext}`);
      assert.ok(broken, "broken file was extracted");
      assert.equal(broken.hasError, true);
      assert.ok(Array.isArray(broken.extract.functions));
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
}
