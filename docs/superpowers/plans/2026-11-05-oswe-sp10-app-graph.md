# SP10 App Graph Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic, schema-validated application graph with a vendored tree-sitter WASM parser and wire it into the audit pipeline as partition-by-reachability, analyzer candidate paths, and a structural-proof ceiling in `apply-verdicts`.

**Architecture:** Sidecar: one new phase (`build-graph.mjs`) and three consumers (`partition-graph.mjs`, `enumerate-paths.mjs`, `check-chain-structure.mjs`), all zero-runtime-dependency Node CLIs following the house `--file/--out` + exit-code contract. The parser runtime and seven grammars are vendored binaries verified by a manifest in CI. Every existing helper keeps its contract; `graph: null` degrades to today's behaviour.

**Tech Stack:** Node ≥ 20 ESM, `node:test`, `web-tree-sitter` 0.27.x loader + grammars copied from `tree-sitter-wasms` 0.1.x (dev-only npm), AJV dev-only for validator regeneration.

**Spec:** `docs/superpowers/specs/2026-11-05-oswe-sp10-app-graph-design.md`

## Global Constraints

- Node ≥ 20; runtime stays zero-dependency: the user never runs `npm install`.
- `skills/audit/vendor/` total size ≤ 10 MiB (CI-enforced).
- `exact` call edges only for demonstrated bindings (spec §1.4); `name-only` is never structural evidence.
- `graph.json` contains identifiers and line numbers only — never source text.
- `graph: null` or zero routes ⇒ every downstream helper's output is byte-identical to today.
- All 320 pipeline tests and 63 benchmark tests stay green at every commit.
- Helper CLI contract: `--file <in.json> --out <out.json> [--checkpoint-dir <abs>]`; exit 0 ok / 1 malformed input / 2 IO|usage.
- Stack ids are `php | node | python | java | dotnet`; language ids are `javascript | typescript | tsx | python | java | php | c_sharp`; framework ids are `express | nest | flask | django | fastapi | spring | laravel | symfony | aspnet`.
- Commit messages: `feat(sp10): …` / `test(sp10): …` / `docs(sp10): …`, ending with the attribution trailer.

## Review Focus

1. A symlink inside scope pointing outside the project root must be skipped by the walker (`skip_reason: "out_of_scope"`), never parsed — test in Task 4.
2. A file with a UTF-8 BOM, CRLF line endings, or invalid UTF-8 bytes must yield `parse_status: "error"` or a correct parse, never a crash — test in Task 4 (BOM/CRLF parse ok) and Task 7 (invalid bytes ⇒ error).
3. A `tsconfig.json` with comments or trailing commas (JSONC) must not abort the graph: resolution config parse failure ⇒ config ignored, counted in `stats.config_errors` — test in Task 6.
4. A repository with thousands of routes must still respect the `max_paths`/depth caps and finish; path enumeration must not be exponential on diamond call graphs — test in Task 13 (diamond graph, cap respected).
5. The same file listed under two fallback partitions, or path case differences on Windows, must not duplicate a file across graph partitions — test in Task 12.

---

## File map

**Create**
- `skills/audit/vendor/tree-sitter/{web-tree-sitter.mjs, tree-sitter.wasm, tree-sitter-<lang>.wasm ×7, MANIFEST.json, LICENSES.md}` — vendored parser.
- `skills/audit/scripts/build-grammars.mjs` — dev-only vendoring script.
- `skills/audit/scripts/graph/parser.mjs` — WASM loader + `langIdForFile`.
- `skills/audit/scripts/graph/surface.mjs` — surface-pattern classification.
- `skills/audit/scripts/graph/walk.mjs` — scope-confined file enumeration.
- `skills/audit/scripts/graph/sink-classes.mjs` — pattern → sink class table.
- `skills/audit/scripts/graph/match.mjs` — shape-aware matching of a classified surface pattern against an AST candidate, shared by every extractor.
- `skills/audit/scripts/graph/lang/common.mjs` — the shared TreeCursor walk, `receiverClass` shadowing rule and `repoPath` used by every extractor.
- `skills/audit/scripts/graph/lang/{javascript,python,java,php,csharp}.mjs` — extractors.
- `skills/audit/scripts/graph/resolve.mjs` — import + call resolution.
- `skills/audit/scripts/graph/ids.mjs` — node/edge identity.
- `skills/audit/scripts/graph/build-graph.mjs` — CLI assembling `graph.json`.
- `skills/audit/scripts/partition-graph.mjs`, `enumerate-paths.mjs`, `check-chain-structure.mjs` — consumers.
- `skills/audit/schemas/graph.schema.json`, `structural-check.schema.json`.
- `test-fixtures/graph/<stack>/` — multi-file graph fixtures + `graph.expected.json` (separate from the existing single-file audit fixtures so `check-structure.mjs` rules 3–4 are untouched).
- `skills/audit/scripts/test/graph/*.test.mjs` — graph tests; `test/graph-conformance.test.mjs` — the shared suite.
- `.github/scripts/check-vendor.mjs` — manifest + size gate.
- `benchmark/webgoat-truth.json`.

**Modify**
- `skills/audit/scripts/cache-wrap.mjs` — add `dirVersionDigest`.
- `skills/audit/scripts/build-validators.mjs` — register the two new schemas.
- `skills/audit/schemas/{finding,final-finding,chain,report}.schema.json` — additive fields.
- `skills/audit/scripts/aggregate-findings.mjs` — merge `candidate_path_ids`.
- `skills/audit/scripts/apply-verdicts.mjs` — `--structural` + confidence ceiling.
- `skills/audit/scripts/write-report.mjs`, `render-html.mjs` — `app_graph` section.
- `skills/audit/SKILL.md`, `agents/oswe-analyzer.md`, `agents/oswe-verifier.md` — pipeline wiring.
- `.github/scripts/check-structure.mjs`, `.github/workflows/ci.yml`.
- `benchmark/{build-ledger,metrics,score-nodegoat}.mjs`, `benchmark/BENCHMARK.md`, `README.md`, `.claude-plugin/plugin.json`.

---

### Task 1: Vendor the parser and prove every grammar loads

**Files:**
- Create: `skills/audit/scripts/build-grammars.mjs`, `skills/audit/vendor/tree-sitter/*`, `skills/audit/scripts/graph/parser.mjs`, `.github/scripts/check-vendor.mjs`
- Modify: `skills/audit/scripts/package.json` (devDependencies `web-tree-sitter: "^0.27.1"`, `tree-sitter-wasms: "^0.1.13"`; script `"build:grammars": "node build-grammars.mjs"`)
- Test: `skills/audit/scripts/test/graph/parser.test.mjs`

**Interfaces:**
- Produces: `parser.mjs` exports
  - `VENDOR_DIR` (absolute path of `skills/audit/vendor/tree-sitter`)
  - `LANG_IDS = ["javascript","typescript","tsx","python","java","php","c_sharp"]`
  - `langIdForFile(relPath) → langId | null` — `.js .mjs .cjs .jsx → javascript`, `.ts .mts .cts → typescript`, `.tsx → tsx`, `.py → python`, `.java → java`, `.php → php`, `.cs → c_sharp`
  - `async loadLanguage(langId, { vendorDir = VENDOR_DIR } = {}) → Language` (memoised per langId)
  - `async parseSource(langId, sourceText, { vendorDir } = {}) → Tree`
  - `async parserAvailable({ vendorDir } = {}) → { ok: true } | { ok: false, reason }` — never throws.

- [ ] **Step 1: Write the failing tests**

```js
// test/graph/parser.test.mjs
test("every LANG_ID loads and parses a one-line snippet", async () => {
  for (const [id, src] of [["javascript","f(1)"],["typescript","f(1)"],["tsx","<a/>"],["python","f(1)"],["java","class A{}"],["php","<?php f(1);"],["c_sharp","class A{}"]]) {
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
  assert.equal(r.ok, false); assert.ok(r.reason.length > 0);
});
```

- [ ] **Step 2: Run to verify failure** — `node --test test/graph/` from `skills/audit/scripts`; expected: cannot find `../graph/parser.mjs`.

- [ ] **Step 3: Write `build-grammars.mjs`** — dev-only: `npm install` then copy `node_modules/web-tree-sitter/{web-tree-sitter.js → web-tree-sitter.mjs, tree-sitter.wasm}` and `node_modules/tree-sitter-wasms/out/tree-sitter-<id>.wasm` for each `LANG_ID` into `vendor/tree-sitter/`; write `MANIFEST.json` as `{ "<file>": { "package", "version", "sha256" } }` sorted by file; write `LICENSES.md` from both packages' LICENSE files. Verify the copied loader is ESM-importable; if the package ships only CJS, copy `web-tree-sitter.cjs` and have `parser.mjs` load it via `createRequire`.

- [ ] **Step 4: Run `npm run build:grammars`** in `skills/audit/scripts`; expected: 9 files + MANIFEST + LICENSES in `vendor/tree-sitter/`, total < 10 MiB (`du -sh`).

- [ ] **Step 5: Write `parser.mjs`** — `Parser.init({ locateFile: () => join(vendorDir, "tree-sitter.wasm") })` once; `Language.load(join(vendorDir, \`tree-sitter-${id}.wasm\`))` memoised. `parserAvailable` wraps init + a `javascript` load in try/catch.

- [ ] **Step 6: Run tests** — expected: 3 pass.

- [ ] **Step 7: Write `.github/scripts/check-vendor.mjs`** — recompute sha256 of every file in `vendor/tree-sitter/` except `MANIFEST.json`/`LICENSES.md`, compare to the manifest (missing/extra/mismatch ⇒ exit 1), and fail if the directory exceeds 10 MiB. Run it: expected `PASS`.

- [ ] **Step 8: Commit** — `feat(sp10): vendor web-tree-sitter + 7 grammars, parser loader, vendor gate`

---

### Task 2: Graph and structural-check schemas

**Files:**
- Create: `skills/audit/schemas/graph.schema.json`, `skills/audit/schemas/structural-check.schema.json`
- Modify: `skills/audit/scripts/build-validators.mjs:20-31` (add `"graph.schema.json": "graph"`, `"structural-check.schema.json": "structuralCheck"`), regenerate `validators.mjs`
- Test: `skills/audit/scripts/test/graph/schemas.test.mjs`

**Interfaces:**
- Produces: `graph.schema.json` = `{ version: 1, generated_by: string, stats: {...}, nodes: [...], edges: [...] }` with node/edge shapes exactly as spec §1.1–1.2 (all objects `additionalProperties: false`; `confidence` enums as specified; `stats` requires `files_total, files_parsed, files_error, files_skipped, functions, calls_total, calls_exact, calls_name_only, calls_unresolved, routes_by_auth, coverage_matrix, config_errors`).
- Produces: `structural-check.schema.json` = `{ findings: { "<OSWE-N>": { structural_path: "proven"|"absent"|"n/a", reason: string } }, transitions: { "<CHAIN-N>": [ { index: integer, structural_path, reason } ] } }`.

- [ ] **Step 1: Write failing tests** — `validate("graph", minimalGraph).ok === true`; a graph whose edge has `confidence: "maybe"` fails; `validate("structural-check", { findings: {}, transitions: {} }).ok === true`; a finding entry with `structural_path: "yes"` fails.
- [ ] **Step 2: Run** — expected: `validate` throws unknown kind.
- [ ] **Step 3: Write both schemas; add them to `EXPORT_NAME`; `npm run build`** in `skills/audit/scripts`.
- [ ] **Step 4: Run tests + `node .github/scripts/check-structure.mjs`** — expected: tests pass; gate rule 5 lists `graph.schema.json -> export const graph` and `structural-check.schema.json -> export const structuralCheck`.
- [ ] **Step 5: Commit** — `feat(sp10): graph + structural-check schemas, validators regenerated`

---

### Task 3: Surface-pattern classification

**Files:**
- Create: `skills/audit/scripts/graph/surface.mjs`, `skills/audit/scripts/graph/sink-classes.mjs`
- Test: `skills/audit/scripts/test/graph/surface.test.mjs`

**Interfaces:**
- Produces: `classifyPattern(token, role) → { raw, shape, normalized }` with `role ∈ "sources"|"sinks"|"sanitizers"|"auth_markers"` and `shape ∈ "call"|"member"|"decorator"|"chain"|"key"|"word"|"literal"`. Rules, in order:
  1. contains `://`, or matches `/^[A-Z][A-Za-z0-9]*(-[A-Za-z0-9]+)+$/` → `literal`, normalized = raw.
  2. starts with `@`, `[`, or `#[` → `decorator`; strip those prefixes and any trailing `(`/`]`.
  3. matches `/^\$[a-z]+$/` → `key` (Mongo operators); normalized = raw.
  4. starts with `.` or `->` → `member`; strip the prefix and a trailing `(`; strip a trailing `('` fragment (`->middleware('auth` → `middleware`).
  5. ends with `(` → `call`; strip `(`; normalize `::` to `.`.
  6. contains `.`, `::`, or `->`, or starts with `$` → role `sinks`/`sanitizers` ⇒ `call` (dotted, suffix match); role `sources`/`auth_markers` ⇒ `chain` (prefix match). Normalize `::`→`.`, `->`→`.`, remove `()`.
  7. otherwise → `word`.
  After the shape-specific stripping, every `normalized` value passes through one shared
  `normalizeToken(text)` = remove whitespace, remove `()`, `::` → `.`, `->` → `.`. Extractors apply the
  same `normalizeToken` to callee / member / decorator text before comparing, so `Runtime.getRuntime().exec`
  ⇒ `Runtime.getRuntime.exec` and `$this->authorize(` ⇒ call `$this.authorize` match their AST text.
- Produces: `loadSurface(stack, referencesDir) → { sources, sinks, sanitizers, auth_markers } | null` (each an array of classified patterns; reuses `parseSurfaceBlock` from `../surface-scan.mjs`).
- Produces: `sink-classes.mjs` export `sinkClassFor(normalizedPattern, stack) → class` by first regex match over the lower-cased normalized token; `stack` is the stack id. Order of evaluation = order listed:
  `cmd-exec` ← `/(child_process|execsync|spawn|execfile|system|popen|proc_open|passthru|shell_exec|processbuilder|runtime\.getruntime|process\.start|processstartinfo|useshellexecute|subprocess)/`, plus `/^exec$/` when `stack !== "python"`;
  `eval` ← `/(^eval$|newfunction|runinnewcontext|mvel|parseexpression|getvalue|preg_replace)/`, plus `/^exec$/` when `stack === "python"`;
  `deser` ← `/(unserialize|objectinputstream|readobject|xmldecoder|xstream|jsontypeinfo|yaml\.load|pickle|marshal|binaryformatter|netdatacontract|losformatter|objectstateformatter|typenamehandling|javascriptserializer)/`;
  `nosql` ← `/^\$/`;
  `template` ← `/(render_template_string|^template$|lodash\.template)/`;
  `sql` ← `/(query|mysqli|db\.raw|db\.select|whereraw|statement\.execute|cursor\.execute|^raw$|^extra$|rawsql|sqlcommand|executereader|executenonquery|fromsqlraw|executesqlraw|sequelize)/`;
  `include` ← `/(include|^require(_once)?$)/`;
  `file-write` ← `/(move_uploaded_file|file_put_contents|writefile)/`;
  `file-read` ← `/(send_file|send_from_directory|sendfile|readfile|path\.combine)/`;
  `ssrf` ← `/(axios|fetch|http\.request|^got$|requests\.)/`;
  `xxe` ← `/(documentbuilder|saxparser|xmldocument|xmlreader|lxml)/`;
  `trust-boundary` ← `/(setattribute|putvalue|addcookie)/`;
  `redirect` ← `/redirect/`;
  default `other`.

- [ ] **Step 1: Write failing tests** — one assertion per shape using these exact tokens: `eval(`→call/`eval`; `.query(`→member/`query`; `@RequestParam`→decorator/`RequestParam`; `[FromBody]`→decorator/`FromBody`; `#[IsGranted`→decorator/`IsGranted`; `$where`(sinks)→key; `$_GET`(sources)→chain/`$_GET`; `req.body`(sources)→chain; `os.system`(sinks)→call/`os.system`; `Runtime.getRuntime().exec`(sinks)→call/`Runtime.getRuntime.exec`; `Auth::check`(auth_markers)→chain/`Auth.check`; `->middleware('auth`→member/`middleware`; `ProcessBuilder`→word; `php://input`→literal; `X-User-Role`→literal. Plus: **every token of every real `references/<stack>.md` block classifies without throwing and never yields `undefined` shape**. Plus `sinkClassFor("child_process.exec","node") === "cmd-exec"`, `sinkClassFor("pickle.loads","python") === "deser"`, `sinkClassFor("$ne","node") === "nosql"`, `sinkClassFor("exec","python") === "eval"`, `sinkClassFor("exec","php") === "cmd-exec"`, `sinkClassFor("Template","python") === "template"`, `sinkClassFor("raw","python") === "sql"`, `sinkClassFor("frobnicate","node") === "other"`. Plus `normalizeToken("Runtime.getRuntime().exec") === "Runtime.getRuntime.exec"` and `normalizeToken("$this->authorize") === "$this.authorize"`.
- [ ] **Step 2: Run** — expected: module not found.
- [ ] **Step 3: Implement `surface.mjs` and `sink-classes.mjs`.**
- [ ] **Step 4: Run tests** — expected: all pass.
- [ ] **Step 5: Commit** — `feat(sp10): surface pattern shapes + sink class table`

---

### Task 4: Scope-confined file walker

**Files:**
- Create: `skills/audit/scripts/graph/walk.mjs`
- Test: `skills/audit/scripts/test/graph/walk.test.mjs`

**Interfaces:**
- Consumes: `confinePath(projectDir, rel)` from `../confine-path.mjs`; `langIdForFile` from `./parser.mjs`.
- Produces: `walkFiles({ projectDir, scopeRealpath, excludes = DEFAULT_EXCLUDES, maxBytes = 1048576 }) → [{ path, abs, langId, bytes, status: "ok"|"skipped", skip_reason? }]` sorted by `path`; `DEFAULT_EXCLUDES = ["vendor","node_modules","dist","build","out","target","bin","obj",".git",".oswe"]`. Only files with a non-null `langId` are returned. `skip_reason ∈ "too_large" | "minified" | "out_of_scope" | "unreadable"`; `minified` = filename matches `/\.min\.[cm]?js$/`.

- [ ] **Step 1: Write failing tests** — excluded dir skipped entirely (not even listed); `a.min.js` ⇒ `skipped/minified`; 1 MiB + 1 byte file ⇒ `skipped/too_large`; **symlink to a file outside the root ⇒ `skipped/out_of_scope`** (skip the test with `t.skip()` if `symlinkSync` throws EPERM on Windows); `.rb` file not listed; a file with BOM + CRLF ⇒ `status: "ok"`; output sorted and uses forward slashes.
- [ ] **Step 2: Run** — expected: module not found.
- [ ] **Step 3: Implement** using `readdirSync(..., { withFileTypes: true })`, `confinePath` for every candidate, `statSync` for size.
- [ ] **Step 4: Run tests** — expected: pass.
- [ ] **Step 5: Commit** — `feat(sp10): graph file walker`

---

### Task 5: JavaScript/TypeScript extractor + conformance suite

**Files:**
- Create: `skills/audit/scripts/graph/match.mjs`, `skills/audit/scripts/graph/lang/javascript.mjs`, `test-fixtures/graph/node/{server.js, routes/users.js, services/userService.js, dao/userDao.js}` (no `graph.expected.json` yet — goldens are built-graph snapshots and start in Task 7), `skills/audit/scripts/test/graph/match.test.mjs`, `skills/audit/scripts/test/graph-conformance.test.mjs`, `skills/audit/scripts/test/graph/javascript.test.mjs`

**Interfaces:**
- Consumes: `parseSource`, `loadSurface`, `sinkClassFor`, `normalizeToken`.
- Produces: `match.mjs` export `matchesPattern(pattern, candidate) → boolean` where `pattern` is a classified surface pattern (`{ raw, shape, normalized }`) and `candidate = { category, text }` with `category ∈ "call" | "new" | "member" | "decorator" | "identifier" | "type" | "key" | "literal"` and `text` already passed through `normalizeToken`. Rules by shape (segments split on `.`): `call` ⇒ category `call`/`new`/`member` and — for a dotted pattern — `text` equals the pattern or ends with `"." + pattern`, while a dot-less pattern (`eval(`, `exec(`, `system(`, `Template(`) matches a bare callee by equality or a dotted callee whose first segment is **not** a self-like receiver (`self`, `cls`, `this`, `$this`, `super`) — so `jinja2.Template(...)` is the sink and `self.exec(...)` (a method named like a builtin) is not; `member` ⇒ category `call` only (every member-shape token is a method call; matching bare member references would turn `req.query` into a `.query(` sink) and the last segment of `text` equals the pattern; `decorator` ⇒ category `decorator` and the first segment equals the pattern; `chain` ⇒ category `member`/`identifier`/`call` and `text` equals the pattern or starts with `pattern + "."`; `key` ⇒ category `key` and equality; `word` ⇒ category `identifier`/`type`/`call`/`new` and the last segment equals the pattern; `literal` ⇒ category `literal` and equality. Every extractor builds candidates from its AST and calls this — no extractor re-implements shape matching.
- Produces: every language module exports
  - `lang = { id, stack, langIds: [...], frameworks: [...], implicitThisCalls: boolean }` (here `{ id: "javascript", stack: "node", langIds: ["javascript","typescript","tsx"], frameworks: ["express","nest"], implicitThisCalls: false }`); `implicitThisCalls` is `true` only for languages where a bare `foo()` inside a method is an implicit `this.foo()` (Java, C#) — the resolver's same-class step for bare callees runs only when it is set. A second descriptor flag, `submoduleImports` (`true` for Python only), lets the resolver fall back from a named binding whose `imported` name is not an export of the target to the specifier `<specifier>.<imported>` resolved as a namespace binding (`from . import views`). A third, `callableLocals` (`true` for JavaScript and Python, `false` for Java, C# and PHP, whose bare calls can never name a variable), says whether a local binding can shadow a bare call: languages with `callableLocals: false` emit `scope_names: []` on every call (so the resolver's shadowing rule never fires) and conformance case (f) is skipped for them.
  - `extractFile({ tree, path, sourceText, frameworks, surface }) → Extract` where `Extract = { functions, calls, imports, exports, classes, routes, sources, sinks, not_extracted }` with:
    - `functions: [{ name, qualified_name, line_start, line_end, start_byte, end_byte, kind, exported, class, param_count }]` (`kind ∈ function|method|arrow|lambda`; anonymous ⇒ `name: "<anon>"`, `qualified_name: "<enclosing>.<anon>@<line>:<col>"`; `param_count` = declared parameters, `null` with rest/varargs/defaults) — calls carry a matching `arg_count` (`null` with spread) so the resolver can pick among overloads by arity
    - `calls: [{ line, start_byte, callee_text, enclosing_start_byte|null, receiver: "this"|null, receiver_class: string|null, scope_names: string[] }]` — `scope_names` = params/locals/closure bindings visible at the call site; `receiver_class` = the class name when the receiver is a plain identifier bound by `new C(...)` in an enclosing scope (module scope included), or declared with a type annotation `C` (variable or parameter — Java/C#/PHP declared types, TS annotations), or when the callee is `this.<prop>.m(...)` and `<prop>` is a class property with a declared type `C` (property declaration, constructor parameter property / promoted constructor parameter, or a `this.<prop> = new C()` assignment in the class); type names reduce to their base identifier (`Repo<T>` ⇒ `Repo`, `ns.Repo` ⇒ `Repo`); `receiver` is `"this"` only for a direct `this.m(...)` (then `receiver_class` is `null` and rule 3 applies); otherwise `null` (spec §1.4 rule 1b).
    - `imports: [{ line, specifier, bindings: [{ imported, local }] | "namespace" | "default" }]`
    - `exports: [{ name, start_byte }]` (`module.exports = {a,b}`, `exports.a`, `export function/const`, `export default` ⇒ name `"default"` only — never a duplicate named export; a `default` entry's `start_byte` is the exported declaration's `start_byte` when the value is a same-file function/class declaration, so the resolver can bind it by offset, else the export statement's offset)
    - `classes: [{ name, extends: string|null, methods: string[], start_byte }]`
    - `namespace: string|null` — the file's declared package/namespace (`package x.y;`, `namespace X;`, C# `namespace X`); `null` for JS/Python.
    - `routes: [{ line, start_byte, http_method, path_pattern, handler_text, middleware_texts: string[], framework }]` — Express `app.use(path?, ...mws, target)` is emitted with `http_method: "USE"` and `handler_text` = the last argument's identifier (the mounted router); Task 7 propagates the mount prefix and middlewares onto the target file's routes.
    - `sources: [{ line, start_byte, kind, pattern }]`, `sinks: [{ line, start_byte, class, callee, pattern }]`
    - `not_extracted: string[]`
  - `resolveImportSpecifier({ specifier, fromPath, filePaths: Set<string>, configs }) → { path, confidence: "exact"|"heuristic" } | null` — JS rules: relative specifiers with extension probing (`.js .mjs .cjs .jsx .ts .tsx .mts`) and `index.*`; `configs.tsconfig?.compilerOptions.{baseUrl,paths}` with a single trailing `*`; bare specifiers ⇒ `null`.
- Express routes: `app|router.<get|post|put|patch|delete|all|use>(path?, ...mws, handler)`; `handler_text` = last argument's identifier text or `"<anon>@<line>:<col>"` for inline functions (which are also emitted as `functions` with that `qualified_name`). Nest: `@Controller(prefix)` + `@Get/@Post/…(path)` on methods; `@UseGuards(...)` guards go to `middleware_texts` as `UseGuards.<GuardName>` (class-level first, then method-level) so the `@UseGuards` auth marker matches on the first segment while the guard name stays visible.
- Source `kind` from the matched pattern: `req.query/@Query→query`, `req.body/@Body→body`, `req.params/@Param→params`, `req.headers/@Headers→header`, `req.cookies→cookie`, `req.files→file`, `process.env→env`, else `body`.

- [ ] **Step 1: Write the fixture** — `server.js`: `const users = require('./routes/users'); function ensureAuthenticated(req,res,next){ next(); } app.use('/users', ensureAuthenticated, users); app.get('/health', (req,res)=>res.send('ok'));`. `routes/users.js`: `const { UserService } = require('../services/userService'); const svc = new UserService(); function run(req, res) { svc.run(req.params.id, req.body.cmd); } router.post('/:id/run', run); function cb() {} function helper(cb) { cb(); } module.exports = router;`. `services/userService.js`: `const child_process = require('child_process'); class UserService { run(id, cmd) { this.exec(cmd); } exec(c) { child_process.exec(c); /* VULN */ } } class AdminService extends UserService { exec(c) {} } module.exports = { UserService, AdminService };`. `dao/userDao.js`: `function find(db, name) { return db.collection('u').find({ name: { $ne: null } }); } module.exports = { find };`. This fixture is what Tasks 12 and 13 assert against: `svc.run` resolves through `receiver_class: "UserService"` (rule 1b), `this.exec` is `name-only` because `AdminService` overrides `exec`, and the mount gives the router's routes the `/users` prefix and `ensureAuthenticated` middleware.
- [ ] **Step 2: Write `graph-conformance.test.mjs`** — for each entry of `IMPLEMENTED = [["node","javascript"]]` (grown by later tasks): build the extract for every fixture file, then assert the **conformance cases**: (a) ≥ 1 `function` with `kind: "method"` and one with `kind: "arrow"` or `"lambda"` (the language's anonymous-function kind); (b) an import whose specifier resolves to another fixture file; (c) a route with `http_method: "POST"` and a non-empty `middleware_texts` somewhere in the fixture; (d) a `source` with `kind: "params"` or `"query"` (Python's surface has no `params` source — route parameters are function arguments); (e) a `sink` with `class: "cmd-exec"`; (f) a call whose `scope_names` contains a name equal to its `callee_text` (the shadowing case) — run only when `lang.callableLocals` is true, otherwise assert every call has `scope_names: []`; (g) a class with `extends` non-null; (h) a deliberately broken file (`broken.<ext>`, written by the test into a temp copy) yields `tree.rootNode.hasError === true` without throwing. Case letters map 1:1 to assertions so a failing language names its gap.
- [ ] **Step 3: Write `javascript.test.mjs`** — language-specific: `module.exports = { run }` ⇒ export `run`; `export default` ⇒ `"default"`; `@Controller('/a') class { @Get('/b') m(){} }` ⇒ route `GET /a/b`; `eval` inside a string literal and a comment ⇒ no sink; `{ $ne: null }` ⇒ nosql sink, `"$ne"` as a free string ⇒ none; `resolveImportSpecifier("./x", "a/b.js", {"a/x/index.js"})` ⇒ `a/x/index.js`; tsconfig `paths: {"@svc/*": ["src/services/*"]}` ⇒ resolves `@svc/user` to `src/services/user.ts`.
- [ ] **Step 4: Run** — expected: module not found.
- [ ] **Step 5: Implement `lang/javascript.mjs`** with tree-sitter queries for `function_declaration`, `method_definition`, `arrow_function`, `call_expression`, `member_expression`, `import_statement`, `export_statement`, `class_declaration`, `decorator`, `pair` (object keys), `require` calls. Use the same queries for `typescript`/`tsx` (their node types are a superset).
- [ ] **Step 6: Run tests** — expected: conformance (a)–(h) + javascript tests pass.
- [ ] **Step 7: Commit** — `feat(sp10): javascript/typescript extractor + graph conformance suite`

---

### Task 6: Import and call resolution

**Files:**
- Create: `skills/audit/scripts/graph/resolve.mjs`
- Test: `skills/audit/scripts/test/graph/resolve.test.mjs`

**Interfaces:**
- Consumes: `Extract` per file and each lang module's `resolveImportSpecifier`.
- Produces:
  - `loadResolutionConfigs(projectDir, scopeRealpath) → { tsconfig, jsconfig, packageJson, composerJson, pyproject, read: [{ path, sha256 }], errors: [{ file, message }] }` — `read` lists every config file found (parsed or not) so Task 7 can hash them into the cache key; JSON parse failures (incl. JSONC) are recorded in `errors`, never thrown.
  - `resolveImports(files, { langModules, filePaths, configs, namespaces }) → Map<"<fromPath>\u0000<specifier>", { path, confidence }>` where `namespaces = Map<path, namespace|null>` built from each file's `Extract.namespace` and passed through to every `resolveImportSpecifier` call.
  - `resolveCalls(files, importMap, { classIndex }) → [{ from_fn_start_byte|null, from_path, line, start_byte, callee_text, to: { path, qualified_name, start_byte } | null, confidence }]` implementing spec §1.4 rules 1, 1b, 2–5 verbatim, where `classIndex = buildClassIndex(files, importMap) → { byName: Map<name, [{ path, extends, methods }]> }`.
- Rule details the signature does not fix: rule 1 looks the callee's **last segment** up among same-file top-level functions — and, only when the file's language declares `lang.implicitThisCalls`, among the enclosing class's methods — only when the callee is a bare identifier (`foo(`), never for `a.foo(`; **rule 1b** applies when `receiver_class` is non-null: the class is looked up in the same file, else through the file's import bindings, else by unique name in `classIndex` (two classes with that name ⇒ `unresolved`); the method is resolved on that class or, if absent there, on its `extends` chain within parsed files; the override check of rule 3 applies to the resolved class; rule 2 applies when the callee's first segment is an import `local` binding — a `namespace` binding resolves `ns.foo` to export `foo` of the target, while a `default` binding resolves `X.m` to method `m` of the class anchored at the target's `default` export (a default export that anchors a function or nothing ⇒ `unresolved`); a class reached through an import must be exported by the target (bind by the export's `start_byte` for aliases), else `unresolved`; the override check walks resolved parent links (`(path, start_byte)` identity, depth ≤ 10) plus unresolved `extends` whose last segment matches, never raw `extends` text; rule 3 applies when `receiver === "this"` and the enclosing class resolves; the override check scans `classIndex.byName` for any class whose `extends` equals the resolved class name and whose `methods` contains the callee; rule 4 counts definitions across **all** files for the bare name; two or more ⇒ `unresolved`. Several same-named definitions in one class/file (overloads) are disambiguated by arity only for languages whose descriptor sets `overloads: true` (Java, C#): `param_count === arg_count` unique ⇒ `exact`, else `name-only` to the first; a single definition whose arity mismatches a known `arg_count` falls through the `extends` chain and is never `exact`; without the flag (JavaScript, Python, PHP) same-named definitions stay `unresolved`; a call inside a `lambda`/`arrow` uses the class of the innermost enclosing method (by byte containment) for rule 3 and implicit-`this`, while a `kind: "function"` expression does not inherit.

- [ ] **Step 1: Write failing tests** — build small in-memory `Extract`s (no parsing): same-file `foo()` ⇒ exact; same name shadowed by a param in `scope_names` ⇒ unresolved; `import {x} from './b'` + `x()` ⇒ exact to `b`'s export `x`; import resolves to a file but no such export ⇒ unresolved; `this.exec()` with no subclass override ⇒ exact; with `AdminService extends UserService` overriding `exec` ⇒ name-only; **rule 1b**: a call with `receiver_class: "UserService"` where `UserService` is an import binding resolving to a class in another file ⇒ exact to that class's `run`, and ⇒ name-only when a subclass overrides it; `receiver_class` naming a class defined in two files ⇒ unresolved; a bare `helper()` defined once in another file with no import ⇒ name-only; defined in two files ⇒ unresolved; `loadResolutionConfigs` on a `tsconfig.json` containing `// comment` and a trailing comma ⇒ `errors.length === 1`, `read.length === 1`, no throw; `namespaces` reaches `resolveImportSpecifier` (assert with a stub lang module).
- [ ] **Step 2: Run** — expected: module not found.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests** — expected: pass.
- [ ] **Step 5: Commit** — `feat(sp10): graded import + call resolution (exact / name-only / unresolved)`

---

### Task 7: `build-graph.mjs` — assembly, ids, stats, cache, null envelope

**Files:**
- Create: `skills/audit/scripts/graph/ids.mjs`, `skills/audit/scripts/graph/build-graph.mjs`
- Modify: `skills/audit/scripts/cache-wrap.mjs` (add `dirVersionDigest`)
- Test: `skills/audit/scripts/test/graph/build-graph.test.mjs`, extend `test/cache-wrap.test.mjs`

**Interfaces:**
- Produces: `dirVersionDigest(dirAbs, { ext = ".mjs" } = {}) → hex` — sha256 over sorted relative paths and file bytes of every `*.mjs` under the dir (recursive).
- Produces: `ids.mjs` — `nodeId(type, parts…) → 12-hex` per spec §1.3 identity strings; `edgeKey(type, from, to, line, start_byte)`.
- Produces: `buildGraph({ projectDir, scopeRealpath, stacks, frameworks, excludes, referencesDir, vendorDir }) → { graph } | { graph: null, reason }` (async) and the CLI `node graph/build-graph.mjs --file <in> --out <out> [--checkpoint-dir <abs>]` with input `{ projectDir, scope_realpath, stacks[], frameworks[], excludes?, referencesDir, vendorDir? }`. Output file is the graph JSON, or `{ "graph": null, "reason": "<msg>" }`. Exit 1 on malformed input (missing `projectDir`/`stacks`/`referencesDir`), 2 on IO.
- Graph assembly: for each walked file → `parseSource` → lang module `extractFile` → nodes; `resolveImports`/`resolveCalls` → edges; route `handler` resolved like a call (bare identifier or `<anon>` function in the same file); `uses_middleware` likewise. **Express mount propagation:** a route entry with `http_method: "USE"` whose `handler_text` resolves through the file's imports to another parsed file is a mount — every route of that file gets `path_pattern = mountPath + ownPath` (collapsing `//`, keeping the child's trailing `/` — Django patterns end with one) and the mount's `middleware_texts` prepended (in order) to its own; an unresolvable mount target is recorded in `not_extracted` as `"mount:<handler_text>"` and the `USE` entry is dropped (no route node). Route `auth` per spec §1.3 using the surface `auth_markers` (shape `decorator`/`call`/`chain`/`word` matched on each middleware text, after `normalizeToken`): any middleware whose name matches a marker ⇒ `authenticated` (whether or not it resolved — the curated name is the evidence); otherwise any unresolved middleware ⇒ `unknown`; otherwise ⇒ `unauthenticated`; C# `AllowAnonymous` forces `unauthenticated`. `enclosing_fn` for sources/sinks = innermost function whose `[start_byte, end_byte]` contains the node. Stats per spec §1.3; `coverage_matrix[stack] = { frameworks_detected, extractors_applied, not_extracted: sorted unique }`. `generated_by` is the constant `"oswe-build-graph/1"` (never a digest — goldens must be stable).
- Goldens: `test-fixtures/graph/<stack>/graph.expected.json` is the pretty-printed (`JSON.stringify(graph, null, 2) + "\n"`) `buildGraph` output for that fixture with `projectDir = scopeRealpath = <fixture dir>`, `referencesDir = skills/audit/references`, `stacks = [<stack>]`, `frameworks` = the fixture's frameworks. The golden test iterates every `test-fixtures/graph/*/` directory that has a `graph.expected.json`, rebuilds, and asserts byte-equality; with `OSWE_UPDATE_GOLDEN=1` it rewrites the golden instead of asserting. This task creates the `node` golden; Tasks 8–11 create theirs.
- Cache: `helperName: "build-graph"`, `inputDigest = sha256Hex(canonicalize({ files: [{path, sha256}], configs: [{path, sha256}], references: [{stack, sha256}], stacks, frameworks, excludes, manifest_sha256 }))`, `versionDigest = sha256Hex(dirVersionDigest(graphDir) + ":" + sha256 of vendor/tree-sitter/web-tree-sitter.mjs)`; payload `{ output: graphOrEnvelope }`, `requiredPayloadKey: "output"`.

- [ ] **Step 1: Write failing tests** — (1) determinism: build the Task 5 fixture twice ⇒ `JSON.stringify` byte-identical; (2) validates against `graph` schema; (3) two sinks on one line ⇒ two sink nodes with distinct ids; (4) a file containing invalid UTF-8 bytes (`Buffer.from([0xff,0xfe,0x00])` + code) ⇒ `parse_status: "error"` for that file, graph still built; (5) `vendorDir` pointing to an empty dir ⇒ `{ graph: null, reason }` and CLI exit 0; (6) mount + auth: the Task 5 fixture yields a route `POST /users/:id/run` with `middlewares` containing the resolved `ensureAuthenticated` function and `auth: "authenticated"`, `/health` ⇒ `unauthenticated`, a route whose only middleware is an unresolved non-marker name ⇒ `unknown`, and no route node for the `USE` entry itself; (7) cache: run CLI twice with `--checkpoint-dir`, second run hits (assert `generated_at` unchanged in the wrapper file); editing `references/node.md` copy (tests use a temp `referencesDir`) ⇒ miss; editing `tsconfig.json` ⇒ miss; (8) `dirVersionDigest` changes when a `lang/*.mjs` byte changes (test on a temp dir copy); (9) performance: building the graph of every `test-fixtures/graph/*` tree present completes in < 2 s wall-clock (`performance.now()`), excluding the one-time WASM init; (10) golden: `test-fixtures/graph/node/graph.expected.json` equals the rebuilt graph byte-for-byte (generate it first with `OSWE_UPDATE_GOLDEN=1`, review it by eye, commit it).
- [ ] **Step 2: Run** — expected: module not found.
- [ ] **Step 3: Implement `ids.mjs`, `dirVersionDigest`, `build-graph.mjs`.**
- [ ] **Step 4: Run all tests** — `node --test` from `skills/audit/scripts`; expected: all previous + new pass.
- [ ] **Step 5: Commit** — `feat(sp10): build-graph CLI (deterministic ids, stats, cache, null envelope)`

---

### Task 8: Python extractor (Flask, Django, FastAPI)

**Files:**
- Create: `skills/audit/scripts/graph/lang/python.mjs`, `test-fixtures/graph/python/{app.py, views/users.py, services/runner.py, urls.py, graph.expected.json}`, `skills/audit/scripts/test/graph/python.test.mjs`
- Modify: `test/graph-conformance.test.mjs` (`IMPLEMENTED` += `["python","python"]`)

**Interfaces:** same module contract as Task 5. Python specifics: `kind: "lambda"` for `lambda`; `exported` = top-level def/class not starting with `_`; routes from `@app.route(path, methods=[...])`, `@bp.route`, `@router.get/post(...)` (FastAPI), `urlpatterns = [path('x/', view), include('a.urls')]` (Django; `include` one level ⇒ route `path_pattern` prefixed, handler resolved through the included module's `urlpatterns`); `middleware_texts` = other decorators on the function (`login_required`, `permission_required(...)`) plus FastAPI `Depends(x)` names; `resolveImportSpecifier`: `from a.b import c` ⇒ `a/b.py` or `a/b/__init__.py` searched from the scope root and from every ancestor directory that contains `__init__.py`; relative `from .x import y` honoured; `source.kind` from `request.args→query`, `request.form/json/data/get_json/POST/body→body`, `request.headers/META→header`, `request.cookies/COOKIES→cookie`, `request.files/FILES→file`, `os.environ→env`.

- [ ] **Step 1: Write fixture** — Flask app with `@app.route('/run', methods=['POST'])` + `@login_required` calling `services.runner.run(request.form['cmd'])` which does `subprocess.run(cmd, shell=True)`; a Django `urls.py` with `include()`; a `def helper(cb): cb()` shadowing case; `class Base: def exec(self)...` + `class Child(Base): def exec(self)...`.
- [ ] **Step 2: Write `python.test.mjs`** — Flask route ⇒ `POST /run` with `middleware_texts: ["login_required"]`; FastAPI `@router.get` ⇒ route; Django `include` ⇒ prefixed route; `from .x import y` resolves; `eval` in a docstring ⇒ no sink.
- [ ] **Step 3: Run** — expected: conformance fails for python (module missing).
- [ ] **Step 4: Implement `lang/python.mjs`**, then generate `test-fixtures/graph/python/graph.expected.json` with `OSWE_UPDATE_GOLDEN=1 node --test test/graph/build-graph.test.mjs`, read it by eye (routes, auth, edges, resolution confidences must match the fixture's intent), and commit it with the extractor.
- [ ] **Step 5: Run tests** — expected: pass, including the golden test.
- [ ] **Step 6: Commit** — `feat(sp10): python extractor (flask/django/fastapi)`

---

### Task 9: Java extractor (Spring)

**Files:**
- Create: `skills/audit/scripts/graph/lang/java.mjs`, `test-fixtures/graph/java/src/main/java/com/ex/{Api.java, UserService.java, AdminService.java, Dao.java, SecurityConfig.java}`, `graph.expected.json`, `skills/audit/scripts/test/graph/java.test.mjs`
- Modify: conformance `IMPLEMENTED` += `["java","java"]`

**Interfaces:** same contract. Java specifics: `qualified_name = <Class>.<method>`; overloads distinct by `start_byte`; `exported` = `public`; routes from `@RequestMapping/@GetMapping/@PostMapping/@PutMapping/@DeleteMapping/@PatchMapping` with class-level `@RequestMapping` prefix; `middleware_texts` = `@PreAuthorize/@Secured/@RolesAllowed` on method or class; a file containing `SecurityFilterChain` ⇒ `not_extracted` entry `"SecurityFilterChain matchers"` and routes in that stack keep their own auth value (no file-level override in SP10); `resolveImportSpecifier`: `import x.y.Z` ⇒ the file whose `namespace` (from `Extract.namespace`, passed in `namespaces`) is `x.y` and whose basename is `Z.java`; same-package unqualified references rely on the resolver's unique-name class lookup; sources from `@RequestParam/@RequestBody/@PathVariable/@RequestHeader/@CookieValue` parameter annotations and `getParameter/getHeader/...` calls. Because Java's surface tokens are written against declared types (`Statement.execute`), every call whose receiver is an identifier with a known declared type also yields a **type-qualified candidate** (`st.execute` ⇒ `Statement.execute`) for sink matching; `callee` keeps the source text. `callableLocals: false`.

- [ ] **Step 1: Write fixture** — `Api.java` controller with `@PostMapping("/run")` + `@PreAuthorize("hasRole('ADMIN')")` calling `userService.run(cmd)` → `Runtime.getRuntime().exec(cmd)`; `AdminService extends UserService` overriding `exec`; a method param shadowing a same-class method name; `Dao.java` with `Statement.execute`.
- [ ] **Step 2: Write `java.test.mjs`** — class prefix + method mapping ⇒ `POST /api/run`; `@PreAuthorize` ⇒ middleware text; overloads ⇒ two function nodes; `SecurityFilterChain` ⇒ `not_extracted` contains `"SecurityFilterChain matchers"`.
- [ ] **Step 3: Run** — expected: fails.
- [ ] **Step 4: Implement**, then generate and eyeball-review `test-fixtures/graph/java/graph.expected.json` (`OSWE_UPDATE_GOLDEN=1 node --test test/graph/build-graph.test.mjs`).
- [ ] **Step 5: Run tests** — expected: pass, including the golden test.
- [ ] **Step 6: Commit** — `feat(sp10): java extractor (spring)`

---

### Task 10: PHP extractor (Laravel, Symfony)

**Files:**
- Create: `skills/audit/scripts/graph/lang/php.mjs`, `test-fixtures/graph/php/{composer.json, routes/web.php, app/Http/Controllers/RunController.php, app/Services/Runner.php, src/Controller/SymfonyController.php}`, `graph.expected.json`, `skills/audit/scripts/test/graph/php.test.mjs`
- Modify: conformance `IMPLEMENTED` += `["php","php"]`

**Interfaces:** same contract. PHP specifics: receiver `this` for `$this->x()`; routes from `Route::get|post|put|patch|delete|any|match(path, handler)` where handler is `[Controller::class, 'method']`, `'Controller@method'`, or a closure; `Route::middleware([...])->group(...)` and `->middleware('auth')` chains populate `middleware_texts` (group middleware applies to every route in the closure); Symfony `#[Route('/x', methods: ['POST'])]` + `#[IsGranted('ROLE_ADMIN')]`; `resolveImportSpecifier`: `use App\Services\Runner;` ⇒ PSR-4 from `configs.composerJson.autoload["psr-4"]`, else any file whose `namespace` (via `namespaces`) is `App\Services` and that declares `class Runner`; sources from `$_GET/$_POST/...` and `$request->input(...)` etc.; sinks incl. `include`/`require` with a variable argument only. `callableLocals: false` (a bare `foo()` always names a function; `$cb()` variable calls are `not_extracted` as `"variable call"`), `implicitThisCalls: false`; `$this->prop->m()` ⇒ `receiver_class` from a typed property, a promoted constructor parameter, or a `$this->prop = new C()` assignment.

- [ ] **Step 1: Write fixture** — Laravel route group with `auth` middleware wrapping `Route::post('/run', [RunController::class, 'run'])`; controller calls `$this->runner->run($request->input('cmd'))`; `Runner::run` does `shell_exec($cmd)`; Symfony controller with attributes; a `$this->exec()` override case.
- [ ] **Step 2: Write `php.test.mjs`** — group middleware propagates to the inner route; `[X::class,'m']` handler resolves to `X.m`; attribute route ⇒ `POST /sym/run` with `middleware_texts: ["IsGranted"]`; PSR-4 resolution; `require 'fixed.php'` ⇒ no sink, `require $p` ⇒ `include` sink.
- [ ] **Step 3: Run** — expected: fails.
- [ ] **Step 4: Implement**, then generate and eyeball-review `test-fixtures/graph/php/graph.expected.json` (`OSWE_UPDATE_GOLDEN=1 node --test test/graph/build-graph.test.mjs`).
- [ ] **Step 5: Run tests** — expected: pass, including the golden test.
- [ ] **Step 6: Commit** — `feat(sp10): php extractor (laravel/symfony)`

---

### Task 11: C# extractor (ASP.NET Core & classic)

**Files:**
- Create: `skills/audit/scripts/graph/lang/csharp.mjs`, `test-fixtures/graph/dotnet/{Program.cs, Controllers/RunController.cs, Services/Runner.cs, Services/AdminRunner.cs}`, `graph.expected.json`, `skills/audit/scripts/test/graph/csharp.test.mjs`
- Modify: conformance `IMPLEMENTED` += `["dotnet","csharp"]` (second element = the `lang/<id>.mjs` module id, as for the other stacks)

**Interfaces:** same contract (`lang.id = "csharp"`, `langIds: ["c_sharp"]`, `stack: "dotnet"`). C# specifics: routes from `[HttpGet/HttpPost/…("path")]` with class-level `[Route("prefix")]` (`[controller]` token replaced by the class name minus `Controller`), `[Authorize]`/`[AllowAnonymous]` ⇒ `middleware_texts` (`AllowAnonymous` forces `auth: "unauthenticated"` in build-graph), minimal APIs `app.MapGet("/x", handler)` / `.RequireAuthorization()`; `resolveImportSpecifier`: `using X.Y;` ⇒ every file whose `namespace` (via `namespaces`) is `X.Y` (returns the first by sorted path with `confidence: "heuristic"`; class lookup then relies on the resolver's unique-name rule); sources from `Request.Query/Form/Body/Cookies/Headers/RouteValues` and `[FromBody]/[FromQuery]/[FromForm]/[FromRoute]` parameters. `callableLocals: false`, `implicitThisCalls: true`; type-qualified sink candidates exactly as Java (`cmd.ExecuteReader` ⇒ `SqlCommand.ExecuteReader`); `_runner.Run()` ⇒ `receiver_class` from the field's declared type.

- [ ] **Step 1: Write fixture** — controller `[Route("api/[controller]")]` + `[HttpPost("run")]` + `[Authorize]` calling `_runner.Run(cmd)` → `Process.Start(...)`; `AdminRunner : Runner` overriding `Run`; minimal API `app.MapGet("/health", () => "ok")`.
- [ ] **Step 2: Write `csharp.test.mjs`** — `[controller]` substitution ⇒ `POST api/Run/run`; `[AllowAnonymous]` on a method ⇒ middleware text; `MapGet` ⇒ route; namespace resolution heuristic flagged.
- [ ] **Step 3: Run** — expected: fails.
- [ ] **Step 4: Implement**, then generate and eyeball-review `test-fixtures/graph/dotnet/graph.expected.json` (`OSWE_UPDATE_GOLDEN=1 node --test test/graph/build-graph.test.mjs`).
- [ ] **Step 5: Run tests** — expected: pass; conformance and the golden test now run for all five stacks.
- [ ] **Step 6: Commit** — `feat(sp10): c# extractor (asp.net core/classic)`

---

### Task 12: `partition-graph.mjs`

**Files:**
- Create: `skills/audit/scripts/partition-graph.mjs`
- Test: `skills/audit/scripts/test/partition-graph.test.mjs`

**Interfaces:**
- Produces: `partitionGraph({ graph, fallback_partitions }) → { mode: "graph"|"fallback", partitions: [{ partition_id, stack, files }], orphan_partition_ids: string[] }` and the CLI `node partition-graph.mjs --file <in> --out <out>` with input `{ graph: <graph or null>, fallback_partitions: [{ partition_id, stack, files }] }`.
- Rules: `graph === null` or no `route` nodes ⇒ `mode: "fallback"`, `partitions` **deep-equal to `fallback_partitions`** (same order, same ids), `orphan_partition_ids: []`. Otherwise: for every route, collect files reachable via `handles`, `uses_middleware`, `calls` (`exact` **and** `name-only`), depth-unbounded BFS; group routes by key `(stack, auth, module)` where `module` = first path segment of the route file (or `"root"`); partition id = `g-<stack>-<auth>-<module>`; `files` = sorted union of reachable files; a file reachable from several groups goes to the **first** group in sorted key order (no duplicates across partitions); files in no group are grouped by their `fallback_partitions` membership, with ids `<fallback id>-orphan`, listed in `orphan_partition_ids`. Paths are compared after `toLowerCase()` on `win32` only.

- [ ] **Step 1: Write failing tests** — fallback equality (deep + JSON byte-equality) when `graph: null` and when routes are empty; the Task 5 fixture graph ⇒ one `g-node-authenticated-routes` partition containing `routes/users.js` and `services/userService.js`, one `g-node-unauthenticated-root` for `/health`; a file reachable from two groups appears once; a file present in two fallback partitions appears in exactly one orphan partition; **Windows case variant** (`Routes/Users.js` vs `routes/users.js`, test only when `process.platform === "win32"`) deduplicated.
- [ ] **Step 2: Run** — expected: module not found.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests** — expected: pass.
- [ ] **Step 5: Commit** — `feat(sp10): partition-graph (reachability partitions, byte-identical fallback)`

---

### Task 13: `enumerate-paths.mjs`

**Files:**
- Create: `skills/audit/scripts/enumerate-paths.mjs`
- Test: `skills/audit/scripts/test/enumerate-paths.test.mjs`

**Interfaces:**
- Produces: `enumeratePaths({ graph, partition, max_depth = 6, max_paths = 50 }) → { partition_id, candidate_paths }` with `candidate_paths: [{ id: "CP-<partition_id>-<n>", route: { file, line, http_method, path_pattern, auth }, hops: [{ file, line, function, edge_confidence }], sink: { file, line, class, callee }, min_confidence }]`; CLI `--file { graph, partition, max_depth?, max_paths? } --out`.
- Ordering key: `(sinkRank, auth === "unauthenticated" ? 0 : 1, hops.length, route.id, sink.id)` with `sinkRank`: `cmd-exec|eval|deser → 0`, `sql|nosql|template|include → 1`, `file-write|file-read|ssrf|xxe → 2`, else `3`. Numbering `<n>` follows that order, 1-based. Traversal: DFS from each route handler over `calls` edges of any confidence into functions **of the partition's files**, memoising per-function sink reachability so a diamond graph is linear; a path ends at every sink whose `enclosing_fn` is on the path. `min_confidence` = weakest edge in `exact > name-only > unresolved`.

- [ ] **Step 1: Write failing tests** — Task 5 fixture ⇒ path `POST /users/:id/run → run → UserService.run → UserService.exec` ending at the `cmd-exec` sink with `min_confidence: "name-only"` (because of the override) and `hops.length === 3`; a synthetic diamond graph of depth 20 with 2 branches per level finishes < 2 s and returns ≤ `max_paths`; `max_depth: 2` prunes the fixture path; ordering: a `sql` sink path sorts after a `cmd-exec` one; output deterministic across two runs.
- [ ] **Step 2: Run** — expected: module not found.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests** — expected: pass.
- [ ] **Step 5: Commit** — `feat(sp10): enumerate-paths (ranked structural candidates)`

---

### Task 14: Finding / report schema additions and aggregation

**Files:**
- Modify: `skills/audit/schemas/finding.schema.json` (add optional `candidate_path_id: string`, `candidate_path_ids: string[] uniqueItems`, `structural_path: enum[proven,absent,n/a]`, `verification_notes: string[]`), `report.schema.json` (add optional `app_graph: { available: boolean, reason?: string, stats?: <graph stats>, multi_file_chain_count: integer }` with `additionalProperties: false`), `skills/audit/scripts/aggregate-findings.mjs:54-73`, `write-report.mjs:12-16`, regenerate `validators.mjs`
- Test: extend `test/aggregate-findings.test.mjs`, `test/write-report.test.mjs`, `test/validate-output.test.mjs`

**Interfaces:**
- Produces: merged findings carry `candidate_path_ids` (sorted unique union of members' `candidate_path_id`) **only when at least one member had one** (absent otherwise, so existing golden outputs are unchanged); `buildReport({ …, app_graph })` includes `app_graph` when passed.

- [ ] **Step 1: Write failing tests** — two raw findings with the same dedupe key, one carrying `candidate_path_id: "CP-p-1"`, the other `"CP-p-2"` ⇒ merged `candidate_path_ids: ["CP-p-1","CP-p-2"]`; no member with one ⇒ key absent; existing aggregate test fixtures still byte-identical; `validate("final-finding", {...structural_path: "proven"})` ok; `validate("report", { …, app_graph: { available: false, reason: "x", multi_file_chain_count: 0 } })` ok; `buildReport` round-trips `app_graph`.
- [ ] **Step 2: Run** — expected: schema rejects unknown properties.
- [ ] **Step 3: Edit schemas, `aggregate-findings.mjs`, `write-report.mjs`; `npm run build`.**
- [ ] **Step 4: Run full suite** — `node --test` from `skills/audit/scripts`; expected: all pass (count ≥ 320 + new).
- [ ] **Step 5: Commit** — `feat(sp10): candidate_path_ids merge, structural_path + app_graph report fields`

---

### Task 15: Typed chain transitions and `check-chain-structure.mjs`

**Files:**
- Modify: `skills/audit/schemas/chain.schema.json:22-30` (transition gains optional `kind: enum[call-path, shared-state, auth-gain]`, `from_anchor`, `to_anchor` (`$ref finding.schema.json#/$defs/fileline`)); regenerate validators
- Create: `skills/audit/scripts/check-chain-structure.mjs`
- Test: `skills/audit/scripts/test/check-chain-structure.test.mjs`

**Interfaces:**
- Produces: `checkChainStructure({ graph, findings, chains, max_depth = 6 }) → structural` (shape of `structural-check.schema.json`), CLI `--file { graph, findings, chains } --out`. `graph === null` ⇒ every finding/transition `n/a` with reason `"graph unavailable"`.
- Mapping: `enclosingFn(graph, file, line)` = innermost `function` node of that file with `line_start ≤ line ≤ line_end`; none ⇒ `null`.
- Per-finding decision table verbatim from spec §3.4: same fn or forward `exact` path ⇒ `proven`; reverse `exact` path only ⇒ `n/a` (`"return-value flow not modelled"`); connected only via non-exact edges ⇒ `n/a`; either end unmapped ⇒ `n/a`; both mapped and no connection in either direction over **any** confidence within `max_depth` ⇒ `absent`.
- Per-transition: `kind !== "call-path"` or missing ⇒ `n/a`; else apply the same table between two locations: `from_anchor` and `to_anchor` when both are present, otherwise the `from` finding's `sink` and the `to` finding's `source` (looked up by `OSWE-N` in `findings`; an unknown id ⇒ `n/a` with reason `"transition references unknown finding"`).

- [ ] **Step 1: Write failing tests** on hand-built graphs (no parsing): forward exact ⇒ proven; same function ⇒ proven; reverse-only ⇒ n/a with the reason string; path through one `name-only` edge ⇒ n/a; sink line outside any function ⇒ n/a; both mapped, disconnected ⇒ absent; transition `kind: "shared-state"` ⇒ n/a; transition without `kind` ⇒ n/a; `graph: null` ⇒ all n/a; a chain with `kind: "call-path"` and anchors validates against the updated `chain` schema and a legacy chain without `kind` still validates.
- [ ] **Step 2: Run** — expected: module not found.
- [ ] **Step 3: Edit schema, `npm run build`, implement helper.**
- [ ] **Step 4: Run tests** — expected: pass.
- [ ] **Step 5: Commit** — `feat(sp10): typed transitions + check-chain-structure`

---

### Task 16: `apply-verdicts --structural` confidence ceiling

**Files:**
- Modify: `skills/audit/scripts/apply-verdicts.mjs:163` (`applyVerdicts({ findings, chains, batches, structural })`), CLI parse `--structural <path>` (optional)
- Test: extend `test/apply-verdicts.test.mjs`

**Interfaces:**
- Produces: when `structural` is given, **after** member verdicts are applied and **before** chain severity/Critical gating: for each finding with `structural.findings[id]`, set `finding.structural_path` to that value; if `final_confidence === "strong static proof"` and `structural_path === "absent"` ⇒ `final_confidence = "to verify"` and push `"structural: absent"` to `finding.verification_notes` (create the array). Chain gating then runs on the updated member confidences unchanged.

- [ ] **Step 1: Write failing tests** — `structural` omitted ⇒ output deep-equal to the existing fixture outputs (reuse an existing test's input and compare with/without an empty `structural`); accepted `strong static proof` + `absent` ⇒ `to verify` + note; `likely` + `absent` ⇒ unchanged, `structural_path` set; `proven` ⇒ unchanged; a chain that was Critical in an existing test becomes `High` (or the gate's non-Critical result) when one member is `absent`; `--structural` pointing to a file that fails `structural-check` validation ⇒ exit 1 with `error_kind: "orchestrator-input"`.
- [ ] **Step 2: Run** — expected: assertions fail (field ignored).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run full suite** — expected: all pass.
- [ ] **Step 5: Commit** — `feat(sp10): apply-verdicts structural confidence ceiling`

---

### Task 17: Pipeline wiring — SKILL.md, agents, replay tests

**Files:**
- Modify: `skills/audit/SKILL.md` (new §1.5 after §0.5; §2 uses `partition-graph.mjs`; §3 dispatch gains `candidate_paths` via `enumerate-paths.mjs` and `dispatch_input` gains `"candidate_paths": [...]`; §5 chains must set `kind`; new §5.5 runs `check-chain-structure.mjs` and the verifier `dispatch_input` gains `"structural": {...}`; §6b passes `--structural`; §7 report gains the App graph section and `app_graph` goes into `write-report` parts; Coverage note on `graph: null`), `agents/oswe-analyzer.md` (candidate-paths instruction block + `candidate_path_id` in the output example), `agents/oswe-verifier.md` (structural context is read-only evidence, not a counterexample to refute)
- Modify: `test/e2e-replay.test.mjs`, `test/e2e-replay-resume.test.mjs`

**Interfaces:**
- Consumes: every CLI from Tasks 7, 12, 13, 15, 16.

- [ ] **Step 1: Extend both replay tests** to call, in order, `graph/build-graph.mjs` (on the temp project; assert a graph with ≥ 1 function), `partition-graph.mjs` (fallback mode here, assert byte-identical partitions), `enumerate-paths.mjs` (assert `candidate_paths` is an array), `check-chain-structure.mjs` (assert every finding is `n/a`/`proven`), and `apply-verdicts.mjs --structural`; the resume test additionally asserts the graph cache hit on the second run.
- [ ] **Step 2: Run both replay tests** — the CLIs already exist (Tasks 7, 12, 13, 15, 16), so expected: PASS. Confirm the new assertions actually executed by adding a `t.diagnostic("sp10 graph stages: N assertions")` line and checking it appears in the `node --test` output; a replay test that passes without that line is not covering the graph stages.
- [ ] **Step 3: Edit `SKILL.md` and both agent prompts** with the exact `node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/…"` invocations, temp-file + `trap` discipline, and the `graph: null` Coverage sentence: `App graph unavailable: <reason> — partitions, candidate paths and structural checks fell back to pre-SP10 behaviour.`
- [ ] **Step 4: Run `claude plugin validate . --strict`** locally (CI runs it too); expected: valid.
- [ ] **Step 5: Run full suite** — expected: pass.
- [ ] **Step 6: Commit** — `feat(sp10): wire graph phases into SKILL.md + agents; replay tests cover them`

---

### Task 18: Report rendering — App graph section

**Files:**
- Modify: `skills/audit/scripts/render-html.mjs`, `skills/audit/SKILL.md` (Markdown report template under `## Report format`)
- Test: extend `test/render-html.test.mjs`

- [ ] **Step 1: Write failing test** — a report with `app_graph.available: true` renders an "App graph" section containing `files parsed`, `routes`, `call resolution`, `multi-file chains` and a per-stack coverage table; `available: false` renders the reason; a report without `app_graph` renders exactly as before (existing snapshot unchanged).
- [ ] **Step 2: Run** — expected: fails.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests** — expected: pass.
- [ ] **Step 5: Commit** — `feat(sp10): app graph section in md/html reports`

---

### Task 19: Gates, CI, benchmark metrics, docs

**Files:**
- Modify: `.github/scripts/check-structure.mjs` (rule 8: every stack has `skills/audit/scripts/graph/lang/<module>.mjs` with `STACK_TO_LANG = { node: "javascript", python: "python", java: "java", php: "php", dotnet: "csharp" }`; rule 9: every `test-fixtures/graph/<stack>/` has `graph.expected.json`), `.github/workflows/ci.yml` (add `node .github/scripts/check-vendor.mjs` to the `test` job; add `npm run build:grammars` + `git diff --quiet -- ../vendor` to `regen-check`), `benchmark/build-ledger.mjs` (copy `structural_path`, `candidate_path_ids`, `app_graph.stats`), `benchmark/metrics.mjs` (`structural_proof_rate`, `candidate_path_hit_rate` per spec §3.3 definition, `call_resolution_ratio` = `calls_exact / calls_total`), `benchmark/score-nodegoat.mjs` (report `structural_proof_rate`, `candidate_path_hit_rate`), `README.md`, `benchmark/BENCHMARK.md` (SP10 section skeleton with the fixed gates table), `.claude-plugin/plugin.json` (`version: "0.2.0"`)
- Test: extend `benchmark/metrics.test.mjs`, `benchmark/score-nodegoat.test.mjs`

- [ ] **Step 1: Write failing tests** — `computeMetrics` on a ledger with 4 accepted findings, 3 `proven`, 2 with `candidate_path_ids` ⇒ `structural_proof_rate: 0.75`, `candidate_path_hit_rate: 0.5`; `scoreNodegoat` surfaces both.
- [ ] **Step 2: Run** — expected: fails.
- [ ] **Step 3: Implement metrics + ledger; edit gates, CI, docs; regenerate nothing else.** README: add the graph step to "How it works", the §1.4 resolution limits to "Honest limits", update test counts to the real numbers from the suite.
- [ ] **Step 4: Run** `node --test` in both dirs, `node .github/scripts/check-structure.mjs`, `node .github/scripts/check-vendor.mjs`, `git diff --check`; expected: all green.
- [ ] **Step 5: Commit** — `feat(sp10): structure/vendor gates, benchmark metrics, docs`

---

### Task 20: Validation campaign (user-run) and gate read

**Files:**
- Create: `benchmark/webgoat-truth.json`, `benchmark/results/nodegoat-sp10.json`, `benchmark/results/webgoat-sp10.json`, `benchmark/results/benchmarkjava-sp10.json`
- Modify: `benchmark/BENCHMARK.md` (SP10 table + gate read), `README.md` ("Proven on real code")

**Interfaces:**
- Consumes: `/oswe:audit` runs by the maintainer on `external/NodeGoat/app/routes`, `external/WebGoat` (clone `https://github.com/WebGoat/WebGoat` into `external/`), the SP6 stratified BenchmarkJava sample, and `external/flaskr`.

- [ ] **Step 1: Write `webgoat-truth.json`** — same shape as `nodegoat-truth.json`; seven file-anchored entries chosen from WebGoat's lesson sources (SQL injection, path traversal, XXE, insecure deserialization, SSRF, JWT, IDOR) with `route_file`/`file`/`class` filled from the checkout; commit before any audit run.
- [ ] **Step 2: Run the four audits** with the plugin loaded from this branch; keep the `.json` reports under `.oswe/reports/` (gitignored); record their SHA-256 in `BENCHMARK.md`.
- [ ] **Step 3: Score** — `node benchmark/score-nodegoat.mjs --report <nodegoat.json> --truth benchmark/nodegoat-truth.json --out benchmark/results/nodegoat-sp10.json`; same with `webgoat-truth.json`; BenchmarkJava through the existing ledger/metrics path into `benchmarkjava-sp10.json`.
- [ ] **Step 4: Read the gates exactly as fixed in spec §4.2** and write the SP10 table in `BENCHMARK.md` with pass/fail per row and no post-hoc revision; if a gate fails, record it as failed and open the follow-up as an SP10.1 note — do not adjust thresholds.
- [ ] **Step 5: Run full verification** — both `node --test` suites, both gates, `git diff --check`, `git status --short --branch` clean.
- [ ] **Step 6: Commit** — `docs(sp10): validation campaign results and gate read`
- [ ] **Step 7: Finish the branch** — invoke `superpowers:finishing-a-development-branch`; merge `feat/oswe-sp10-app-graph` into `master` locally; do not push unless separately authorized.
