# SP10 — App Graph (tree-sitter, deterministic, structural proof)

> **Status:** design spec, approved in conversation on 2026-11-05. Implementation plan to follow.
>
> **Position in the roadmap.** SP9 closed with real-app recall validated (NodeGoat 7/7) but **zero
> accepted multi-file exploit chains** — an explicit validation gap. The project's next goal is to beat
> large SASTs (CodeQL, Semgrep Pro, Checkmarx, Snyk) for an **open-source / community** audience: zero
> friction to install, impressive on well-known public repositories. That goal is four sub-projects,
> built in this order because each depends on the previous:
>
> | sprint | goal | depends on |
> |---|---|---|
> | **SP10 — App Graph** (this spec) | Deterministic application graph; multi-file chains become findable and structurally provable. | — |
> | SP11 — Slices & cost | Replace the 12-partition directory budget with graph-derived entry→sink slices; cross-run cache keyed on graph hashes; `--diff` incremental mode; `--dry-run` cost estimate. | SP10 |
> | SP12 — Product & distribution | Marketplace listing, headless `claude -p` validated, GitHub Action, `--baseline` run diff, semver v1.0, demo on a public repo. | SP11 |
> | SP13 — Breadth | Go, Ruby/Rails, then Kotlin / Next.js / GraphQL — each a grammar + route extractor + reference + fixtures. | SP10 contract |
>
> An out-of-sprint quick win (merge Dependabot PR #2, tag `v0.1.0`, list the current plugin on the
> marketplace) may be done at any time; it needs no design.

**Goal:** Give the pipeline a deterministic, schema-validated **application graph** (files, functions,
imports, calls, routes, auth middleware, source/sink anchors) built by a vendored tree-sitter WASM
parser, and use it in three places: partition by reachability, feed the analyzer structural candidate
paths, and let the verifier refuse "strong static proof" when the graph shows no call path. The
division of labour is explicit: **the graph says who can call whom; the LLM says whether attacker data
gets through.**

**Architecture:** Sidecar, pipeline preserved. One new phase (§1.5 build graph), three touch points
(§2 partition, §3 analyze, §5 verify), one new report section. Every existing helper keeps its input
and output contract; if the graph cannot be built, the audit runs exactly as it does today.

**Tech stack:** existing Node ≥ 20 zero-runtime-dependency helpers + `node:test`; **new:**
`web-tree-sitter` loader and per-language grammar `.wasm` files vendored into the repo (MIT), built
by a dev-only npm script and verified by a manifest check in CI. The user still runs no `npm install`.

---

## 0. Why a graph, and why this shape

SP9 showed that the analyzer can surface cross-file *findings* (route → DAO) but never produced a
multi-file *chain* with proof. Two causes, both structural rather than reasoning:

1. Partitions are cut by directory, so a route and its sink often sit in different partitions and no
   single analyzer sees the wiring.
2. The verifier has no way to check topology; a chain that "feels right" is accepted or rejected on
   reasoning alone, so the orchestrator rightly stays conservative.

Large SASTs have the opposite failure: a precise call graph and a dumb reasoner — hence their
0.341 false-positive rate on BenchmarkJava. Combining a deterministic graph with the existing
refutation-based verifier is the differentiator, not a feature.

Three approaches were considered: (A) graph as a sidecar with the pipeline preserved, (B) a
graph-first rewrite with a deterministic taint engine and the LLM only confirming, (C) a partial graph
(routes + imports only). **A was chosen**: it keeps the 383-test contract, the "model finds, helpers
decide" property that produces the current precision, and gives SP11/SP13 a stable interface. B is
months of work across five languages and would move decisions into an engine we would have to make
smarter than CodeQL's; C does not close the SP9 gap because it proves nothing.

Decisions made in conversation that constrain this spec:

- **All five stacks in SP10** (PHP, Node, Python, Java, .NET). Mitigation for breadth: one shared
  extractor interface, one conformance suite every extractor must pass, and a per-stack coverage matrix
  published in the report so the breadth is honest.
- **Structural proof counts only `exact` call edges.** A `name-only` edge is a hint for the analyzer,
  never evidence for the verifier.
- **Metrics and gates are fixed in this spec** before any code is written and are not revised after
  observation (SP9 discipline).

---

## 1. Graph model — `graph.schema.json`

One artifact, `graph.json`, validated like every other pipeline artifact. It contains **no source
text**: identifiers and line numbers only, so it carries no secrets and needs no redaction.

### 1.1 Nodes

| type | fields |
|---|---|
| `file` | `id`, `path` (repo-relative, forward slashes), `stack`, `lang`, `parse_status: "ok" \| "error" \| "skipped"`, `skip_reason` (optional) |
| `function` | `id`, `file`, `name`, `qualified_name`, `line_start`, `line_end`, `kind: "function" \| "method" \| "arrow" \| "lambda"`, `exported: boolean`, `class` (optional) |
| `route` | `id`, `file`, `line`, `http_method` (`GET`…`ANY`), `path_pattern`, `handler` (function id or `null`), `middlewares[]` (function ids or unresolved names), `framework`, `auth: "unauthenticated" \| "authenticated" \| "unknown"` |
| `source` | `id`, `file`, `line`, `enclosing_fn` (function id or `null`), `kind: "query" \| "body" \| "params" \| "header" \| "cookie" \| "file" \| "env"`, `pattern` (the surface pattern that matched) |
| `sink` | `id`, `file`, `line`, `enclosing_fn`, `class` (cmd-exec, eval, sql, nosql, deser, file-write, file-read, ssrf, template, include, redirect, trust-boundary), `callee` (identifier text only), `pattern` |

### 1.2 Edges

| type | from → to | attributes |
|---|---|---|
| `imports` | file → file | `confidence: "exact" \| "heuristic"`, `specifier` |
| `calls` | function → function or `null` | `line`, `callee_text`, `confidence: "exact" \| "name-only" \| "unresolved"` |
| `handles` | route → function | — |
| `uses_middleware` | route → function | `order` |
| `nests` | function → function (its innermost lexical container, by byte range, to a function nested in it: a callback, a closure, a local helper) | — (a closure runs only within its enclosing function, so every consumer follows `nests` like an `exact` call; callback-style code keeps most of its calls inside closures) |

### 1.3 Determinism and identity

- Node id = first 12 hex chars of SHA-1 over a per-type identity string that includes the AST
  **start byte offset**, so two constructs on one line never collide (`exec(a); eval(b);` are two
  sinks):
  - `function`: `"fn:<path>:<qualified_name>:<start_byte>"` — overloads (Java/C#) and anonymous
    functions are distinct by offset; anonymous functions get `name: "<anon>"` and
    `qualified_name: "<enclosing>.<anon>@<line>:<col>"`.
  - `source` / `sink`: `"<type>:<path>:<start_byte>"`.
  - `route`: `"route:<path>:<start_byte>"`.
  - `file`: `"file:<path>"`.
  Edge identity = `(type, from, to, line, start_byte)`. Edge order and node order are sorted by
  `(type, id)`. **Two builds of identical input are byte-identical.**
- `auth` on a route is computed deterministically from the `auth_markers` list already present in the
  `surface` block of `references/<stack>.md`: any middleware/decorator/attribute whose name matches a
  marker → `authenticated` (the curated name is the evidence, whether or not the middleware resolved to
  a parsed function); otherwise any unresolved middleware → `unknown`; otherwise → `unauthenticated`.
  Framework-specific overrides (e.g. ASP.NET `[AllowAnonymous]`) force `unauthenticated`. Express
  `app.use(path, …mws, router)` mounts propagate their path prefix and middlewares onto the mounted
  file's routes; an `app.use(…)` whose last argument resolves to neither a parsed function nor a parsed
  router file is an unresolved global middleware for the later routes under its prefix (marker ⇒
  `authenticated`, else `unknown`), except the built-in `BENIGN_MIDDLEWARE` list of Express middlewares
  that never decide auth (`express.json`/`urlencoded`/`static`/`text`/`raw`/`Router`, `bodyParser`,
  `cors`, `helmet`, `morgan`, `compression`, `cookieParser`, `methodOverride`, `favicon`, `serveStatic`),
  which is ignored entirely. The analyzer and verifier may disagree with the graph in their reasoning; the graph
  value is never overwritten.
- `stats` block: `files_total`, `files_parsed`, `files_error`, `files_skipped`, `functions`,
  `calls_total`, `calls_exact`, `calls_name_only`, `calls_unresolved`, `routes_by_auth`,
  `coverage_matrix` (per stack: frameworks detected, extractors applied, constructs not extracted).

### 1.4 Call resolution — graded, never hidden

Resolution happens in `resolve.mjs`, language-independent, driven by hints the language module emits
(declared names, exports, import bindings, class membership):

`exact` is reserved for bindings the graph can **demonstrate**; anything with a plausible alternative
target is downgraded. Each language module emits, per call site, the set of names declared in the
enclosing lexical scopes (parameters, locals, closure variables) so the resolver can detect shadowing.

1. callee is a **top-level or class-member definition in the same file** and the name is **not
   shadowed** by a parameter/local/closure binding in any enclosing scope of the call site → `exact`.
   Shadowed → `unresolved` (the callee is a runtime value the graph cannot see). A **definition nested
   in a function** whose name is bound in the scope enclosing it — the extractor marks it `binds_name`:
   a nested declaration (`function f() {}`, `def f():`), or an anonymous function / arrow / lambda named
   by the local or assignment initialising it (`const f = () => {}`, `x = lambda: …`, C# / Java
   `Action a = () => …`) — is a definition, not a shadowing binding: a call from its enclosing function,
   or from any closure nested in it, resolves to the innermost such definition on the lexical chain →
   `exact` (two at one level are a redefinition → `unresolved`; a nested definition is invisible outside
   its function and never counts for rule 4). An object-literal method, a named function expression
   (`app.get('/', function index() {})`), `const f = function g() {}` and `const C = class {}` bind no
   callable name in the enclosing scope: they are never such definitions (the last two shadow like any
   local).
   1b. callee is `x.m()` where the receiver `x` has a **demonstrable class**: `x` is a local bound by
   `new C(...)` in the same function or file, or (Java / C# / PHP) a field, parameter or property with
   a declared type `C` → the method `m` of `C` (resolved in the same file, through the import bindings,
   or by unique name across parsed files; two classes named `C` → `unresolved`), subject to rule 3's
   override check → `exact`. A constructor call or a declared type is a demonstrated binding, not type
   inference; receiver *reassignment* is not tracked, which the override check and the verifier absorb.
2. callee is an **imported binding** (not shadowed) → the export of the resolved target file → `exact`.
   If the import resolves to a file but the export is not found → `unresolved`.
3. `this.x()` / `self.x()` / `$this->x()` → the method `x` of the enclosing class, resolved in the same
   file or the resolved parent file, **only if no parsed class in scope extends that class and
   redefines `x`**. If any subclass overrides `x` → `name-only` (dispatch is dynamic; the graph names a
   candidate, not a proof).
4. callee name is unique across all parsed functions in scope → `name-only`.
5. otherwise → `unresolved` (`to: null`); `callee_text` kept so sink matching still works.

Two refinements shared by all rules: **overloads** (several same-named methods in one class, Java/C#)
are disambiguated by arity — a unique definition whose parameter count equals the call's argument
count is `exact`, otherwise the first overload is `name-only`; and a **lambda / arrow** function
inherits the class of the innermost enclosing method for rule 3 and for implicit-`this` bare calls
(a JavaScript `function` expression, whose `this` is dynamic, does not). The lexical class body an
arrow must stay within is a `class` body or, for a constructor-style class (`function F(db) {
this.m = (req, res) => { dao.find(id, (err, rows) => { this.n(); }); }; }`), the constructor
function itself, so `this.n()` inside a callback nested in a constructor-style method resolves.

**Interface and abstract dispatch.** Extractors mark interface methods and abstract methods
`bodiless` (Java / C# / PHP / TypeScript) and list each class's implemented interfaces (`implements`).
A call whose resolved target is bodiless is **never `exact`**: when the class declaring it has
subclasses / implementors defining the method with a body, it resolves to the first of them by
`(path, start_byte)` as `name-only` (the DI implementation hint: `@Autowired UserService` →
`UserServiceImpl.run`, `IRunner` → `Runner.Run`), else to the bodiless method, `name-only`. A class
whose `implements` names the target class counts as a subclass for rule 3's override check (by resolved
identity, else by last name segment). Bodiless signatures are not rule-4 definitions.

Explicit non-goals: type inference, virtual dispatch resolution beyond rule 3's conservative check,
interprocedural taint summaries, dynamic requires / reflection. A homonymous function defined in two
files is **never** resolved to either; it yields `unresolved` with a stats counter. Tests guard:
parameter shadowing a same-file function, local shadowing an import, subclass override of a
`this.x()` target, and the two-file homonym.

---

## 2. Extraction engine

### 2.1 Vendored parser

```
skills/audit/vendor/tree-sitter/
  web-tree-sitter.mjs          loader (MIT, from the web-tree-sitter npm package)
  tree-sitter.wasm             runtime
  tree-sitter-javascript.wasm
  tree-sitter-typescript.wasm
  tree-sitter-tsx.wasm
  tree-sitter-python.wasm
  tree-sitter-java.wasm
  tree-sitter-php.wasm
  tree-sitter-c_sharp.wasm
  MANIFEST.json                { package, version, sha256 } per file
  LICENSES.md                  upstream licences
```

- `skills/audit/scripts/build-grammars.mjs` is **dev-only** (needs `npm install` in
  `skills/audit/scripts`, like AJV today): copies the `.wasm` files from their npm packages, writes
  `MANIFEST.json`. CI recomputes the hashes and fails on drift — the same mechanism as the
  `validators.mjs` ↔ schemas sync check.
- Size budget: `vendor/` ≤ 10 MiB, enforced in CI.
- Loading: Node ≥ 20 instantiates WASM natively; no native addon, no network.
- **Failure mode:** any load/parse-engine failure → `build-graph.mjs` exits 0 with
  `{ "graph": null, "reason": "<message>" }`. The orchestrator records a Coverage note
  "app graph unavailable: <reason>" and continues **exactly as today**. Building the graph never aborts
  an audit.

### 2.2 Layout

```
skills/audit/scripts/graph/
  build-graph.mjs        CLI: --file <in.json> --out <graph.json> --checkpoint-dir <dir>
  walk.mjs               file enumeration (excludes list from SKILL.md, 1 MiB per-file cap, scope-confined)
  resolve.mjs            import + call resolution (§1.4), language-independent
  surface.mjs            loads the `surface` blocks of references/<stack>.md (single source of truth)
  lang/javascript.mjs    one module per language, common interface (§2.3); TS/TSX share this module
  lang/python.mjs
  lang/java.mjs
  lang/php.mjs
  lang/csharp.mjs
```

Input to `build-graph.mjs`: `{ projectDir, scope_realpath, stacks[], frameworks[], excludes[] }`
(all values resolved by the existing recon step). Output: `graph.json` or the `graph: null` envelope.
Exit codes follow the house convention: 0 ok, 1 malformed input, 2 IO.

### 2.3 Language module interface

```js
export const lang = { id, extensions, grammar, frameworks: [...] };
export function extractFile({ tree, path, sourceText, frameworks, surface }) → {
  functions: [...], calls: [...], imports: [...], exports: [...],
  routes: [...], sources: [...], sinks: [...],
  resolution_hints: { declared: [...], classMembers: {...}, importBindings: [...] },
  not_extracted: [ "construct name" ]        // feeds coverage_matrix
}
```

`sourceText` is used only for tree-sitter queries and for reading identifier text; it is never copied
into the output. Queries are tree-sitter `.scm` strings kept inside the module.

### 2.4 Route and auth extractors per framework (SP10 scope)

| lang | frameworks | captured |
|---|---|---|
| JS/TS | Express, Nest | `app/router.<verb>(path, mw…, handler)`, `app/router.use(path?, mw)` with registration order, `@Controller`/`@Get…`/`@UseGuards` |
| Python | Flask, Django, FastAPI | `@app.route`/`@bp.route` (+ `methods=`), `urlpatterns` incl. `include()` one level, `@router.<verb>`, `@login_required`/`Depends(...)` auth markers |
| Java | Spring, Servlet | `@RequestMapping`/`@GetMapping`…, class-level prefix, `@PreAuthorize`/`@Secured`; `SecurityFilterChain` / `configure(HttpSecurity)` request rules (`requestMatchers`/`antMatchers`/`mvcMatchers` + the call chained on them: `permitAll`/`authenticated`/`hasRole`…, `anyRequest`; `securityMatcher` scope; `web.ignoring()`) applied first-match to every java route, several chains voting by agreement (§4.4); an unread config stays the file-level `unknown` hint; `@WebServlet` + `doGet`/`doPost`/…/`service`, `@ServletSecurity`, a servlet `Filter` as an `unknown` hint |
| PHP | Laravel, Symfony | `Route::<verb>(…)`, `Route::group/middleware(…)`, `->middleware('auth')`, `#[Route]`, `#[IsGranted]` |
| C# | ASP.NET Core & classic | `[HttpGet]`/`[Route]`/`[Authorize]`/`[AllowAnonymous]`, `MapGet/MapPost` minimal APIs, class-level route prefix |

Anything outside this table is listed in `not_extracted` and surfaces in the coverage matrix — it is
not silently missed.

### 2.5 Sources and sinks

The `sources` / `sinks` / `sanitizers` / `auth_markers` lists in each `references/<stack>.md` `surface`
block remain the **single source of truth**. They are written as grep-style text (`eval(`, `.query(`,
`$_GET`, `$where`, `@RequestParam`, `[FromBody]`, `ProcessBuilder`), so `surface.mjs` **classifies
each pattern by shape** and the extractor matches it against a specific AST node category. An `eval`
inside a comment or a string literal no longer counts.

| pattern shape | example | normalisation | AST nodes matched |
|---|---|---|---|
| call, trailing `(` | `eval(`, `system(`, `getParameter` (bare word also treated as call) | strip `(` | callee identifier of `call_expression` / `new_expression` / `object_creation`; for a dotted name (`os.system`, `pickle.loads`, `Runtime.getRuntime().exec`) the callee text must **end with** the dotted sequence |
| member, leading `.` | `.query(`, `.readObject(`, `.raw(` | strip `.` and `(` | last segment of `member_expression` / `attribute` / `member_access` used as a callee |
| decorator / attribute | `@RequestParam`, `@login_required`, `[FromBody]`, `[Authorize]`, `#[IsGranted` | strip `@`, `[`, `#[`, `(` | `decorator` / `annotation` / `attribute` nodes (name match on the first segment) |
| variable / global / member chain | `$_GET`, `request.args`, `req.body`, `Request.Query`, `$request->input(` | strip trailing `(` | `identifier` / `variable_name` / `member_expression` whose text **starts with** the chain |
| object key, leading `$` (Mongo operators) | `$where`, `$ne`, `$gt`, `$regex` | none | property keys of object literals and string literals **used as keys** (never free-standing string literals) |
| bare type / word | `ProcessBuilder`, `BinaryFormatter`, `XStream`, `TypeNameHandling` | none | `identifier` / `type_identifier` in `new_expression`, `object_creation`, type references, or as a callee |
| scheme / header | `php://input`, `X-User-Role` | none | **string literals only**, matched by equality; flagged `pattern_kind: "literal"` so they never seed a `sink` node on their own |

A pattern that fits no shape is listed in `stats.coverage_matrix.<stack>.patterns_unmatched` — never
silently dropped. The classification is unit-tested against every entry of every `surface` block (a
new entry that fits no shape fails CI). **`surface-scan.mjs` is not modified in SP10** (zero regression
on budget allocation); replacing it with graph-derived counts is SP11 scope.

### 2.6 Import resolution per language (hints consumed by `resolve.mjs`)

- JS/TS: relative specifiers, `index.{js,ts,…}`, extension probing, `tsconfig` `baseUrl`/`paths`
  (one level, no wildcards beyond `*`). Package specifiers → external (`heuristic` edge to `null`).
- Python: `from a.b import c` / `import a.b` → `a/b.py` or `a/b/__init__.py` relative to the scope and
  to any directory containing `__init__.py` chain; relative imports honoured.
- Java: `import x.y.Z` → file declaring `package x.y;` and a top-level type `Z`.
- PHP: `use X\Y;` → PSR-4 roots from `composer.json` autoload, else any file declaring `namespace X;`
  with class `Y`.
- C#: `using X;` → every file declaring `namespace X` (file-level, `heuristic`).

### 2.7 Performance targets

NodeGoat (~60 files) < 2 s; 10 000 files < 60 s; single process, no parallelism in SP10. Files over
1 MiB are `skipped` with a reason.

---

## 3. Pipeline integration

### 3.1 §1.5 Build app graph (new phase)

After recon (stacks/frameworks known, scope confined), before §2 partition. Wrapped by `cache-wrap`
like other helpers. The cache key must cover **every input that can change the graph**:

- `input_digest` = canonical digest over: the content digest of every file `walk.mjs` would parse; the
  content digest of every **resolution config** read in §2.6 (`tsconfig*.json`, `jsconfig.json`,
  `package.json` (`main`/`exports`), `composer.json`, `pyproject.toml`/`setup.cfg` package roots); the
  content digest of every `references/<stack>.md` for the detected stacks (the `surface` blocks); the
  `stacks[]`/`frameworks[]`/`excludes[]` values; and the `MANIFEST.json` digest.
- `version_digest` = digest over **all** of `scripts/graph/**/*.mjs` (a new `dirVersionDigest` in
  `cache-wrap.mjs`, alongside the existing single-file `helperVersionDigest`) + the vendored loader.

A test edits a reference file between a kill and a resume and asserts a cache miss; another edits
`tsconfig.json` paths and asserts the same. The artifact lives in `.oswe/tmp/` under the standard
hygiene (purged at end/abort) and is checkpointed under `.oswe/checkpoints/<run-id>/` for resume.

### 3.2 §2 Partition by reachability — `partition-graph.mjs`

- Entry points = `route` nodes. From each route, transitive closure over `handles`, `uses_middleware`,
  `nests` and `calls` edges of confidence **`exact` or `name-only`** (inclusive is right for
  partitioning; a handler's callbacks are reached through `nests`, so their calls count).
- Group into partitions by `(stack, auth class, top-level module of the route file)`. Output is
  **exactly today's shape** `{ partition_id, stack, files[] }`, so `surface-scan.mjs` and
  `allocate-budget.mjs` are untouched. A file reachable from several groups goes to one of them, the
  most exposed first: `unauthenticated`, then `unknown`, then `authenticated` (then stack, module).
- Files reached by no route → "orphan" partitions cut by directory, i.e. today's behaviour.
- **Zero-regression guarantee:** `graph: null` or zero routes extracted ⇒ partition output is identical
  to the current directory partitioning. A test asserts this byte-for-byte on every fixture.

### 3.3 §3 Analyze — candidate paths — `enumerate-paths.mjs`

- For each partition in `analyze[]`: enumerate `route → … → sink` paths over `calls` and `nests` edges
  (a route is a root of the partition that owns its **handler's** file — the route's own registration
  file may be owned by another group, as NodeGoat's `routes/index.js` registers every route while the
  handlers live in files that follow their routes' auth groups; the hops in any file; a nested
  closure is a hop entered as `exact`), depth ≤ 6, at most 50 paths per partition, ordered by `(sink
  class severity rank, auth == unauthenticated first, path length, id)`. Each hop = `{ file, line,
  function, edge_confidence }`; a path carries `min_confidence` (the weakest edge).
- The analyzer dispatch payload gains `candidate_paths[]` (part of the cache key, so a graph change
  invalidates the analyzer cache correctly).
- `agents/oswe-analyzer.md` gains one instruction block: candidate paths are *structural* hints; confirm
  or refute each *semantically* (sanitizers, auth, attacker control); flows not in the list are still
  expected.
- `finding.schema.json` gains an optional `candidate_path_id` (analyzer output). Additive, backward
  compatible.
- **Aggregation preserves it.** `aggregate-findings.mjs` rebuilds every merged finding field
  explicitly (`aggregate-findings.mjs:54-73`), so the merged record gains
  `candidate_path_ids: uniqSortedStrings(group.flatMap(f => f.candidate_path_id ? [f.candidate_path_id] : []))`
  and `final-finding.schema.json` / `report.schema.json` carry it through to `report.json`. Without this
  the metric below cannot be computed.
- **`candidate_path_hit_rate`, fixed now:** numerator = findings in `report.json` with
  `verification_status ∈ {accepted, downgraded}` **and** non-empty `candidate_path_ids`; denominator =
  all findings with `verification_status ∈ {accepted, downgraded}`. Findings the graph could not see
  count against the metric on purpose — that is a graph failure, not an excuse.

### 3.4 §5 Verify — structural proof — `check-chain-structure.mjs`

Runs deterministically **before** the LLM verifier, on the aggregated findings and candidate chains,
and writes its own artifact `structural.json` (schema `structural-check.schema.json`), keyed by
`OSWE-N` finding id and `CHAIN-N` + transition index.

**Per finding** — let `S` = `enclosing_fn(source)`, `K` = `enclosing_fn(sink)`, where a location
`{ file, line }` maps to the function the graph's own `source` / `sink` nodes on that line sit in when
every such node (those of the location's role first) agrees (byte-precise), else to the innermost
function containing the line — except that when that function *opens* on the line and an enclosing
function contains the line too, the location is read **both ways** (`dao.find(id, (err, rows) => {` is
the caller's call and the callback's first line): the verdict stands only when both readings give one
`structural_path`, else `"n/a"` (`"ambiguous location: the line opens a nested function"`), so the
caller reading — which reaches every closure the caller defines through `nests` — can never prove a
path into an unrelated sibling closure; the two ends of one line are read together. A `call-path`
transition's `from_anchor` is read as the caller's call site and its `to_anchor` as the function it
opens (SKILL.md §5 defines them so). `nests` edges count as `exact` edges in every search below and
never make a closure incomplete:

| condition | `structural_path` |
|---|---|
| `S == K`, or a **forward** path `S → … → K` over `exact` `calls` / `nests` edges (depth ≤ 6) — a sink inside a callback of the source's function is proven | `"proven"` |
| no forward path, but a **reverse** path `K → … → S` over `exact` edges — the source is read inside a callee and flows back through a return value (`handler() { eval(readInput()); }`) | `"n/a"` (return-value flow is real but not modelled; the graph must not contradict it) |
| `S` and `K` connected only through `name-only` / `unresolved` edges, in either direction | `"n/a"` |
| source or sink line maps to no graph node | `"n/a"` |
| no connection, but a call reachable from `S` or from `K` (forward closure over `exact` / `name-only` edges within depth 6) is not `exact` — a `name-only` edge, or an `unresolved` edge with any `to`, `null` included | `"n/a"` (`"graph incomplete on the path"`) |
| `S` and `K` both mapped, **no** connection at all over any edge confidence within depth 6, forward or reverse, and every call reachable from either end is `exact` | `"absent"` |

`"absent"` is therefore a strong claim: the graph saw both ends, resolved every call around them
exactly, and found nothing linking them — an unresolved call on the way (a DAO behind `this.dao.find()`,
an interface method) could be the missing link, so it makes the result `"n/a"`. Every other
uncertainty is `"n/a"`.

**Per chain transition** — `chain.schema.json` gains an optional typed field on each transition:
`kind: "call-path" | "shared-state" | "auth-gain"` plus optional anchors `from_anchor` / `to_anchor`
(`fileline`). The orchestrator sets `kind` when it builds the chain (§4); legacy chains without `kind`
are treated as `"n/a"` (backward compatible, no re-validation of old reports). Only `call-path`
transitions are checked, with the same table applied between the transition's `from_anchor` and
`to_anchor` when both are present, otherwise between the `from` finding's sink and the `to` finding's
source. `shared-state` and `auth-gain` (mass-assignment → admin route) are
`"n/a"` and remain the verifier's call. The helper does not pretend to prove what it cannot.

**Authoritative channel.** The result is **not** injected as a verifier counterexample — the verifier
contract (`apply-verdicts.mjs:141`) rejects an `accepted` verdict with an unrefuted counterexample, which
would make "verifier may still accept" impossible. Instead:

1. `structural.json` is passed to the verifier dispatch as read-only context
   (`dispatch_input.structural`), so it is part of the verifier cache key and a graph change
   invalidates verifier caches.
2. `apply-verdicts.mjs` takes a new `--structural <path>` input and applies **one** new deterministic
   rule after the verdict is applied: **`confidence == "strong static proof"` and
   `structural_path == "absent"` ⇒ `confidence = "to verify"`**, recorded in the finding's
   `verification_notes` as `"structural: absent"`. The verifier's verdict (accept/downgrade/reject) is
   unchanged; only the confidence ceiling is. Through the existing Critical gate (every member at
   "strong static proof"), a chain with such a member can no longer be Critical. A chain verdict
   whose `new_confidence` / `new_severity` lies within the ceilings computed from the members' pre-cap
   confidences but above the post-cap ceilings (losing the Critical natural level also lowers the
   severity ceiling) is clamped to the post-cap ceilings (chain note `"structural: member cap"`)
   rather than failed as verifier output — the verifier could not have known the cap, and a retry
   could not fix it.
3. No existing rule changes; the 320 pipeline tests stay green with `--structural` omitted.

### 3.5 §7 Report

New "App graph" section in `.md`/`.html`: files parsed / errors / skipped, routes by auth class, call
resolution ratio, per-stack coverage matrix, multi-file chain count. `report.schema.json` and
`report-summary.schema.json` extended additively. Exports (SARIF/JUnit) unchanged.

### 3.6 Failure handling summary

| failure | behaviour |
|---|---|
| WASM load fails | `graph: null`, coverage note, pipeline as today |
| one file fails to parse | `parse_status: "error"`, counted, rest of graph built |
| file > 1 MiB | `skipped`, counted |
| no route extracted | partitions identical to today; candidate paths empty; structural checks `n/a` |
| graph schema invalid | treated as `graph: null` (helper bug surfaced in stats, never trusted) |

---

## 4. Tests, benchmark, gates

### 4.1 Unit tests (`node --test`, zero deps)

- **Conformance suite** — one parameterised suite applied to all five language modules over the existing
  `test-fixtures/<stack>/{vulnerable,safe}`, with a golden `graph.expected.json` per fixture. Every
  language must pass the same cases: function/method extraction, resolved import, cross-file `exact`
  call, `name-only` call, route + auth middleware, source, sink, non-fatal parse error.
- **Determinism** — build twice, byte-identical.
- **Resolution** — per-language edge cases (`index.js`, `__init__.py`, PSR-4, C# namespaces, homonymous
  class in two packages ⇒ `unresolved`, never `exact`); **shadowing**: parameter shadows a same-file
  function ⇒ `unresolved`, local shadows an import ⇒ `unresolved`; **override**: `this.x()` with a
  subclass redefining `x` ⇒ `name-only`, without ⇒ `exact`.
- **Identity** — two sinks on one line ⇒ two distinct ids; Java/C# overloads ⇒ distinct function ids;
  anonymous functions ⇒ distinct, deterministic ids.
- **Surface classification** — every entry of every `surface` block maps to exactly one shape of the
  §2.5 table (CI fails on a new unclassifiable entry); `eval` in a comment/string ⇒ no sink; `$where`
  as a free-standing string ⇒ no sink, as an object key ⇒ sink.
- **`partition-graph`** — zero-regression byte-equality when no routes; grouping rules; bounds.
- **`enumerate-paths`** — depth/cap, deterministic order, `min_confidence` labelling.
- **`check-chain-structure`** — forward `exact` path ⇒ `proven`; same function ⇒ `proven`; reverse-only
  path (return-value flow) ⇒ `n/a`; path containing a `name-only` link ⇒ `n/a`; unmapped line ⇒ `n/a`;
  both ends mapped and disconnected ⇒ `absent`; transition `kind: "shared-state"` ⇒ `n/a`; legacy
  transition without `kind` ⇒ `n/a`.
- **`aggregate-findings`** — `candidate_path_ids` merged across duplicates (union, sorted); absent on
  findings that never cited one.
- **`apply-verdicts`** — `--structural` omitted ⇒ byte-identical output to today; `absent` + "strong
  static proof" ⇒ "to verify" with note; `absent` + "likely" ⇒ unchanged; a Critical chain whose member
  is downgraded this way is no longer Critical. All 320 existing tests stay green.
- **Cache invalidation** — resume after editing a `references/<stack>.md`, a `tsconfig.json`, or a
  `graph/lang/*.mjs` module ⇒ graph cache miss and verifier cache miss.
- **E2E replay** — both existing replay tests (no-cache, kill-then-resume) extended with the graph stage
  and its cache hit.
- **CI** — `MANIFEST.json` ↔ binaries hash check, `vendor/` ≤ 10 MiB, structure gate extended (each
  stack in `check-structure.mjs` must have a `graph/lang/*.mjs`).

### 4.2 Benchmark gates (fixed now, read once at the end, not revised after observation)

| gate | target | rationale |
|---|---|---|
| NodeGoat — declared-set recall | stays **7/7** | no regression |
| NodeGoat — accepted multi-file chains | **≥ 1** with `structural_path: proven` | the SP9 debt |
| NodeGoat — `candidate_path_hit_rate` | **≥ 0.60** | proves the analyzer actually uses the graph |
| OWASP BenchmarkJava (88-case stratified sample) | precision stays **1.000**, recall **≥ 0.98** | the graph must not cost precision |
| WebGoat (Spring, second public app) | **≥ 3** accepted High findings with `proven`, **0** noisy | Java showcase; validates the Spring extractor on real code |
| Flask `flaskr` (negative control) | **0** exploitable findings | stays quiet on clean code |

New ledger metrics: `structural_proof_rate`, `candidate_path_hit_rate`, `multi_file_chain_count`,
`call_resolution_ratio`. WebGoat gets a file-anchored truth manifest in the SP9 `nodegoat-truth.json`
style; the scorer is reused, not forked.

### 4.3 Documentation

README: "How it works" gains the graph step and the structural-proof rule; "Honest limits" gains the
resolution limits of §1.4. `BENCHMARK.md` gains the SP10 table with the gate read.

---

## 4.4 Pre-campaign amendments (2026-11-06, from the real-NodeGoat probe)

Probing a real NodeGoat checkout before the Task 20 campaign found that the graph was right (every
handler → DAO call `exact`) while the consumers were blind: zero candidate paths (every route is
registered in `routes/index.js`, owned by the unauthenticated group, while the handlers' files follow
their routes' groups), sinks inside callbacks unreachable (no edge from a function to its closures),
and three NodeGoat idioms unresolved (a `const helper = () => {}` nested in a method, `this.m()` from
a callback inside a constructor-style method, a ctor-body helper called from a callback). The
amendments above — `nests` edges (§1.2, §3.2, §3.3, §3.4), nested definitions and the constructor-style
lexical class body (§1.4), handler-file root binding (§3.3), byte-precise / opening-line mapping (§3.4)
— plus a wider Node surface (HTTP clients, `redirect(`, `fs` read / write, template compilers, Express
auth-middleware conventions such as `isLoggedIn`) turn that probe into 12 candidates (eval, `$where`
through a nested helper, `needle.get`, `res.redirect`) and `proven` for the cross-file NoSQL and the
SSRF flows. Gates in §4.2 are unchanged.

**Second probe (WebGoat, BenchmarkJava, flaskr), same day.** Building the graph of the other three
campaign targets before any audit run exposed four more blind spots, all on the Java side:
WebGoat's 246 lesson routes were `unknown` because its one `SecurityFilterChain` uses the lambda DSL
(`authorizeHttpRequests(auth -> auth.requestMatchers(...).permitAll()...anyRequest().authenticated())`),
which the extractor only noted; the Java surface saw one SQL sink in all of WebGoat (its tokens were
written against declared types, `Statement.execute`, so `statement.executeQuery(query)` on a local
never matched) and no SSRF, path-traversal or file sink at all; `.getValue(` (meant for SpEL) turned
every `session.getValue` / `entry.getValue` into an `eval` candidate (27 in WebGoat, 1 204 in
BenchmarkJava), crowding the real sinks out of the 50 ranked candidates; and BenchmarkJava's 2 740
`@WebServlet` test cases had no route at all, leaving the whole corpus as one orphan partition.
Amendments: (1) `security_chains` — java.mjs emits, for each method returning a
`SecurityFilterChain` or overriding `configure(HttpSecurity)`, its `securityMatcher` scope and its
rules in source order: a `requestMatchers` / `antMatchers` / `mvcMatchers` (optional `HttpMethod.X`)
or `anyRequest` matcher INSIDE an `authorizeHttpRequests(...)` / `authorizeRequests()` call, whose
auth is the call chained directly on it (`permitAll` / `anonymous` → unauthenticated, the
authorization rules → authenticated, `access(...)` / `hasIpAddress` / `not()` / anything else →
unknown; a non-literal pattern or `regexMatchers` → `patterns: null`, noted). Matchers elsewhere
(`requiresChannel`, `csrf.ignoringRequestMatchers`) and rule-named calls elsewhere (`formLogin(l ->
l.permitAll())`) are not rules — the first cut paired matchers with the next rule-named call in
source order and the independent review showed it turning an IP-restricted admin path
`unauthenticated`. `requestMatchers(antMatcher("/p"))` reads the factory's literal (verb kept when
the factories agree); a RequestMatcher object or a constant is unreadable. Rules the extractor cannot
see — the chain's `HttpSecurity` handed to a helper (`common(http)`), `http.with(dsl)` / `apply`, an
authorize call given a method reference or a Customizer value — are an unreadable rule at their
position, so first-match makes every route not settled before them `unknown`. A chain without any
rule is still emitted (noted "security(unread chain)") and votes `unknown`; a chain whose
`securityMatcher` scope is not literal (a RequestMatcher object, a constant, a `regexMatcher`), or
opened with the zero-argument `securityMatchers()` / Spring 5 `requestMatchers()`, has an unread
scope and votes on every route; a `WebSecurityCustomizer` / `configure(WebSecurity)` with
`web.ignoring()` literal matchers is a chain scoped to them that permits exactly them, verb kept.
build-graph applies the rules first-match (Spring's AntPathMatcher: `?`, `*`, whole-segment `**`,
`{var}`, `{*rest}`, an empty trailing token dropped; a pattern without a leading `/` or with a
`{var:regex}` constraint is unreadable → unknown) to every java route no marker already
authenticates; a route serving ANY verb against verb-specific rules is `unknown` unless every verb
it serves agrees. With several chains (WebGoat hosts two contexts, WebGoat and WebWolf, each with
its own chain) the chains whose scope (path and verb) fully covers the route vote, else the unscoped
ones (plus, for a route serving ANY verb, the chains covering only some of its verbs), every
unread-scope chain always votes, and a route no chain covers for sure casts an `unknown` vote; the
route takes the verdict only when the votes agree — `unknown` otherwise, because the graph cannot
tell which context serves a route. Four hints turn an `unauthenticated` verdict into `unknown`: the
§2.4 file-level hint (a security type named in a file that yields no chain: WebFlux chains,
`@EnableWebSecurity` without a readable config...), a `web.xml` at a conventional location
(`src/main/webapp/WEB-INF`, `WebContent/WEB-INF`, `web/WEB-INF`, `WEB-INF`) declaring a
`<security-constraint>` with an `<auth-constraint>`, Spring Security named in `pom.xml` /
`build.gradle(.kts)` while no chain was read (Boot's default chain authenticates everything), and a
servlet filter class when no chain exists (Boot registers every Filter bean on `/*`). Residuals,
all in the safe direction: `formLogin().permitAll()` / `logout().permitAll()` are not rules (a
login route reads as its chain says), `requestMatchers(CONSTANT)` is unreadable, a non-literal
ignore is only noted, `web.xml` url-patterns are not matched (any constraint hints every route),
`X.super.m()` keeps X as receiver. (2) `@WebServlet` routes: one per `doGet` / `doPost` / … /
`service` method on the class's first literal pattern, framework `servlet` (further patterns
noted), with the class's and method's auth annotations (`@ServletSecurity`, `@RolesAllowed`) as
middleware texts; a `@WebFilter`, `implements Filter`, or `HttpFilter` / `GenericFilter` /
`OncePerRequestFilter` / `GenericFilterBean` subclass is the hint "servlet(filter)" that turns an
unmarked servlet route `unknown` — BenchmarkJava's helper filters make its 5 480 servlet routes
`unknown` rather than `unauthenticated`. `super.m()` now carries the
superclass as receiver class, so `ProfileUpload.uploadFileHandler → super.execute` resolves. (3)
The Java surface widened to method-shaped tokens (`executeQuery(`, `executeUpdate(`,
`prepareStatement(`, `queryFor*(`, `batchUpdate(`, `Runtime.exec`, `openConnection(`, `openStream(`,
`RestTemplate`, `WebClient`, `HttpClient`, `getForObject(`…, `FileInputStream`, `FileOutputStream`,
`Files.read*/write*/copy`, `FileCopyUtils.copy`, `createNewFile(`, `XMLInputFactory[.newInstance]`,
`DocumentBuilderFactory.newInstance`, `createXMLStreamReader(`, `createUnmarshaller(`, `.unmarshal(`,
`TransformerFactory`, `SchemaFactory`, `Ognl.getValue`, `createValueExpression(`; sources
`getParameterValues`, `getParameterMap`, `getPart(`, `getRequestURI`, `getPathInfo`) and
`.getValue(` dropped — `parseExpression(` already anchors every SpEL chain, `Ognl.getValue` keeps
OGNL. No existing token of any stack changes class. (4) The benchmark scorer's class synonyms gain
path-traversal, XXE and insecure-deserialization groups (and `authorization` under access-control)
for the WebGoat manifest, whose JKU entry is declared graph-blind up front. Gates in §4.2 are
unchanged.

## 5. Out of scope (explicit)

- Replacing `surface-scan.mjs` with graph-derived counts — **SP11**.
- Slices replacing the 12-partition budget, cross-run cache, `--diff`, `--dry-run` cost — **SP11**.
- Marketplace, GitHub Action, `--baseline` — **SP12**.
- New languages/frameworks beyond the table in §2.4 — **SP13**.
- Parallel parsing, incremental re-parse, persistent graph outside `.oswe/`.
- Any taint engine, type inference, or dynamic execution.
