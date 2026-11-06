import { test } from "node:test";
import assert from "node:assert/strict";
import { escapeHtml, mdToHtml } from "../render-html.mjs";

test("escapeHtml escapes the four dangerous chars", () => {
  assert.equal(escapeHtml(`<a href="x">&`), "&lt;a href=&quot;x&quot;&gt;&amp;");
});
test("headings render h1/h2/h3", () => {
  assert.match(mdToHtml("# A\n## B\n### C"), /<h1>A<\/h1>[\s\S]*<h2>B<\/h2>[\s\S]*<h3>C<\/h3>/);
});
test("bold then italic, asterisk-only, longer delimiter first", () => {
  assert.equal(mdToHtml("**a** and *b*").includes("<strong>a</strong> and <em>b</em>"), true);
});
test("underscores stay literal (no <em>)", () => {
  const h = mdToHtml("render_template_string and __class__ and SECRET_KEY");
  assert.equal(h.includes("<em>"), false);
  assert.equal(h.includes("render_template_string"), true);
});
test("inline code is escaped and not emphasis-formatted", () => {
  const h = mdToHtml("`a*b*c` and `<script>`");
  assert.equal(h.includes("<code>a*b*c</code>"), true);
  assert.equal(h.includes("<code>&lt;script&gt;</code>"), true);
});
test("table renders thead/tbody", () => {
  const h = mdToHtml("| A | B |\n|---|---|\n| 1 | 2 |");
  assert.match(h, /<table><thead><tr><th>A<\/th><th>B<\/th><\/tr><\/thead><tbody><tr><td>1<\/td><td>2<\/td><\/tr><\/tbody><\/table>/);
});
test("blockquote, list, hr, strikethrough render", () => {
  assert.match(mdToHtml("> note"), /<blockquote>note<\/blockquote>/);
  assert.match(mdToHtml("- x\n- y"), /<ul><li>x<\/li><li>y<\/li><\/ul>/);
  assert.match(mdToHtml("---"), /<hr>/);
  assert.match(mdToHtml("~~gone~~"), /<del>gone<\/del>/);
});
test("malicious MD is escaped, never live tags", () => {
  const evil = "# <script>alert(1)</script>\n\n| <img onerror=x> | b |\n|---|---|\n| `\"><img onerror=y>` | 2 |";
  const h = mdToHtml(evil);
  assert.equal(/<script\b/i.test(h), false);
  assert.equal(/<img\b/i.test(h), false);
  assert.equal(h.includes("&lt;script&gt;"), true);
  assert.equal(h.includes("&lt;img onerror=x&gt;"), true);
});

import { severityDonut, coverageBar, statusBar, chainDiagram } from "../render-html.mjs";

const SEV = { Critical: 1, High: 2, Medium: 0, Low: 0, Info: 0 };
const CHAINS = [{ id: "CHAIN-1", severity: "Critical", entry_auth: "unauthenticated", final_impact: "unauth-rce",
                  nodes: ["entry", "OSWE-1", "OSWE-2", "RCE"],
                  edges: [{ from: "entry", to: "OSWE-1", verdict: "accepted" }, { from: "OSWE-1", to: "OSWE-2", verdict: "accepted" }] }];

test("severity donut reflects counts and total, no NaN", () => {
  const svg = severityDonut(SEV);
  assert.equal(svg.includes("Critical: 1"), true);
  assert.equal(svg.includes("High: 2"), true);
  assert.equal(svg.includes(">3<"), true);          // total in the center
  assert.equal(/NaN/.test(svg), false);
});
test("empty donut: grey ring + 'No findings', no NaN", () => {
  const svg = severityDonut({ Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 });
  assert.equal(svg.includes("No findings"), true);
  assert.equal(svg.includes("#dddddd"), true);
  assert.equal(/NaN/.test(svg), false);
});
test("chain diagram: node/edge counts match; zero chains -> note", () => {
  const svg = chainDiagram(CHAINS);
  assert.equal((svg.match(/<rect /g) || []).length, 4);    // 4 nodes
  assert.equal((svg.match(/<polygon /g) || []).length, 2); // 2 edge arrowheads
  assert.equal(chainDiagram([]).includes("No exploit chains"), true);
});
test("coverage and status bars reflect counts, no NaN on empty", () => {
  assert.equal(coverageBar({ analyzed: 2, skipped: 0 }).includes("analyzed 2"), true);
  assert.equal(statusBar({ accepted: 2, downgraded: 0, rejected: 0, "not-requested": 0 }).includes("accepted 2"), true);
  assert.equal(/NaN/.test(statusBar({ accepted: 0, downgraded: 0, rejected: 0, "not-requested": 0 })), false);
  assert.equal(/NaN/.test(coverageBar({ analyzed: 0, skipped: 0 })), false);
});

import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { renderReport, graphErrors } from "../render-html.mjs";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "..", "render-html.mjs");

const fullSummary = () => ({
  meta: { target: "test-fixtures/python/vulnerable", stack: "Python / Flask 3.0.3", date: "2026-06-16 10:15", verdict: "unauth-rce", proof_level: "strong static proof" },
  severity_counts: { Critical: 1, High: 2, Medium: 0, Low: 0, Info: 0 },
  finding_status_counts: { accepted: 2, downgraded: 0, rejected: 0, "not-requested": 0 },
  coverage: { analyzed: 2, skipped: 0 },
  chains: [{ id: "CHAIN-1", severity: "Critical", entry_auth: "unauthenticated", final_impact: "unauth-rce",
             nodes: ["entry", "OSWE-1", "OSWE-2", "RCE"],
             edges: [{ from: "entry", to: "OSWE-1", verdict: "accepted" }, { from: "OSWE-1", to: "OSWE-2", verdict: "accepted" }] }]
});

test("renderReport: meta fields are escaped, never live tags", () => {
  const s = fullSummary();
  s.meta.target = "<img src=x onerror=1>";
  s.meta.stack = `a"&b`;
  const html = renderReport({ md: "# ok", summary: s });
  assert.equal(/<img\b/i.test(html), false);
  assert.equal(html.includes("&lt;img src=x onerror=1&gt;"), true);
  assert.equal(html.includes("a&quot;&amp;b"), true);
});
test("renderReport: self-contained + CSP, no active/external markup", () => {
  const html = renderReport({ md: "# ok\n\nbody `code`", summary: fullSummary() });
  assert.equal(html.includes(`content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"`), true);
  for (const tag of ["<script", "<img", "<iframe", "<object", "<embed", "<link"]) {
    assert.equal(html.toLowerCase().includes(tag), false, "must not emit " + tag);
  }
  assert.equal(/\ssrc=/.test(html), false);
  assert.equal(/\shref=/.test(html), false);
});
test("renderReport: escaped active markup in body is allowed", () => {
  const html = renderReport({ md: "value `<img src=x>`", summary: fullSummary() });
  assert.equal(html.includes("&lt;img src=x&gt;"), true);
  assert.equal(/<img\b/i.test(html), false);
});
test("renderReport: deterministic", () => {
  const a = renderReport({ md: "# A\n\n- x", summary: fullSummary() });
  const b = renderReport({ md: "# A\n\n- x", summary: fullSummary() });
  assert.equal(a, b);
});
test("graphErrors: coherent graph -> no errors", () => {
  assert.equal(graphErrors(fullSummary()).length, 0);
  assert.equal(graphErrors({ chains: [] }).length, 0);
});
test("graphErrors: edge endpoint not in nodes -> error", () => {
  const s = fullSummary();
  s.chains[0].edges.push({ from: "OSWE-2", to: "OSWE-9", verdict: "accepted" }); // OSWE-9 not a node
  const errs = graphErrors(s);
  assert.equal(errs.length, 1);
  assert.equal(errs[0].includes("OSWE-9"), true);
});

function mkdir() { return mkdtempSync(join(tmpdir(), "oswe-html-")); }

test("CLI: valid input writes html, exit 0", () => {
  const d = mkdir();
  const md = join(d, "r.md"), sum = join(d, "s.json"), out = join(d, "r.html");
  writeFileSync(md, "# Report\n\nbody");
  writeFileSync(sum, JSON.stringify(fullSummary()));
  execFileSync(process.execPath, [SCRIPT, "--md", md, "--summary", sum, "--out", out]);
  assert.equal(existsSync(out), true);
  assert.equal(readFileSync(out, "utf8").includes("OSWE Audit Report"), true);
  rmSync(d, { recursive: true, force: true });
});
test("CLI: invalid summary -> exit 1, no html, no tmp leftover", () => {
  const d = mkdir();
  const md = join(d, "r.md"), sum = join(d, "s.json"), out = join(d, "r.html");
  writeFileSync(md, "# Report");
  const bad = fullSummary();
  bad.chains[0].nodes = ["<img onerror=x>"]; // schema-invalid node label
  writeFileSync(sum, JSON.stringify(bad));
  let code = 0;
  try { execFileSync(process.execPath, [SCRIPT, "--md", md, "--summary", sum, "--out", out], { stdio: "pipe" }); }
  catch (e) { code = e.status; }
  assert.equal(code, 1);
  assert.equal(existsSync(out), false);
  assert.equal(readdirSync(d).some((f) => f.includes(".tmp-")), false);
  rmSync(d, { recursive: true, force: true });
});
test("CLI: incoherent chain graph -> exit 1, no html, no tmp leftover", () => {
  const d = mkdir();
  const md = join(d, "r.md"), sum = join(d, "s.json"), out = join(d, "r.html");
  writeFileSync(md, "# Report");
  const bad = fullSummary();
  bad.chains[0].edges.push({ from: "OSWE-2", to: "OSWE-9", verdict: "accepted" }); // schema-valid, graph-incoherent
  writeFileSync(sum, JSON.stringify(bad));
  let code = 0;
  try { execFileSync(process.execPath, [SCRIPT, "--md", md, "--summary", sum, "--out", out], { stdio: "pipe" }); }
  catch (e) { code = e.status; }
  assert.equal(code, 1);
  assert.equal(existsSync(out), false);
  assert.equal(readdirSync(d).some((f) => f.includes(".tmp-")), false);
  rmSync(d, { recursive: true, force: true });
});
test("CLI: missing flags / nonexistent files -> exit 2", () => {
  const d = mkdir();
  let code = 0;
  try {
    execFileSync(process.execPath, [SCRIPT, "--md", join(d, "nope.md"), "--summary", join(d, "nope.json"), "--out", join(d, "o.html")], { stdio: "pipe" });
  } catch (e) { code = e.status; }
  assert.equal(code, 2);
  let code2 = 0;
  try { execFileSync(process.execPath, [SCRIPT, "--md", join(d, "x.md")], { stdio: "pipe" }); }
  catch (e) { code2 = e.status; }
  assert.equal(code2, 2);
  rmSync(d, { recursive: true, force: true });
});
test("CLI: unwritable --out (parent dir missing) -> exit 2, no tmp leftover", () => {
  const d = mkdir();
  const md = join(d, "r.md"), sum = join(d, "s.json");
  const out = join(d, "no-such-dir", "r.html"); // parent does not exist -> writeFileSync ENOENT
  writeFileSync(md, "# Report");
  writeFileSync(sum, JSON.stringify(fullSummary()));
  let code = 0;
  try { execFileSync(process.execPath, [SCRIPT, "--md", md, "--summary", sum, "--out", out], { stdio: "pipe" }); }
  catch (e) { code = e.status; }
  assert.equal(code, 2);
  assert.equal(existsSync(out), false);
  // the .tmp-<pid> sibling lives in the (missing) dir, so nothing can leak into d
  assert.equal(readdirSync(d).some((f) => f.includes(".tmp-")), false);
  rmSync(d, { recursive: true, force: true });
});

const CLI_RH = fileURLToPath(new URL("../render-html.mjs", import.meta.url));

function runRender(md, summary, checkpointDir) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-rh-cache-")));
  const mdP = join(dir, "r.md");
  const sumP = join(dir, "s.json");
  const outP = join(dir, "r.html");
  writeFileSync(mdP, md);
  writeFileSync(sumP, JSON.stringify(summary));
  const args = [CLI_RH, "--md", mdP, "--summary", sumP, "--out", outP];
  if (checkpointDir) args.push("--checkpoint-dir", checkpointDir);
  const r = spawnSync(process.execPath, args, { encoding: "utf8" });
  return { code: r.status, stderr: r.stderr, html: existsSync(outP) ? readFileSync(outP, "utf8") : null };
}

function minimalSummary() {
  return {
    meta: { target: "test-project", stack: "python", date: "2026-06-20", verdict: "no-critique", proof_level: null },
    severity_counts: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
    finding_status_counts: { accepted: 0, downgraded: 0, rejected: 0, "not-requested": 0 },
    coverage: { analyzed: 0, skipped: 0 },
    chains: []
  };
}

test("render-html --checkpoint-dir miss writes the cache file (html_output payload)", () => {
  const ckpt = realpathSync(mkdtempSync(join(tmpdir(), "oswe-rh-ckpt-")));
  const r = runRender("# Report\n", minimalSummary(), ckpt);
  assert.equal(r.code, 0);
  const cacheDir = join(ckpt, "render-html");
  const files = readdirSync(cacheDir);
  assert.equal(files.length, 1);
  const wrapper = JSON.parse(readFileSync(join(cacheDir, files[0]), "utf8"));
  assert.equal(typeof wrapper.html_output, "string");
  assert.ok(wrapper.html_output.startsWith("<!"));
});

test("render-html --checkpoint-dir hit on second call: stderr 'cache hit', html byte-identical", () => {
  const ckpt = realpathSync(mkdtempSync(join(tmpdir(), "oswe-rh-ckpt-")));
  const first = runRender("# Report\n", minimalSummary(), ckpt);
  const second = runRender("# Report\n", minimalSummary(), ckpt);
  assert.equal(second.code, 0);
  assert.match(second.stderr, /cache hit/i);
  assert.equal(second.html, first.html);
});

// ---------- SP10: App graph section + structural info ----------
import { createHash } from "node:crypto";
import { appGraphSection } from "../render-html.mjs";

const REPO_ROOT_RH = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const GRAPH_STACKS = ["dotnet", "java", "node", "php", "python"];
// Real graph.stats from the committed conformance goldens (never hand-built).
const goldenStats = (stack) =>
  JSON.parse(readFileSync(join(REPO_ROOT_RH, "test-fixtures", "graph", stack, "graph.expected.json"), "utf8")).stats;
const sha = (s) => createHash("sha256").update(s).digest("hex");
const appGraph = (stack = "node", over = {}) => ({ available: true, stats: goldenStats(stack), multi_file_chain_count: 1, ...over });
const withApp = (ag) => ({ ...fullSummary(), app_graph: ag });
const countOf = (html, needle) => html.split(needle).length - 1;

test("app graph: no app_graph -> no section, helper returns empty string", () => {
  const html = renderReport({ md: "# ok", summary: fullSummary() });
  assert.equal(html.includes("App graph"), false);
  assert.equal(appGraphSection(undefined), "");
  assert.equal(appGraphSection(null), "");
});

test("app graph: available:false renders the escaped reason as the whole section", () => {
  const html = renderReport({
    md: "# ok",
    summary: withApp({ available: false, reason: "parser <b>wasm</b> failed & \"died\"", multi_file_chain_count: 0 })
  });
  assert.equal(html.includes("<h2>App graph</h2>"), true);
  assert.equal(html.includes("App graph unavailable: parser &lt;b&gt;wasm&lt;/b&gt; failed &amp; &quot;died&quot;"), true);
  assert.equal(/<b>/.test(html), false);
  assert.equal(html.includes("Call resolution"), false);   // no stats table when unavailable
  assert.equal(html.includes("Multi-file chains"), false);
});

test("app graph: available:true with the node golden stats -> headings, rows, numbers", () => {
  const html = renderReport({ md: "# ok", summary: withApp(appGraph("node")) });
  assert.equal(html.includes("<h2>App graph</h2>"), true);
  assert.equal(html.includes("<td>Files parsed / errors / skipped</td><td>4 / 0 / 0 of 4</td>"), true);
  assert.equal(html.includes("<td>Functions</td><td>9</td>"), true);
  assert.equal(html.includes("<td>Routes by auth</td><td>1 unauthenticated / 1 authenticated / 0 unknown</td>"), true);
  assert.equal(html.includes("<td>Call resolution</td><td>0.13 (1 exact / 8 total; 1 name-only; 6 unresolved)</td>"), true);
  assert.equal(html.includes("<td>Multi-file chains</td><td>1</td>"), true);
  assert.equal(html.includes("App graph unavailable"), false);
  // per-stack coverage table: stack, frameworks detected, extractors applied, not extracted
  assert.equal(html.includes("<th>Stack</th><th>Frameworks detected</th><th>Extractors applied</th><th>Not extracted</th>"), true);
  assert.equal(html.includes("<td>node</td><td>express</td><td>express, nest</td><td>—</td>"), true);
  assert.equal(/NaN|undefined|Infinity/.test(html), false);
});

test("app graph: every golden stack renders its own numbers", () => {
  for (const stack of GRAPH_STACKS) {
    const st = goldenStats(stack);
    const html = appGraphSection(appGraph(stack));
    const ratio = (st.calls_exact / st.calls_total).toFixed(2);
    const r = st.routes_by_auth;
    assert.equal(html.includes(`<td>Files parsed / errors / skipped</td><td>${st.files_parsed} / ${st.files_error} / ${st.files_skipped} of ${st.files_total}</td>`), true, stack);
    assert.equal(html.includes(`<td>Functions</td><td>${st.functions}</td>`), true, stack);
    assert.equal(html.includes(`<td>Routes by auth</td><td>${r.unauthenticated} unauthenticated / ${r.authenticated} authenticated / ${r.unknown} unknown</td>`), true, stack);
    assert.equal(html.includes(`<td>Call resolution</td><td>${ratio} (${st.calls_exact} exact / ${st.calls_total} total; ${st.calls_name_only} name-only; ${st.calls_unresolved} unresolved)</td>`), true, stack);
    assert.equal(html.includes(`<tr><td>${stack}</td>`), true, stack);
    assert.equal(/NaN|undefined|Infinity/.test(html), false, stack);
  }
});

test("app graph: calls_total 0 -> em dash, no NaN/Infinity", () => {
  const stats = { ...goldenStats("node"), calls_total: 0, calls_exact: 0, calls_name_only: 0, calls_unresolved: 0 };
  const html = appGraphSection(appGraph("node", { stats }));
  assert.equal(html.includes("<td>Call resolution</td><td>—</td>"), true);
  assert.equal(/NaN|Infinity/.test(html), false);
});

test("app graph: ratio uses 2 decimals (2/3 -> 0.67, 1/1 -> 1.00)", () => {
  const two = appGraphSection(appGraph("node", { stats: { ...goldenStats("node"), calls_exact: 2, calls_total: 3, calls_name_only: 1, calls_unresolved: 0 } }));
  assert.equal(two.includes("<td>0.67 (2 exact / 3 total; 1 name-only; 0 unresolved)</td>"), true);
  const one = appGraphSection(appGraph("node", { stats: { ...goldenStats("node"), calls_exact: 1, calls_total: 1, calls_name_only: 0, calls_unresolved: 0 } }));
  assert.equal(one.includes("<td>1.00 (1 exact / 1 total; 0 name-only; 0 unresolved)</td>"), true);
});

test("app graph: config_errors listed only when non-empty, escaped", () => {
  const none = appGraphSection(appGraph("node"));
  assert.equal(none.includes("Config errors"), false);
  const stats = { ...goldenStats("node"), config_errors: [{ file: "tsconfig.json", message: "Unexpected token <" }] };
  const some = appGraphSection(appGraph("node", { stats }));
  assert.equal(some.includes("Config errors"), true);
  assert.equal(some.includes("tsconfig.json: Unexpected token &lt;"), true);
  assert.equal(some.includes("Unexpected token <"), false);
});

test("app graph: coverage cells join with ', ', '—' when empty, and are escaped", () => {
  const stats = goldenStats("node");
  stats.coverage_matrix = {
    node: { frameworks_detected: ["express", "<img src=x>"], extractors_applied: [], not_extracted: ["nest", "a&b"], patterns_unmatched: ["zzz"] },
    "<s>": { frameworks_detected: [], extractors_applied: ["koa"], not_extracted: [], patterns_unmatched: [] }
  };
  const html = renderReport({ md: "# ok", summary: withApp(appGraph("node", { stats })) });
  assert.equal(html.includes("<tr><td>node</td><td>express, &lt;img src=x&gt;</td><td>—</td><td>nest, a&amp;b</td></tr>"), true);
  assert.equal(html.includes("<tr><td>&lt;s&gt;</td><td>—</td><td>koa</td><td>—</td></tr>"), true);
  assert.equal(/<img\b/i.test(html), false);
  assert.equal(/<s>/.test(html), false);
  assert.equal(html.includes("zzz"), false);   // patterns_unmatched is not part of the section
});

test("app graph: available:true without stats still shows the multi-file chain count", () => {
  const html = appGraphSection({ available: true, multi_file_chain_count: 2 });
  assert.equal(html.includes("<td>Multi-file chains</td><td>2</td>"), true);
  assert.equal(html.includes("Call resolution"), false);
});

test("app graph: section sits after the charts and exploit chains, before the full report", () => {
  const html = renderReport({ md: "# ok", summary: withApp(appGraph("node")) });
  const iCov = html.indexOf("<figcaption>Coverage</figcaption>");
  const iChains = html.indexOf("<h2>Exploit chains</h2>");
  const iApp = html.indexOf("<h2>App graph</h2>");
  const iFull = html.indexOf("<h2>Full report</h2>");
  assert.equal(iCov > -1 && iCov < iApp, true);
  assert.equal(iApp > iChains, true);
  assert.equal(iApp < iFull, true);
  assert.equal(countOf(html, "<h2>App graph</h2>"), 1);
});

test("app graph: rendering is deterministic and independent of stack key order", () => {
  const a = goldenStats("node");
  a.coverage_matrix = { python: a.coverage_matrix.node, node: a.coverage_matrix.node };
  const b = goldenStats("node");
  b.coverage_matrix = { node: b.coverage_matrix.node, python: b.coverage_matrix.node };
  assert.equal(appGraphSection(appGraph("node", { stats: a })), appGraphSection(appGraph("node", { stats: b })));
});

test("structural: finding block lines in the Markdown body reach the HTML, escaped", () => {
  const md = "### OSWE-3 Command injection\n\nStructural: absent\nNotes: structural: absent\n\n### OSWE-4 XSS\n\nStructural: <proven>\nNotes: a & b; c";
  const html = renderReport({ md, summary: fullSummary() });
  assert.equal(html.includes("Structural: absent<br>Notes: structural: absent"), true);
  assert.equal(html.includes("Structural: &lt;proven&gt;<br>Notes: a &amp; b; c"), true);
  assert.equal(/<proven>/.test(html), false);
});

test("structural: chain verification_notes -> a Notes: line under the chain id", () => {
  const s = fullSummary();
  s.chains[0].verification_notes = ["structural: member cap", "x <b> & y"];
  const html = renderReport({ md: "# ok", summary: s });
  assert.equal(html.includes('<p class="muted">Notes: structural: member cap; x &lt;b&gt; &amp; y</p>'), true);
  assert.equal(/<b>/.test(html), false);
  const idPos = html.indexOf("CHAIN-1 — Critical");
  const notesPos = html.indexOf("Notes: structural: member cap");
  const svgPos = html.indexOf('aria-label="Exploit chain CHAIN-1"');
  assert.equal(idPos > -1 && idPos < notesPos && notesPos < svgPos, true);
});

test("structural: chains without (or with empty) verification_notes render no Notes: line", () => {
  assert.equal(renderReport({ md: "# ok", summary: fullSummary() }).includes("Notes:"), false);
  const s = fullSummary();
  s.chains[0].verification_notes = [];
  assert.equal(renderReport({ md: "# ok", summary: s }).includes("Notes:"), false);
  assert.equal(chainDiagram(CHAINS).includes("Notes:"), false);
});

test("byte-identity: a pre-task report (no app_graph, no notes) renders exactly as the previous renderer did", () => {
  // sha256 of renderReport() output computed once from render-html.mjs at e744a85 (the commit before Task 18).
  const md = "# OSWE Report\n\n## Detailed findings\n\n### OSWE-1 SQL injection\n\n- Severity: High\n\n## Coverage\n\n| Stack | Files |\n|---|---|\n| python | 3 |\n";
  const html = renderReport({ md, summary: fullSummary() });
  assert.equal(sha(html), "5094b98017e4ee30cf2aaf0e6d88d46c524b453b5dd6c8e0407ece37b1d8246f");
  assert.equal(sha(renderReport({ md: "# Report\n", summary: minimalSummary() })), "0ff503e916ee2608de744b110f968115d9783fcbcf718c490798ef9bd069f4f8");
  assert.equal(html.includes("App graph"), false);
  assert.equal(html.includes("Structural:"), false);
});

test("self-contained: app graph + notes add no external references or active markup", () => {
  const s = withApp(appGraph("python", { stats: { ...goldenStats("python"), config_errors: [{ file: "pyproject.toml", message: "bad" }] } }));
  s.chains[0].verification_notes = ["structural: member cap"];
  const html = renderReport({ md: "# ok", summary: s });
  assert.equal(html.includes(`content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"`), true);
  for (const tag of ["<script", "<img", "<iframe", "<object", "<embed", "<link"]) {
    assert.equal(html.toLowerCase().includes(tag), false, "must not emit " + tag);
  }
  assert.equal(/\ssrc=/.test(html), false);
  assert.equal(/\shref=/.test(html), false);
  assert.equal(/https?:\/\//.test(html), false);
  assert.equal(/url\(|@import/.test(html), false);
});

test("CLI: summary with app_graph (golden stats) + chain notes validates and renders the section", () => {
  const s = withApp(appGraph("java"));
  s.chains[0].verification_notes = ["structural: member cap"];
  const r = runRender("# Report\n", s);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.html.includes("<h2>App graph</h2>"), true);
  assert.equal(r.html.includes(`<td>Functions</td><td>${s.app_graph.stats.functions}</td>`), true); // the golden stats, copied
  assert.equal(r.html.includes("Notes: structural: member cap"), true);
  assert.equal(r.stderr, "");
});

test("CLI: summary with app_graph unavailable renders the reason", () => {
  const r = runRender("# Report\n", withApp({ available: false, reason: "grammar load failed", multi_file_chain_count: 0 }));
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.html.includes("App graph unavailable: grammar load failed"), true);
});

test("CLI: malformed app_graph in the summary -> exit 1, no html", () => {
  const badStats = goldenStats("node");
  delete badStats.routes_by_auth;
  for (const bad of [
    { available: true, stats: badStats, multi_file_chain_count: 0 },        // stats missing a required key
    { available: true, multi_file_chain_count: -1 },                        // negative count
    { available: "yes", multi_file_chain_count: 0 },                        // wrong type
    { available: true, multi_file_chain_count: 0, extra: 1 },               // additionalProperties
    { available: true }                                                     // missing multi_file_chain_count
  ]) {
    const r = runRender("# Report\n", withApp(bad));
    assert.equal(r.code, 1);
    assert.equal(r.html, null);
  }
  const s = fullSummary();
  s.chains[0].verification_notes = [""];                                    // minLength 1
  assert.equal(runRender("# Report\n", s).code, 1);
});

test("CLI cache: app_graph is part of the input digest (changing it is a miss, same value is a hit)", () => {
  const ckpt = realpathSync(mkdtempSync(join(tmpdir(), "oswe-rh-ckpt-")));
  const first = runRender("# Report\n", withApp(appGraph("node")), ckpt);
  const same = runRender("# Report\n", withApp(appGraph("node")), ckpt);
  const changed = runRender("# Report\n", withApp(appGraph("node", { multi_file_chain_count: 7 })), ckpt);
  const noGraph = runRender("# Report\n", fullSummary(), ckpt);
  assert.equal(first.code, 0);
  assert.match(same.stderr, /cache hit/i);
  assert.equal(same.html, first.html);
  assert.doesNotMatch(changed.stderr, /cache hit/i);
  assert.equal(changed.html.includes("<td>Multi-file chains</td><td>7</td>"), true);
  assert.doesNotMatch(noGraph.stderr, /cache hit/i);
  assert.equal(noGraph.html.includes("App graph"), false);
  assert.equal(readdirSync(join(ckpt, "render-html")).length, 3);
});

import { buildReport } from "../write-report.mjs";

test("CLI: a summary shaped as SKILL.md describes (report.json's app_graph + settled chain notes) renders card and Notes", () => {
  // SKILL.md section 7: the summary's app_graph is the app_graph of the report.json just written
  // (parts' { available, stats } + the multi_file_chain_count write-report computes); chain
  // verification_notes are the settled chain's own notes.
  const ev = (file) => [{ file, line: 1 }];
  const settledChain = {
    chain_id: "CHAIN-1", verification_status: "accepted", verification_notes: ["structural: member cap"],
    transitions: [{ from: "entry", to: "OSWE-1", how: "x", evidence: ev("a.js") }, { from: "OSWE-1", to: "OSWE-2", how: "y", evidence: ev("b.js") }]
  };
  const report = buildReport({
    run: {}, coverage: { analyzed: 2, skipped: 0 }, chains: [settledChain],
    app_graph: { available: true, stats: goldenStats("python") }
  });
  assert.equal(report.app_graph.multi_file_chain_count, 1);          // computed by the helper, not by the caller
  const summary = fullSummary();
  summary.app_graph = report.app_graph;                               // copied verbatim from report.json
  summary.chains[0].verification_notes = settledChain.verification_notes;
  const r = runRender("# Report\n", summary);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.stderr, "");
  assert.equal(r.html.includes("<h2>App graph</h2>"), true);
  assert.equal(r.html.includes("<td>Multi-file chains</td><td>1</td>"), true);
  assert.equal(r.html.includes("<td>Functions</td><td>12</td>"), true);
  assert.equal(r.html.includes("<tr><td>python</td>"), true);
  assert.equal(r.html.includes('<p class="muted">Notes: structural: member cap</p>'), true);

  // SKILL.md and the summary schema name the same keys.
  const skill = readFileSync(join(REPO_ROOT_RH, "skills", "audit", "SKILL.md"), "utf8");
  const section = skill.slice(skill.indexOf("### HTML export"), skill.indexOf("### Report security"));
  const schema = JSON.parse(readFileSync(join(REPO_ROOT_RH, "skills", "audit", "schemas", "report-summary.schema.json"), "utf8"));
  for (const k of Object.keys(schema.properties)) assert.equal(section.includes("`" + k + "`") || section.includes("`" + k + "[]`"), true, "SKILL.md HTML export names " + k);
  for (const k of Object.keys(schema.properties.app_graph.properties)) assert.equal(section.includes(k), true, "SKILL.md names app_graph." + k);
  assert.equal(section.includes("verification_notes"), true);
  assert.deepEqual(Object.keys(schema.properties.chains.items.properties).filter((k) => !section.includes(k)), []);
});
