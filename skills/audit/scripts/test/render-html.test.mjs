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
