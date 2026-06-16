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
