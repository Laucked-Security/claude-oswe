// render-html.mjs — Zero runtime dependency. Renders a self-contained visual HTML report from the
// redaction-safe Markdown report (--md) plus a non-sensitive summary JSON (--summary), to --out.
// Body = MD->HTML over a FIXED construct set; charts (added later) = inline SVG from the summary.
// All MD- and summary-derived text is HTML-escaped; the document carries a strict CSP and no script.

// ---------- escaping ----------
export function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ---------- inline Markdown (operates after escaping) ----------
function formatEmphasis(escaped) {
  // asterisk-only emphasis; underscores stay literal; bold (**) before italic (*).
  return escaped
    .replace(/\*\*([^*]+?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+?)\*/g, "<em>$1</em>")
    .replace(/~~([^~]+?)~~/g, "<del>$1</del>");
}

function renderInline(text) {
  // Protect inline code spans first: their content is escaped but never emphasis-formatted.
  const parts = [];
  const re = /`([^`]+)`/g;
  let last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parts.push({ code: false, s: text.slice(last, m.index) });
    parts.push({ code: true, s: m[1] });
    last = m.index + m[0].length;
  }
  if (last < text.length) parts.push({ code: false, s: text.slice(last) });
  return parts
    .map((p) => (p.code ? `<code>${escapeHtml(p.s)}</code>` : formatEmphasis(escapeHtml(p.s))))
    .join("");
}

// ---------- block Markdown ----------
export function mdToHtml(md) {
  const lines = String(md).replace(/\r\n/g, "\n").split("\n");
  const out = [];
  let i = 0;
  const isSep = (l) => l.includes("-") && /^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)*\|?\s*$/.test(l);
  const splitRow = (l) => {
    let s = l.trim();
    if (s.startsWith("|")) s = s.slice(1);
    if (s.endsWith("|")) s = s.slice(0, -1);
    return s.split("|").map((c) => c.trim());
  };
  const isStructural = (l) =>
    /^\s*$/.test(l) || /^(#{1,3})\s+/.test(l) || /^---+\s*$/.test(l) || /^>\s?/.test(l) || /^[-*]\s+/.test(l);
  while (i < lines.length) {
    const line = lines[i];
    if (/^\s*$/.test(line)) { i++; continue; }
    const h = /^(#{1,3})\s+(.*)$/.exec(line);
    if (h) { const n = h[1].length; out.push(`<h${n}>${renderInline(h[2].trim())}</h${n}>`); i++; continue; }
    if (/^---+\s*$/.test(line)) { out.push("<hr>"); i++; continue; }
    if (line.includes("|") && i + 1 < lines.length && isSep(lines[i + 1])) {
      const header = splitRow(line);
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].includes("|") && !/^\s*$/.test(lines[i])) { rows.push(splitRow(lines[i])); i++; }
      let t = "<table><thead><tr>" + header.map((c) => `<th>${renderInline(c)}</th>`).join("") + "</tr></thead><tbody>";
      for (const r of rows) t += "<tr>" + r.map((c) => `<td>${renderInline(c)}</td>`).join("") + "</tr>";
      t += "</tbody></table>";
      out.push(t); continue;
    }
    if (/^>\s?/.test(line)) {
      const buf = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) { buf.push(renderInline(lines[i].replace(/^>\s?/, ""))); i++; }
      out.push(`<blockquote>${buf.join("<br>")}</blockquote>`); continue;
    }
    if (/^[-*]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^[-*]\s+/.test(lines[i])) { items.push(`<li>${renderInline(lines[i].replace(/^[-*]\s+/, ""))}</li>`); i++; }
      out.push(`<ul>${items.join("")}</ul>`); continue;
    }
    const para = [];
    while (i < lines.length && !isStructural(lines[i]) && !(lines[i].includes("|") && i + 1 < lines.length && isSep(lines[i + 1]))) {
      para.push(renderInline(lines[i])); i++;
    }
    out.push(`<p>${para.join("<br>")}</p>`);
  }
  return out.join("\n");
}

// ---------- charts (inline SVG, deterministic, computed from the summary) ----------
const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];
const SEV_COLOR = { Critical: "#b00020", High: "#e65100", Medium: "#f9a825", Low: "#1565c0", Info: "#607d8b" };

export function severityDonut(counts) {
  const total = SEVERITIES.reduce((a, s) => a + (counts[s] || 0), 0);
  const cx = 90, cy = 90, r = 60, sw = 26, C = 2 * Math.PI * r;
  let ring = "";
  if (total === 0) {
    ring = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#dddddd" stroke-width="${sw}"></circle>`
         + `<text x="${cx}" y="${cy + 5}" text-anchor="middle" class="donut-empty">No findings</text>`;
  } else {
    let offset = 0;
    for (const s of SEVERITIES) {
      const v = counts[s] || 0;
      if (!v) continue;
      const seg = (v / total) * C;
      ring += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${SEV_COLOR[s]}" stroke-width="${sw}"`
            + ` stroke-dasharray="${seg.toFixed(3)} ${(C - seg).toFixed(3)}" stroke-dashoffset="${(-offset).toFixed(3)}"`
            + ` transform="rotate(-90 ${cx} ${cy})"></circle>`;
      offset += seg;
    }
    ring += `<text x="${cx}" y="${cy + 6}" text-anchor="middle" class="donut-total">${total}</text>`;
  }
  let legend = "", ly = 26;
  for (const s of SEVERITIES) {
    legend += `<rect x="190" y="${ly - 11}" width="12" height="12" fill="${SEV_COLOR[s]}"></rect>`
            + `<text x="208" y="${ly}" class="legend">${escapeHtml(s)}: ${counts[s] || 0}</text>`;
    ly += 22;
  }
  return `<svg viewBox="0 0 340 180" role="img" aria-label="Severity counts" class="chart">${ring}${legend}</svg>`;
}

export function coverageBar(coverage) {
  const a = coverage.analyzed || 0, s = coverage.skipped || 0, tot = a + s;
  const W = 300, H = 26;
  const aw = tot === 0 ? 0 : (a / tot) * W;
  const sw = tot === 0 ? 0 : (s / tot) * W;
  const base = tot === 0 ? `<rect x="0" y="0" width="${W}" height="${H}" fill="#dddddd"></rect>` : "";
  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Coverage" class="chart bar">`
    + base
    + `<rect x="0" y="0" width="${aw.toFixed(2)}" height="${H}" fill="#2e7d32"></rect>`
    + `<rect x="${aw.toFixed(2)}" y="0" width="${sw.toFixed(2)}" height="${H}" fill="#c62828"></rect>`
    + `<text x="6" y="17" class="bar-label">analyzed ${a}</text>`
    + `<text x="${W - 6}" y="17" text-anchor="end" class="bar-label">skipped ${s}</text>`
    + `</svg>`;
}

const STATUSES = ["accepted", "downgraded", "rejected", "not-requested"];
const STATUS_COLOR = { accepted: "#2e7d32", downgraded: "#f9a825", rejected: "#9e9e9e", "not-requested": "#1565c0" };

export function statusBar(counts) {
  const tot = STATUSES.reduce((acc, k) => acc + (counts[k] || 0), 0);
  const W = 320, H = 26;
  let x = 0, rects = "";
  if (tot === 0) {
    rects = `<rect x="0" y="0" width="${W}" height="${H}" fill="#dddddd"></rect>`
          + `<text x="6" y="17" class="bar-label">no findings</text>`;
  } else {
    for (const k of STATUSES) {
      const v = counts[k] || 0;
      if (!v) continue;
      const w = (v / tot) * W;
      rects += `<rect x="${x.toFixed(2)}" y="0" width="${w.toFixed(2)}" height="${H}" fill="${STATUS_COLOR[k]}"></rect>`;
      x += w;
    }
  }
  let legend = "", lx = 0;
  for (const k of STATUSES) {
    legend += `<rect x="${lx}" y="34" width="12" height="12" fill="${STATUS_COLOR[k]}"></rect>`
            + `<text x="${lx + 16}" y="44" class="legend">${escapeHtml(k)} ${counts[k] || 0}</text>`;
    lx += 80;
  }
  return `<svg viewBox="0 0 ${W} 52" role="img" aria-label="Finding statuses" class="chart bar">${rects}${legend}</svg>`;
}

export function chainDiagram(chains) {
  if (!chains || chains.length === 0) return `<p class="muted">No exploit chains.</p>`;
  const svgs = [];
  for (const ch of chains) {
    const nodes = ch.nodes;
    const boxW = 92, boxH = 34, gap = 38, x0 = 10, y = 26;
    const width = x0 * 2 + nodes.length * boxW + (nodes.length - 1) * gap;
    const xOf = (idx) => x0 + idx * (boxW + gap);
    let g = "";
    for (const e of ch.edges) {
      const fi = nodes.indexOf(e.from), ti = nodes.indexOf(e.to);
      if (fi < 0 || ti < 0) continue;
      const x1 = xOf(fi) + boxW, x2 = xOf(ti), my = y + boxH / 2;
      g += `<line x1="${x1}" y1="${my}" x2="${x2}" y2="${my}" class="edge"></line>`
         + `<polygon points="${x2},${my} ${x2 - 7},${my - 4} ${x2 - 7},${my + 4}" class="arrow"></polygon>`
         + `<text x="${((x1 + x2) / 2).toFixed(1)}" y="${my - 6}" text-anchor="middle" class="edge-label">${escapeHtml(e.verdict)}</text>`;
    }
    nodes.forEach((n, idx) => {
      const isRce = n === "RCE";
      const crit = ch.severity === "Critical" || ch.final_impact === "unauth-rce";
      const cls = isRce ? (crit ? "node node-rce-crit" : "node node-rce") : (n === "entry" ? "node node-entry" : "node");
      const label = n === "entry" && ch.entry_auth === "unauthenticated" ? "entry (unauth)" : n;
      g += `<rect x="${xOf(idx)}" y="${y}" width="${boxW}" height="${boxH}" rx="5" class="${cls}"></rect>`
         + `<text x="${xOf(idx) + boxW / 2}" y="${y + boxH / 2 + 5}" text-anchor="middle" class="node-label">${escapeHtml(label)}</text>`;
    });
    svgs.push(`<div class="chain"><div class="chain-id">${escapeHtml(ch.id)} — ${escapeHtml(ch.severity)}</div>`
      + `<svg viewBox="0 0 ${width} 76" role="img" aria-label="Exploit chain ${escapeHtml(ch.id)}" class="chart">${g}</svg></div>`);
  }
  return svgs.join("\n");
}

// ---------- document assembly ----------
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync, renameSync, unlinkSync } from "node:fs";
import * as validators from "./validators.mjs";

const CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'";
const STYLE = `
:root{
  --ink:#0f172a; --body:#1e293b; --muted:#64748b; --faint:#94a3b8;
  --line:#e2e8f0; --panel:#f8fafc; --panel2:#f1f5f9; --bg:#ffffff;
  --brand:#4f46e5; --brand-ink:#c7d2fe;
  --crit:#b00020; --haute:#e65100; --moyenne:#f9a825; --basse:#1565c0; --info:#607d8b;
  --ok:#2e7d32;
}
*{box-sizing:border-box}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{font-family:'Inter',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;
  color:var(--body);background:var(--panel);line-height:1.55;font-size:15px}

/* ---- header band ---- */
.band{background:linear-gradient(135deg,#0f172a 0%,#1e293b 60%,#312e81 100%);color:#e2e8f0;
  padding:2rem 1.5rem 2.2rem;border-bottom:3px solid var(--brand)}
.band-inner{max-width:980px;margin:0 auto}
.eyebrow{display:flex;align-items:center;gap:.5rem;font-size:.8rem;letter-spacing:.12em;
  text-transform:uppercase;color:var(--brand-ink);font-weight:600;margin:0 0 .6rem}
.eyebrow .dot{color:var(--faint);font-weight:400}
.band h1{margin:0;font-size:1.9rem;line-height:1.15;color:#fff;letter-spacing:-.01em}
.band .meta{margin:.5rem 0 0;color:#94a3b8;font-size:.9rem}
.band .meta strong{color:#cbd5e1;font-weight:600}
.verdict{display:inline-flex;align-items:center;gap:.5rem;margin-top:1.1rem;padding:.45rem .9rem;
  border-radius:999px;font-weight:700;font-size:.95rem;border:1px solid transparent}
.verdict::before{content:"";width:.6rem;height:.6rem;border-radius:50%;background:currentColor;opacity:.9}
.verdict-rce{background:rgba(176,0,32,.18);color:#fca5a5;border-color:rgba(252,165,165,.4)}
.verdict-clear{background:rgba(46,125,50,.18);color:#86efac;border-color:rgba(134,239,172,.4)}
.verdict small{font-weight:500;color:#cbd5e1}

/* ---- layout ---- */
main{max-width:980px;margin:0 auto;padding:1.6rem 1.5rem 2.5rem}
h2{font-size:1.3rem;line-height:1.2;color:var(--ink);margin:2rem 0 .8rem;padding-bottom:.35rem;
  border-bottom:1px solid var(--line)}
h3{font-size:1.05rem;color:var(--ink);margin:1.4rem 0 .5rem}
h1{line-height:1.2}
p{margin:.6rem 0}
a{color:var(--brand)}

/* ---- charts as cards ---- */
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem;margin:0 0 .5rem}
.card{background:var(--bg);border:1px solid var(--line);border-radius:12px;padding:1rem 1.1rem;
  box-shadow:0 1px 2px rgba(15,23,42,.04),0 1px 3px rgba(15,23,42,.06)}
.card figcaption,.card-title{font-size:.78rem;letter-spacing:.08em;text-transform:uppercase;
  color:var(--muted);font-weight:700;margin:0 0 .6rem}
.chart{max-width:100%;display:block}
.chains-section .card{margin-top:.4rem}

/* ---- SVG text ---- */
.legend,.bar-label{font-size:12px;fill:var(--body);font-weight:500}
.donut-total{font-size:30px;fill:var(--ink);font-weight:800}
.donut-empty{font-size:13px;fill:var(--muted)}
.node{fill:#eef2ff;stroke:#6366f1}
.node-entry{fill:#dbeafe;stroke:#1565c0}
.node-rce{fill:#ffedd5;stroke:#e65100}
.node-rce-crit{fill:#fee2e2;stroke:#b00020}
.node-label{font-size:12px;fill:var(--ink);font-weight:600}
.edge{stroke:#94a3b8;stroke-width:1.5}
.arrow{fill:#94a3b8}
.edge-label{font-size:10px;fill:var(--muted);font-weight:600}
.chain{margin:.2rem 0 1rem}
.chain-id{font-weight:700;color:var(--ink);margin:.2rem 0 .3rem;font-size:.95rem}

/* ---- report body ---- */
.report-body{background:var(--bg);border:1px solid var(--line);border-radius:12px;
  padding:.4rem 1.4rem 1.2rem;box-shadow:0 1px 2px rgba(15,23,42,.04)}
table{border-collapse:separate;border-spacing:0;margin:1rem 0;width:100%;
  border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:.92rem}
th,td{padding:.55rem .8rem;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
th{background:var(--panel2);color:var(--ink);font-weight:700;font-size:.82rem;
  letter-spacing:.02em;text-transform:uppercase}
tbody tr:nth-child(even){background:var(--panel)}
tbody tr:last-child td{border-bottom:0}
code{background:var(--panel2);padding:.1em .35em;border-radius:4px;
  font-family:ui-monospace,'SF Mono',Consolas,monospace;font-size:.86em;color:#312e81}
blockquote{border-left:3px solid var(--brand);background:var(--panel);margin:.8rem 0;
  padding:.5rem .9rem;color:var(--muted);border-radius:0 8px 8px 0}
hr{border:0;border-top:1px solid var(--line);margin:1.4rem 0}
del{color:var(--faint)}
ul{margin:.5rem 0;padding-left:1.3rem}
li{margin:.2rem 0}
strong{color:var(--ink)}
.muted{color:var(--muted)}

/* ---- footer ---- */
.foot{max-width:980px;margin:0 auto;padding:1.2rem 1.5rem 2rem;color:var(--faint);
  font-size:.82rem;border-top:1px solid var(--line)}
.foot strong{color:var(--muted)}

@media print{
  body{background:#fff}
  .band{padding:1.2rem 0 1.3rem}
  main{padding:.6rem 0}
  .card,.report-body{box-shadow:none;break-inside:avoid}
  .chain,h2,h3{break-inside:avoid}
  h2{break-before:auto}
}
`;

// Runtime graph coherence the schema cannot express: every edge endpoint must be one of that chain's
// declared nodes. The schema guarantees label PATTERNS and minItems/uniqueItems; this guarantees the
// edges actually connect declared nodes (otherwise the diagram would silently drop edges). Returns a
// list of human-readable problems (empty = coherent).
export function graphErrors(summary) {
  const errs = [];
  for (const ch of summary.chains) {
    const set = new Set(ch.nodes);
    for (const e of ch.edges) {
      if (!set.has(e.from)) errs.push(`${ch.id}: edge.from "${e.from}" not in nodes`);
      if (!set.has(e.to)) errs.push(`${ch.id}: edge.to "${e.to}" not in nodes`);
    }
  }
  return errs;
}

export function renderReport({ md, summary }) {
  const m = summary.meta;
  const verdictText = m.verdict === "unauth-rce" ? "Unauthenticated RCE found" : "No Critical chain";
  const verdictClass = m.verdict === "unauth-rce" ? "verdict verdict-rce" : "verdict verdict-clear";
  const head =
    `<header class="band"><div class="band-inner">`
    + `<p class="eyebrow">\u{1F6E1} oswe <span class="dot">·</span> Laucked Security</p>`
    + `<h1>OSWE Audit Report</h1>`
    + `<p class="meta"><strong>${escapeHtml(m.target)}</strong> · ${escapeHtml(m.stack)} · ${escapeHtml(m.date)}</p>`
    + `<p class="${verdictClass}">${escapeHtml(verdictText)}`
    + `${m.proof_level ? ` <small>${escapeHtml(m.proof_level)}</small>` : ""}</p>`
    + `</div></header>`;
  const card = (title, svg) => `<figure class="card"><figcaption>${title}</figcaption>${svg}</figure>`;
  const charts =
    `<section class="charts">`
    + card("Severity", severityDonut(summary.severity_counts))
    + card("Coverage", coverageBar(summary.coverage))
    + card("Verification status", statusBar(summary.finding_status_counts))
    + `</section>`
    + `<section class="chains-section"><h2>Exploit chains</h2>`
    + `<div class="card">${chainDiagram(summary.chains)}</div></section>`;
  const body = `<h2>Full report</h2><section class="report-body">${mdToHtml(md)}</section>`;
  const foot =
    `<footer class="foot"><strong>Generated by oswe — Laucked Security.</strong> `
    + `Static white-box source audit, not a penetration test. `
    + `&ldquo;No path to RCE&rdquo; means none found within the analyzed coverage, not proof of absence.</footer>`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${CSP}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSWE Audit Report — Laucked Security</title>
<style>${STYLE}</style>
</head>
<body>
${head}
<main>
${charts}
${body}
</main>
${foot}
</body>
</html>
`;
}

// ---------- CLI: node render-html.mjs --md <report.md> --summary <summary.json> --out <report.html> ----------
function isMain() {
  return Boolean(process.argv[1]) && fileURLToPath(import.meta.url) === process.argv[1];
}

if (isMain()) {
  const args = process.argv.slice(2);
  const flag = (name) => { const i = args.indexOf(name); return i !== -1 ? args[i + 1] : undefined; };
  const mdPath = flag("--md"), sumPath = flag("--summary"), outPath = flag("--out");
  const fail2 = (msg) => { process.stderr.write("render-html: " + msg + "\n"); process.exit(2); };
  if (!mdPath || !sumPath || !outPath) {
    fail2("usage: render-html.mjs --md <report.md> --summary <summary.json> --out <report.html>");
  }
  let md, sumRaw;
  try { md = readFileSync(mdPath, "utf8"); } catch (e) { fail2("cannot read --md " + mdPath + ": " + e.message); }
  try { sumRaw = readFileSync(sumPath, "utf8"); } catch (e) { fail2("cannot read --summary " + sumPath + ": " + e.message); }
  let summary;
  try { summary = JSON.parse(sumRaw); } catch (e) { fail2("invalid JSON in --summary: " + e.message); }
  if (!validators.reportSummary(summary)) {
    process.stderr.write("render-html: invalid summary: " + JSON.stringify(validators.reportSummary.errors || []) + "\n");
    process.exit(1);
  }
  const gErrs = graphErrors(summary);
  if (gErrs.length) {
    process.stderr.write("render-html: incoherent chain graph: " + gErrs.join("; ") + "\n");
    process.exit(1);   // orchestrator built an edge to an undeclared node -> no HTML
  }
  let html;
  try { html = renderReport({ md, summary }); } catch (e) { fail2("render failed: " + e.message); }
  const tmp = outPath + ".tmp-" + process.pid;
  try {
    writeFileSync(tmp, html);
    renameSync(tmp, outPath);   // atomic: never leaves a partial report.html
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* nothing to clean */ }
    fail2("cannot write --out " + outPath + ": " + e.message);
  }
  process.exit(0);
}
