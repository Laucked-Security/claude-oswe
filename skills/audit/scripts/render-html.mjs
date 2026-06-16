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
const SEVERITIES = ["Critique", "Haute", "Moyenne", "Basse", "Info"];
const SEV_COLOR = { Critique: "#b00020", Haute: "#e65100", Moyenne: "#f9a825", Basse: "#1565c0", Info: "#607d8b" };

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
      const crit = ch.severity === "Critique" || ch.final_impact === "unauth-rce";
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
