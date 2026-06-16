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
