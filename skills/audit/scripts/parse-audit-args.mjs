// Deterministic $ARGUMENTS parser. Reads { raw_args } from --file, writes
// { ok, error, scope, sarifPath, concurrency } to --out. Exit codes:
//   0 ok / 1 invalid args / 2 IO|usage. No FS access on the parsed values.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";

// Tokenize a single string with minimal shell-like grammar (spec §3.1):
//   - whitespace separates tokens
//   - a token starting with " ends at the next ", surrounding quotes stripped, no escapes
//   - " inside an unquoted token is literal
//   - unterminated quote throws
export function tokenize(raw) {
  const tokens = [];
  let i = 0;
  const n = raw.length;
  while (i < n) {
    // skip whitespace
    while (i < n && /\s/.test(raw[i])) i++;
    if (i >= n) break;
    if (raw[i] === '"') {
      // quoted token
      const start = i + 1;
      let j = start;
      while (j < n && raw[j] !== '"') j++;
      if (j >= n) {
        const frag = raw.slice(i, Math.min(i + 20, n));
        throw new Error(`unterminated quoted token: ${frag}`);
      }
      tokens.push(raw.slice(start, j));
      i = j + 1;
    } else {
      // unquoted token: until whitespace; embedded " is literal
      const start = i;
      while (i < n && !/\s/.test(raw[i])) i++;
      tokens.push(raw.slice(start, i));
    }
  }
  return tokens;
}

export function parseArgs(rawArgs) {
  let tokens;
  try { tokens = tokenize(rawArgs || ""); }
  catch (e) { return { ok: false, error: e.message, scope: null, sarifPath: null, concurrency: 4 }; }

  let scope = null;
  let sarifPath = null;
  let concurrency = 4;
  const positionals = [];

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === "--concurrency") {
      const v = tokens[++i];
      if (v === undefined || !/^\d+$/.test(v)) {
        return { ok: false, error: `--concurrency requires a positive integer, got: ${v}`, scope: null, sarifPath: null, concurrency: 4 };
      }
      const n = parseInt(v, 10);
      if (!(n >= 1 && n <= 16)) {
        return { ok: false, error: `--concurrency must be in 1..16, got: ${n}`, scope: null, sarifPath: null, concurrency: 4 };
      }
      concurrency = n;
    } else if (t === "--sarif") {
      const v = tokens[++i];
      if (v === undefined) {
        return { ok: false, error: "--sarif requires a path argument", scope: null, sarifPath: null, concurrency: 4 };
      }
      sarifPath = v;
    } else if (t.startsWith("--")) {
      return { ok: false, error: `unknown flag: ${t}`, scope: null, sarifPath: null, concurrency: 4 };
    } else {
      positionals.push(t);
    }
  }

  if (positionals.length > 1) {
    return { ok: false, error: "too many positional arguments (only one scope allowed)", scope: null, sarifPath: null, concurrency: 4 };
  }
  if (positionals.length === 1) scope = positionals[0];

  return { ok: true, error: null, scope, sarifPath, concurrency };
}

// CLI
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const fi = args.indexOf("--file"), oi = args.indexOf("--out");
  if (fi === -1 || !args[fi + 1] || oi === -1 || !args[oi + 1]) {
    process.stderr.write("usage: parse-audit-args.mjs --file <input.json> --out <out.json>\n");
    process.exit(2);
  }
  let input;
  try { input = JSON.parse(readFileSync(args[fi + 1], "utf8")); }
  catch (e) { process.stderr.write("cannot read --file: " + e.message + "\n"); process.exit(2); }
  if (typeof input.raw_args !== "string") {
    process.stderr.write("bad input: raw_args (string) required\n"); process.exit(2);
  }
  const r = parseArgs(input.raw_args);
  try { writeFileSync(args[oi + 1], JSON.stringify(r, null, 2)); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
  if (!r.ok) process.stderr.write("parse-audit-args: " + r.error + "\n");
  process.exit(r.ok ? 0 : 1);
}
