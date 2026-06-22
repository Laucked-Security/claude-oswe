// Assemble + validate the canonical run report (.oswe/reports/oswe-report-*.json). Zero runtime deps
// (uses generated validators.mjs via validate-output.mjs). The report is the machine-readable artifact
// every downstream consumer (benchmark ledger, baseline/diff, exports) keys on.
//
// CLI: node write-report.mjs --file <parts.json> --out <report.json>
//   <parts.json> = { run, coverage, findings[], chains[], verdicts[], lead_adjudications[] }
//   exit 0 ok / 1 invalid report / 2 IO|usage.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";
import { validate } from "./validate-output.mjs";

export function buildReport({ run, coverage, findings = [], chains = [], verdicts = [], lead_adjudications } = {}) {
  const report = { run, coverage, findings, chains, verdicts };
  if (lead_adjudications && lead_adjudications.length) report.lead_adjudications = lead_adjudications;
  return report;
}

export function validateReport(report) {
  return validate("report", report);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const get = (f) => { const i = args.indexOf(f); return i === -1 ? null : args[i + 1]; };
  const filePath = get("--file"), outPath = get("--out");
  if (!filePath || !outPath) {
    process.stderr.write("usage: write-report.mjs --file <parts.json> --out <report.json>\n");
    process.exit(2);
  }
  let parts;
  try { parts = JSON.parse(readFileSync(filePath, "utf8")); }
  catch (e) { process.stderr.write("cannot read --file: " + e.message + "\n"); process.exit(2); }
  const report = buildReport(parts);
  const res = validateReport(report);
  if (!res.valid) {
    process.stderr.write("report failed schema validation: " + JSON.stringify(res.errors) + "\n");
    process.exit(1);
  }
  try { writeFileSync(outPath, JSON.stringify(report, null, 2) + "\n"); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
  process.stdout.write(`wrote ${outPath}: ${report.findings.length} findings, ${report.chains.length} chains, ${report.verdicts.length} verdicts\n`);
  process.exit(0);
}
