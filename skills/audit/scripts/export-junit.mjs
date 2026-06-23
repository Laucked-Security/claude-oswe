// Export a canonical report.json to JUnit XML. Zero external deps.
// export buildJunit(report, opts) -> XML string (deterministic, no timestamps)
// CLI: node export-junit.mjs --file <report.json> --out <junit.xml> [--fail-on critical|high|medium]
//      exit 0 ok / 2 IO|usage
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";
import { fingerprintFinding, fingerprintChain } from "./finding-fingerprint.mjs";

// Severity order for threshold comparisons. Absent = treat as lowest.
const SEV_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function sevIndex(s) {
  if (!s) return -1;
  return SEV_ORDER[String(s).toLowerCase()] ?? -1;
}

// XML-escape a value: escape & first, then other special chars.
function esc(v) {
  return String(v ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/**
 * Build a JUnit XML string from an oswe report.
 *
 * @param {object} report - canonical report.json object
 * @param {{ failOn?: string }} opts
 * @returns {string} XML
 */
export function buildJunit(report, opts = {}) {
  const failOn = String(opts.failOn || "high").toLowerCase();
  const threshold = sevIndex(failOn);
  const findings = report.findings || [];
  const chains = report.chains || [];
  const leadAdj = report.lead_adjudications || [];

  const testcases = [];
  let failures = 0;
  let skipped = 0;

  // --- Findings (skip rejected) ---
  for (const f of findings) {
    if (f.verification_status === "rejected") continue;
    const fp = fingerprintFinding(f);
    const classname = f.vuln_class;
    const sev = f.final_severity || f.provisional_severity;
    const sevIdx = sevIndex(sev);
    const isAcceptedOrDowngraded =
      f.verification_status === "accepted" || f.verification_status === "downgraded";
    const shouldFail = isAcceptedOrDowngraded && sevIdx >= threshold && threshold >= 0;

    if (shouldFail) {
      failures++;
      const msg = esc(`${sev} ${classname}: ${f.title}`);
      const body = esc(`finding_id=${f.finding_id} source=${f.source.file}:${f.source.line} sink=${f.sink.file}:${f.sink.line}`);
      testcases.push(
        `  <testcase classname="${esc(classname)}" name="${esc(fp)}">\n` +
        `    <failure message="${msg}">${body}</failure>\n` +
        `  </testcase>`
      );
    } else {
      testcases.push(`  <testcase classname="${esc(classname)}" name="${esc(fp)}"/>`);
    }
  }

  // --- Chains ---
  for (const c of chains) {
    const fp = fingerprintChain(c, findings);
    const sev = c.severity;
    const sevIdx = sevIndex(sev);
    const isAcceptedOrDowngraded =
      c.verification_status === "accepted" || c.verification_status === "downgraded";
    const shouldFail = isAcceptedOrDowngraded && sevIdx >= threshold && threshold >= 0;

    if (shouldFail) {
      failures++;
      const msg = esc(`${sev} exploit-chain: ${c.final_impact} via ${c.chain_id}`);
      const body = esc(`chain_id=${c.chain_id} entry=${c.entry_point.file}:${c.entry_point.line} impact=${c.final_impact}`);
      testcases.push(
        `  <testcase classname="exploit-chain" name="${esc(fp)}">\n` +
        `    <failure message="${msg}">${body}</failure>\n` +
        `  </testcase>`
      );
    } else {
      testcases.push(`  <testcase classname="exploit-chain" name="${esc(fp)}"/>`);
    }
  }

  // --- Refuted leads only (promoted/inconclusive -> omit) ---
  for (const la of leadAdj) {
    if (la.outcome !== "refuted") continue;
    skipped++;
    const reason = esc(la.reason || "refuted by oswe");
    testcases.push(
      `  <testcase classname="sast-lead-refuted" name="${esc(la.lead_id)}">\n` +
      `    <skipped message="${reason}"/>\n` +
      `  </testcase>`
    );
  }

  const tests = testcases.length;
  const suite =
    `<testsuite name="oswe" tests="${tests}" failures="${failures}" skipped="${skipped}">\n` +
    testcases.join("\n") +
    (testcases.length ? "\n" : "") +
    `</testsuite>`;

  return `<?xml version="1.0" encoding="UTF-8"?>\n${suite}\n`;
}

// CLI
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const fi = args.indexOf("--file");
  const oi = args.indexOf("--out");
  const foi = args.indexOf("--fail-on");
  if (fi === -1 || !args[fi + 1] || oi === -1 || !args[oi + 1]) {
    process.stderr.write(
      "usage: export-junit.mjs --file <report.json> --out <junit.xml> [--fail-on critical|high|medium]\n"
    );
    process.exit(2);
  }
  const failOn = foi !== -1 && args[foi + 1] ? args[foi + 1] : "high";
  let rep;
  try { rep = JSON.parse(readFileSync(args[fi + 1], "utf8")); }
  catch (e) { process.stderr.write("cannot read --file: " + e.message + "\n"); process.exit(2); }
  let xml;
  try { xml = buildJunit(rep, { failOn }); }
  catch (e) { process.stderr.write("build error: " + e.message + "\n"); process.exit(2); }
  try { writeFileSync(args[oi + 1], xml); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
  process.exit(0);
}
