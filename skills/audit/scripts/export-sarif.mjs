// Export a canonical report.json to SARIF 2.1.0. Zero external deps.
// export buildSarif(report) -> SARIF object (deterministic, no timestamps)
// CLI: node export-sarif.mjs --file <report.json> --out <out.sarif>  exit 0 ok / 2 IO|usage
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";
import { fingerprintFinding, fingerprintChain } from "./finding-fingerprint.mjs";

const SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

// Severity → SARIF level
function levelFor(sev) {
  if (!sev) return "warning";
  switch (String(sev).toLowerCase()) {
    case "critical":
    case "high":    return "error";
    case "medium":  return "warning";
    case "low":
    case "info":    return "note";
    default:        return "warning";
  }
}

// Minimal CWE map (extend later)
const CWE_MAP = {
  "trust-boundary": "CWE-501",
};

function makeRule(id, level, cwe) {
  const rule = {
    id,
    name: id,
    shortDescription: { text: id },
    defaultConfiguration: { level },
  };
  if (cwe) {
    rule.properties = { cwe };
  }
  return rule;
}

function physLoc(file, line) {
  return {
    physicalLocation: {
      artifactLocation: { uri: file },
      region: { startLine: line },
    },
  };
}

export function buildSarif(report) {
  const findings = report.findings || [];
  const chains = report.chains || [];

  // Track which rule ids are actually emitted so we only declare used rules.
  const emittedRuleIds = new Map(); // id -> level (first emission wins for determinism)

  function ensureRule(id, level) {
    if (!emittedRuleIds.has(id)) {
      emittedRuleIds.set(id, level);
    }
  }

  const results = [];

  // --- Findings (skip rejected) ---
  for (const f of findings) {
    if (f.verification_status === "rejected") continue;
    const sev = f.final_severity || f.provisional_severity;
    const level = levelFor(sev);
    const ruleId = f.vuln_class;
    ensureRule(ruleId, level);

    const props = f.vuln_class === "trust-boundary" ? { lane: "hygiene" } : {};

    results.push({
      ruleId,
      level,
      message: { text: f.title },
      locations: [physLoc(f.source.file, f.source.line)],
      relatedLocations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.sink.file },
            region: { startLine: f.sink.line },
          },
          message: { text: "sink" },
        },
      ],
      partialFingerprints: { "oswe/v1": fingerprintFinding(f) },
      properties: props,
    });
  }

  // --- Chains ---
  for (const c of chains) {
    const level = c.severity === "Critical" ? "error" : levelFor(c.severity);
    ensureRule("exploit-chain", level);

    // Build threadFlow locations: entry_point + each transition's evidence[0]
    const threadFlowLocs = [];
    threadFlowLocs.push({
      location: physLoc(c.entry_point.file, c.entry_point.line),
    });
    for (const tr of c.transitions || []) {
      const ev = tr.evidence && tr.evidence[0];
      if (ev) {
        threadFlowLocs.push({ location: physLoc(ev.file, ev.line) });
      }
    }

    results.push({
      ruleId: "exploit-chain",
      level,
      message: { text: `${c.final_impact} via ${c.chain_id}` },
      locations: [physLoc(c.entry_point.file, c.entry_point.line)],
      codeFlows: [
        {
          threadFlows: [{ locations: threadFlowLocs }],
        },
      ],
      partialFingerprints: { "oswe/v1": fingerprintChain(c, findings) },
    });
  }

  // --- Lead adjudications ---
  for (const la of report.lead_adjudications || []) {
    if (la.outcome === "promoted") continue; // already represented by a finding

    if (la.outcome === "refuted") {
      ensureRule("sast-lead-refuted", "note");
      const entry = {
        ruleId: "sast-lead-refuted",
        level: "note",
        message: { text: la.reason || "refuted by oswe" },
        suppressions: [
          {
            kind: "external",
            justification: la.reason || "oswe assessed not exploitable",
          },
        ],
        partialFingerprints: { "oswe/v1": la.lead_id || "0000000000000000" },
      };
      if (la.location) {
        entry.locations = [physLoc(la.location.file, la.location.line)];
      }
      results.push(entry);
    } else if (la.outcome === "inconclusive") {
      ensureRule("sast-lead-inconclusive", "note");
      const entry = {
        ruleId: "sast-lead-inconclusive",
        level: "note",
        message: { text: la.reason || "inconclusive" },
        partialFingerprints: { "oswe/v1": la.lead_id || "0000000000000000" },
      };
      if (la.location) {
        entry.locations = [physLoc(la.location.file, la.location.line)];
      }
      results.push(entry);
    }
    // unknown outcomes: skip gracefully
  }

  // Build rules list from emittedRuleIds (stable insertion order)
  const rules = [];
  for (const [id, level] of emittedRuleIds) {
    const cwe = CWE_MAP[id] || null;
    rules.push(makeRule(id, level, cwe));
  }

  return {
    version: "2.1.0",
    $schema: SARIF_SCHEMA,
    runs: [
      {
        tool: {
          driver: {
            name: "oswe",
            informationUri: "https://github.com/Laucked-Security/claude-oswe",
            rules,
          },
        },
        results,
      },
    ],
  };
}

// CLI
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const fi = args.indexOf("--file");
  const oi = args.indexOf("--out");
  if (fi === -1 || !args[fi + 1] || oi === -1 || !args[oi + 1]) {
    process.stderr.write("usage: export-sarif.mjs --file <report.json> --out <out.sarif>\n");
    process.exit(2);
  }
  let rep;
  try { rep = JSON.parse(readFileSync(args[fi + 1], "utf8")); }
  catch (e) { process.stderr.write("cannot read --file: " + e.message + "\n"); process.exit(2); }
  let sarif;
  try { sarif = buildSarif(rep); }
  catch (e) { process.stderr.write("build error: " + e.message + "\n"); process.exit(2); }
  try { writeFileSync(args[oi + 1], JSON.stringify(sarif, null, 2)); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
  process.exit(0);
}
