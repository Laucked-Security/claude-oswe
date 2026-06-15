// CLI around validateBoundBatch — phase 6 runs this per response BEFORE exhausting the retry, with
// the SAME contract applyVerdicts enforces in 6b. node validate-batch.mjs --file <in.json>
//   in.json: { "findings": [ …full finding objects ], "chains": [ …full chain objects ], "batch": { … } }
//   exit 0 valid / 1 invalid (prints {ok:false,error,error_kind}) / 2 usage|IO.
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { validateBoundBatch, checkCanonicalIds } from "./apply-verdicts.mjs";

export function runCli(argv) {
  const fi = argv.indexOf("--file");
  if (fi === -1) { process.stderr.write("usage: validate-batch.mjs --file <in.json>\n"); return 2; }
  let input;
  try { input = JSON.parse(readFileSync(argv[fi + 1], "utf8")); }
  catch (e) { process.stderr.write("cannot read --file: " + e.message + "\n"); return 2; }
  const findings = input.findings || [], chains = input.chains || [];
  // Same id preflight applyVerdicts runs, so duplicate canonical ids aren't silently merged here.
  const idCheck = checkCanonicalIds(findings, chains);
  if (!idCheck.ok) { console.log(JSON.stringify(idCheck)); return 1; }
  const findingById = new Map(findings.map((f) => [f.finding_id, f]));
  const chainById = new Map(chains.map((c) => [c.chain_id, c]));
  const r = validateBoundBatch(input.batch, { findingById, chainById });
  console.log(JSON.stringify(r));
  return r.ok ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exit(runCli(process.argv.slice(2)));
}
