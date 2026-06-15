// Runtime validation API + CLI. Zero runtime deps (uses generated validators.mjs).
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import * as validators from "./validators.mjs";

const KIND_TO_EXPORT = {
  "analyzer-response": "analyzerResponse",
  "verifier-response": "verifierResponse",
  "finding": "finding",
  "final-finding": "finalFinding",
  "chain": "chain",
  "verdict": "verdict"
};

export function validate(kind, data) {
  const name = KIND_TO_EXPORT[kind];
  if (!name) throw new Error(`unknown kind: ${kind} (expected one of ${Object.keys(KIND_TO_EXPORT).join(", ")})`);
  const validateFn = validators[name];
  const valid = validateFn(data);
  return { valid: Boolean(valid), errors: valid ? [] : (validateFn.errors || []) };
}

// CLI: node validate-output.mjs <kind> --file <path>   (preferred — avoids shell interpolation)
//      node validate-output.mjs <kind>                  (reads JSON from stdin)
function isMain() {
  if (!process.argv[1]) return false;
  return fileURLToPath(import.meta.url) === process.argv[1];
}

if (isMain()) {
  const args = process.argv.slice(2);
  const kind = args[0];
  const fileIdx = args.indexOf("--file");

  const run = (raw) => {
    let data;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      console.error(JSON.stringify({ valid: false, errors: [{ message: "invalid JSON: " + e.message }] }));
      process.exit(1);
    }
    let result;
    try {
      result = validate(kind, data);
    } catch (e) {
      console.error(JSON.stringify({ valid: false, errors: [{ message: e.message }] }));
      process.exit(2);
    }
    console.log(JSON.stringify(result));
    process.exit(result.valid ? 0 : 1);
  };

  if (fileIdx !== -1) {
    const path = args[fileIdx + 1];
    let raw;
    try {
      raw = readFileSync(path, "utf8");
    } catch (e) {
      console.error(JSON.stringify({ valid: false, errors: [{ message: "cannot read --file " + path + ": " + e.message }] }));
      process.exit(2);
    }
    run(raw);
  } else {
    let raw = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (raw += c));
    process.stdin.on("end", () => run(raw));
  }
}
