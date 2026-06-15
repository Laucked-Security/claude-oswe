// Deterministic scope confinement. Resolves the REAL canonical path and rejects anything that
// escapes the project dir: ../ traversal, symlink/junction escapes, and sibling-prefix dirs
// (e.g. /x/project vs /x/project-old). Throws on nonexistent (ENOENT) or escaping paths.
import { realpathSync } from "node:fs";
import { resolve, sep } from "node:path";

export function confinePath(projectDir, arg) {
  const root = realpathSync(resolve(projectDir));
  const candidate = resolve(root, arg == null || arg === "" ? "." : arg);
  let real;
  try {
    real = realpathSync(candidate);
  } catch {
    const err = new Error(`path does not exist: ${arg}`);
    err.code = "ENOENT";
    throw err;
  }
  // Containment: equal to root, or strictly under root + path separator.
  // The `+ sep` is what rejects the sibling-prefix case (project-old).
  if (real !== root && !real.startsWith(root + sep)) {
    throw new Error(`path escapes project dir: ${arg}`);
  }
  return real;
}

// CLI: node confine-path.mjs --file <input.json>   input: { "projectDir": "...", "arg": "..."|null }
//   Reads the path from a JSON file (not argv) so values containing quotes, $(), or backticks cannot
//   be interpolated by the shell. Prints the confined real path (exit 0); error -> exit 1 (escape /
//   nonexistent) or exit 2 (usage / IO).
import { fileURLToPath } from "node:url";
import { readFileSync as _readFileSync } from "node:fs";
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const fileIdx = args.indexOf("--file");
  if (fileIdx === -1 || !args[fileIdx + 1]) {
    process.stderr.write("usage: confine-path.mjs --file <input.json>\n");
    process.exit(2);
  }
  let input;
  try {
    input = JSON.parse(_readFileSync(args[fileIdx + 1], "utf8"));
  } catch (e) {
    process.stderr.write("cannot read --file: " + e.message + "\n");
    process.exit(2);
  }
  if (typeof input.projectDir !== "string") {
    process.stderr.write("bad input: projectDir must be a string\n");
    process.exit(2);
  }
  try {
    process.stdout.write(confinePath(input.projectDir, input.arg) + "\n");
  } catch (e) {
    // exit 1 ONLY for a genuine confinement decision (target missing, or escapes the project);
    // any other error (malformed input, etc.) is a usage error -> exit 2, so the orchestrator
    // never mistakes a config bug for a path-escape.
    if (e.code === "ENOENT" || /escapes project dir/.test(e.message)) {
      process.stderr.write(String(e.message) + "\n");
      process.exit(1);
    }
    process.stderr.write("bad input: " + e.message + "\n");
    process.exit(2);
  }
}
