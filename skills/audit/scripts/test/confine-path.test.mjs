import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { confinePath } from "../confine-path.mjs";

const CLI = fileURLToPath(new URL("../confine-path.mjs", import.meta.url));

function setup() {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "oswe-confine-")));
  const root = join(base, "project");
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src", "app.js"), "// x");
  mkdirSync(join(base, "project-old"), { recursive: true }); // sibling sharing a prefix
  writeFileSync(join(base, "project-old", "secret.txt"), "s");
  writeFileSync(join(base, "outside.txt"), "o");
  return { base, root };
}

test("accepts project root when no arg", () => {
  const { root } = setup();
  assert.equal(confinePath(root, undefined), realpathSync(root));
});

test("accepts a sub-path", () => {
  const { root } = setup();
  assert.equal(confinePath(root, "src/app.js"), realpathSync(join(root, "src", "app.js")));
});

test("rejects ../ escape", () => {
  const { root } = setup();
  assert.throws(() => confinePath(root, "../outside.txt"), /escapes project dir/);
});

test("rejects sibling-prefix dir (project vs project-old)", () => {
  const { root } = setup();
  assert.throws(() => confinePath(root, "../project-old/secret.txt"), /escapes project dir/);
});

test("rejects nonexistent path with ENOENT", () => {
  const { root } = setup();
  assert.throws(() => confinePath(root, "nope/missing.js"), (e) => e.code === "ENOENT");
});

test("rejects a symlink escaping the project", (t) => {
  const { base, root } = setup();
  const link = join(root, "evil-link");
  try {
    symlinkSync(join(base, "outside.txt"), link);
  } catch (e) {
    t.skip("symlink creation not permitted here: " + e.code);
    return;
  }
  assert.throws(() => confinePath(root, "evil-link"), /escapes project dir/);
});

// --- CLI (--file JSON) exit codes 0/1/2 ---

function runCli(input) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-cli-")));
  const f = join(dir, "in.json");
  writeFileSync(f, JSON.stringify(input));
  return spawnSync(process.execPath, [CLI, "--file", f], { encoding: "utf8" });
}

test("CLI exit 0 for a confined sub-path (with spaces and shell metachars in the name)", () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "oswe-cli-root-")));
  const root = join(base, "project");
  const weird = "a b $(touch pwned) `id`"; // never reaches a shell — passed as JSON
  mkdirSync(join(root, weird), { recursive: true });
  writeFileSync(join(root, weird, "f.js"), "// x");
  const r = runCli({ projectDir: root, arg: join(weird, "f.js") });
  assert.equal(r.status, 0);
  assert.equal(r.stdout.trim(), realpathSync(join(root, weird, "f.js")));
});

test("CLI exit 1 for an escaping path", () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "oswe-cli-esc-")));
  const root = join(base, "project");
  mkdirSync(root, { recursive: true });
  writeFileSync(join(base, "outside.txt"), "o");
  const r = runCli({ projectDir: root, arg: "../outside.txt" });
  assert.equal(r.status, 1);
});

test("CLI exit 2 when --file is missing", () => {
  const r = spawnSync(process.execPath, [CLI], { encoding: "utf8" });
  assert.equal(r.status, 2);
});
