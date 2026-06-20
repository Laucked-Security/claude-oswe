import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../parse-audit-args.mjs", import.meta.url));

function call(rawArgs) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-parse-args-")));
  const inP = join(dir, "in.json");
  const outP = join(dir, "out.json");
  writeFileSync(inP, JSON.stringify({ raw_args: rawArgs }));
  const r = spawnSync(process.execPath, [CLI, "--file", inP, "--out", outP], { encoding: "utf8" });
  let parsed = null;
  try { parsed = JSON.parse(readFileSync(outP, "utf8")); } catch { /* exit != 0 may not write --out */ }
  return { code: r.status, stderr: r.stderr, out: parsed };
}

test("empty raw_args -> defaults (scope:null, sarifPath:null, concurrency:4)", () => {
  const r = call("");
  assert.equal(r.code, 0);
  assert.deepEqual(r.out, { ok: true, error: null, scope: null, sarifPath: null, concurrency: 4 });
});

test("whitespace-only raw_args -> same defaults", () => {
  const r = call("   \t  ");
  assert.equal(r.code, 0);
  assert.equal(r.out.concurrency, 4);
});

test("--concurrency 8 parses ok", () => {
  const r = call("--concurrency 8");
  assert.equal(r.code, 0);
  assert.equal(r.out.concurrency, 8);
});

test("--concurrency 0 (below range) -> exit 1", () => {
  const r = call("--concurrency 0");
  assert.equal(r.code, 1);
  assert.match(r.stderr, /concurrency/i);
});

test("--concurrency 17 (above range) -> exit 1", () => {
  const r = call("--concurrency 17");
  assert.equal(r.code, 1);
});

test("--concurrency abc (non-integer) -> exit 1 (strict)", () => {
  const r = call("--concurrency abc");
  assert.equal(r.code, 1);
});

test("--concurrency 4.5 (float) -> exit 1 (strict integer)", () => {
  const r = call("--concurrency 4.5");
  assert.equal(r.code, 1);
});

test("--sarif x.sarif src/api parses both fields", () => {
  const r = call("--sarif x.sarif src/api");
  assert.equal(r.code, 0);
  assert.equal(r.out.sarifPath, "x.sarif");
  assert.equal(r.out.scope, "src/api");
});

test("two positional arguments -> exit 1 with diagnostic", () => {
  const r = call("a b");
  assert.equal(r.code, 1);
  assert.match(r.stderr, /positional|too many/i);
});

test("unknown flag -> exit 1", () => {
  const r = call("--bogus 1");
  assert.equal(r.code, 1);
});

test('quoted path with space: "path with spaces" parses as one positional', () => {
  const r = call('"path with spaces"');
  assert.equal(r.code, 0);
  assert.equal(r.out.scope, "path with spaces");
});

test('--sarif "my project/x.sarif" extracts the quoted path', () => {
  const r = call('--sarif "my project/x.sarif"');
  assert.equal(r.code, 0);
  assert.equal(r.out.sarifPath, "my project/x.sarif");
});

test('unterminated quote "foo -> exit 1 with diagnostic', () => {
  const r = call('"foo');
  assert.equal(r.code, 1);
  assert.match(r.stderr, /unterminated/i);
});

test('double quote inside an unquoted token (fo"o) is treated literally (no special mid-token)', () => {
  const r = call('fo"o');
  assert.equal(r.code, 0);
  assert.equal(r.out.scope, 'fo"o');
});

test("single quotes are NOT special (parsed as literal chars)", () => {
  const r = call("'foo'");
  assert.equal(r.code, 0);
  assert.equal(r.out.scope, "'foo'");
});

test("missing --file flag -> exit 2 usage", () => {
  const r = spawnSync(process.execPath, [CLI], { encoding: "utf8" });
  assert.equal(r.status, 2);
});
