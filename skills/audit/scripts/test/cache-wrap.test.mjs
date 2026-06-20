import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalize, sha256Hex, helperVersionDigest, cacheLookup, cacheStore } from "../cache-wrap.mjs";

function tmp() {
  return realpathSync(mkdtempSync(join(tmpdir(), "oswe-cache-wrap-")));
}

test("canonicalize sorts keys recursively and produces stable output", () => {
  const a = canonicalize({ b: 2, a: 1, nested: { y: 4, x: 3 } });
  const b = canonicalize({ nested: { x: 3, y: 4 }, a: 1, b: 2 });
  assert.equal(a, b);
  assert.equal(a, '{"a":1,"b":2,"nested":{"x":3,"y":4}}');
});

test("canonicalize preserves array order (arrays are sequences, not sets)", () => {
  assert.equal(canonicalize([3, 1, 2]), "[3,1,2]");
});

test("canonicalize handles null, numbers, strings", () => {
  assert.equal(canonicalize(null), "null");
  assert.equal(canonicalize(42), "42");
  assert.equal(canonicalize("hi"), '"hi"');
});

test("sha256Hex returns 64-hex of input bytes", () => {
  const h = sha256Hex("abc");
  assert.equal(h.length, 64);
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.equal(sha256Hex("abc"), h);
  assert.notEqual(sha256Hex("abd"), h);
});

test("helperVersionDigest digests a file's bytes", () => {
  const dir = tmp();
  const p = join(dir, "fake-helper.mjs");
  writeFileSync(p, "export const x = 1;\n");
  const d1 = helperVersionDigest(p);
  assert.match(d1, /^[0-9a-f]{64}$/);
  writeFileSync(p, "export const x = 2;\n");
  assert.notEqual(helperVersionDigest(p), d1);
});

test("cacheLookup returns hit:false when no cache file exists", () => {
  const dir = tmp();
  const r = cacheLookup({ checkpointDir: dir, helperName: "x", inputDigest: "a".repeat(64), versionDigest: "b".repeat(64) });
  assert.equal(r.hit, false);
});

test("cacheStore then cacheLookup returns hit:true with wrapper", () => {
  const dir = tmp();
  const opts = { checkpointDir: dir, helperName: "h", inputDigest: "a".repeat(64), versionDigest: "b".repeat(64) };
  cacheStore({ ...opts, payload: { output: { foo: "bar" } } });
  const r = cacheLookup(opts);
  assert.equal(r.hit, true);
  assert.deepEqual(r.wrapper.output, { foo: "bar" });
  assert.equal(r.wrapper.input_digest, opts.inputDigest);
  assert.equal(r.wrapper.helper_version_digest, opts.versionDigest);
  assert.match(r.wrapper.generated_at, /^\d{4}-\d{2}-\d{2}T/);
});

test("cacheLookup returns hit:false on malformed cache JSON (silent miss per §6)", () => {
  const dir = tmp();
  const opts = { checkpointDir: dir, helperName: "h", inputDigest: "a".repeat(64), versionDigest: "b".repeat(64) };
  mkdirSync(join(dir, "h"), { recursive: true });
  writeFileSync(join(dir, "h", `${opts.inputDigest}-${opts.versionDigest}.json`), "{not json");
  const r = cacheLookup(opts);
  assert.equal(r.hit, false);
});

test("cacheLookup returns hit:false on input_digest mismatch inside the wrapper", () => {
  const dir = tmp();
  const opts = { checkpointDir: dir, helperName: "h", inputDigest: "a".repeat(64), versionDigest: "b".repeat(64) };
  mkdirSync(join(dir, "h"), { recursive: true });
  writeFileSync(
    join(dir, "h", `${opts.inputDigest}-${opts.versionDigest}.json`),
    JSON.stringify({ input_digest: "z".repeat(64), helper_version_digest: opts.versionDigest, output: {}, generated_at: "x" })
  );
  const r = cacheLookup(opts);
  assert.equal(r.hit, false);
});

test("cacheLookup with requiredPayloadKey returns hit:false when the wrapper is missing that key (silent miss per §6)", () => {
  const dir = tmp();
  const opts = { checkpointDir: dir, helperName: "h", inputDigest: "a".repeat(64), versionDigest: "b".repeat(64) };
  mkdirSync(join(dir, "h"), { recursive: true });
  writeFileSync(
    join(dir, "h", `${opts.inputDigest}-${opts.versionDigest}.json`),
    JSON.stringify({ input_digest: opts.inputDigest, helper_version_digest: opts.versionDigest, generated_at: "x" })
  );
  assert.equal(cacheLookup({ ...opts, requiredPayloadKey: "output" }).hit, false);
  assert.equal(cacheLookup({ ...opts, requiredPayloadKey: "html_output" }).hit, false);
  assert.equal(cacheLookup(opts).hit, true);
});

test("cacheStore is atomic (writes via .tmp-<pid> then rename — no partial file after error path)", () => {
  const dir = tmp();
  const opts = { checkpointDir: dir, helperName: "h", inputDigest: "a".repeat(64), versionDigest: "b".repeat(64) };
  cacheStore({ ...opts, payload: { output: { x: 1 } } });
  const p = join(dir, "h", `${opts.inputDigest}-${opts.versionDigest}.json`);
  assert.equal(existsSync(p), true);
  const w = JSON.parse(readFileSync(p, "utf8"));
  assert.deepEqual(w.output, { x: 1 });
  const tmpPath = `${p}.tmp-${process.pid}`;
  assert.equal(existsSync(tmpPath), false);
});
