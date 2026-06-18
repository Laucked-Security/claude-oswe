import { test } from "node:test";
import assert from "node:assert/strict";
import { allocate, scoreVector } from "../allocate-budget.mjs";

// A scannable count vector. content_key stands in for surface-scan's sha256 (any stable string works).
const vec = (id, over = {}) => ({
  partition_id: id, stack: "python", scannable: true, files: 1,
  sources: 0, sinks: 0, sanitizers: 0, auth_markers: 0, source_and_auth_files: 0,
  source_hits: 0, sink_hits: 0, auth_hits: 0, content_key: id, ...over
});

test("budget >= scannable count -> everything analyzed, no deprioritized gaps (zero-regression)", () => {
  const r = allocate([vec("a", { sources: 1, sinks: 1 }), vec("b", { sinks: 1 })], 12);
  assert.equal(r.ok, true);
  assert.equal(r.analyze.length, 2);
  assert.equal(r.gaps.filter((g) => g.gap_class === "deprioritized").length, 0);
});

test("source+sink+no-auth outranks an auth-gated source+sink", () => {
  const open = vec("open", { sources: 1, sinks: 1, source_and_auth_files: 0 });
  const gated = vec("gated", { sources: 1, sinks: 1, auth_markers: 1, source_and_auth_files: 1 });
  assert.ok(scoreVector(open) > scoreVector(gated)); // W_UNAUTH only on the open one
});

test("small-and-deadly is NEVER ranked below large-and-flat (>=, not strict >)", () => {
  const deadly = vec("deadly", { sources: 1, sinks: 1, source_and_auth_files: 0, sink_hits: 30 });
  const flat = vec("flat", { sources: 30, sinks: 1, source_and_auth_files: 0, sink_hits: 1 });
  assert.ok(scoreVector(deadly) >= scoreVector(flat)); // capped density may tie, never invert
});

test("mixed partition: auth markers only in NON-source files still fires the unauth fail-safe", () => {
  // sources=10, auth_markers=11 (global ratio would suppress), but source_and_auth_files=0 (no source file gated)
  const mixed = vec("mixed", { sources: 10, sinks: 1, auth_markers: 11, source_and_auth_files: 0 });
  const baseline = vec("base", { sources: 10, sinks: 1, auth_markers: 0, source_and_auth_files: 0 });
  assert.equal(scoreVector(mixed), scoreVector(baseline)); // co-location, not global count, decides
});

test("a fully-gated partition (every source file has auth) does NOT get the unauth bonus", () => {
  const gated = vec("g", { sources: 3, sinks: 1, auth_markers: 3, source_and_auth_files: 3 });
  const open = vec("o", { sources: 3, sinks: 1, auth_markers: 0, source_and_auth_files: 0 });
  assert.ok(scoreVector(open) > scoreVector(gated));
});

test("ties break deterministically on content_key (ascending), independent of input order", () => {
  const x = vec("x", { sources: 1, sinks: 1, content_key: "bbb" });
  const y = vec("y", { sources: 1, sinks: 1, content_key: "aaa" });
  const r1 = allocate([x, y], 1).analyze.map((a) => a.partition_id);
  const r2 = allocate([y, x], 1).analyze.map((a) => a.partition_id);
  assert.deepEqual(r1, r2);          // same selection regardless of input order
  assert.deepEqual(r1, ["y"]);        // content_key "aaa" < "bbb" wins the single slot
});

test("unscannable vectors never enter analyze and surface as unsupported-stack gaps", () => {
  const r = allocate([{ partition_id: "u", stack: "perl", scannable: false, files: 3 }, vec("a", { sinks: 1 })], 12);
  assert.deepEqual(r.analyze.map((a) => a.partition_id), ["a"]);
  const g = r.gaps.find((x) => x.partition_id === "u");
  assert.equal(g.gap_class, "unsupported-stack");
});

test("SARIF term is zero when absent and lifts a partition when present (capped)", () => {
  const v = vec("s", { sources: 1, sinks: 1, source_and_auth_files: 1, auth_markers: 1 }); // gated, no unauth bonus
  const base = scoreVector(v);
  const lifted = scoreVector(v, { count: 3 });
  assert.ok(lifted > base);
  const capped = scoreVector(v, { count: 9999 });
  assert.equal(capped, scoreVector(v, { count: 10 })); // LEAD_CAP=10
});

test("sanitizers never lower a score", () => {
  const without = vec("a", { sources: 1, sinks: 1 });
  const withSan = vec("b", { sources: 1, sinks: 1, sanitizers: 5 });
  assert.equal(scoreVector(withSan), scoreVector(without));
});

test("deprioritized gaps carry score + counts; over-budget partitions land there", () => {
  const vs = [vec("hi", { sources: 1, sinks: 1, source_and_auth_files: 0 }), vec("lo", { sinks: 0, sources: 0 })];
  const r = allocate(vs, 1);
  assert.equal(r.analyze.length, 1);
  const dep = r.gaps.find((g) => g.gap_class === "deprioritized");
  assert.equal(typeof dep.score, "number");
  assert.ok(dep.counts && typeof dep.counts.sinks === "number");
});

test("allocate threads the SARIF map by partition_id and the lift can change the selection", () => {
  // two equal-structure gated partitions (no unauth bonus); the one with SARIF leads must win the slot.
  const a = vec("a", { sources: 1, sinks: 1, auth_markers: 1, source_and_auth_files: 1, content_key: "aaa" });
  const b = vec("b", { sources: 1, sinks: 1, auth_markers: 1, source_and_auth_files: 1, content_key: "bbb" });
  // without SARIF, content_key tie-break picks "a" for the single slot:
  assert.deepEqual(allocate([a, b], 1).analyze.map((x) => x.partition_id), ["a"]);
  // with leads on "b", b outranks a and takes the slot — proves the map→partition_id join is wired:
  assert.deepEqual(allocate([a, b], 1, { b: { count: 5 } }).analyze.map((x) => x.partition_id), ["b"]);
});

test("invalid budget and non-array vectors are rejected (ok:false)", () => {
  assert.equal(allocate([], 0).ok, false);
  assert.equal(allocate("nope", 12).ok, false);
});
