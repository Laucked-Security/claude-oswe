import { test } from "node:test";
import assert from "node:assert/strict";
import { matchesPattern } from "../../graph/match.mjs";
import { classifyPattern } from "../../graph/surface.mjs";

const sink = (token) => classifyPattern(token, "sinks");
const source = (token) => classifyPattern(token, "sources");
const c = (category, text) => ({ category, text });

// [description, pattern, candidate, expected]
const CASES = [
  // call: categories call/new/member; equality or a "."-boundary suffix
  ["call: bare callee equality", sink("eval("), c("call", "eval"), true],
  ["call: dotted suffix on a boundary", sink("os.system"), c("call", "x.os.system"), true],
  ["call: member category accepted", sink("child_process.exec"), c("member", "child_process.exec"), true],
  ["call: no match across a non-boundary prefix", sink("os.system"), c("call", "foos.system"), false],
  ["call: identifier category rejected", sink("eval("), c("identifier", "eval"), false],
  ["call: a longer last segment does not match", sink("eval("), c("call", "evaluate"), false],
  // member: categories call/member; last segment equality
  ["member: last segment of a callee", sink(".query("), c("call", "db.pool.query"), true],
  ["member: other last segment", sink(".query("), c("call", "query.run"), false],
  ["member: new category rejected", sink(".spawn("), c("new", "spawn"), false],
  // decorator: category decorator; first segment equality
  ["decorator: first segment", source("@Body("), c("decorator", "Body"), true],
  ["decorator: dotted decorator compares the first segment", source("@Body("), c("decorator", "nest.Body"), false],
  ["decorator: call category rejected", source("@Body("), c("call", "Body"), false],
  // chain: categories member/identifier/call; equality or a "."-boundary prefix
  ["chain: equality", source("req.body"), c("member", "req.body"), true],
  ["chain: prefix on a boundary", source("req.body"), c("member", "req.body.cmd"), true],
  ["chain: call category accepted", source("req.body"), c("call", "req.body.toString"), true],
  ["chain: different root", source("req.body"), c("member", "request.body"), false],
  ["chain: non-boundary prefix", source("req.body"), c("member", "req.bodyParser"), false],
  ["chain: decorator category rejected", source("req.body"), c("decorator", "req.body"), false],
  // key: category key; equality
  ["key: object key", sink("$ne"), c("key", "$ne"), true],
  ["key: free string literal rejected", sink("$ne"), c("literal", "$ne"), false],
  ["key: other key", sink("$ne"), c("key", "$nin"), false],
  // word: categories identifier/type/call/new; last segment equality
  ["word: constructor", sink("ProcessBuilder"), c("new", "java.lang.ProcessBuilder"), true],
  ["word: type", sink("ProcessBuilder"), c("type", "ProcessBuilder"), true],
  ["word: callee last segment", sink("execSync"), c("call", "child_process.execSync"), true],
  ["word: member category rejected", sink("execSync"), c("member", "cp.execSync"), false],
  ["word: other identifier", sink("execSync"), c("identifier", "execSyncSafe"), false],
  // literal: category literal; equality
  ["literal: string literal", source("php://input"), c("literal", "php://input"), true],
  ["literal: identifier category rejected", source("X-User-Role"), c("identifier", "X-User-Role"), false],
  ["literal: other string", source("php://input"), c("literal", "php://stdin"), false]
];

for (const [name, pattern, candidate, expected] of CASES) {
  test(`matchesPattern ${name}`, () => {
    assert.equal(matchesPattern(pattern, candidate), expected);
  });
}

test("matchesPattern covers every pattern shape with a positive and a negative case", () => {
  const shapes = (want) => new Set(CASES.filter(([, , , e]) => e === want).map(([, p]) => p.shape));
  const all = ["call", "member", "decorator", "chain", "key", "word", "literal"];
  assert.deepEqual([...shapes(true)].sort(), [...all].sort());
  assert.deepEqual([...shapes(false)].sort(), [...all].sort());
});

test("matchesPattern returns false for an unknown shape or category", () => {
  assert.equal(matchesPattern({ raw: "x", shape: "nope", normalized: "x" }, c("call", "x")), false);
  assert.equal(matchesPattern({ raw: "x", shape: "constructor", normalized: "x" }, c("call", "x")), false);
  assert.equal(matchesPattern(sink("eval("), c("comment", "eval")), false);
});
