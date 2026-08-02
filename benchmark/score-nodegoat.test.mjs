import { test } from "node:test";
import assert from "node:assert/strict";
import { scoreNodegoat } from "./score-nodegoat.mjs";

const truth = { app:"NodeGoat", vulns: [
  { id:"v-eval", vuln_class:"code-injection", file:"app/routes/contributions.js", auth:"authenticated" },
  { id:"v-nosql", vuln_class:"nosql-injection", file:"app/data/allocations-dao.js", auth:"authenticated" },
  { id:"v-xss", vuln_class:"xss", file:"app/routes/profile.js", auth:"authenticated" },
  { id:"v-ssrf", vuln_class:"ssrf", file:"app/routes/research.js", auth:"authenticated" }
]};
const report = {
  run:{}, coverage:{ analyzed:[
    "external/NodeGoat/app/routes/contributions.js",
    "external/NodeGoat/app/data/allocations-dao.js",
    "external/NodeGoat/app/routes/profile.js"
    // research.js NOT analyzed -> structural miss
  ], skipped:[] },
  findings: [
    { finding_id:"OSWE-1", vuln_class:"ssjs", verification_status:"accepted", final_severity:"Critical", source:{file:"external/NodeGoat/app/routes/contributions.js",line:32}, sink:{file:"external/NodeGoat/app/routes/contributions.js",line:32} },
    { finding_id:"OSWE-2", vuln_class:"nosql-injection", verification_status:"accepted", final_severity:"High", source:{file:"external/NodeGoat/app/routes/allocations.js",line:21}, sink:{file:"external/NodeGoat/app/data/allocations-dao.js",line:78} },
    // profile.js analyzed but NO finding -> reasoning miss for v-xss
    { finding_id:"OSWE-9", vuln_class:"prototype-pollution", verification_status:"accepted", final_severity:"Medium", source:{file:"external/NodeGoat/app/data/memos-dao.js",line:5}, sink:{file:"external/NodeGoat/app/data/memos-dao.js",line:9} } // extra
  ],
  chains: [
    { chain_id:"CHAIN-1", verification_status:"accepted", finding_ids:["OSWE-1"], transitions:[
      { from:"entry", to:"OSWE-1", how:"x", evidence:[{file:"external/NodeGoat/app/routes/index.js",line:52},{file:"external/NodeGoat/app/routes/contributions.js",line:32}] }
    ], final_impact:"rce", severity:"Critical", entry_point:{file:"app/routes/index.js",line:52} }
  ],
  verdicts: []
};

test("recall counts class+file matches (synonyms ok)", () => {
  const r = scoreNodegoat(report, truth);
  assert.equal(r.total, 4);
  assert.deepEqual(r.found.map(f=>f.id).sort(), ["v-eval","v-nosql"]); // eval via 'ssjs' synonym; nosql via sink.file
  assert.equal(r.recall, 0.5);
});
test("structural vs reasoning miss classification", () => {
  const r = scoreNodegoat(report, truth);
  assert.deepEqual(r.structural_missed.map(m=>m.id), ["v-ssrf"]);   // research.js not analyzed
  assert.deepEqual(r.reasoning_missed.map(m=>m.id), ["v-xss"]);     // profile.js analyzed, no finding
  assert.equal(r.structural_missed_share, 0.5);
});
test("extra findings (no truth match) are reported, not scored as recall", () => {
  const r = scoreNodegoat(report, truth);
  assert.ok(r.extra.some(e=>e.vuln_class==="prototype-pollution"));
});
test("multi_file_chains counts chains whose evidence spans >=2 files", () => {
  const r = scoreNodegoat(report, truth);
  assert.equal(r.chains, 1);
  assert.equal(r.multi_file_chains, 1); // index.js + contributions.js
});
test("a rejected finding does not satisfy recall", () => {
  const t2 = { vulns:[{ id:"v", vuln_class:"xss", file:"a.js", auth:"authenticated" }] };
  const rep2 = { coverage:{analyzed:["a.js"],skipped:[]}, findings:[{ finding_id:"X", vuln_class:"xss", verification_status:"rejected", source:{file:"a.js",line:1}, sink:{file:"a.js",line:2} }], chains:[], verdicts:[] };
  const r = scoreNodegoat(rep2, t2);
  assert.equal(r.recall, 0);
  assert.equal(r.reasoning_missed.length, 1); // a.js analyzed, only a rejected finding
});

test("SQL injection does not satisfy a NoSQL injection truth entry", () => {
  const sqlTruth = { vulns:[{ id:"v-nosql", vuln_class:"nosql-injection", file:"app/data/user-dao.js" }] };
  const sqlReport = {
    coverage:{ analyzed:["app/data/user-dao.js"], skipped:[] },
    findings:[{
      finding_id:"SQL-1",
      vuln_class:"sql-injection",
      verification_status:"accepted",
      source:{ file:"app/data/user-dao.js", line:1 },
      sink:{ file:"app/data/user-dao.js", line:2 }
    }],
    chains:[]
  };

  const r = scoreNodegoat(sqlReport, sqlTruth);
  assert.equal(r.recall, 0);
});

test("path matching requires a segment boundary before a truth path suffix", () => {
  const pathTruth = { vulns:[{ id:"v-path", vuln_class:"xss", file:"app/data/user-dao.js" }] };
  const pathReport = {
    coverage:{ analyzed:["notapp/data/user-dao.js"], skipped:[] },
    findings:[{
      finding_id:"PATH-1",
      vuln_class:"xss",
      verification_status:"accepted",
      source:{ file:"notapp/data/user-dao.js", line:1 },
      sink:{ file:"notapp/data/user-dao.js", line:2 }
    }],
    chains:[]
  };

  const r = scoreNodegoat(pathReport, pathTruth);
  assert.equal(r.recall, 0);
});
