// End-to-end replay smoke test: drives the full helper chain via real CLIs with pre-baked
// analyzer/verifier responses. Proves "from fixed inputs, with no agents, the SKILL's deterministic
// pipeline produces a valid report by passing the right contracts in the right order, with SP3
// included". Does NOT prove analysis quality. Spec: docs/superpowers/specs/2026-06-18-oswe-e2e-replay-smoke-design.md.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPTS = join(HERE, "..");                                                       // skills/audit/scripts/
const REFS = realpathSync(join(SCRIPTS, "..", "references"));                           // skills/audit/references/
const CLI = (name) => join(SCRIPTS, `${name}.mjs`);
const run = (args) => spawnSync(process.execPath, args, { encoding: "utf8" });

test("e2e replay smoke: 8 helpers chain via real CLIs with pre-baked responses", (t) => {
  // === 1. SETUP: a real temp project with three partitions ===
  const root = realpathSync(mkdtempSync(join(tmpdir(), "oswe-e2e-")));
  const outside = realpathSync(mkdtempSync(join(tmpdir(), "oswe-e2e-outside-")));      // for partC escape
  t.after(() => { try { rmSync(root, { recursive: true, force: true }); } catch {} try { rmSync(outside, { recursive: true, force: true }); } catch {} });

  // partA: vulnerable Python — source (request.args) + sink (render_template_string), no auth marker
  mkdirSync(join(root, "a"), { recursive: true });
  writeFileSync(join(root, "a", "app.py"),
    "from flask import request, render_template_string\n" +
    "def view():\n" +
    "    tpl = request.args.get('t', '')\n" +
    "    return render_template_string(tpl)\n"
  );
  // partB: neutral Python (no source, no sink)
  mkdirSync(join(root, "b"), { recursive: true });
  writeFileSync(join(root, "b", "util.py"), "import json\ndef to_str(x):\n    return json.dumps(x)\n");
  // partC: one missing path + one real out-of-scope sibling-temp file (the escape target must EXIST
  // so confinePath's realpathSync succeeds and the containment check — not ENOENT — fires the
  // out-of-scope classification cross-platform; mirrors confine-path.test.mjs and the SP3 test).
  const escapeAbs = join(outside, "evil.py");
  writeFileSync(escapeAbs, "x\n");

  // === 2. PIPELINE STEP 1: confine-path (sanity — the path is reachable) ===
  const cpIn = join(root, "_confine-in.json");
  writeFileSync(cpIn, JSON.stringify({ projectDir: root, arg: "a/app.py" }));
  const cpResult = run([CLI("confine-path"), "--file", cpIn]);
  assert.equal(cpResult.status, 0, `confine-path failed: ${cpResult.stderr}`);
  assert.ok(cpResult.stdout.trim().length > 0, "confine-path printed empty stdout");
  assert.ok(cpResult.stdout.includes("app.py"), "confine-path stdout missing app.py");

  // === 3. PIPELINE STEP 2: surface-scan over partA (scannable) + partB (scannable, low surface) + partC (all-unreadable) ===
  const ssIn = join(root, "_surface-scan-in.json");
  writeFileSync(ssIn, JSON.stringify({
    projectDir: root,
    referencesDir: REFS,
    partitions: [
      { partition_id: "partA", stack: "python", files: ["a/app.py"] },
      { partition_id: "partB", stack: "python", files: ["b/util.py"] },
      // partC references one missing path inside the root + one absolute path OUTSIDE the root.
      // surface-scan classifies the first as skipped_missing (ENOENT) and the second as
      // skipped_out_of_scope (confinePath escape). All files skipped → scannable:false with reason.
      { partition_id: "partC", stack: "python", files: ["c/missing.py", escapeAbs] }
    ]
  }));
  const ssOut = join(root, "_surface-scan-out.json");
  const ssResult = run([CLI("surface-scan"), "--file", ssIn, "--out", ssOut]);
  assert.equal(ssResult.status, 0, `surface-scan failed: ${ssResult.stderr}`);
  const ssPayload = JSON.parse(readFileSync(ssOut, "utf8"));
  assert.equal(ssPayload.ok, true);
  assert.equal(ssPayload.vectors.length, 3);
  const vA = ssPayload.vectors.find((v) => v.partition_id === "partA");
  const vB = ssPayload.vectors.find((v) => v.partition_id === "partB");
  const vC = ssPayload.vectors.find((v) => v.partition_id === "partC");
  // partA: source+sink+no-auth = the high-score case (will win the budget=1 slot)
  assert.equal(vA.scannable, true);
  assert.ok(vA.sources > 0, "partA must detect at least one source");
  assert.ok(vA.sinks > 0, "partA must detect at least one sink");
  assert.equal(vA.source_and_auth_files, 0, "partA has no auth marker — fail-safe must fire");
  assert.equal(typeof vA.content_key, "string");
  assert.equal(vA.content_key.length, 64, "content_key is a sha256 hex digest");
  // partB: scannable but no surface signal
  assert.equal(vB.scannable, true);
  assert.equal(vB.sources, 0);
  assert.equal(vB.sinks, 0);
  // partC: all files skipped → scannable:false with skip counts + a reason
  assert.equal(vC.scannable, false);
  assert.ok((vC.skipped_missing || 0) + (vC.skipped_out_of_scope || 0) === 2, "partC must report both skips");
  assert.match(vC.reason || "", /unreadable/i);

  // === 4. PIPELINE STEP 3: allocate-budget with budget=1 → partA in analyze[], partB in deprioritized, partC in unreadable-partition ===
  const abIn = join(root, "_allocate-in.json");
  writeFileSync(abIn, JSON.stringify({ budget: 1, vectors: ssPayload.vectors }));
  const abOut = join(root, "_allocate-out.json");
  const abResult = run([CLI("allocate-budget"), "--file", abIn, "--out", abOut]);
  assert.equal(abResult.status, 0, `allocate-budget failed: ${abResult.stderr}`);
  const allocation = JSON.parse(readFileSync(abOut, "utf8"));
  assert.equal(allocation.ok, true);
  assert.equal(allocation.analyze.length, 1, "budget=1 → exactly one analyzed");
  assert.equal(allocation.analyze[0].partition_id, "partA", "partA must win the slot (highest score)");
  // The SP3 semantic lock: exactly the two non-analyzed classes the fixture produces — no more, no less.
  assert.deepEqual(
    new Set(allocation.gaps.map((g) => g.gap_class)),
    new Set(["deprioritized", "unreadable-partition"]),
    "SP3 gap_class taxonomy must include exactly these two classes for this fixture"
  );
  // The unreadable-partition gap must carry its skip counts (SP3 review #2 fix preserved here)
  const unreadable = allocation.gaps.find((g) => g.gap_class === "unreadable-partition");
  assert.equal(unreadable.partition_id, "partC");
  assert.ok(unreadable.counts.skipped_missing + unreadable.counts.skipped_out_of_scope >= 1, "unreadable-partition must carry skip counts");

  // === 5. PRE-BAKED ANALYZER RESPONSE for partA — one raw finding, schema-valid ===
  // Required fields per finding.schema.json: finding_id, partition_id, title, vuln_class, source,
  // sink, auth, provisional_severity, confidence, verification_status. analyzer-response forbids
  // origin:"both" and orchestration-only fields (final_severity, partitions, source_finding_ids).
  const analyzerResponse = {
    partition_id: "partA", status: "ok", coverage: { analyzed: ["partA"], skipped: [] },
    findings: [{
      finding_id: "partA-F001", partition_id: "partA",
      title: "Unauth SSTI via render_template_string",
      vuln_class: "ssti",
      source: { file: "a/app.py", line: 3, symbol: "request.args.get", kind: "http-param" },
      sink:   { file: "a/app.py", line: 4, symbol: "render_template_string", kind: "template-render" },
      auth: "unauthenticated",
      provisional_severity: "High",
      confidence: "strong static proof",                    // Pinned per spec §3.5 — drives final_confidence after apply.
      verification_status: "not-requested"
    }]
  };
  const arPath = join(root, "_analyzer-response.json");
  writeFileSync(arPath, JSON.stringify(analyzerResponse));
  // Schema-gate the response (the SKILL §3 contract — validate-output before aggregating)
  const arVal = run([CLI("validate-output"), "analyzer-response", "--file", arPath]);
  assert.equal(arVal.status, 0, `analyzer-response failed schema gate: ${arVal.stdout} ${arVal.stderr}`);

  // === 6. PIPELINE STEP 4: aggregate-findings → canonical OSWE-1 ===
  const agIn = join(root, "_aggregate-in.json");
  writeFileSync(agIn, JSON.stringify({ findings: analyzerResponse.findings }));
  const agOut = join(root, "_aggregate-out.json");
  const agResult = run([CLI("aggregate-findings"), "--file", agIn, "--out", agOut]);
  assert.equal(agResult.status, 0, `aggregate-findings failed: ${agResult.stderr}`);
  const agPayload = JSON.parse(readFileSync(agOut, "utf8"));
  assert.equal(agPayload.ok, true);
  assert.equal(agPayload.findings.length, 1);
  const osweFinding = agPayload.findings[0];
  assert.equal(osweFinding.finding_id, "OSWE-1", "aggregate assigns canonical OSWE-1");
  assert.equal(osweFinding.provisional_severity, "High");
  assert.equal(osweFinding.confidence, "strong static proof");
  assert.equal(osweFinding.verification_status, "not-requested");

  // Schema-gate the OSWE-1 finding (the SKILL §4 contract — backstop the aggregator's output)
  const findingPath = join(root, "_oswe-1.json");
  writeFileSync(findingPath, JSON.stringify(osweFinding));
  const findingVal = run([CLI("validate-output"), "finding", "--file", findingPath]);
  assert.equal(findingVal.status, 0, `OSWE-1 finding failed schema gate: ${findingVal.stdout}`);

  // === 7. CONSTRUCT THE CANDIDATE CHAIN (the SKILL builds chains in-text, not via a helper) ===
  // Required per chain.schema.json: chain_id, entry_point{file,line,route,auth}, finding_ids,
  // transitions[{from,to,how,evidence[]}], final_impact, severity, confidence, verification_status.
  // severity MUST NOT be "Critical" pre-apply — schema:36 makes Critical incompatible with
  // not-requested. Confidence pinned to "strong static proof" so post-apply assertion is reachable.
  const candidateChain = {
    chain_id: "CHAIN-1",
    entry_point: { file: "a/app.py", line: 3, route: "/view", auth: "unauthenticated" },
    finding_ids: ["OSWE-1"],
    transitions: [{
      from: "entry", to: "OSWE-1", how: "header → request.args → render_template_string",
      evidence: [{ file: "a/app.py", line: 4 }]
    }],
    final_impact: "unauth-rce",
    severity: "High",                                       // Pinned per spec §3.5 — NOT Critical pre-apply.
    confidence: "strong static proof",                      // Pinned per spec §3.5 — required by schema:7.
    verification_status: "not-requested"
  };
  const chainPath = join(root, "_chain-pre-apply.json");
  writeFileSync(chainPath, JSON.stringify(candidateChain));
  // Schema-gate the candidate chain (the SKILL §5 contract — validate each built chain)
  const chainVal = run([CLI("validate-output"), "chain", "--file", chainPath]);
  assert.equal(chainVal.status, 0, `candidate chain failed schema gate: ${chainVal.stdout}`);

  // === 8. PRE-BAKED VERIFIER RESPONSES — TWO SEPARATE BATCHES (apply-verdicts:105 enforces
  // 1-5 findings XOR exactly 1 chain per batch) ===
  // (a) finding batch: accepts OSWE-1.
  const findingVerifierResponse = {
    status: "ok",
    verdicts: [{
      target_type: "finding", target_id: "OSWE-1",
      verdict: "accepted",
      justification: "Substantiated: request.args flows unmodified into render_template_string at a/app.py:4."
    }]
  };
  // (b) chain batch: accepts CHAIN-1 — chain verdicts REQUIRE transition_verdicts per verdict.schema.json:30.
  const chainVerifierResponse = {
    status: "ok",
    verdicts: [{
      target_type: "chain", target_id: "CHAIN-1",
      verdict: "accepted",
      justification: "End-to-end chain holds: unauth route → SSTI sink → RCE primitive.",
      transition_verdicts: [{
        from: "entry", to: "OSWE-1", verdict: "accepted",
        justification: "Tainted flow from request.args to render_template_string is direct."
      }]
    }]
  };
  // Schema-gate both verifier responses (the SKILL §6 Step A contract — validate response BEFORE validate-batch)
  const vrFindingPath = join(root, "_verifier-response-finding.json");
  writeFileSync(vrFindingPath, JSON.stringify(findingVerifierResponse));
  const vrFindingVal = run([CLI("validate-output"), "verifier-response", "--file", vrFindingPath]);
  assert.equal(vrFindingVal.status, 0, `finding verifier-response failed schema gate: ${vrFindingVal.stdout}`);

  const vrChainPath = join(root, "_verifier-response-chain.json");
  writeFileSync(vrChainPath, JSON.stringify(chainVerifierResponse));
  const vrChainVal = run([CLI("validate-output"), "verifier-response", "--file", vrChainPath]);
  assert.equal(vrChainVal.status, 0, `chain verifier-response failed schema gate: ${vrChainVal.stdout}`);

  // === 9. PIPELINE STEP 7: validate-batch × 2 (per-batch local check) ===
  // Both batches always carry the FULL findings + chains arrays; batch.expected_targets declares
  // what each one covers — this matches applyVerdicts semantics.
  const bFindWrapper = {
    batch_id: "b-find",
    expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }],
    response: findingVerifierResponse
  };
  const bChainWrapper = {
    batch_id: "b-chain",
    expected_targets: [{ target_type: "chain", target_id: "CHAIN-1" }],
    response: chainVerifierResponse
  };
  // The candidate chain at this stage; apply-verdicts mutates it (severity → Critical, vs → accepted).
  const findingsArr = [osweFinding];
  const chainsArr = [candidateChain];

  const vbFindIn = join(root, "_validate-batch-find-in.json");
  writeFileSync(vbFindIn, JSON.stringify({ findings: findingsArr, chains: chainsArr, batch: bFindWrapper }));
  const vbFind = run([CLI("validate-batch"), "--file", vbFindIn]);
  assert.equal(vbFind.status, 0, `validate-batch (finding) failed: ${vbFind.stdout} ${vbFind.stderr}`);

  const vbChainIn = join(root, "_validate-batch-chain-in.json");
  writeFileSync(vbChainIn, JSON.stringify({ findings: findingsArr, chains: chainsArr, batch: bChainWrapper }));
  const vbChain = run([CLI("validate-batch"), "--file", vbChainIn]);
  assert.equal(vbChain.status, 0, `validate-batch (chain) failed: ${vbChain.stdout} ${vbChain.stderr}`);

  // === 10. PIPELINE STEP 8: apply-verdicts → finding accepted at High, chain ELEVATED to Critical ===
  const avIn = join(root, "_apply-verdicts-in.json");
  writeFileSync(avIn, JSON.stringify({ findings: findingsArr, chains: chainsArr, batches: [bFindWrapper, bChainWrapper] }));
  const avOut = join(root, "_apply-verdicts-out.json");
  const avResult = run([CLI("apply-verdicts"), "--file", avIn, "--out", avOut]);
  assert.equal(avResult.status, 0, `apply-verdicts failed: ${avResult.stderr}`);
  // The CLI ALSO prints the result JSON to stdout (SKILL §6 Step B captures stdout); the file is the
  // same payload, more convenient to parse here. Read from the file.
  const avPayload = JSON.parse(readFileSync(avOut, "utf8"));
  assert.equal(avPayload.ok, true);
  assert.equal(avPayload.gaps.length, 0, "no batches were neutralized");
  // FINDING: accepted at High / strong static proof (final_* fields set by apply-verdicts)
  const finalFinding = avPayload.findings.find((f) => f.finding_id === "OSWE-1");
  assert.equal(finalFinding.verification_status, "accepted");
  assert.equal(finalFinding.final_severity, "High", "finding's final_severity stays High; only the chain is elevated to Critical");
  assert.equal(finalFinding.final_confidence, "strong static proof");
  // CHAIN: ELEVATED to Critical (the gating rule fires: member accepted+strong-proof, entry
  // unauthenticated, impact unauth-rce; see apply-verdicts.mjs:309-314). Chain uses severity/
  // confidence, NOT final_severity (chain.schema.json:32-33).
  const finalChain = avPayload.chains.find((c) => c.chain_id === "CHAIN-1");
  assert.equal(finalChain.verification_status, "accepted");
  assert.equal(finalChain.severity, "Critical", "chain elevated to Critical by gating");
  assert.equal(finalChain.confidence, "strong static proof");

  // === 11. POST-APPLY REVALIDATION (the SKILL §6b ligne 274 contract — revalidate every returned
  // finding AND every returned chain) ===
  const finalFindingPath = join(root, "_final-finding.json");
  writeFileSync(finalFindingPath, JSON.stringify(finalFinding));
  const finalFindingVal = run([CLI("validate-output"), "final-finding", "--file", finalFindingPath]);
  assert.equal(finalFindingVal.status, 0, `final-finding failed schema gate: ${finalFindingVal.stdout}`);

  const finalChainPath = join(root, "_final-chain.json");
  writeFileSync(finalChainPath, JSON.stringify(finalChain));
  const finalChainVal = run([CLI("validate-output"), "chain", "--file", finalChainPath]);
  assert.equal(finalChainVal.status, 0, `post-apply chain failed schema gate: ${finalChainVal.stdout}`);

  // === 12. PIPELINE STEP 9: render-html with a SKILL-shaped Markdown body + a minimal report-summary ===
  // The Markdown body the test feeds to render-html mirrors what SKILL §7 prose would produce —
  // a Coverage section naming the 3 populated classes, a chain block, a finding block, and an
  // XSS canary in an evidence excerpt to redo render-html's escape contract end-to-end.
  const XSS_CANARY = "<img src=x onerror=alert(1)>";
  const mdBody =
    "# OSWE Audit Report\n\n" +
    "## Executive summary\n\n" +
    "Verdict: unauthenticated RCE — Critical\n\n" +
    "## Exploit chains\n\n" +
    "### CHAIN-1 — Critical · strong static proof · accepted\n\n" +
    "Entry: /view (unauthenticated) → OSWE-1 → RCE\n\n" +
    "## Detailed findings\n\n" +
    "### OSWE-1 — SSTI via render_template_string\n\n" +
    "Source: a/app.py:3 — request.args.get\n" +
    "Sink:   a/app.py:4 — render_template_string\n" +
    "Evidence excerpt: `" + XSS_CANARY + "`\n\n" +     // canary embedded as an evidence excerpt
    "## Coverage\n\n" +
    "- Analyzed: partA\n" +
    "- Deprioritized: partB (score 0)\n" +
    "- Unreadable partition: partC (skipped_missing=1, skipped_out_of_scope=1)\n";
  const mdPath = join(root, "_report.md");
  writeFileSync(mdPath, mdBody);

  // Minimal report-summary per report-summary.schema.json (meta + severity_counts +
  // finding_status_counts + coverage + chains — every key required, additionalProperties:false)
  const summary = {
    meta: { target: root, stack: "python", date: "2026-06-18", verdict: "unauth-rce", proof_level: "strong static proof" },
    severity_counts: { Critical: 1, High: 1, Medium: 0, Low: 0, Info: 0 },
    finding_status_counts: { accepted: 1, downgraded: 0, rejected: 0, "not-requested": 0 },
    coverage: { analyzed: 1, skipped: 2 },
    chains: [{
      id: "CHAIN-1", severity: "Critical", entry_auth: "unauthenticated", final_impact: "unauth-rce",
      nodes: ["entry", "OSWE-1", "RCE"],
      edges: [{ from: "entry", to: "OSWE-1", verdict: "accepted" }, { from: "OSWE-1", to: "RCE", verdict: "accepted" }]
    }]
  };
  const summaryPath = join(root, "_summary.json");
  writeFileSync(summaryPath, JSON.stringify(summary));
  const htmlPath = join(root, "_report.html");

  const rhResult = run([CLI("render-html"), "--md", mdPath, "--summary", summaryPath, "--out", htmlPath]);
  assert.equal(rhResult.status, 0, `render-html failed: ${rhResult.stderr}`);
  assert.ok(existsSync(htmlPath), "HTML file was not written");
  const html = readFileSync(htmlPath, "utf8");
  assert.ok(html.length > 0, "HTML file is empty");

  // === 13. STRUCTURAL INVARIANTS on the rendered HTML ===
  assert.match(html, /<title>/i, "HTML must contain <title>");
  assert.match(html, /default-src 'none'/, "HTML must carry the CSP default-src 'none'");
  assert.match(html, /<svg/i, "HTML must contain at least one inline SVG chart");
  assert.match(html, /CHAIN-1/, "HTML must preserve CHAIN-1 from the body");
  assert.match(html, /OSWE-1/, "HTML must preserve OSWE-1 from the body");
  assert.equal(/<script\b/i.test(html), false, "HTML must contain NO <script tags (CSP belt-and-suspenders)");

  // The XSS canary contract: the raw `<img src=x onerror=` substring MUST NOT appear intact in the
  // rendered HTML. Either escaped (`&lt;img …`) or otherwise defanged is acceptable; the raw
  // unescaped sequence appearing would mean render-html lost its HTML-escape discipline.
  assert.equal(html.includes(XSS_CANARY), false,
    "XSS canary <img src=x onerror=alert(1)> must NOT appear intact in the HTML — render-html must escape it");

  // === 14. STRUCTURAL INVARIANTS on the Markdown body the test fed in (sanity for what we exercised) ===
  assert.match(mdBody, /CHAIN-1/);
  assert.match(mdBody, /OSWE-1/);
  assert.match(mdBody, /Analyzed/);
  assert.match(mdBody, /Deprioritized/);
  assert.match(mdBody, /Unreadable partition/);
  assert.match(mdBody, /skipped_missing/);
});
