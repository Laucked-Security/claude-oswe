// Deterministic application of verifier verdicts to findings and chains. Pure logic + a thin CLI.
// applyVerdicts({ findings, chains, batches })
//   -> { ok, error, error_kind, error_batch_id, findings, chains, gaps, decisions }
//   decisions: [{ target_type, target_id, outcome, reason }] — auditable log of settled outcomes;
//     outcome:"rejected" entries (incl. a chain rejected because a member was rejected) drive the
//     report annex. Transition-mismatch/neutralization causes live in Coverage, not here.
//
// batches bind each verifier response to the exact targets it was asked about (round-trip integrity):
//   batches: [{ batch_id, expected_targets: [{target_type, target_id}], response: { status, verdicts } }]
//   - expected_targets across batches must be DISJOINT and reference real findings/chains.
//   - response.verdicts may ONLY target this batch's expected_targets (no cross-batch leakage).
//   - status "ok"      → verdicts cover EXACTLY expected_targets.
//     status "partial" → verdicts cover a strict NON-EMPTY subset (the rest → gaps).
//     status "error"   → ZERO verdicts (all expected_targets → gaps).
//
// ok:false sets error + error_kind (+ error_batch_id for verifier-output):
//   "verifier-output"    → the verifier's response is bad; retry/drop THAT batch (verdict for an
//                          unexpected target, duplicate verdict, coverage mismatch vs status,
//                          status=error with verdicts, downgrade-raise). error_batch_id names it.
//   "orchestrator-input" → our findings/chains/batches are malformed; a retry cannot fix it (dup
//                          canonical id, chain→unknown finding, invalid topology, batch expecting an
//                          unknown target, overlapping expected_targets).
// gaps: [{ target_type, target_id, reason }] for expected-but-unverified targets.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";
import { canonicalize, sha256Hex, helperVersionDigest, cacheLookup, cacheStore } from "./cache-wrap.mjs";

// Deterministic ordering so a "downgrade" can never RAISE severity or confidence.
const SEV_INDEX = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const SEV_BY_INDEX = ["Info", "Low", "Medium", "High", "Critical"];
const CONF_INDEX = { "to verify": 0, "likely": 1, "strong static proof": 2 };
const notIncrease = (origSev, origConf, newSev, newConf) =>
  SEV_INDEX[newSev] <= SEV_INDEX[origSev] && CONF_INDEX[newConf] <= CONF_INDEX[origConf];

// A chain's transitions must form the exact linear path entry -> f0 -> f1 -> ... -> fN,
// with exactly finding_ids.length transitions. Anything else is a malformed chain.
function topologyValid(c) {
  const ids = c.finding_ids;
  if (c.transitions.length !== ids.length) return false;
  for (let i = 0; i < ids.length; i++) {
    const expectedFrom = i === 0 ? "entry" : ids[i - 1];
    const t = c.transitions[i];
    if (t.from !== expectedFrom || t.to !== ids[i]) return false;
  }
  return true;
}

const _tkey = (tt, tid) => `${tt}:${tid}`;

// Shared id preflight: canonical finding_id / chain_id must be unique (a Map would silently
// overwrite a duplicate, making source_finding_ids / verdict targeting ambiguous). Used by BOTH
// applyVerdicts and the validate-batch CLI so they enforce an identical contract.
export function checkCanonicalIds(findings, chains) {
  if (!Array.isArray(findings) || !Array.isArray(chains)) return { ok: false, error: "findings and chains must be arrays", error_kind: "orchestrator-input" };
  const fset = new Set();
  for (const f of findings) {
    if (!f || typeof f.finding_id !== "string") return { ok: false, error: "a finding is missing a string finding_id", error_kind: "orchestrator-input" };
    if (fset.has(f.finding_id)) return { ok: false, error: "duplicate canonical finding_id in input", error_kind: "orchestrator-input" };
    fset.add(f.finding_id);
  }
  const cset = new Set();
  for (const c of chains) {
    if (!c || typeof c.chain_id !== "string") return { ok: false, error: "a chain is missing a string chain_id", error_kind: "orchestrator-input" };
    if (cset.has(c.chain_id)) return { ok: false, error: "duplicate chain_id in input", error_kind: "orchestrator-input" };
    cset.add(c.chain_id);
  }
  return { ok: true };
}

// The verifier's transition_verdicts must be the EXACT set of the chain's transitions (no missing,
// extra, or duplicated {from,to}) — required for EVERY chain verdict, including 'rejected'.
function exactTransitionMatch(c, tv) {
  const vKeys = tv.map((t) => `${t.from}->${t.to}`);
  const cKeys = c.transitions.map((t) => `${t.from}->${t.to}`);
  const vSet = new Set(vKeys), cSet = new Set(cKeys);
  return vKeys.length === cKeys.length && vKeys.length === vSet.size && cKeys.length === cSet.size &&
    [...cSet].every((k) => vSet.has(k)) && [...vSet].every((k) => cSet.has(k));
}

// Single-batch contract check, shared by the orchestrator (phase 6, BEFORE exhausting the retry) and
// by applyVerdicts (phase 6b backstop). Pure; `findingById`/`chainById` are Maps of the FULL objects
// so it can also catch transition mismatches/contradictions and finding downgrade-raises pre-retry.
// Returns { ok:true } or { ok:false, error, error_kind }. NOTE: the chain downgrade ceiling depends on
// member verdicts from OTHER batches, so it is checked by the full applyVerdicts (run as §6's GLOBAL
// preflight, which names error_batch_id and is retried there). Cross-batch checks (duplicate batch_id,
// overlapping expected_targets) and completeness are also the caller's job (they need all batches).
export function validateBoundBatch(batch, { findingById, chainById }) {
  const bad = (error, error_kind) => ({ ok: false, error, error_kind });
  // Defensive shape validation (the wrapper is orchestrator-built; a malformed one is our bug).
  if (!batch || typeof batch !== "object") return bad("batch is not an object", "orchestrator-input");
  const bid = batch.batch_id;
  if (typeof bid !== "string" || bid.length === 0) return bad("batch is missing a non-empty batch_id", "orchestrator-input");
  if (!Array.isArray(batch.expected_targets) || batch.expected_targets.length === 0) return bad(`batch ${bid} has no expected_targets`, "orchestrator-input");
  if (!batch.response || typeof batch.response !== "object" || !Array.isArray(batch.response.verdicts)) return bad(`batch ${bid} has no response.verdicts array`, "orchestrator-input");
  if (!["ok", "partial", "error"].includes(batch.response.status)) return bad(`batch ${bid} has invalid status ${batch.response.status}`, "verifier-output");

  const exists = (tt, tid) => (tt === "finding" ? findingById.has(tid) : chainById.has(tid));
  // Every expected_target must be a well-formed {target_type, target_id} (a null/typeless element is
  // our bug). Validate shape BEFORE reading fields, so [null] can't throw.
  for (const t of batch.expected_targets) {
    if (!t || (t.target_type !== "finding" && t.target_type !== "chain") || typeof t.target_id !== "string")
      return bad(`batch ${bid} has a malformed expected_target`, "orchestrator-input");
  }
  const chainCount = batch.expected_targets.filter((t) => t.target_type === "chain").length;
  const findingCount = batch.expected_targets.length - chainCount;
  if (!((chainCount === 1 && findingCount === 0) || (chainCount === 0 && findingCount >= 1 && findingCount <= 5)))
    return bad(`batch ${bid} composition must be 1-5 findings XOR exactly 1 chain`, "orchestrator-input");

  const expected = new Set();
  for (const t of batch.expected_targets) {
    const k = _tkey(t.target_type, t.target_id);
    if (expected.has(k)) return bad(`batch ${bid} lists ${k} twice in expected_targets`, "orchestrator-input");
    if (!exists(t.target_type, t.target_id)) return bad(`batch ${bid} expects unknown ${k}`, "orchestrator-input");
    expected.add(k);
  }
  const covered = new Set();
  for (const v of batch.response.verdicts) {
    // A null/typeless verdict is a verifier-output defect (the response is JSON the verifier emitted).
    if (!v || (v.target_type !== "finding" && v.target_type !== "chain") || typeof v.target_id !== "string")
      return bad(`batch ${bid} returned a malformed verdict`, "verifier-output");
    const k = _tkey(v.target_type, v.target_id);
    if (!expected.has(k)) return bad(`batch ${bid} returned a verdict for unexpected target ${k}`, "verifier-output");
    if (covered.has(k)) return bad(`batch ${bid} returned a duplicate verdict for ${k}`, "verifier-output");
    covered.add(k);
    // Semantic checks possible from THIS batch alone:
    if (v.target_type === "finding" && v.verdict === "downgraded") {
      const f = findingById.get(v.target_id);
      if (!notIncrease(f.provisional_severity, f.confidence, v.new_severity, v.new_confidence)) return bad(`downgraded finding ${v.target_id} raises severity/confidence`, "verifier-output");
    }
    // SP6: counterexample checklist on FINDING verdicts.
    //  - PRESENCE: accepted/downgraded findings MUST carry a non-empty counterexamples[] (the
    //    refutation checklist — schema-required too, gated here so a hand-built batch can't bypass it).
    //  - RESOLUTION: accepted ⇒ every checked counterexample refuted; rejected/downgraded (when any
    //    counterexample is present) ⇒ at least one holds (refuted:false), i.e. cites why it is not real.
    if (v.target_type === "finding") {
      const ces = Array.isArray(v.counterexamples) ? v.counterexamples : [];
      if ((v.verdict === "accepted" || v.verdict === "downgraded") && ces.length === 0)
        return bad(`${v.verdict} finding ${v.target_id} has no counterexamples (refutation checklist required)`, "verifier-output");
      if (ces.length) {
        if (v.verdict === "accepted") {
          if (!ces.every((c) => c.checked === true && c.refuted === true))
            return bad(`accepted finding ${v.target_id} has an unrefuted counterexample`, "verifier-output");
        } else if (v.verdict === "rejected" || v.verdict === "downgraded") {
          if (!ces.some((c) => c.checked === true && c.refuted === false))
            return bad(`${v.verdict} finding ${v.target_id} cites no holding counterexample`, "verifier-output");
        }
      }
    }
    if (v.target_type === "chain") {
      const c = chainById.get(v.target_id);
      const tv = v.transition_verdicts || [];
      if (!exactTransitionMatch(c, tv)) return bad(`chain ${v.target_id} transition_verdicts do not match its transitions`, "verifier-output");
      if (v.verdict !== "rejected" && !tv.every((t) => t.verdict === "accepted")) return bad(`chain ${v.target_id} has a rejected transition but its verdict is '${v.verdict}', not 'rejected'`, "verifier-output");
    }
  }
  const st = batch.response.status;
  if (st === "error") { if (covered.size !== 0) return bad(`batch ${bid} status=error must carry no verdicts`, "verifier-output"); }
  else if (st === "ok") { if (covered.size !== expected.size) return bad(`batch ${bid} status=ok must cover all expected targets`, "verifier-output"); }
  else { if (covered.size === 0 || covered.size === expected.size) return bad(`batch ${bid} status=partial must cover a strict non-empty subset`, "verifier-output"); }
  return { ok: true };
}

export function applyVerdicts({ findings, chains, batches } = {}) {
  const fail = (error, error_kind, error_batch_id = null) =>
    ({ ok: false, error, error_kind, error_batch_id, findings, chains, gaps: [] });

  // Defensive: a malformed orchestrator call yields a structured orchestrator-input error, not a throw.
  if (!Array.isArray(findings) || !Array.isArray(chains) || !Array.isArray(batches))
    return fail("findings, chains, and batches must be arrays", "orchestrator-input");

  const idCheck = checkCanonicalIds(findings, chains);
  if (!idCheck.ok) return fail(idCheck.error, idCheck.error_kind);
  const findingById = new Map(findings.map((f) => [f.finding_id, f]));
  const chainById = new Map(chains.map((c) => [c.chain_id, c]));

  const tkey = (tt, tid) => `${tt}:${tid}`;

  // --- Per-batch contract (shared helper) + cross-batch checks; bind verdicts to their batch. ---
  const expectedBatchOf = new Map();          // "type:id" -> batch_id (also enforces disjointness)
  const verdictOf = new Map();                // "type:id" -> { v, batch_id }
  const seenBatchIds = new Set();
  for (const b of batches) {
    // validateBoundBatch first: it tolerates a null/shapeless wrapper and a missing batch_id, so we
    // never touch b.batch_id before the shape is known good.
    const vb = validateBoundBatch(b, { findingById, chainById }); // the SAME check phase 6 runs pre-retry
    if (!vb.ok) return fail(vb.error, vb.error_kind, vb.error_kind === "verifier-output" ? b.batch_id : null);
    if (seenBatchIds.has(b.batch_id)) return fail(`duplicate batch_id ${b.batch_id}`, "orchestrator-input");
    seenBatchIds.add(b.batch_id);
    for (const t of b.expected_targets) {
      const k = tkey(t.target_type, t.target_id);
      if (expectedBatchOf.has(k)) return fail(`target ${k} expected by multiple batches`, "orchestrator-input");
      expectedBatchOf.set(k, b.batch_id);
    }
    for (const v of (b.response.verdicts || [])) verdictOf.set(tkey(v.target_type, v.target_id), { v, batch_id: b.batch_id });
  }

  for (const c of chains) {
    for (const id of c.finding_ids) {
      if (!findingById.has(id)) return fail(`chain ${c.chain_id} references unknown finding ${id}`, "orchestrator-input");
    }
  }

  // Completeness: every chain, every chain member, and every provisional-High finding MUST have
  // been dispatched (appear in some batch's expected_targets). A missing one is an orchestrator bug.
  const required = new Set();
  for (const c of chains) {
    required.add(tkey("chain", c.chain_id));
    for (const id of c.finding_ids) required.add(tkey("finding", id));
  }
  for (const f of findings) if (f.provisional_severity === "High") required.add(tkey("finding", f.finding_id));
  for (const k of required) {
    if (!expectedBatchOf.has(k)) return fail(`required target ${k} was not dispatched to any batch`, "orchestrator-input");
  }

  // Per-batch contract (incl. transition match/contradiction and FINDING downgrade-raise) was already
  // enforced by validateBoundBatch above; here we only apply verdicts and resolve cross-batch state.
  const findingVerdict = new Map();
  const chainVerdict = new Map();
  for (const [k, { v }] of verdictOf) {
    if (v.target_type === "finding") findingVerdict.set(v.target_id, v);
    else chainVerdict.set(v.target_id, v);
  }

  // Every expected target with no verdict (status=partial/error) is a coverage gap.
  const gaps = [];
  for (const [k, batch_id] of expectedBatchOf) {
    if (!verdictOf.has(k)) {
      const idx = k.indexOf(":");
      gaps.push({ target_type: k.slice(0, idx), target_id: k.slice(idx + 1), reason: `no verdict (batch ${batch_id})` });
    }
  }

  // decisions: an auditable log of every settled outcome + reason. outcome:"rejected" entries
  // (incl. a chain implicitly rejected because a MEMBER was rejected) drive the report's
  // "Dismissed findings" annex. Transition-mismatch causes are NOT here — such a response is a
  // verifier-output error retried/neutralized in §6, and the orchestrator records that cause in Coverage.
  const decisions = [];

  const outFindings = findings.map((f) => {
    const v = findingVerdict.get(f.finding_id);
    const nf = { ...f };
    if (!v) {
      // Unverified (never dispatched, or a partial/error batch gap — already recorded in `gaps`).
      nf.verification_status = "not-requested";
      nf.final_severity = f.provisional_severity;
      nf.final_confidence = f.confidence;
      decisions.push({ target_type: "finding", target_id: f.finding_id, outcome: "not-requested", reason: "no verifier verdict (unverified)" });
      return nf;
    }
    nf.verification_status = v.verdict;
    if (v.verdict === "accepted") {
      nf.final_severity = f.provisional_severity;
      nf.final_confidence = f.confidence;
    } else if (v.verdict === "downgraded") {
      nf.final_severity = v.new_severity;
      nf.final_confidence = v.new_confidence;
    } else {
      delete nf.final_severity;
      delete nf.final_confidence;
    }
    decisions.push({ target_type: "finding", target_id: f.finding_id, outcome: v.verdict, reason: v.justification });
    return nf;
  });

  const statusById = new Map(outFindings.map((f) => [f.finding_id, f.verification_status]));
  const sevById = new Map(outFindings.map((f) => [f.finding_id, f.final_severity]));
  const confById = new Map(outFindings.map((f) => [f.finding_id, f.final_confidence]));
  // Rejecting a chain must never RAISE its severity (a Low/Info candidate stays at most that).
  const reject = (nc) => {
    nc.severity = SEV_BY_INDEX[Math.min(SEV_INDEX[nc.severity], SEV_INDEX["Medium"])];
    nc.confidence = "to verify";
    nc.verification_status = "rejected";
    return nc;
  };

  const outChains = [];
  for (const c of chains) {
    const nc = { ...c };

    // Topology is an ORCHESTRATOR-bug check and must run REGARDLESS of any verdict — a malformed
    // chain that loses its verdict (e.g. after a dropped batch) must NOT slip through as not-requested.
    if (!topologyValid(c)) return fail(`chain ${c.chain_id} has invalid topology (must be entry->f0->...->fN)`, "orchestrator-input");

    const v = chainVerdict.get(c.chain_id);

    // No verdict → not verified: stay not-requested (any gap was already recorded from expected_targets).
    if (!v) {
      nc.verification_status = "not-requested";
      decisions.push({ target_type: "chain", target_id: c.chain_id, outcome: "not-requested", reason: "no verifier verdict (unverified)" });
      outChains.push(nc);
      continue;
    }

    // validateBoundBatch already guaranteed (for EVERY chain verdict, incl. 'rejected') that
    // transition_verdicts exactly match the chain's transitions, and that an accepted/downgraded
    // verdict has no rejected transition. So here we trust the transitions and resolve member state.
    if (v.verdict === "rejected") {
      decisions.push({ target_type: "chain", target_id: c.chain_id, outcome: "rejected", reason: v.justification });
      outChains.push(reject(nc));
      continue;
    }

    const members = c.finding_ids.map((id) => statusById.get(id));
    const anyRejected = members.some((s) => s === "rejected");
    const anyNotRequested = members.some((s) => s === "not-requested");
    const allMembersAccepted = members.every((s) => s === "accepted");

    // A member finding REJECTED (refuted) → the chain is rejected (legitimate, with reason).
    if (anyRejected) {
      const bad = c.finding_ids.filter((id) => statusById.get(id) === "rejected");
      decisions.push({ target_type: "chain", target_id: c.chain_id, outcome: "rejected", reason: `member finding(s) rejected: ${bad.join(", ")}` });
      outChains.push(reject(nc));
      continue;
    }
    // A member merely UNVERIFIED (its batch errored → gap) is NOT a refutation → not-requested + gap.
    if (anyNotRequested) {
      const bad = c.finding_ids.filter((id) => statusById.get(id) === "not-requested");
      nc.verification_status = "not-requested";
      gaps.push({ target_type: "chain", target_id: c.chain_id, reason: `member finding(s) unverified: ${bad.join(", ")}` });
      decisions.push({ target_type: "chain", target_id: c.chain_id, outcome: "not-requested", reason: `member finding(s) unverified: ${bad.join(", ")}` });
      outChains.push(nc);
      continue;
    }

    // Weakest member confidence — the chain is only as strong as its weakest verified link.
    const minMemberConfIdx = Math.min(...c.finding_ids.map((id) => CONF_INDEX[confById.get(id) ?? "to verify"]));
    const minMemberConf = ["to verify", "likely", "strong static proof"][minMemberConfIdx];

    // Critical requires every member accepted AND every member confidence "strong static proof".
    const canBeCritique =
      allMembersAccepted && minMemberConfIdx === CONF_INDEX["strong static proof"] &&
      c.entry_point.auth === "unauthenticated" && c.final_impact === "unauth-rce";
    const naturalSev = canBeCritique
      ? "Critical"
      : SEV_BY_INDEX[Math.max(0, ...c.finding_ids.map((id) => SEV_INDEX[sevById.get(id) ?? "Info"]))];
    const naturalConf = canBeCritique ? "strong static proof" : minMemberConf;

    if (v.verdict === "downgraded") {
      // A downgrade may not exceed EITHER the candidate's originally-claimed level (c.severity/
      // c.confidence) OR the natural computed level. Use the lower of the two as the ceiling.
      const ceilSev = SEV_BY_INDEX[Math.min(SEV_INDEX[c.severity], SEV_INDEX[naturalSev])];
      const ceilConf = ["to verify", "likely", "strong static proof"][
        Math.min(CONF_INDEX[c.confidence], CONF_INDEX[naturalConf])
      ];
      if (!notIncrease(ceilSev, ceilConf, v.new_severity, v.new_confidence)) {
        return fail(`downgraded chain ${c.chain_id} raises severity/confidence above its ceiling`, "verifier-output", verdictOf.get(tkey("chain", c.chain_id)).batch_id);
      }
      nc.verification_status = "downgraded";
      nc.severity = v.new_severity;
      nc.confidence = v.new_confidence;
      decisions.push({ target_type: "chain", target_id: c.chain_id, outcome: "downgraded", reason: v.justification });
      outChains.push(nc);
      continue;
    }

    // v.verdict === "accepted"
    nc.verification_status = "accepted";
    nc.severity = naturalSev;
    nc.confidence = naturalConf;
    decisions.push({ target_type: "chain", target_id: c.chain_id, outcome: "accepted", reason: v.justification });
    outChains.push(nc);
  }

  return { ok: true, error: null, error_kind: null, error_batch_id: null, findings: outFindings, chains: outChains, gaps, decisions };
}

// CLI: node apply-verdicts.mjs --file <input.json> --out <result.json> [--checkpoint-dir <abs>]
//   input.json: { "findings": [...], "chains": [...], "batches": [...] }
//   exit 0 when result.ok, 1 when !ok (see error_kind/error_batch_id), 2 on usage/IO error.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const fileIdx = args.indexOf("--file");
  const outIdx = args.indexOf("--out");
  const ci = args.indexOf("--checkpoint-dir");
  if (ci !== -1 && (!args[ci + 1] || args[ci + 1].startsWith("--"))) {
    process.stderr.write("usage: apply-verdicts.mjs ... --checkpoint-dir <abs>   (--checkpoint-dir requires a path argument, got: " + (args[ci + 1] ?? "<end of args>") + ")\n");
    process.exit(2);
  }
  const checkpointDir = ci !== -1 ? args[ci + 1] : null;
  if (fileIdx === -1 || outIdx === -1) {
    process.stderr.write("usage: apply-verdicts.mjs --file <input.json> --out <result.json> [--checkpoint-dir <abs>]\n");
    process.exit(2);
  }
  let input;
  try {
    input = JSON.parse(readFileSync(args[fileIdx + 1], "utf8"));
  } catch (e) {
    process.stderr.write("cannot read --file: " + e.message + "\n");
    process.exit(2);
  }

  if (checkpointDir) {
    const inputDigest = sha256Hex(canonicalize(input));
    const versionDigest = helperVersionDigest(fileURLToPath(import.meta.url));
    const lookup = cacheLookup({ checkpointDir, helperName: "apply-verdicts", inputDigest, versionDigest, requiredPayloadKey: "output" });
    if (lookup.hit) {
      try { writeFileSync(args[outIdx + 1], JSON.stringify(lookup.wrapper.output, null, 2)); }
      catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
      process.stderr.write("apply-verdicts: cache hit\n");
      process.exit(0);
    }
  }

  const result = applyVerdicts(input);
  try {
    writeFileSync(args[outIdx + 1], JSON.stringify(result, null, 2));
  } catch (e) {
    process.stderr.write("cannot write --out: " + e.message + "\n");
    process.exit(2);
  }

  if (checkpointDir && result.ok) {
    const inputDigest = sha256Hex(canonicalize(input));
    const versionDigest = helperVersionDigest(fileURLToPath(import.meta.url));
    try { cacheStore({ checkpointDir, helperName: "apply-verdicts", inputDigest, versionDigest, payload: { output: result } }); }
    catch (e) { process.stderr.write("apply-verdicts: cache store failed (non-fatal): " + e.message + "\n"); }
  }

  process.exit(result.ok ? 0 : 1);
}
