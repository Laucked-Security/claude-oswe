# SP7 — Trust-Boundary Hygiene Lane

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or
> superpowers:executing-plans. Steps use checkbox syntax. Prompt-only tasks are verified by re-auditing
> the benchmark `trustbound` category, not by unit tests.

**Goal:** Recover the 8 `trustbound` recall misses the SP6 gate measured — honestly, without diluting the
OSWE/RCE identity — by adding a strictly-bounded **hygiene lane** for CWE-501 trust-boundary violations.

**Architecture:** A secondary finding lane, separate from exploit chains. `oswe` stays RCE-chain-first;
on top of it, an *obvious* trust-boundary crossing (attacker data written into trusted/session/server
state) is reported as a **Low/Info hygiene finding** — never a chain member, never High/Medium/Critical,
never an "RCE path". Enforced deterministically (schema + apply-verdicts) where possible; the recognition
itself is prompt + reference-catalog work, measured on the benchmark.

**Tech stack:** existing — Node ≥ 20 zero-dep helpers, AJV-generated validators, the `trustbound`
category of OWASP BenchmarkJava (`subset-sp6.json`), `benchmark/metrics.mjs`.

---

## 0. Why (grounded in the SP6 gate read)

The SP6 Phase-3 gate (commit `ef86e6b`) opened with **`structural_fn_share` = 0.05** → residual misses are
reasoning, not structural → **Phase 2, not the app graph**. The single concrete recall failure is **8
cases, all `trustbound`** (BT00031/00098/00251/00324/00325/00327/00424/00425). Every one is the same
shape:

```java
String param = request.getParameter(...);          // attacker-controlled source
request.getSession().putValue("userid", param);    // sink: untrusted data -> trusted store (CWE-501)
```

This is **not** an RCE chain. oswe *refuted* them — defensible for an RCE-first tool (cf. the cmdi `envp`
caveat in `BENCHMARK.md`), but the benchmark counts them as false negatives. The cause is also concrete:
`skills/audit/references/java.md` lists trust-boundary **sources** (`X-User-Role`, …) but **no
trust-boundary sink** (`session.setAttribute`/`putValue`, cookie/trusted-context writes), so the analyzer
has nothing to promote and the verifier refutes.

## 1. The locked contract (the spec's invariants)

1. CWE-501 is **in scope as a hygiene finding**, never as an exploitable chain.
2. Default severity **Low**; **Info** when the security impact can't be qualified.
3. **Never** Critical/High/Medium for a pure trust-boundary finding (those require a *proven downstream
   consequence* — which would be a different `vuln_class`/chain, not this lane).
4. A trust-boundary finding **never** counts as an "RCE path" and is **never a chain member**.
5. The verifier **accepts only a direct crossing**: attacker-controlled data → write into
   trusted/session/server state. It **rejects/downgrades** if the value is constant, already server-side,
   sanitized, or not attacker-controlled (this maps onto the SP6 counterexample checklist).
6. The report presents these under **"Hygiene / Trust-boundary"**, visually distinct from exploit chains.

`vuln_class` for this lane is the literal string **`"trust-boundary"`** (with CWE-501 in the title/notes).

## 2. Files touched

| File | Task | Change |
|---|---|---|
| `skills/audit/schemas/finding.schema.json` | 1 | invariant: `vuln_class:"trust-boundary"` ⇒ `provisional_severity` ∈ {Low, Info} |
| `skills/audit/schemas/final-finding.schema.json` | 1 | same for `final_severity` (non-rejected) |
| `skills/audit/scripts/validators.mjs` | 1 | regenerated |
| `skills/audit/scripts/apply-verdicts.mjs` + test | 2 | a `trust-boundary` finding may not appear in any chain's `finding_ids` (orchestrator-input error) |
| `skills/audit/references/java.md` | 3 | add trust-boundary **sinks** to the surface block + prose |
| `skills/audit/scripts/test/` (validator + structure) | 3 | fixture-link the new sink |
| `test-fixtures/java/vulnerable/` | 3 | a minimal `trust-boundary` fixture (source→session write) |
| `agents/oswe-analyzer.md` | 4 | recognize the lane: emit `vuln_class:"trust-boundary"`, Low/Info, no chain |
| `agents/oswe-verifier.md` | 5 | accept only direct crossings; reject constant/server-side/sanitized/uncontrolled |
| `skills/audit/SKILL.md` | 6 | report **"Hygiene / Trust-boundary"** section, separate from chains; report.json carries them |
| `benchmark/metrics.mjs` + test | 7 | `hygiene_findings` count (visibility; recall already recovers via `promoted`) |

## 3. Bite-sized plan

### Task 1: schema invariant — trust-boundary is Low/Info only

**Files:** `skills/audit/schemas/finding.schema.json`, `skills/audit/schemas/final-finding.schema.json`,
test in `skills/audit/scripts/test/validate-output.test.mjs`; regenerate `validators.mjs`.

- [ ] **Step 1: Failing test** —

```js
test("trust-boundary finding must be Low or Info", () => {
  const tb = (sev) => baseFinding({ vuln_class: "trust-boundary", provisional_severity: sev });
  assert.equal(validate("finding", tb("Low")).valid, true);
  assert.equal(validate("finding", tb("Info")).valid, true);
  assert.equal(validate("finding", tb("Medium")).valid, false);
  assert.equal(validate("finding", tb("High")).valid, false);
});
```

- [ ] **Step 2: Run, confirm FAIL** — `node --test skills/audit/scripts/test/validate-output.test.mjs`.
- [ ] **Step 3: Implement** — add to `finding.schema.json` `allOf`:

```json
{ "if": { "properties": { "vuln_class": { "const": "trust-boundary" } }, "required": ["vuln_class"] },
  "then": { "properties": { "provisional_severity": { "enum": ["Low", "Info"] } } } }
```
  and to `final-finding.schema.json` an analogous clause gating `final_severity` to `{Low, Info}` when
  `vuln_class:"trust-boundary"` and `verification_status` ≠ `rejected`. Run `build-validators.mjs`.
- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** — `git add skills/audit/schemas/*.json skills/audit/scripts/validators.mjs skills/audit/scripts/test/ && git commit -m "feat(sp7): trust-boundary findings are Low/Info only"`

### Task 2: a trust-boundary finding can never be a chain member

**Files:** `skills/audit/scripts/apply-verdicts.mjs`, `skills/audit/scripts/test/apply-verdicts.test.mjs`

- [ ] **Step 1: Failing test** — a chain whose `finding_ids` includes a `trust-boundary` finding is an
  `orchestrator-input` error.

```js
test("a trust-boundary finding may not be a chain member", () => {
  const tb = { ...finding("OSWE-1"), vuln_class: "trust-boundary", provisional_severity: "Low" };
  const r = applyVerdicts({ findings: [tb, finding("OSWE-2")], chains: [chain()], batches: [] });
  assert.equal(r.ok, false);
  assert.match(r.error, /trust-boundary .* chain/);
  assert.equal(r.error_kind, "orchestrator-input");
});
```

- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** — in `applyVerdicts`, after the chain→unknown-finding check, reject any chain
  referencing a finding whose `vuln_class === "trust-boundary"` (a hygiene finding is never an RCE link).
- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** — `git add skills/audit/scripts/apply-verdicts.mjs skills/audit/scripts/test/ && git commit -m "feat(sp7): trust-boundary findings excluded from exploit chains"`

### Task 3: java.md trust-boundary sinks + fixture

**Files:** `skills/audit/references/java.md`, `test-fixtures/java/vulnerable/TrustBoundary.java` (new),
re-run `.github/scripts/check-structure.mjs`.

- [ ] **Step 1: Failing check** — add a fixture `test-fixtures/java/vulnerable/TrustBoundary.java`:

```java
// attacker source -> trusted-store sink (CWE-501), no RCE
String userid = request.getParameter("uid");
request.getSession().setAttribute("userid", userid);
```
  Run `node .github/scripts/check-structure.mjs` → FAILS (a declared sink must be fixture-linked, or the
  new sink isn't yet in `java.md`).
- [ ] **Step 2: Implement** — add to `java.md` surface block `sinks`: `setAttribute`, `putValue`,
  `addCookie` (trusted-store writes), and a prose bullet: *"Trust-boundary (CWE-501): attacker-controlled
  data written into session/cookie/trusted server state — a **hygiene** finding (Low/Info), not an RCE
  sink."*
- [ ] **Step 3: Run, confirm PASS** — structure check green.
- [ ] **Step 4: Commit** — `git add skills/audit/references/java.md test-fixtures/java/vulnerable/TrustBoundary.java && git commit -m "feat(sp7): java trust-boundary sinks + fixture"`

### Task 4: analyzer recognizes the hygiene lane (prompt)

**Files:** `agents/oswe-analyzer.md`

- [ ] **Step 1: Edit** — add a section: when attacker-controlled data is written into trusted/session/
  server state with no further dangerous sink, emit a finding with `vuln_class:"trust-boundary"`,
  `provisional_severity:"Low"` (or `"Info"` if impact can't be qualified), title naming CWE-501, and **do
  NOT** build or join an exploit chain for it. Keep the proof fields (source/sink) populated.
- [ ] **Step 2: Manual verification** — re-audit one trustbound case via the SP5 smoke / a real run;
  confirm the emitted finding is `trust-boundary` Low and not in any chain.
- [ ] **Step 3: Commit** — `git add agents/oswe-analyzer.md && git commit -m "feat(sp7): analyzer emits trust-boundary hygiene findings (Low/Info, no chain)"`

### Task 5: verifier accepts only direct crossings (prompt)

**Files:** `agents/oswe-verifier.md`

- [ ] **Step 1: Edit** — for `vuln_class:"trust-boundary"`, the counterexample checklist is: source not
  attacker-controlled; value is a constant; value already server-side; value sanitized before the write.
  **Accept (Low/Info) only when every such counterexample is refuted AND the crossing is direct**
  (attacker source → trusted-store write). Otherwise reject/downgrade citing the holding counterexample.
  Never raise a trust-boundary finding above Low.
- [ ] **Step 2: Manual verification** — re-audit a trustbound case; confirm accept at Low with a resolved
  counterexample checklist, and that a constant-value case (e.g. the `scr.getTheValue` pattern) is rejected.
- [ ] **Step 3: Commit** — `git add agents/oswe-verifier.md && git commit -m "feat(sp7): verifier accepts only direct trust-boundary crossings"`

### Task 6: report + report.json present the hygiene lane separately (prompt)

**Files:** `skills/audit/SKILL.md`

- [ ] **Step 1: Edit §7 report format** — add a **"Hygiene / Trust-boundary (CWE-501)"** section, listed
  **after** exploit findings/chains and visually separate, stating these are non-exploitable hygiene
  findings. They appear in `report.json.findings` with `vuln_class:"trust-boundary"` like any finding (no
  new field needed); the Markdown/HTML must not mix them into the exploit-chain or RCE sections.
- [ ] **Step 2: Manual verification** — a run with a trustbound case shows the Hygiene section, and the
  case is absent from the exploit-chain section.
- [ ] **Step 3: Commit** — `git add skills/audit/SKILL.md && git commit -m "feat(sp7): report a separate Hygiene/Trust-boundary lane"`

### Task 7: `hygiene_findings` metric (visibility)

**Files:** `benchmark/metrics.mjs`, `benchmark/metrics.test.mjs`

- [ ] **Step 1: Failing test** — `computeMetrics(...).quality.hygiene_findings` counts ledger entries
  promoted as trust-boundary. (Requires the ledger to carry a per-case `hygiene` boolean — extend
  `extract-oswe-adjudications.mjs` to set `hygiene:true` when a case's only accepted findings are
  `vuln_class:"trust-boundary"`, and `build-ledger.mjs` to pass it through, mirroring the SP6 counters.)
- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** the extractor flag + ledger field + metric sum.
- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** — `git add benchmark/extract-oswe-adjudications.mjs benchmark/build-ledger.mjs benchmark/metrics.mjs benchmark/*.test.mjs && git commit -m "feat(sp7): hygiene_findings visibility metric"`

### Task 8: re-audit `trustbound` + gate read

- [ ] Re-run `/oswe:audit --sarif external/bench-stage-sp6/trustbound.sarif external/bench-stage-sp6/trustbound`
  (after session reload), **remove the stale trustbound report** from `.oswe/reports/` first, then
  extract → build-ledger → metrics.
- [ ] **Assert SP7 gates:**
  - `precision` (oswe_over_semgrep) **held at 1.000** — the hygiene lane must not introduce false positives.
  - the 8 trustbound cases are now `promoted` (recall recovers); `recall` ↑ from 0.929.
  - **every** promoted trustbound finding is `Low`/`Info` (schema-guaranteed) and in **no** chain.
  - SP6 gates unchanged: `finding_proof_complete_rate`/`chain_proof_complete_rate`/`ce_resolved_rate` = 1.000.
- [ ] Record the new numbers + the "OSWE-core + hygiene lane" framing in `benchmark/BENCHMARK.md`.

## 4. Non-goals (v1)

- No trust-boundary support for non-Java stacks in v1 (the benchmark is Java; add node/python/php/.NET
  sinks as a fast follow once the Java lane is measured).
- No Medium+/chain promotion for trust-boundary — ever (contract §3/§4).
- No new severity enum — Low/Info already exist; the lane is a `vuln_class` + invariants, not new types.
- No app graph (the SP6 gate said reasoning, not structural).

## 5. Gates (success criteria)

| Gate | Threshold |
|---|---|
| `precision` (oswe_over_semgrep) | **= 1.000** (no regression — the lane adds no FP) |
| `recall` | **> 0.929** (the 8 trustbound recovered) |
| trust-boundary severity | **100% Low/Info** (schema-enforced, Task 1) |
| trust-boundary in chains | **0** (apply-verdicts-enforced, Task 2) |
| `finding_proof_complete_rate` / `chain_proof_complete_rate` / `ce_resolved_rate` | **= 1.000** (unchanged) |

## 6. Self-review

- Contract coverage: §1.2/1.3 → Task 1 (schema Low/Info). §1.4 → Task 2 (chain exclusion). §1.5 → Task 5
  (verifier direct-crossing). §1.1/recognition → Tasks 3–4 (sinks + analyzer). §1.6 → Task 6 (report).
- Deterministic where possible (Tasks 1, 2, 7 are TDD-tested); prompt tasks (4, 5, 6) are benchmark-verified
  in Task 8.
- Type consistency: the lane key is the literal `vuln_class:"trust-boundary"` everywhere (schema, apply-
  verdicts, extractor, prompts).
- No placeholder: every code step shows the schema/test it adds.
