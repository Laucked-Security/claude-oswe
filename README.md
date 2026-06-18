<div align="center">

# 🛡️ claude-oswe

### White-Box Security Audit plugin for Claude Code

**A [Laucked Security](https://github.com/Laucked-Security) project**

[![ci](https://github.com/Laucked-Security/claude-oswe/actions/workflows/ci.yml/badge.svg)](https://github.com/Laucked-Security/claude-oswe/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Tests: 190 passing](https://img.shields.io/badge/tests-190%20passing-brightgreen)
![Node ≥ 20](https://img.shields.io/badge/node-%E2%89%A520-339933?logo=node.js&logoColor=white)
![Stacks: PHP · Node · Python · Java · .NET](https://img.shields.io/badge/stacks-PHP%20%C2%B7%20Node%20%C2%B7%20Python%20%C2%B7%20Java%20%C2%B7%20.NET-blue)
![Claude Code plugin](https://img.shields.io/badge/Claude%20Code-plugin-d97757)

</div>

**Deep, OSWE-style white-box web-app security audit, run from your editor.** Type `/oswe:audit` in a
repo you're allowed to test; the plugin traces attacker input from **source → sink**, chains the
findings toward **unauthenticated RCE**, **verifies** each chain under a proof contract, and writes an
evidence-backed report (Markdown **+** a self-contained visual HTML report you can save as PDF).

---

## The problem it solves

Asking an LLM "are there vulnerabilities in this code?" gives you a confident wall of maybes: false
positives on safe code, no exploit chain, no proof, no reproducibility. That's noise, not an audit.

`oswe` is built to **not do that**:

- **Determinism where it matters.** Severity, dedup, and the "is this a Critical unauth-RCE?" decision
  are **not** left to the model — they run in tested, dependency-free Node helpers with **190 unit
  tests** (158 pipeline + 32 benchmark). The model *finds*; the helpers *decide*.
- **A verifier that pushes back.** Every candidate chain and high-severity finding is re-checked by an
  independent verifier that can **downgrade or reject** — it doesn't rubber-stamp the analyzer.
- **Schema-gated I/O.** Each agent response is validated against a JSON Schema before it's trusted; a
  malformed response is rejected and re-run, never silently used to invent data.
- **Low noise, proven.** On the clean, real-world [Flask tutorial](docs/examples/python-safe.md) it
  reports **0 exploitable findings**. On real vulnerable code (OWASP NodeGoat) it finds and verifies a
  real RCE chain. See [Proven on real code](#proven-on-real-code).

This is an **OSWE-style audit assistant** for finding and fixing bugs — **not** a penetration test and
not a safety guarantee. See [Honest limits](#honest-limits).

---

## Install

Requires **Node.js ≥ 20** (the validators and tests target it; the audit aborts early without it).

```bash
# Run Claude Code with the plugin loaded from a local checkout:
git clone https://github.com/Laucked-Security/claude-oswe.git
claude --plugin-dir ./claude-oswe
```

That's it — no `npm install` needed to *use* it. The runtime validators are committed as a
self-contained, zero-dependency file (AJV is a **dev-only** tool used to regenerate them).

## Usage

```text
/oswe:audit                # audit the whole project
/oswe:audit src/api        # restrict to a sub-path (kept inside the project root)
/oswe:audit --sarif results.sarif        # also adjudicate a SAST's findings (Semgrep/CodeQL SARIF)
/oswe:audit --sarif results.sarif src/api  # ...restricted to a sub-path
```

The audit **never auto-runs** (`disable-model-invocation: true`) — it triggers only on the explicit
command. A timestamped report is written to `.oswe/reports/oswe-report-YYYY-MM-DD-HHMM.{md,html}`.

### Example run (abridged)

```text
/oswe:audit test-fixtures/python/vulnerable

Verdict: unauthenticated RCE — Critical (strong static proof)

CHAIN-1  POST /login  { "is_admin": true }   → session["admin"] mass-assignment (OSWE-1)
           └─►  /render?tpl={{ … }}          → Jinja2 SSTI via render_template_string (OSWE-2)  → RCE
         entry: unauthenticated · 2 transitions, both accepted

Findings: 2 High (accepted) · Coverage: 2/2 partitions · no gaps
Report:  .oswe/reports/oswe-report-2026-06-16-1600.md  (+ .html)
```

📄 **Full example reports** (real output, public fixtures, no secrets): [`docs/examples/`](docs/examples/) —
[Python](docs/examples/python-vulnerable.md) · [Java](docs/examples/java-vulnerable.md) ·
[.NET](docs/examples/dotnet-vulnerable.md) · [a clean "safe" run](docs/examples/python-safe.md).

---

## Supported stacks

| Stack | Frameworks | Example sink classes detected |
|---|---|---|
| **PHP** | Laravel, Symfony, vanilla | type-juggling/magic-hash auth bypass, unrestricted upload, SQLi, command injection, PHP object injection |
| **Node.js** | Express, Nest | NoSQL operator injection, SSJI (`eval`), prototype pollution, command injection, SSRF |
| **Python** | Flask, Django | SSTI (`render_template_string`), `pickle`/`yaml.load` deserialization, mass assignment, SQLi |
| **Java** | Spring | SpEL/OGNL injection, Java deserialization gadget chains, command injection, XXE |
| **.NET** | ASP.NET (Core & classic) | forgeable/unsigned auth cookies, `BinaryFormatter` deserialization, command injection, XXE |

Each stack has a curated source→sink reference under [`skills/audit/references/`](skills/audit/references/).
A polyglot repo loads every relevant reference and partitions the audit by stack.

---

## Hybrid mode — make your SAST precise (optional)

Pass a SARIF file and `oswe` treats each result as a **lead**: it reads the cited code and either
**promotes** it into a proven finding (chained + verified like any other) or **refutes** it with a
reason. You get your SAST's scale and rule coverage, plus `oswe`'s discovery of the logic/auth bugs
SAST misses — and a report where every item is proven or explicitly refuted.

**Measured against raw Semgrep on OWASP BenchmarkJava** (an 88-case stratified subset spanning
**all 11 CWE categories**, CWE-matched per the OWASP methodology):

| | precision | false-positive rate |
|---|---|---|
| Semgrep (official Java rules) | 0.732 | 0.341 |
| **oswe-over-Semgrep** | **1.000** | **0.000** |

`oswe` refuted **all 15** of Semgrep's false positives — across every category — while keeping 40 of
41 true positives (one defensible recall cost, scored against us anyway). On the categories where
Semgrep was already precise (`xss`/`weakrand`/`securecookie`/`crypto`), `oswe` added **zero** false
refutations. It also **recovered a true positive Semgrep missed** (a trust-boundary bug found by LLM
analysis) and chained a SQLi to **unauthenticated RCE** via HSQLDB `CALL`. Full result, per-category
breakdown, and honest caveats: [`benchmark/BENCHMARK.md`](benchmark/BENCHMARK.md); reproduce via
[`benchmark/README.md`](benchmark/README.md).

---

## How it works

```text
recon → partition (by module / framework / auth boundary)
      → analyze   (parallel read-only oswe-analyzer subagents, max 4)
      → aggregate/dedupe   (deterministic Node helper, stable OSWE-N ids)
      → build chains  → verify  (independent oswe-verifier, bound batches)
      → apply verdicts (deterministic Critical gating) → report (.md + .html)
```

- **Read-only agents.** The analyzer/verifier subagents cannot modify your code.
- **Confined scope.** The path argument is normalized by a tested confinement helper that rejects
  anything escaping the project root (`../`, symlinks, sibling-prefix tricks).
- **Critical gating.** A chain is `Critical` **only if** the verifier accepted it end-to-end, every
  member finding is accepted, the entry is `unauthenticated`, and the impact is `unauth-rce`.
- **Secrets never leave.** Discovered secret values are `[REDACTED]`; only `file:line` is cited.
  Intermediate `.oswe/tmp/` files are purged at start, end, and on any abort.

The seven JSON Schemas live in [`skills/audit/schemas/`](skills/audit/schemas/); the deterministic
helpers and their tests in [`skills/audit/scripts/`](skills/audit/scripts/).

---

## Proven on real code

Run against [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) — a real multi-module Express + MongoDB
app, not a toy fixture — `/oswe:audit` found and **verified** an end-to-end RCE chain:

```text
Verdict: effectively-unauthenticated RCE — Critical (strong static proof)

CHAIN-1   POST /signup  (open self-registration → instant authenticated session)
            └─►  eval(req.body.preTax)  on POST /contributions   → server-side RCE
          24 findings across 6 partitions · 7 High accepted
```

What makes the result trustworthy rather than noisy:

- the **verifier downgraded 4 over-eager `High` findings** (e.g. a "stored XSS" neutralised by
  `marked sanitize:true`) instead of accepting them;
- the **schema gate rejected one malformed analyzer response** and re-ran that partition once — no data
  is invented to fill a gap;
- the headline chain is reported as **"effectively-unauthenticated"** with the open-registration caveat
  stated, not inflated.

And the control: against the clean [Flask tutorial `flaskr`](docs/examples/python-safe.md) the same
pipeline reports **0 exploitable findings** (one Info-level hardening note, not inflated). Finds real
chains on real vulnerable code; stays quiet on clean code.

---

## Honest limits

- **OSWE-style assistant, not a pentest.** This is **static** white-box source analysis. "Verified" =
  **strong static proof** (source→sink under a proof contract), **not** a live exploit fired at a
  running target. No dynamic execution, fuzzing, or runtime confirmation.
- **"No path to RCE" ≠ safe.** It means *none found within the analyzed coverage*. Budgeted partitions,
  unsupported stacks, and skipped paths are listed in each report's **Coverage** section — read it.
- **The verifier shares the model's blind spots.** It's an independent pass with a strict contract, not
  ground truth. Confirm findings before acting; triage `not-requested` items yourself.
- **Scope/scale bounded.** Up to 12 partitions per audit; very large monorepos will hit coverage gaps
  (reported, never hidden). Dependency/gadget analysis is read-on-demand, not exhaustive.
- **Five stacks**, one curated reference page each — broad sink coverage, not an exhaustive SAST ruleset.

Treat the output as **high-quality leads with evidence**, to be confirmed and fixed by an engineer.

---

## Development

The runtime validator [`skills/audit/scripts/validators.mjs`](skills/audit/scripts/validators.mjs) is a
**self-contained, zero-runtime-dependency** ESM file (the AJV-generated validators with the one runtime
helper inlined). Run the suites (Node ≥ 20 only, no install):

```bash
( cd skills/audit/scripts && node --test )          # 158 pipeline tests
( cd benchmark && node --test )                     # 32 benchmark-engine tests
node .github/scripts/check-structure.mjs            # stacks / references / fixtures-markers gate
```

Regenerate `validators.mjs` after changing any schema (AJV is dev-only, used only to generate):

```bash
( cd skills/audit/scripts && npm install && npm run build && node --test )
```

**CI** ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the unit tests on Node 20 & 22,
runs the structure gate, and verifies the committed `validators.mjs` is in sync with the schemas.
`claude plugin validate . --strict` is run as a **local gate** before release (it needs the Claude
Code CLI, which isn't available on the CI runner).

---

## Authorization & ethics

For **authorized** white-box review of code you own or are permitted to test, for **defensive**
purposes only. **Do not** audit untrusted, hostile, or unauthorized repositories. A hostile repo's
comments and strings are treated as untrusted data, never instructions. See [SECURITY.md](SECURITY.md)
for the full responsible-use policy and how to report a vulnerability in the plugin itself.

## License

[MIT](LICENSE) © 2026 [Laucked](https://github.com/Laucked-Security)
