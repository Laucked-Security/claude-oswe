# oswe — White-Box Security Audit Plugin for Claude Code

Deep, OSWE-style white-box web application security audit. Run `/oswe:audit` in a trusted
workspace to detect source-to-sink vulnerabilities and chain them toward unauthenticated RCE,
with an evidence-backed report.

## Scope
PHP (Laravel/Symfony/vanilla), Node.js (Express/Nest), Python (Flask/Django), Java (Spring), and .NET (ASP.NET).

Each audit writes a redaction-safe Markdown report to `.oswe/reports/` **and**, alongside it, a
self-contained visual HTML report (`oswe-report-*.html`) with severity, exploit-chain, coverage, and
finding-status charts. The HTML is a single zero-dependency file (inline CSS + SVG, no scripts) —
open it in a browser and `Ctrl+P → Save as PDF` for a shareable PDF.

## Install (local dev)
```bash
claude --plugin-dir /path/to/claude-oswe
```

## Usage
```
/oswe:audit            # audit the whole project
/oswe:audit src/api    # restrict to a path (must stay inside the project)
```
The audit never auto-runs (`disable-model-invocation: true`); it triggers only on the explicit
command. A dated report is written to `.oswe/reports/`.

## How it works
A skill orchestrates: recon → partition → analyze (parallel read-only `oswe-analyzer` subagents,
max 4) → aggregate/dedupe → build chains → verify (independent `oswe-verifier`, batched) → report.
Agent outputs are JSON validated against `skills/audit/schemas/` by the Node validators in
`skills/audit/scripts/` (AJV under the hood). Requires **Node.js ≥ 20**.

## Authorization & ethics
For **authorized** white-box review of code you own or are permitted to test, for **defensive**
purposes (find and fix). Do not audit untrusted/hostile repositories. Secrets are never written to
the report (`[REDACTED]`). "No path to RCE" means "none found within the analyzed coverage", not
proof of absence.

## Development
`skills/audit/scripts/validators.mjs` is a **self-contained, zero-runtime-dependency** ESM file
(committed): the six AJV-generated validators with the one runtime helper inlined — no `import`, no
`require`, no `node_modules` needed to run it. Run the test suites (they need only Node ≥ 20):
```bash
( cd skills/audit/scripts && node --test )
```

Regenerate `validators.mjs` after changing any schema (AJV is a **dev-only** dependency, used only to
generate; not needed at runtime):
```bash
( cd skills/audit/scripts && npm install && npm run build && node --test )
```
`build-validators.mjs` runs AJV standalone code generation and inlines the single `ucs2length` runtime
helper — no bundler (no esbuild) required.
