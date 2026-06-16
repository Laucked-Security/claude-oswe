# Security & Responsible Use

`oswe` is a **defensive** white-box code-audit assistant. It reads source code you control and
reports vulnerabilities **so they can be fixed**. Using it is subject to the rules below.

## Authorized use only

Run `/oswe:audit` **only** on code that you own or are **explicitly authorized** to test
(your own repo, an employer's codebase under a signed engagement, a CTF target, a security-research
target you have permission for).

**Do not** point it at:
- repositories or applications you do not own and have no written permission to assess;
- third-party / hostile codebases (a hostile repo's comments, READMEs, and string literals are treated
  as **untrusted data**, never instructions — but you still must not audit code you're not allowed to);
- production systems for which testing is not contractually permitted.

The tool refuses to silently overreach: the scope argument is confined to the project root by a tested
path-confinement helper, the analyzer/verifier subagents are **read-only**, and the audit only runs on
the explicit `/oswe:audit` command (`disable-model-invocation: true`) — never automatically.

## What this tool is **not**

- **Not a penetration test.** It performs *static* white-box source analysis. "Verified" means
  **strong static proof** (source→sink with a proof contract), **not** a live exploit fired against a
  running target. There is no dynamic execution, fuzzing, or runtime confirmation.
- **Not a guarantee of safety.** "No path to RCE found" means **"none found within the analyzed
  coverage"**, never proof of absence. Budgeted partitions, unsupported stacks, and skipped paths are
  reported in the **Coverage** section — read it.
- **Not a replacement for human review.** Findings are leads for an engineer to confirm and fix.

## Handling of sensitive data

- **Secrets are never written to a report.** Any discovered secret value is replaced with `[REDACTED]`;
  only `file:line` is cited.
- Intermediate working files (`.oswe/tmp/`) may contain pre-redaction data and are **purged at the
  start, end, and on any abort** of every run. `.oswe/` is gitignored — do not commit it.
- Reports under `.oswe/reports/` are redaction-safe by design, but **review before sharing**: file
  paths, route names, and vulnerability detail are disclosed by nature.

## Reporting a vulnerability in this plugin

This is a security tool, so flaws in *it* (e.g. a way to make the auditor write a secret to a report,
a path-confinement escape, a schema-gate bypass, or prompt-injection from audited content escaping the
trust boundary) are taken seriously.

- Please report privately via **GitHub Security Advisories** ("Report a vulnerability") on
  [Laucked-Security/claude-oswe](https://github.com/Laucked-Security/claude-oswe/security/advisories),
  or by email to the maintainer listed in `.claude-plugin/plugin.json`.
- Do **not** open a public issue for an unfixed security flaw.
- Include: affected file(s)/version, a minimal reproduction, and the impact (e.g. "redaction bypass",
  "scope escape").

There is no bug-bounty; this is a best-effort open-source project. Fixes are prioritized by severity.
