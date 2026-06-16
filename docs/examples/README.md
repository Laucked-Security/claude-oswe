# Example reports

These are **illustrative** `/oswe:audit` deliverables, committed here so you can see what the tool
produces **before** installing it. Each is the Markdown report exactly as written to `.oswe/reports/`
during a real run; an equivalent self-contained **HTML** report (charts + exploit-chain diagram) is
emitted alongside every `.md`.

They were generated against the in-repo `test-fixtures/` (public, intentionally-vulnerable / hardened
sample apps), so they contain **no real secrets**. In a real audit, any discovered secret value is
replaced with `[REDACTED]` and only `file:line` is cited — see [SECURITY.md](../../SECURITY.md).

| File | Fixture | Outcome |
|---|---|---|
| [`python-vulnerable.md`](python-vulnerable.md) | Flask | **Critique** — unauth mass-assignment → SSTI → RCE |
| [`java-vulnerable.md`](java-vulnerable.md) | Spring Boot | **Critique** — trusted header authz bypass → SpEL → RCE |
| [`dotnet-vulnerable.md`](dotnet-vulnerable.md) | ASP.NET Core | **Critique** — forgeable cookie → command injection → RCE |
| [`python-safe.md`](python-safe.md) | Flask (hardened) | **Clean** — 0 findings (low-noise control) |

> Reading guide: an audit is reported by **final severity**. A finding is `accepted` (verified),
> `downgraded` (verifier reduced it), `rejected` (refuted — moved to the annex), or `not-requested`
> (unverified, shown at provisional severity). The **Coverage** section states what was *not* analyzed.
