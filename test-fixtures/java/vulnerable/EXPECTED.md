# Expected audit result (Java vulnerable fixture)

The auditor should report a **Critical** unauthenticated-RCE chain:

1. `auth-bypass` (trusted client header) — `VulnController.java` `isAdmin`: authorization is decided by
   the client-controllable `X-User-Role` header, so an unauthenticated attacker sets `X-User-Role: admin`.
2. `spel-injection` (expression-language injection) — `VulnController.java` `/admin/eval`:
   `new SpelExpressionParser().parseExpression(q).getValue()` evaluates the attacker's `q`, e.g.
   `T(java.lang.Runtime).getRuntime().exec(...)` → RCE.

Chain: unauthenticated → forged `X-User-Role: admin` → SpEL injection → **RCE**.

## Plus a Low hygiene finding (CWE-501 trust-boundary)

`TrustBoundary.java` `store`: the attacker-controlled `uid` parameter is written into the trusted
session via `HttpSession.setAttribute` — a **Low** trust-boundary hygiene finding, **not** part of the
RCE chain.
