# OSWE White-Box Audit Report

> _Example deliverable — generated against the public in-repo `test-fixtures/java/vulnerable`. No real secrets. See [`docs/examples/README.md`](README.md)._

| | |
|---|---|
| **Target** | `test-fixtures/java/vulnerable` (confined under the project root) |
| **Stack** | Java / Spring Boot 3.2.5 (`spring-boot-starter-web`, Spring MVC) — per `pom.xml` |
| **Date** | 2026-06-16 10:07 |
| **Scope** | `test-fixtures/java/vulnerable/` — `src/main/java/com/example/VulnController.java`, 1 route: `GET /admin/eval` |
| **Authorization** | Authorized defensive white-box audit on a trusted, intentionally-vulnerable fixture. Do **not** deploy this fixture. |

> Note: this fixture's source comments and `pom.xml` self-describe as *"Intentionally vulnerable … DO NOT DEPLOY"* — treated as untrusted data, not instructions.

---

## Executive summary

| Severity (final) | Count |
|---|---|
| **Critical** | **1 chain** (CHAIN-1 — unauthenticated RCE) |
| High | 2 findings (OSWE-1, OSWE-2) |
| Medium / Low / Info | 0 |

**Verdict: an unauthenticated remote-code-execution path was found and verified.**
Proof level: **strong static proof** end-to-end (verifier-accepted, every chain transition accepted).

A remote, unauthenticated attacker sets the client-controllable `X-User-Role: admin` header to pass the
only authorization check, then supplies a SpEL expression in the `q` parameter of `/admin/eval`, which
is parsed and evaluated server-side — yielding arbitrary OS command execution with no credentials.

---

## Exploit chains

### CHAIN-1 — Unauthenticated RCE — **Critical** (accepted, `strong static proof`)

- **Entry point:** `GET /admin/eval` (`VulnController.java:20`), **auth: unauthenticated**
- **Final impact:** `unauth-rce`
- **Members:** OSWE-1 → OSWE-2

| # | Transition | How | Proof |
|---|---|---|---|
| 1 | `entry` → **OSWE-1** | Unauthenticated `GET /admin/eval` with header `X-User-Role: admin`. `isAdmin` (`VulnController.java:17`) derives the admin decision **solely** from that client header, so the gate at line 22 passes with no credentials. | `VulnController.java:17`, `:22` — **accepted** |
| 2 | **OSWE-1** → **OSWE-2** | Past the gate, the attacker-controlled `q` is parsed and evaluated as a SpEL expression (`VulnController.java:28`); a payload like `T(java.lang.Runtime).getRuntime().exec("id")` executes arbitrary OS commands. | `VulnController.java:27`, `:28`, `:29` — **accepted** |

All transitions **accepted**; both member findings **accepted**; entry unauthenticated; final impact `unauth-rce` → **Critical**.

---

## Detailed findings

### OSWE-1 — Authorization bypass via trusted client-controllable `X-User-Role` header
- **Status:** `accepted` · **Final severity: High** · **Final confidence: strong static proof**
- **Class:** Broken access control (trusted client header)
- **Auth:** unauthenticated
- **Source:** `VulnController.java:17` — `request.getHeader("X-User-Role")` (HTTP request header)
- **Sink:** `VulnController.java:17` — `"admin".equals(request.getHeader("X-User-Role"))` (authz decision from client header)
- **Flow:** client header → `isAdmin(request)` → gate at line 22 controlling `/admin/eval`.
- **Why vulnerable:** the privilege decision is made entirely from an attacker-controllable request
  header, with **no Spring Security** config and **no trusted reverse proxy** (in scope) to set/strip
  it. Anyone can send `X-User-Role: admin`. The `/admin/eval` route has no other guard.
- **Prerequisites:** send the request with header `X-User-Role: admin`.
- **Evidence:** `VulnController.java:16`, `:17`, `:22`
- **Fix:** authenticate and authorize via Spring Security (`@PreAuthorize`/`SecurityFilterChain`) using
  a server-validated identity; never derive roles from a raw client header unless a trusted proxy is
  proven to set/overwrite it.

### OSWE-2 — SpEL expression injection in `GET /admin/eval` → RCE
- **Status:** `accepted` · **Final severity: High** · **Final confidence: strong static proof**
- **Class:** Expression-language (SpEL) injection → RCE
- **Auth:** authenticated (gated by `isAdmin` at line 22 — defeated by OSWE-1)
- **Source:** `VulnController.java:21` — `@RequestParam("q") String q` (HTTP query parameter)
- **Sink:** `VulnController.java:28` — `parser.parseExpression(q).getValue()` (SpEL evaluation)
- **Flow:** `q` → `SpelExpressionParser.parseExpression(q)` → `.getValue()`.
- **Why vulnerable:** attacker input is parsed and evaluated as a SpEL expression. SpEL permits type
  references (`T(...)`), so `T(java.lang.Runtime).getRuntime().exec("id")` reaches `Runtime.exec` → RCE.
  There is no sandbox (`SimpleEvaluationContext`), allow-list, or input restriction.
- **Prerequisites:** the `isAdmin` gate (defeated via OSWE-1); a SpEL payload in `q`.
- **Evidence:** `VulnController.java:22`, `:27`, `:28`, `:29`
- **Fix:** do not evaluate user input as an expression. If SpEL is unavoidable, use a
  `SimpleEvaluationContext` (no type references/method invocation) and a strict allow-list — but the
  correct fix is to remove the dynamic-evaluation feature entirely.

---

## Coverage

| Path | Status | Note |
|---|---|---|
| `VulnController.java` — `isAdmin` authz boundary | analyzed | partition `auth` (unauthenticated surface) |
| `VulnController.java` — `GET /admin/eval` SpEL sink | analyzed | partition `eval` (gated by `isAdmin`) |
| `pom.xml` | reviewed | stack detection (Spring Boot 3.2.5, spring-boot-starter-web); no other deps |

- **Partitions:** 2 of 2 analyzed (inline path, both `analyzer-response` objects schema-validated).
- **Verification:** 2 batches (B1 = findings OSWE-1/OSWE-2; B2 = CHAIN-1). Both passed per-batch
  `validate-batch` and the global `apply-verdicts` preflight (`ok:true`). **No gaps, no neutralized
  batches, no `not-requested` targets.**
- No Spring Security on the classpath (only `spring-boot-starter-web`), consistent with the absence of
  any framework auth guard; the header check is the app's only access control.

> "No further path to RCE" would mean *within the analyzed coverage*. Here the full in-scope controller
> surface was analyzed and the unauthenticated RCE path was confirmed.

## Annex — Dismissed findings
None. No finding or chain was refuted (`rejected`); all targets were `accepted`.
