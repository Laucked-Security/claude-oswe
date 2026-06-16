# OSWE White-Box Audit Report

> _Example deliverable — generated against the public in-repo `test-fixtures/dotnet/vulnerable`. No real secrets. See [`docs/examples/README.md`](README.md)._

| | |
|---|---|
| **Target** | `test-fixtures/dotnet/vulnerable` (confined under the project root) |
| **Stack** | .NET / ASP.NET Core 8.0 (minimal API, `Microsoft.NET.Sdk.Web`) — per `vulnerable.csproj` |
| **Date** | 2026-06-16 10:15 |
| **Scope** | `test-fixtures/dotnet/vulnerable/` — `Program.cs`, 1 route: `GET /admin/ping` |
| **Authorization** | Authorized defensive white-box audit on a trusted, intentionally-vulnerable fixture. Do **not** deploy this fixture. |

> Note: this fixture's source comments and `.csproj` self-describe as *"Intentionally vulnerable … DO NOT DEPLOY"* — treated as untrusted data, not instructions.

---

## Executive summary

| Severity (final) | Count |
|---|---|
| **Critical** | **1 chain** (CHAIN-1 — unauthenticated RCE) |
| High | 2 findings (OSWE-1, OSWE-2) |
| Medium / Low / Info | 0 |

**Verdict: an unauthenticated remote-code-execution path was found and verified.**
Proof level: **strong static proof** end-to-end (verifier-accepted, every chain transition accepted).

A remote, unauthenticated attacker sets a forgeable `admin=1` cookie to pass the only authorization
check, then supplies shell metacharacters in the `host` query parameter of `/admin/ping`, which are
concatenated into a `/bin/sh -c` command string — yielding arbitrary OS command execution with no
credentials.

---

## Exploit chains

### CHAIN-1 — Unauthenticated RCE — **Critical** (accepted, `strong static proof`)

- **Entry point:** `GET /admin/ping` (`Program.cs:10`), **auth: unauthenticated**
- **Final impact:** `unauth-rce`
- **Members:** OSWE-1 → OSWE-2

| # | Transition | How | Proof |
|---|---|---|---|
| 1 | `entry` → **OSWE-1** | Unauthenticated `GET /admin/ping` with header `Cookie: admin=1`. `IsAdmin` (`Program.cs:8`) trusts the raw, unsigned cookie, so the gate at line 12 passes with no credentials. | `Program.cs:8`, `:12` — **accepted** |
| 2 | **OSWE-1** → **OSWE-2** | Past the gate, the attacker-controlled `host` (`?host=127.0.0.1; id`) is concatenated into the `/bin/sh -c "ping -c 1 …"` argument string (`Program.cs:21`) and executed via `Process.Start` (line 25); shell metacharacters run arbitrary commands. | `Program.cs:15`, `:21`, `:25` — **accepted** |

All transitions **accepted**; both member findings **accepted**; entry unauthenticated; final impact `unauth-rce` → **Critical**.

---

## Detailed findings

### OSWE-1 — Authorization bypass via forgeable unsigned `admin` cookie
- **Status:** `accepted` · **Final severity: High** · **Final confidence: strong static proof**
- **Class:** Broken access control (forgeable client cookie)
- **Auth:** unauthenticated
- **Source:** `Program.cs:8` — `request.Cookies["admin"]` (HTTP request cookie)
- **Sink:** `Program.cs:8` — `request.Cookies["admin"] == "1"` (authz decision from unsigned cookie)
- **Flow:** client cookie → `IsAdmin(request)` → gate at line 12 controlling `/admin/ping`.
- **Why vulnerable:** authorization is decided from a raw, unsigned, client-controllable cookie with
  **no ASP.NET Data Protection, no authentication cookie, and no `[Authorize]`/policy**. Anyone can send
  `Cookie: admin=1`. The route has no other guard.
- **Prerequisites:** send the request with `Cookie: admin=1`.
- **Evidence:** `Program.cs:8`, `:12`
- **Fix:** use ASP.NET Core authentication (cookie auth with Data Protection, or JWT) and
  `[Authorize]`/authorization policies; never derive identity/role from a raw unsigned cookie value.

### OSWE-2 — OS command injection in `GET /admin/ping` via `host` → RCE
- **Status:** `accepted` · **Final severity: High** · **Final confidence: strong static proof**
- **Class:** OS command injection → RCE
- **Auth:** authenticated (gated by `IsAdmin` at line 12 — defeated by OSWE-1)
- **Source:** `Program.cs:15` — `request.Query["host"]` (HTTP query parameter)
- **Sink:** `Program.cs:25` — `Process.Start(psi)` with `FileName="/bin/sh"`, `Arguments="-c \"ping -c 1 " + host + "\""`
- **Flow:** `host` → string concatenation into the `-c` argument → `/bin/sh` via `Process.Start`.
- **Why vulnerable:** `host` is concatenated into a shell command string executed by `/bin/sh -c`.
  Even with `UseShellExecute=false`, the program is `/bin/sh` and `-c` interprets metacharacters, so
  `host=127.0.0.1; id`, `$(id)`, or `` `id` `` run arbitrary commands.
- **Prerequisites:** the `IsAdmin` gate (defeated via OSWE-1); a `host` carrying shell metacharacters.
- **Evidence:** `Program.cs:12`, `:15`, `:21`, `:25`
- **Fix:** invoke the program directly with an argument array — `FileName="ping"`,
  `ArgumentList = { "-c", "1", host }`, no `/bin/sh` — and validate `host` against a strict
  hostname/IP allow-list. Never build a shell string from user input.

---

## Coverage

| Path | Status | Note |
|---|---|---|
| `Program.cs` — `IsAdmin` authz boundary | analyzed | partition `auth` (unauthenticated surface) |
| `Program.cs` — `GET /admin/ping` command sink | analyzed | partition `ping` (gated by `IsAdmin`) |
| `vulnerable.csproj` | reviewed | stack detection (.NET 8.0, ASP.NET Core minimal API); no NuGet deps declared |

- **Partitions:** 2 of 2 analyzed (inline path, both `analyzer-response` objects schema-validated).
- **Verification:** 2 batches (B1 = findings OSWE-1/OSWE-2; B2 = CHAIN-1). Both passed per-batch
  `validate-batch` and the global `apply-verdicts` preflight (`ok:true`). **No gaps, no neutralized
  batches, no `not-requested` targets.**
- No authentication/authorization middleware is configured (minimal API with only the cookie check),
  consistent with the absence of any framework auth guard; the cookie comparison is the app's only access control.

> "No further path to RCE" would mean *within the analyzed coverage*. Here the full in-scope program
> surface was analyzed and the unauthenticated RCE path was confirmed.

## Annex — Dismissed findings
None. No finding or chain was refuted (`rejected`); all targets were `accepted`.
