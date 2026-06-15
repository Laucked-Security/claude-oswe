# Expected audit result (.NET vulnerable fixture)

The auditor should report a **Critique** unauthenticated-RCE chain:

1. `auth-bypass` (forgeable cookie) — `Program.cs` `IsAdmin`: authorization checks the raw, unsigned
   client cookie `admin == "1"`, so an unauthenticated attacker sets `Cookie: admin=1`.
2. `cmd-injection` (OS command injection) — `Program.cs` `/admin/ping`: `Request.Query["host"]` is
   concatenated into a `/bin/sh -c "ping -c 1 ..."` string and executed via `Process.Start`, e.g.
   `host=127.0.0.1; id` → RCE.

Chain: unauthenticated → forged `admin=1` cookie → command injection → **RCE**.
