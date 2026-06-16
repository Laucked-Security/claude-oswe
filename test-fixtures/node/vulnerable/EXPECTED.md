# Expected audit result (Node vulnerable fixture)

The auditor should report a **Critical** unauthenticated-RCE chain:

1. `auth-bypass` (NoSQL operator injection) — `app.js` `/login`: `req.body.pass` can be an object
   such as `{"$ne": null}`, bypassing the credential check (no `String()` cast / mongo-sanitize).
2. `cmd-injection` — `app.js` `/diag/ping`: `req.query.host` concatenated into `exec("ping -c 1 " + host)`.

Chain: unauthenticated → NoSQLi login bypass → `host=x; id` command injection → **RCE**.
