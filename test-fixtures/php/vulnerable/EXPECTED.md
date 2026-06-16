# Expected audit result (PHP vulnerable fixture)

The auditor should report a **Critical** unauthenticated-RCE chain:

1. `auth-bypass` (type-juggling) — `public/login.php`: `md5($pass) == $STORED_HASH` with a `0e`
   magic hash → unauthenticated login bypass.
2. `file-upload` (unrestricted) — `public/upload.php`: `move_uploaded_file` with attacker-controlled
   name, no validation, under web root → upload a `.php` web shell.

Chain: unauthenticated → magic-hash login bypass → upload `shell.php` → **RCE**.
