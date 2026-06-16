# Expected audit result (Python vulnerable fixture)

The auditor should report a **Critical** unauthenticated-RCE chain:

1. `auth-bypass` (broken access control / mass assignment) — `app.py` `/login`: `session["admin"]`
   is set from the client-supplied `is_admin` body field, so an unauthenticated attacker sending
   `{"is_admin": true}` becomes admin.
2. `ssti` (server-side template injection) — `app.py` `/render`: `render_template_string(request.values["tpl"])`
   renders an attacker-controlled string as a Jinja2 template → RCE.

Chain: unauthenticated → `is_admin:true` session bypass → Jinja2 SSTI → **RCE**.
