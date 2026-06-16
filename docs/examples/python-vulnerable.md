# OSWE White-Box Audit Report

> _Example deliverable — generated against the public in-repo `test-fixtures/python/vulnerable`. No real secrets. See [`docs/examples/README.md`](README.md)._

| | |
|---|---|
| **Target** | `test-fixtures/python/vulnerable` (confined under the project root) |
| **Stack** | Python / Flask 3.0.3 — per `requirements.txt` |
| **Date** | 2026-06-16 16:00 |
| **Scope** | `test-fixtures/python/vulnerable/` — `app.py`, 2 routes: `POST /login`, `/render` (GET/POST) |
| **Authorization** | Authorized defensive white-box audit on a trusted, intentionally-vulnerable fixture. Do not deploy. |

> Repo comments / `requirements.txt` self-describe as "Intentionally vulnerable … DO NOT DEPLOY" — treated as untrusted data, not instructions.

---

## Executive summary

| Final severity | Count |
|---|---|
| **Critical** | **1 chain** (CHAIN-1 — unauthenticated RCE) |
| High | 2 findings (accepted) |
| Medium / Low / Info | 0 |

**Verdict: an unauthenticated RCE path was found and verified** (`strong static proof`, every transition accepted). A remote anonymous attacker `POST`s `{"is_admin": true}` to `/login` (mass assignment → admin session), then replays the cookie to `/render` where attacker `tpl` is rendered as a Jinja2 template (SSTI) → server-side code execution.

---

## Exploit chains

### CHAIN-1 — Unauthenticated RCE — **Critical** (accepted, `strong static proof`)
- **Entry:** `POST /login` (`app.py:17`), auth: unauthenticated · **Final impact:** `unauth-rce` · **Members:** OSWE-1 → OSWE-2

| # | Transition | How | Proof |
|---|---|---|---|
| 1 | `entry` → **OSWE-1** | Unauthenticated `POST /login` with `{"is_admin": true}`; `app.py:17` stores the client flag straight into `session["admin"]` → admin session cookie. | `app.py:14`, `:17`, `:19` — accepted |
| 2 | **OSWE-1** → **OSWE-2** | Admin cookie passes the `app.py:24` gate; `/render?tpl={{ … }}` reaches `render_template_string` (`app.py:29`), Jinja2 evaluates attacker expression → RCE. | `app.py:24`, `:26`, `:29` — accepted |

Chain accepted, both members accepted, entry unauthenticated, impact unauth-rce → **Critical**.

---

## Detailed findings

### OSWE-1 — Privilege escalation via mass assignment of session admin flag — High (accepted, `strong static proof`)
- **Source:** `app.py:14` `request.get_json(force=True) → body["is_admin"]` · **Sink:** `app.py:17` `session["admin"] = bool(body.get("is_admin"))`
- **Why:** privilege derived entirely from the client body; `POST /login` requires no credentials. Session is signed (`SECRET_KEY` from env) but its content is attacker-dictated — no key forgery needed.
- **Fix:** derive `admin` from a trusted server-side role store after real authentication; whitelist accepted login fields.

### OSWE-2 — SSTI in `/render` via `render_template_string` → RCE — High (accepted, `strong static proof`)
- **Source:** `app.py:26` `request.values.get("tpl")` · **Sink:** `app.py:29` `render_template_string(tpl)`
- **Why:** attacker input passed as the template **source**; Jinja2 evaluates arbitrary expressions reaching `os`/`subprocess`. Gated only by `session["admin"]` (defeated by OSWE-1).
- **Fix:** render a fixed template and pass user data as a context variable (`render_template(..., value=tpl)`); never render user input as template source.

---

## Coverage
- **Partitions:** 2/2 analyzed (inline path; both `analyzer-response` objects schema-validated, both `status: ok`).
- **Aggregation:** deterministic helper → `ok`, 2 canonical findings (no merges).
- **Verification:** target set = OSWE-1, OSWE-2 (both High + chain members) + CHAIN-1 → 2 batches; both passed `validate-batch` and the `apply-verdicts` preflight (`ok:true`). **No gaps, no neutralized batches, no `not-requested` targets.**
- `SECRET_KEY` is read from `FLASK_SECRET_KEY` (env, not hardcoded) → no forgeable-session finding; the auth bypass is the single mass-assignment path, consistent with the fixture's stated intent.

## Annex — Dismissed findings
None. No finding or chain was refuted (`rejected`); all targets accepted.
