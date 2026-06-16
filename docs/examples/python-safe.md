# OSWE White-Box Audit Report

> _Example deliverable — generated against the public in-repo `test-fixtures/python/safe`. No real secrets. See [`docs/examples/README.md`](README.md)._

| | |
|---|---|
| **Target** | `test-fixtures/python/safe` (confined under the project root) |
| **Stack** | Python / Flask 3.0.3 — per `requirements.txt` |
| **Date** | 2026-06-16 10:01 |
| **Scope** | `test-fixtures/python/safe/` — single module `app.py`, 2 routes: `POST /login`, `/render` (GET/POST) |
| **Authorization** | Authorized defensive white-box audit on a trusted fixture (hardened negative fixture). |

---

## Executive summary

| Severity (final) | Count |
|---|---|
| Critique / Haute / Moyenne / Basse / Info | **0** |

**Verdict: no path to unauthenticated RCE was identified within the analyzed coverage.**
No vulnerabilities were found. This is the **hardened counterpart** of the vulnerable Python fixture:
the two flaws that produced a Critique unauth-RCE chain there (mass-assignment privilege escalation on
`/login`, SSTI on `/render`) are both **correctly mitigated** here.

> "No path to RCE found" means *no path identified within the analyzed coverage* (both routes of
> `app.py`) — it is not a proof of absolute absence.

---

## Exploit chains
None. No findings were produced, so no candidate chains were built and no verification batches were dispatched.

---

## Detailed findings
None.

### Why the analogous vulnerabilities do **not** apply here (defensive confirmation)

These are not findings — they confirm that the expected sinks are properly guarded:

- **`POST /login` — mass assignment / privilege escalation: mitigated.** The admin role is **never**
  taken from the client body. `session["admin"]` is computed from a server-side credential comparison
  (`user == _ADMIN_USER and password == _ADMIN_PASS`, `app.py:23`) where `_ADMIN_USER`/`_ADMIN_PASS`
  come from the **environment only** (`app.py:13-14`) with **deny-by-default** if unconfigured
  (`bool(_ADMIN_USER) and bool(_ADMIN_PASS) and …`). No default/hardcoded credential exists in source,
  so a white-box reader cannot recover one. Inputs are coerced with `str()` (`app.py:20-21`),
  neutralizing object/type-confusion.
- **`/render` — SSTI → RCE: mitigated.** `render_template_string` is called with a **fixed literal
  template** `"<h1>Hello {{ name }}</h1>"` and the user value is passed as a **context variable**
  (`name=name`, `app.py:35`), not as the template source. Attacker input is rendered as autoescaped
  **data**, never compiled/evaluated as a Jinja2 expression — so no `{{ … }}` payload reaches
  `os`/`subprocess`. The admin gate at `app.py:30` remains, but even an authenticated admin cannot
  achieve SSTI here.
- **Session integrity: sound.** `app.secret_key` is read from `FLASK_SECRET_KEY` (`app.py:9`) — not a
  hardcoded literal — so there is no forgeable-session (cookie-forgery) auth-bypass path.

---

## Coverage

| Path | Status | Note |
|---|---|---|
| `app.py` — `POST /login` | analyzed | partition `auth` (unauthenticated surface) — clean |
| `app.py` — `/render` (GET/POST) | analyzed | partition `render` (gated by `session["admin"]`) — clean |
| `requirements.txt` | reviewed | stack detection only (Flask 3.0.3; no lockfile in scope) |

- **Partitions:** 2 of 2 analyzed (inline path; both `analyzer-response` objects schema-validated, both `status: ok`, zero findings).
- **Aggregation:** ran the deterministic helper on the empty finding set → `ok`, 0 canonical findings.
- **Verification:** no targets (no chain members, no provisional-`Haute` findings) → no batches dispatched.
- **No gaps, no neutralized batches, no `not-requested` targets, no analyzer/partition errors.**

## Annexe — Findings écartés
None. No finding or chain was produced, so nothing was refuted.
