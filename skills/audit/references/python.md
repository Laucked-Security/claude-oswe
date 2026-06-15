# Python / Flask / Django — Source→Sink Reference

## Sources (attacker-controllable)
- Flask: `request.args`, `request.form`, `request.values`, `request.json` / `request.get_json()`,
  `request.data`, `request.cookies`, `request.headers`, `request.files`. **Note:** `request.json`
  values can be objects/arrays/booleans, not just strings — central to type-confusion and
  mass-assignment bugs.
- Django: `request.GET`, `request.POST`, `request.body`, `request.COOKIES`, `request.META`
  (headers like `HTTP_*`), `request.FILES`.

## Dangerous sinks by class
- **SSTI (template injection) → RCE**: `flask.render_template_string(user_input)`,
  `jinja2.Template(user_input).render()`, `Template(...).render()` where the **template string** is
  attacker-controlled. Payloads like `{{ ''.__class__.__mro__[1].__subclasses__() }}` reach
  `os`/`subprocess`. Safe form: a **fixed** template with user input passed as a context variable.
- **Deserialization → RCE**: `pickle.loads` / `pickle.load`, `cPickle`, `yaml.load` without
  `Loader=SafeLoader` (use `yaml.safe_load`), `marshal.loads`, `shelve`, `jsonpickle` on attacker data.
- **Command injection**: `os.system`, `subprocess.call/run/Popen` with `shell=True` and a built string,
  `os.popen`, `commands.getoutput` (py2). Safe form: an argument **list** with `shell=False`.
- **Code eval**: `eval`, `exec`, `compile`, `__import__` on attacker input.
- **SQLi**: string concatenation / f-strings into `cursor.execute(...)`, Django `.raw()` /
  `.extra()` / `RawSQL` with concatenation, SQLAlchemy `text()` built from input.
- **SSRF**: `requests.get/post`, `urllib.request.urlopen`, `httpx` to an attacker URL/host.
- **Path traversal / LFI**: `open`, `flask.send_file` / `send_from_directory`, `os.path.join(root, x)`
  without normalization + `..` containment check.
- **XXE**: `lxml.etree` / `xml.sax` / `xml.dom.minidom` parsing attacker XML with external entities /
  DTDs enabled (`resolve_entities=True`).

## Auth boundaries (Flask / Django)
- Flask: `@login_required`, manual `session[...]` checks, `flask_login`. A route without a guard, or one
  that derives privilege from **client-supplied data** (e.g. trusting an `is_admin` field in the request
  body — broken access control / mass assignment), is unauthenticated-reachable as that privilege.
- Flask `SECRET_KEY`: a **weak/hardcoded** key lets an attacker forge a signed session cookie →
  auth bypass. Treat a constant `app.secret_key = "..."` as a finding when sessions gate access.
- Django: `@login_required`, `@permission_required`, `PermissionRequiredMixin`, `request.user`.

## Sanitizers and why they often fail
- `markupsafe.escape` / Jinja autoescape is **output encoding (XSS)** — irrelevant to SSTI/RCE/SQLi sinks.
- `shlex.quote` mitigates shell injection **only if actually applied**; its absence around a built shell
  string is the smell.
- `os.path.basename` does not stop all traversal when the extension/path is attacker-influenced downstream.
- Casting to `str()` neutralizes type-confusion (object-valued JSON) — its **absence** is the smell.
